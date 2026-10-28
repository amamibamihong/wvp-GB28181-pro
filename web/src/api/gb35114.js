import request from '@/utils/request'

// ----------------------------------------------------------------------
// 证书用途常量（与后端 Gb35114Cert / Gb35114Ca 保持一致）
// ----------------------------------------------------------------------

// 证书用途
export const TYPE_SERVER_IDENTITY = 'SERVER_IDENTITY'   // 服务端证书（本平台）·UAS 签 sign2
export const TYPE_DEVICE_IDENTITY = 'DEVICE_IDENTITY'   // 客户端证书（本平台）·UAC 签 sign1
export const TYPE_ISSUED_DEVICE = 'ISSUED_DEVICE'       // 客户端证书（下级设备）·签发给下级
export const TYPE_TRUSTED_PLATFORM = 'TRUSTED_PLATFORM' // 服务端证书（上级平台）·仅公钥，验 sign2

// CA 用途
// 两者的区别只在「是否持有私钥、能否签发」，不在「服务哪个方向」：
// TRUSTED_CA 既用于验证上级平台证书，也用于验证第三方机构签发的下级设备证书。
export const TYPE_LOCAL_CA = 'LOCAL_CA'     // 本地根 CA（持有私钥，可签发）
export const TYPE_TRUSTED_CA = 'TRUSTED_CA' // 受信任的 CA（仅公钥，参与证书链校验，不可签发）

// 用途中文名，供列表展示
export const TYPE_LABELS = {
  SERVER_IDENTITY: '服务端证书（本平台）',
  DEVICE_IDENTITY: '客户端证书（本平台）',
  ISSUED_DEVICE: '客户端证书（下级设备）',
  TRUSTED_PLATFORM: '服务端证书（上级平台）',
  LOCAL_CA: '本地根CA',
  TRUSTED_CA: '受信任的CA'
}

// ----------------------------------------------------------------------
// CA 管理
// ----------------------------------------------------------------------

/**
 * 生成本地根 CA（私钥留在本平台）
 * @param data {subjectCn, country, province, locality, organization, organizationalUnit, remark}
 * @param validityDays 有效期天数；不传则由后端回退到全局默认
 */
export function generateCa(data, validityDays) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/ca/generate',
    params: { ...data, validityDays }
  })
}

/**
 * 导入外部 CA。CA 没有独立的名称字段，其身份取自证书的主题 CN。
 * @param data {type, remark, certFile, keyFile} —— keyFile 仅本地根 CA 需要
 */
export function importCa(data) {
  const formData = new FormData()
  // 不传 type 由后端默认：带私钥即 LOCAL_CA，仅证书即 TRUSTED_CA
  if (data.type) formData.append('type', data.type)
  if (data.remark) formData.append('remark', data.remark)
  formData.append('certFile', data.certFile)
  if (data.keyFile) formData.append('keyFile', data.keyFile)
  return request({
    method: 'post',
    url: '/api/gb35114/cert/ca/import',
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}

/** 查询 CA 列表，type 可选（LOCAL_CA / TRUSTED_CA） */
export function listCa(type) {
  return request({
    method: 'get',
    url: '/api/gb35114/cert/ca/list',
    params: type ? { type } : {}
  })
}

/** 下载 CA 证书 PEM（交付对端/摄像头导入，用于验签本平台证书） */
export function downloadCa(id) {
  return request({
    method: 'get',
    url: `/api/gb35114/cert/ca/download/${id}`,
    responseType: 'blob'
  })
}

/**
 * 查询该 CA 签发的证书清单（CA 列表点开「关联证书」用）。
 *
 * <p>列表接口只带 certCount 一个数，避免每次刷新都为每张 CA 拉一遍明细。
 */
export function listCaCerts(id) {
  return request({
    method: 'get',
    url: `/api/gb35114/cert/ca/certs/${id}`
  })
}

export function deleteCa(id) {
  return request({
    method: 'delete',
    url: `/api/gb35114/cert/ca/delete/${id}`
  })
}

// ----------------------------------------------------------------------
// 本地身份证书
//
// 服务端证书（本平台）有三条路：
//   1. 一步创建（生成密钥对 + 当场签发）—— createServerIdentity；
//   2. CSR → 本平台签发 —— createCsr 出 CSR，再由 signPendingCsr 用本地根 CA
//      签发（caId 留空即自签），私钥始终留在本平台；
//   3. 回填外部签发的证书 —— importIdentity，或 createCsr 后 completePendingCsr。
// 客户端证书（本平台）只有 CSR 一条路：这张必须由上级签发，本平台只能先出 CSR、
// 等上级签完再回填。
// ----------------------------------------------------------------------

/**
 * 一步创建服务端证书（本平台）：生成密钥对并当场签发。
 * @param data 证书档案 {type, gbId, subjectCn, country, province, locality,
 *             organization, organizationalUnit, remark, keyUsage}
 * @param caId 签发 CA；不传则自签
 * @param validityDays 有效期天数，自签发时刻起算
 */
export function createServerIdentity(data, caId, validityDays) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/server-identity/create',
    params: Object.assign({}, data, { caId: caId, validityDays: validityDays })
  })
}

/**
 * 创建待签发记录（生成密钥对 + CSR，私钥加密后与 CSR 存于同一记录）。
 *
 * 服务端证书与客户端证书（本平台）都用它：前者随后由本平台签发
 * （signPendingCsr）或回填外部证书，后者必须交上级签发后回填。
 * @param data 证书档案 {type, gbId, subjectCn, country, province, locality,
 *             organization, organizationalUnit, remark, keyUsage}
 * @param validityDays 有效期天数，从签发时刻起算
 */
export function createCsr(data, validityDays) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/csr/generate',
    params: Object.assign({}, data, { validityDays: validityDays })
  })
}

/**
 * 用本地根 CA 签发待签发的服务端证书（原地更新该记录，不新增行）。
 *
 * <p>只对服务端证书（本平台）开放：客户端证书必须由上级签发，
 * 本地签出来的上级不认，接入必然被拒。
 * @param id 待签发记录 id
 * @param caId 签发 CA；不传则自签
 * @param validityDays 有效期天数，自签发时刻起算
 */
export function signPendingCsr(id, caId, validityDays) {
  return request({
    method: 'post',
    url: `/api/gb35114/cert/csr/sign/${id}`,
    params: { caId: caId, validityDays: validityDays }
  })
}

/** 用外部 CA 返回的证书回填待签发记录（后端会校验公私钥是否配对） */
export function completePendingCsr(id, certFile) {
  const formData = new FormData()
  formData.append('certFile', certFile)
  return request({
    method: 'post',
    url: `/api/gb35114/cert/csr/complete/${id}`,
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}

/** 导出待签发记录的 CSR（交付外部 CA 用；CSR 不含私钥） */
export function downloadCsr(id) {
  return request({
    method: 'get',
    url: `/api/gb35114/cert/csr/download/${id}`,
    responseType: 'blob'
  })
}

/** 导入本平台身份证书（证书 + 私钥，后端校验配对后加密存私钥） */
export function importIdentity(data, certFile, keyFile) {
  const formData = new FormData()
  Object.keys(data || {}).forEach(k => {
    if (data[k] !== undefined && data[k] !== null) formData.append(k, data[k])
  })
  formData.append('certFile', certFile)
  formData.append('keyFile', keyFile)
  return request({
    method: 'post',
    url: '/api/gb35114/cert/import/identity',
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}

// ----------------------------------------------------------------------
// 下级 / 上级对端证书
// ----------------------------------------------------------------------

/**
 * 由下级提交的 CSR 签发证书（私钥始终留在下级）。
 * @param data {caId, gbId, remark, csrPem, validityDays}
 */
export function issueFromCsr(data) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/issue/csr',
    params: data
  })
}

/** 由下级提交的 CSR 再次签发（续期/补发，复用原记录与国标 ID） */
export function reissueFromCsr(data) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/issue/csr/reissue',
    params: data
  })
}

/**
 * 导入对端证书（仅公钥）：服务端证书（上级平台） / 客户端证书（下级设备）。
 *
 * <p>响应里可能带 importWarning（瞬态字段，不落库）：导入下级设备证书时，
 * 若签发它的 CA 还没导入本平台，会在这里给一句提示。它只是提示，
 * 不影响导入结果 —— 是否信任由设备注册时的证书链校验实时判定。
 */
export function importPeer(data, certFile) {
  const formData = new FormData()
  Object.keys(data || {}).forEach(k => {
    if (data[k] !== undefined && data[k] !== null) formData.append(k, data[k])
  })
  formData.append('certFile', certFile)
  return request({
    method: 'post',
    url: '/api/gb35114/cert/import/peer',
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}

// ----------------------------------------------------------------------
// 查询 / 下载证书 / 删除
// ----------------------------------------------------------------------

/** 查询证书列表（响应不含私钥，仅有 hasKey 布尔） */
export function listCert(type) {
  return request({
    method: 'get',
    url: '/api/gb35114/cert/list',
    params: type ? { type } : {}
  })
}

/**
 * 查询证书策略（只读）。
 *
 * 目前有 rejectExpiredCert、verifyUpstreamCertChain 与 skipCertChainVerify：
 * - rejectExpiredCert：过期证书是否拒绝注册。默认 false —— 过期只在列表上标出，
 *   不拦截注册，由运维决定删除/重签；
 * - verifyUpstreamCertChain：本平台作下级时是否校验上级证书链。默认 true —— 自签的
 *   上级证书必须也作为「受信任的 CA」导入一份；置 false 即放宽，页面顶部显示黄色告警；
 * - skipCertChainVerify：是否全局跳过证书链验证。默认 false —— 置 true 用于现场
 *   拿不到 CA 的情况，此时页面顶部显示红色告警；指纹反查、有效期与握手验签不受影响；
 * - moduleId：主题 CN 里「设备ID_密码模块ID」后半段用的密码模块 ID（附录 B：22 位十进制）。
 *   取自配置 `gb35114.module-id`，留空即 22 个 0。由运维按现场备案调整，页面只读不改。
 * 页面据此渲染策略感知的提示文案。
 */
export function getCertPolicy() {
  return request({
    method: 'get',
    url: '/api/gb35114/cert/policy'
  })
}

export function listCertByGbId(gbId) {
  return request({
    method: 'get',
    url: `/api/gb35114/cert/list/${gbId}`
  })
}

/** 下载证书 PEM（私钥无对应接口，不对外提供） */
export function downloadCert(id) {
  return request({
    method: 'get',
    url: `/api/gb35114/cert/download/cert/${id}`,
    responseType: 'blob'
  })
}

export function revokeCert(id) {
  return request({
    method: 'post',
    url: `/api/gb35114/cert/revoke/${id}`
  })
}

/**
 * 删除证书；本地身份证书的私钥与 CSR 同记录，会一并删除。被设备/平台引用时后端拒绝。
 *
 * <p>页面上的「删除」是让证书失效的唯一入口 —— 没有单独的「吊销」按钮，
 * 因为两者对「能不能接入」等价（指纹反查命中已吊销记录拒绝，查不到记录同样拒绝），
 * 而多留一个入口会造出"记录还在、占着唯一性守卫"的中间态。
 * {@link revokeCert} 保留给后端接口与将来的批量/自动化场景，页面不再调用。
 */
export function deleteCert(id) {
  return request({
    method: 'delete',
    url: `/api/gb35114/cert/delete/${id}`
  })
}

/**
 * 删除证书并解除本平台的绑定。
 *
 * <p>用于「国标级联 → 编辑」页删自己的证书：证书此刻仍被<b>本</b> platform 行引用，
 * 直接调 {@link deleteCert} 会被引用守卫拒绝。本接口先把引用它的
 * {@code wvp_platform.device_cert_id} / {@code platform_cert_id} 置空，再删证书。
 * 若还被<b>别的</b>平台或设备引用，照旧拒绝并点名。
 */
export function unbindAndDeleteCert(id) {
  return request({
    method: 'post',
    url: `/api/gb35114/cert/unbind-and-delete/${id}`
  })
}

/**
 * 把证书绑定到级联平台（certId 传 null 表示解绑）。
 *
 * <p>绑定必须<b>即时落库</b>，不能只改前端内存等用户点「保存」：
 * 「国标级联 → 编辑」页拿到的是列表行对象本身，改内存会让人以为绑上了，
 * 一刷新就没了；而且整行保存还要过 {@code uk_platform_unique_server_gb_id}
 * 等前置校验，失败时绑定跟着一起丢，页面上看不出来。
 *
 * <p>type 只接受 DEVICE_IDENTITY（本平台设备证书）与 TRUSTED_PLATFORM（上级平台证书）——
 * 这两类都是「按上级各一张」，归属必须显式记录。
 */
export function bindCertToPlatform(platformId, type, certId) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/bind-platform',
    params: { platformId, type, certId }
  })
}
