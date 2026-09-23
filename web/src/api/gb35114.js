import request from '@/utils/request'

// ----------------------------------------------------------------------
// 证书用途常量（与后端 Gb35114Cert / Gb35114Ca 保持一致）
// ----------------------------------------------------------------------

// 证书用途
export const PURPOSE_SERVER_IDENTITY = 'SERVER_IDENTITY'   // 本地服务端证书（UAS，签 sign2）
export const PURPOSE_DEVICE_IDENTITY = 'DEVICE_IDENTITY'   // 本地客户端证书（UAC，签 sign1）
export const PURPOSE_ISSUED_DEVICE = 'ISSUED_DEVICE'       // 下级客户端证书（签发给下级）
export const PURPOSE_TRUSTED_PLATFORM = 'TRUSTED_PLATFORM' // 上级服务端证书（仅公钥，验 sign2）

// CA 用途
export const PURPOSE_LOCAL_CA = 'LOCAL_CA'     // 本地 CA（持有私钥，可签发）
export const PURPOSE_TRUSTED_CA = 'TRUSTED_CA' // 上级 CA（仅公钥，作为上级服务端证书的签发者留存）

// 用途中文名，供列表展示
export const PURPOSE_LABELS = {
  SERVER_IDENTITY: '本地服务端证书',
  DEVICE_IDENTITY: '本地客户端证书',
  ISSUED_DEVICE: '下级客户端证书',
  TRUSTED_PLATFORM: '上级服务端证书',
  LOCAL_CA: '本地CA',
  TRUSTED_CA: '上级CA'
}

// ----------------------------------------------------------------------
// CA 管理
// ----------------------------------------------------------------------

/** 生成本地根 CA（私钥留在本平台） */
export function generateCa(data) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/ca/generate',
    params: data
  })
}

/**
 * 导入外部 CA。CA 没有独立的名称字段，其身份取自证书的主题 CN。
 * @param data {purpose, remark, certFile, keyFile} —— keyFile 仅本地 CA 需要
 */
export function importCa(data) {
  const formData = new FormData()
  // 不传 purpose 由后端默认：带私钥即 LOCAL_CA，仅证书即 TRUSTED_CA
  if (data.purpose) formData.append('purpose', data.purpose)
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

/** 查询 CA 列表，purpose 可选（LOCAL_CA / TRUSTED_CA） */
export function listCa(purpose) {
  return request({
    method: 'get',
    url: '/api/gb35114/cert/ca/list',
    params: purpose ? { purpose } : {}
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

export function deleteCa(id) {
  return request({
    method: 'delete',
    url: `/api/gb35114/cert/ca/delete/${id}`
  })
}

// ----------------------------------------------------------------------
// 本地身份证书：CSR 流程（私钥由本平台生成并留存，不对外下发）
// ----------------------------------------------------------------------

/**
 * 创建待签发记录（生成密钥对 + CSR，私钥加密后与 CSR 存于同一记录）。
 * @param data 证书档案 {purpose, gbId, subjectCn, country, province, locality,
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

/** 用本平台 CA 签发待签发记录 */
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

/** 生成本平台自签身份证书（无 CA 时的便捷方式） */
export function selfSigned(data, validityDays) {
  return request({
    method: 'post',
    url: '/api/gb35114/cert/selfsigned',
    params: Object.assign({}, data, { validityDays: validityDays })
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

/** 导入对端证书（仅公钥）：上级服务端证书 / 下级客户端证书 */
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
// 查询 / 下载证书 / 吊销 / 删除
// ----------------------------------------------------------------------

/** 查询证书列表（响应不含私钥，仅有 hasKey 布尔） */
export function listCert(purpose) {
  return request({
    method: 'get',
    url: '/api/gb35114/cert/list',
    params: purpose ? { purpose } : {}
  })
}

/**
 * 查询证书策略（只读）。
 *
 * 目前只有 rejectExpiredCert：过期证书是否拒绝注册。默认 false —— 过期只在列表上标出，
 * 不拦截注册，由运维决定吊销/重签。页面据此渲染策略感知的提示文案。
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

/** 删除证书；本地身份证书的私钥与 CSR 同记录，会一并删除 */
export function deleteCert(id) {
  return request({
    method: 'delete',
    url: `/api/gb35114/cert/delete/${id}`
  })
}

/**
 * 复用现有密钥对再签一张服务端证书（公钥不变）。
 * 同组证书可互换，设备导入任一张皆可接入，换证书无需重新配置设备。
 */
export function reissueServerIdentity(sourceId, profile, caId, validityDays) {
  return request({
    method: 'post',
    url: `/api/gb35114/cert/reissue/${sourceId}`,
    params: { caId, validityDays },
    data: profile
  })
}
