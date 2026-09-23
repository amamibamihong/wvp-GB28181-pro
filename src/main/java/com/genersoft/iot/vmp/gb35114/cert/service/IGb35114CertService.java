package com.genersoft.iot.vmp.gb35114.cert.service;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * GB35114 证书管理服务。
 *
 * <p>证书按用途（{@link Gb35114Cert#getPurpose()}）区分，私钥只在本平台自持身份的证书上存在，
 * 且永不通过接口下发。
 */
public interface IGb35114CertService {

    // ------------------------------------------------------------------
    // CA
    // ------------------------------------------------------------------

    /**
     * 生成本地自签根 CA（purpose=LOCAL_CA）。
     *
     * <p><b>本地 CA 全局只保留一份</b>：已存在 LOCAL_CA 时直接拒绝，需先删除旧的
     * （{@link #deleteCa(int)} 会校验引用，仍被证书引用的删不掉）。上级 CA
     * （purpose=TRUSTED_CA）不受此限制，多个上级平台各一份。
     *
     * <p>CA 没有独立的「名称」字段：它的身份就是证书的主题 CN，取自生成参数或证书本身，
     * 不由调用方另起别名 —— 否则同一张 CA 会在页面上出现两个都像名字的字段。
     */
    Gb35114Ca generateCa(String subjectCn, String remark);

    /**
     * 导入外部 CA。purpose=LOCAL_CA 需带私钥；purpose=TRUSTED_CA 仅证书。
     *
     * <p>导入 LOCAL_CA 等价于新建，同样受「本地 CA 只保留一份」约束。
     */
    Gb35114Ca importCa(String purpose, String certPem, String keyPem, String remark);

    /** 查询全部 CA（不含私钥密文）；TRUSTED_CA 附带其服务的上级平台名（瞬态）。 */
    List<Gb35114Ca> queryAllCa();

    /** 按用途查询 CA；TRUSTED_CA 附带其服务的上级平台名（瞬态）。 */
    List<Gb35114Ca> queryCaByPurpose(String purpose);

    /** 按 ID 查询 CA 全列（含私钥密文），供下载证书/内部签发用，禁止直接返回前端。 */
    Gb35114Ca queryCa(int id);

    /** 删除 CA；被证书引用时拒绝。 */
    void deleteCa(int id);

    // ------------------------------------------------------------------
    // 本地身份证书：本平台生成密钥对，私钥加密留存本地
    //
    // 服务端证书（SERVER_IDENTITY）全局只保留一组密钥对：设备侧只存得下一把公钥，
    // 多组并存时「设备绑定的是哪一组」无从判断，选错会让设备验 sign2 失败而平台日志正常。
    // 因此下面三个「新建密钥对」的入口在已存在未吊销的 SERVER_IDENTITY 时一律拒绝，
    // 正常换发请用 reissueServerIdentity（复用密钥对）。
    // 密钥泄露等应急场景：先吊销该组全部证书，守卫即失效，可干净地新建第二组。
    // ------------------------------------------------------------------

    /**
     * 创建待签发记录：生成 SM2 密钥对与 CSR，<b>私钥加密后与 CSR 存在同一条记录</b>，
     * 证书列留空，等待签发。返回记录含 id 与 csrPem。
     *
     * <p>用途为 SERVER_IDENTITY 时受「服务端只保留一组密钥对」约束，已有未吊销的
     * 服务端证书时会被拒绝。
     */
    Gb35114Cert createPendingCsr(Gb35114Cert profile, int validityDays);

    /**
     * 用本平台 CA 签发待签发记录（复用记录中的私钥对应公钥，只回填证书）。
     *
     * <p>仅限<b>本地服务端证书</b>。客户端证书要交给上级验 sign1，靠「上级自己签发过」
     * 才被信任，本地 CA 签的上级不认 —— 调用会拒绝。
     */
    Gb35114Cert signPendingByCa(int certId, int caId, int validityDays);

    /** 用外部 CA 返回的证书回填待签发记录；校验证书公钥与本地私钥匹配。 */
    Gb35114Cert completePendingWithCert(int certId, String certPem);

    /**
     * 生成本平台自签身份证书（不建 CA 层级，仅调试/无 CA 场景）。
     *
     * <p>仅限<b>本地服务端证书</b>。客户端证书必须由上级签发 —— 调用会拒绝。
     * 同样受「服务端只保留一组密钥对」约束。
     */
    Gb35114Cert generateSelfSigned(Gb35114Cert profile, int validityDays);

    /**
     * 导入本平台身份证书（证书 + 私钥，校验配对）。
     *
     * <p>用途为 SERVER_IDENTITY 时受「服务端只保留一组密钥对」约束。
     */
    Gb35114Cert importIdentityCert(Gb35114Cert profile, String certPem, String keyPem);

    // ------------------------------------------------------------------
    // 下级客户端证书：只做 CA 签发，私钥不在本平台
    // ------------------------------------------------------------------

    /** 用下级提交的 CSR 签发证书（purpose 固定 ISSUED_DEVICE，不落私钥）。 */
    /**
     * 由下级提交的 CSR 签发证书（私钥始终留在下级）。
     *
     * @param keyUsage 密钥用途扩展描述串，为空时默认 {@code digitalSignature}
     */
    Gb35114Cert issueFromExternalCsr(int caId, String gbId, String remark, String csrPem,
                                     int validityDays, String keyUsage);

    /**
     * 同一份下级 CSR 再次签发（续期/补发）：CSR 已在本平台留存时复用原记录，
     * 新证书写入该记录；否则走 {@link #issueFromExternalCsr} 新建。
     *
     * @param caId       签发 CA
     * @param gbId       下级国标 ID（为空时从 CSR 主题 CN 提取）
     * @param remark     备注
     * @param csrPem     下级 CSR
     * @param validityDays 有效期天数
     * @param keyUsage   密钥用途扩展描述串
     */
    Gb35114Cert reissueFromCsr(int caId, String gbId, String remark, String csrPem,
                               int validityDays, String keyUsage);

    /** 导入下级/上级的对端证书（仅公钥，不落私钥）。 */
    Gb35114Cert importPeerCert(Gb35114Cert profile, String certPem);

    // ------------------------------------------------------------------
    // 查询 / 生命周期
    // ------------------------------------------------------------------

    /** 查询全部证书（列表列，含 hasKey，不含私钥密文）。 */
    List<Gb35114Cert> queryAllCerts();

    /** 按用途查询证书（列表列）。 */
    List<Gb35114Cert> queryCertsByPurpose(String purpose);

    /** 按 ID 查询证书（列表列）。 */
    Gb35114Cert queryCert(int id);

    /** 按国标 ID 查询证书（列表列）。 */
    List<Gb35114Cert> queryByGbId(String gbId);

    /**
     * UAS 侧验 sign1 用：按国标 ID 取有效的「下级客户端证书」。
     * 用途不符、已吊销的均返回 {@code null}；<b>已过期</b>的按
     * {@code gb35114.reject-expired-cert} 决定（默认不拒绝，优先返回未过期的那张）。
     */
    Gb35114Cert queryIssuedDeviceCert(String gbId);

    /**
     * 取本平台当前可用的「本地服务端证书」（SERVER_IDENTITY，持有私钥、未吊销；过期与否
     * 取决于 {@code gb35114.reject-expired-cert}）。用于未显式配置
     * {@code gb35114.server-cert-id} 时自动确定 UAS 签名身份。
     */
    Gb35114Cert queryActiveServerIdentity();

    /**
     * 取当前可用的服务端签名身份（同 {@link #queryActiveServerIdentity()}）。
     *
     * <p><b>服务端只保留一组密钥</b>：设备侧只存得下一把公钥，平台若在多个密钥组之间挑用，
     * 等于悄悄换掉设备信任的公钥，设备验 sign2 必然失败，而平台日志上一切正常 ——
     * 故障点会漂到设备侧。因此本方法<b>绝不跨密钥组回退</b>。
     *
     * <p>「多个证书」只允许是<b>同一密钥组内的多张</b>（有效期/签发者/序列号不同），
     * 它们对设备完全等价。锚点取该用途下最新的一张未吊销记录，再在锚点所在组内解析可用证书。
     *
     * @return 可用的服务端证书；锚点已吊销、或其所在组内已无可用证书时返回 {@code null}
     */
    Gb35114Cert queryDefaultServerIdentity();

    /**
     * 取指定 ID 的服务端证书，校验其确实可用（用途为 SERVER_IDENTITY、持有私钥、
     * 未吊销、未过期）。不可用时返回 {@code null}。
     */
    Gb35114Cert queryUsableServerIdentity(Integer certId);

    /**
     * 按「<b>密钥组</b>」解析可用的服务端证书。
     *
     * <p>签名身份的本质是<b>密钥对</b>而非证书：同一密钥对签出的多张证书（有效期不同、
     * 签发者不同、序列号不同）对设备完全等价 —— 设备只存公钥，用组内任意一张的私钥
     * 签名都能被验过。因此给定证书过期时，只要同组还有可用证书就继续用它，
     * 设备无需重新配置。这正是「生成多张有效期不同的服务端证书供不同客户端使用」的
     * 落地依据：客户端拿到的是哪一张不重要，重要的是它们共用同一个公钥。
     *
     * <p>但<b>吊销不参与这个顺延</b>：吊销是对该签名身份「停用」的明确指令。同组证书
     * 共用私钥，一旦泄露必然整组一起吊销；若还能顺延到兄弟证书，吊销就形同虚设。
     *
     * @return 可用的证书；给定证书已吊销、用途不符、不存在，或同组内也无可用证书时返回 null
     */
    Gb35114Cert resolveUsableServerIdentity(int certId);

    /**
     * <b>复用现有密钥对</b>再签一张服务端证书：私钥不变，只重新签发证书。
     *
     * <p>新证书的公钥与源证书完全相同（{@link Gb35114Cert#getKeyFingerprint()} 一致），
     * 因此设备侧<b>无需重新配置</b>：设备导入的是源证书或新证书中的任意一张，平台用
     * 同组内任意一张的私钥签 sign2 都能被验过。用于延长有效期、更换 DN 或改由 CA 签发。
     *
     * @param sourceCertId 提供密钥对的源服务端证书（必须有私钥）
     * @param profile      新证书的档案（DN、国标 ID、备注等）
     * @param caId         签发 CA，为 null 时自签
     * @param validityDays 有效期天数（自签发起算）
     */
    Gb35114Cert reissueServerIdentity(int sourceCertId, Gb35114Cert profile,
                                      Integer caId, int validityDays);

    /** 按公钥指纹查询同组服务端证书（同一个签名身份）。 */
    List<Gb35114Cert> queryServerIdentitiesByFingerprint(String keyFingerprint);

    /**
     * 解析本平台作为下级注册时使用的「本地客户端证书」（DEVICE_IDENTITY）。
     *
     * <p><b>该用途不唯一</b>：本平台可以同时接入多个上级，每个上级用自己的那张
     * （证书里 CN 通常就是本平台在该上级处的国标编码）。因此解析规则是：
     * <ol>
     *   <li>{@code gbId} 非空时，先按 {@code gb_id} 精确匹配；</li>
     *   <li>匹配不到（或 gbId 为空）时，若该用途下<b>只有一张</b>未吊销的证书，就用它；</li>
     *   <li>仍有多张 —— <b>返回 null 并告警，绝不猜</b>。猜错等于用别的上级的身份去注册，
     *       对方验签失败，而本平台日志上一切正常。</li>
     * </ol>
     *
     * @param gbId 本平台向上注册的国标编码，可为 null
     * @return 可用的证书；无候选或有歧义时返回 {@code null}
     */
    Gb35114Cert queryDeviceIdentity(String gbId);

    /**
     * 解析某个上级平台的「上级服务端证书」（TRUSTED_PLATFORM，仅公钥，用于验 sign2）。
     *
     * <p>与 {@link #queryDeviceIdentity(String)} 同理：该用途也不唯一（多个上级各有各的），
     * 按 {@code serverGbId} 匹配 {@code gb_id}；匹配不到且只有一张时用它；有多张则返回 null。
     *
     * @param serverGbId 上级平台国标编码，可为 null
     */
    Gb35114Cert queryTrustedPlatformCert(String serverGbId);

    /** 加载证书 PEM 为 X509Certificate（不涉私钥）。 */
    X509Certificate loadCert(int id);

    /** 加载证书 + 私钥为身份（解密私钥）；证书不含私钥时抛可读异常。 */
    Gb35114CertUtil.Gb35114Identity loadIdentity(int id);

    /**
     * 校验设备在 Capability 自报的证书是否仍可接入。
     *
     * <p>自报路径不经过数据库，必须按<b>公钥指纹</b>反查本地证书表：命中已吊销的记录直接拒绝。
     * <b>已过期</b>的记录是否拒绝取决于 {@code gb35114.reject-expired-cert}（默认不拒绝，
     * 只记告警）—— A 级握手既不校验证书链也不校验有效期，到期拦截与否是运维策略而非协议要求。
     *
     * <p><b>本平台未保存过这张证书时同样拒绝</b>：「本平台保存且有效」是接入的前提。
     * 放行一张无记录的证书，等于允许任何持有该设备 gb_id 的人用自签证书（A 级握手不校验
     * 证书链，自签也验得过）冒充该设备接入，且平台侧无任何记录可供吊销 —— 出事时连
     * 「这台设备是谁签的」都查不到。外部 CA 签发的设备证书，应先经
     * {@link #importPeerCert} 导入本平台保存。
     *
     * @return 校验通过的证书
     * @throws Gb35114Exception 未在本平台保存、已吊销或已过期
     */
    X509Certificate validateAnnouncedDeviceCert(String gbId, X509Certificate cert);

    /**
     * 说明某设备为何取不到可用的下级客户端证书。
     *
     * <p>{@link #queryIssuedDeviceCert(String)} 返回 {@code null} 有两种原因 ——
     * 「本平台没给这台设备签发过」和「签发过但已吊销/过期」，二者的处置完全不同
     * （前者要签发，后者要重新签发并换发证书）。UAS 侧据此生成可行动的日志。
     *
     * @return 原因描述；本平台从未给该设备签发过证书时返回 {@code null}
     */
    String describeDeviceCertUnavailable(String gbId);

    /** 吊销证书。 */
    void revokeCert(int id);

    /** 删除证书（本地身份证书连同其私钥一并删除）。 */
    void deleteCert(int id);
}
