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
 * <p>证书按类型（{@link Gb35114Cert#getType()}）区分，私钥只在本平台自持身份的证书上存在，
 * 且永不通过接口下发。
 */
public interface IGb35114CertService {

    // ------------------------------------------------------------------
    // CA
    // ------------------------------------------------------------------

    /**
     * 生成本地自签根 CA（type=LOCAL_CA）。
     *
     * <p><b>本地 CA 全局只保留一份</b>：已存在 LOCAL_CA 时直接拒绝，需先删除旧的
     * （{@link #deleteCa(int)} 会校验引用，仍被证书引用的删不掉）。受信任的 CA
     * （type=TRUSTED_CA）不受此限制，多个上级平台各一份，第三方签发机构也可能不止一家。
     *
     * <p>CA 没有独立的「名称」字段：它的身份就是证书的主题 CN，取自生成参数或证书本身，
     * 不由调用方另起别名 —— 否则同一张 CA 会在页面上出现两个都像名字的字段。
     *
     * <p>{@code profile} 提供 CN 与 DN 各段（C/ST/L/O/OU），与其它证书创建入口一致；
     * {@code validityDays} 不传或非正数时回退到 {@code gb35114.cert-validity-days}。
     * 落库的各段一律由签出的证书反解析得到，不采信表单原值。
     */
    Gb35114Ca generateCa(Gb35114Ca profile, int validityDays);

    /**
     * 导入外部 CA。type=LOCAL_CA 需带私钥；type=TRUSTED_CA 仅证书。
     *
     * <p>导入 LOCAL_CA 等价于新建，同样受「本地 CA 只保留一份」约束。
     */
    Gb35114Ca importCa(String type, String certPem, String keyPem, String remark);

    /** 查询全部 CA（不含私钥密文）；TRUSTED_CA 附带其服务的上级平台名（瞬态）。 */
    List<Gb35114Ca> queryAllCa();

    /** 按类型查询 CA；TRUSTED_CA 附带其服务的上级平台名（瞬态）。 */
    List<Gb35114Ca> queryCaByType(String type);

    /** 按 ID 查询 CA 全列（含私钥密文），供下载证书/内部签发用，禁止直接返回前端。 */
    Gb35114Ca queryCa(int id);

    /**
     * 查询某 CA 签发的证书清单（CA 页面点开「关联证书」用）。
     *
     * <p>列表接口只返回 {@code certCount} 一个数，清单按需单独拉 —— CA 多、证书多时
     * 把清单塞进列表响应会把响应撑大，而多数时候用户只看张数。
     */
    List<Gb35114Cert> queryCertsByCaId(int caId);

    /** 删除 CA；被证书引用时拒绝，并在信息里点名是哪些证书在占位。 */
    void deleteCa(int id);

    // ------------------------------------------------------------------
    // 本地身份证书：本平台生成密钥对，私钥加密留存本地
    //
    // 服务端证书（SERVER_IDENTITY）有三条创建路径，签发的都是本平台（本地根 CA 或自签）：
    //   1) createServerIdentity —— 一步创建：生成密钥对并当场签发；
    //   2) createPendingCsr → signPendingServerIdentity —— 先出 CSR，再由本平台签发；
    //   3) importIdentityCert —— 导入外部工具签发的证书 + 私钥（回填）。
    // 三条路都受同一条约束：全局只保留一组密钥对 —— 设备侧只存得下一把公钥，多组并存时
    // 「设备绑定的是哪一组」无从判断，选错会让设备验 sign2 失败而平台日志正常。
    // 已有服务端证书时创建一律被拒，换发路径是「先删除、再重新创建」：
    // 新证书是新的密钥对，绑定过旧证书的设备必须重新导入平台证书才能注册。
    //
    // 客户端证书（DEVICE_IDENTITY）不能由本平台签发（见 requireLocallyIssuableType），
    // 只能走 createPendingCsr → 导出交上级签发 → completePendingWithCert 回填。
    // ------------------------------------------------------------------

    /**
     * <b>一步创建服务端证书（本平台）</b>：生成 SM2 密钥对并当场签发。
     *
     * <p>这是服务端证书最省事的一条创建路径：三步并作一步。另外两条是
     * {@link #createPendingCsr} + {@link #signPendingServerIdentity}（先出 CSR 再签）与
     * {@link #importIdentityCert}（导入外部签发的证书）。签发方式由 {@code caId} 决定：
     * <ul>
     *   <li>{@code caId} 非空 —— 用该本地 CA 签发（CA 私钥须在本平台）；</li>
     *   <li>{@code caId} 为空 —— 自签（签发者即自身，无 CA 的联调环境可用）。</li>
     * </ul>
     * 两条路径都不建 CA 层级、都不需要外部参与，因此一次调用即可拿到可用证书。
     *
     * <p>仅限<b>服务端证书（本平台）</b>：本平台作 UAS 用它签 sign2，设备侧只需要拿到公钥，
     * 谁签的、是不是自签都不影响验签。客户端证书必须由上级签发 —— 调用会拒绝。
     *
     * <p>受「服务端只保留一组密钥对」约束：已有服务端证书（未删除）时拒绝。
     *
     * @param caId 签发 CA；为 {@code null} 时自签
     */
    Gb35114Cert createServerIdentity(Gb35114Cert profile, Integer caId, int validityDays);

    /**
     * 创建待签发记录：生成 SM2 密钥对与 CSR，<b>私钥加密后与 CSR 存在同一条记录</b>，
     * 证书列留空，等待签发。返回记录含 id 与 csrPem。
     *
     * <p>服务端证书（本平台）与客户端证书（本平台）都走这条路，区别在签发者：
     * <ul>
     *   <li>服务端证书 —— 用 {@link #signPendingServerIdentity} 由本平台签发（本地根 CA 或自签），
     *       也可用 {@link #completePendingWithCert} 回填外部签发的证书；</li>
     *   <li>客户端证书 —— 只能把 CSR 交给上级签发，再 {@link #completePendingWithCert} 回填
     *       （本平台签的证书上级那边没有记录，接入必被拒）。</li>
     * </ul>
     *
     * <p>类型为 SERVER_IDENTITY 时受「服务端只保留一组密钥对」约束。
     */
    Gb35114Cert createPendingCsr(Gb35114Cert profile, int validityDays);

    /**
     * 用本平台签发待签发的服务端证书（本地根 CA 签发或自签），原地回填该记录。
     *
     * <p>与 {@link #completePendingWithCert} 并列：那条回填外部签发的证书，这条在本平台内完成。
     * {@code caId} 为空即自签。只接受 SERVER_IDENTITY —— 客户端证书必须由上级签发。
     */
    Gb35114Cert signPendingServerIdentity(int certId, Integer caId, int validityDays);

    /** 用外部 CA 返回的证书回填待签发记录；校验证书公钥与本地私钥匹配。 */
    Gb35114Cert completePendingWithCert(int certId, String certPem);

    /**
     * 导入本平台身份证书（证书 + 私钥，校验配对）。
     *
     * <p>类型为 SERVER_IDENTITY 时受「服务端只保留一组密钥对」约束。
     */
    Gb35114Cert importIdentityCert(Gb35114Cert profile, String certPem, String keyPem);

    // ------------------------------------------------------------------
    // 客户端证书（下级设备）：只做 CA 签发，私钥不在本平台
    // ------------------------------------------------------------------

    /** 用下级提交的 CSR 签发证书（type 固定 ISSUED_DEVICE，不落私钥）。 */
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

    /** 按类型查询证书（列表列）。 */
    List<Gb35114Cert> queryCertsByType(String type);

    /** 按 ID 查询证书（列表列）。 */
    Gb35114Cert queryCert(int id);

    /** 按国标 ID 查询证书（列表列）。 */
    List<Gb35114Cert> queryByGbId(String gbId);

    /**
     * UAS 侧验 sign1 用：按国标 ID 取有效的「客户端证书（下级设备）」。
     * 类型不符、已吊销的均返回 {@code null}；<b>已过期</b>的按
     * {@code gb35114.reject-expired-cert} 决定（默认不拒绝，优先返回未过期的那张）。
     */
    Gb35114Cert queryIssuedDeviceCert(String gbId);

    /**
     * 取本平台当前可用的「服务端证书（本平台）」（SERVER_IDENTITY，持有私钥、未吊销；过期与否
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
     * <p>锚点取该类型下最新的一张记录，再在锚点所在组内解析可用证书 ——
     * 存量环境可能因早期版本留有同密钥对的多张证书，它们对设备完全等价。
     *
     * @return 可用的服务端证书；锚点不可用、或其所在组内已无可用证书时返回 {@code null}
     */
    Gb35114Cert queryDefaultServerIdentity();

    /**
     * 取指定 ID 的服务端证书，校验其确实可用（类型为 SERVER_IDENTITY、持有私钥、
     * 未吊销、未过期）。不可用时返回 {@code null}。
     */
    Gb35114Cert queryUsableServerIdentity(Integer certId);

    /**
     * 按「<b>密钥组</b>」解析可用的服务端证书。
     *
     * <p>签名身份的本质是<b>密钥对</b>而非证书：同一密钥对签出的多张证书（有效期不同、
     * 签发者不同、序列号不同）对设备完全等价 —— 设备只存公钥，用组内任意一张的私钥
     * 签名都能被验过。因此给定证书过期时，只要同组还有可用证书就继续用它，
     * 设备无需重新配置。
     *
     * <p>但<b>吊销不参与这个顺延</b>：吊销是对该签名身份「停用」的明确指令。同组证书
     * 共用私钥，一旦泄露必然整组一起吊销；若还能顺延到兄弟证书，吊销就形同虚设。
     *
     * @return 可用的证书；给定证书已吊销、类型不符、不存在，或同组内也无可用证书时返回 null
     */
    Gb35114Cert resolveUsableServerIdentity(int certId);

    /**
     * 解析本平台作为下级注册时使用的「客户端证书（本平台）」（DEVICE_IDENTITY）。
     *
     * <p><b>该类型不唯一</b>：本平台可以同时接入多个上级，每个上级用自己的那张
     * （证书里 CN 通常就是本平台在该上级处的国标编码）。因此解析规则是：
     * <ol>
     *   <li>{@code gbId} 非空时，先按 {@code gb_id} 精确匹配；</li>
     *   <li>匹配不到（或 gbId 为空）时，若该类型下<b>只有一张</b>未吊销的证书，就用它；</li>
     *   <li>仍有多张 —— <b>返回 null 并告警，绝不猜</b>。猜错等于用别的上级的身份去注册，
     *       对方验签失败，而本平台日志上一切正常。</li>
     * </ol>
     *
     * @param gbId 本平台向上注册的国标编码，可为 null
     * @return 可用的证书；无候选或有歧义时返回 {@code null}
     */
    Gb35114Cert queryDeviceIdentity(String gbId);

    /**
     * 解析某个上级平台的「服务端证书（上级平台）」（TRUSTED_PLATFORM，仅公钥，用于验 sign2）。
     *
     * <p>与 {@link #queryDeviceIdentity(String)} 同理：该类型也不唯一（多个上级各有各的），
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
     * UAS 侧：校验设备证书确实由本平台的 CA 签发（证书链校验）。
     *
     * <p>对齐 GB/T 43026—2023 附录 B 表 B.1 序号 6/7 的「需验证证书链是否正确」——
     * 该要求只出现在 7.4（单向/双向设备身份认证），7.5（平台间）没有。
     *
     * <p><b>与 {@link #validateAnnouncedDeviceCert} 是叠加关系，不是替代</b>：指纹反查回答
     * 「本平台是否给这把公钥签发过证书」，链校验回答「这张证书是不是本平台 CA 签出来的」。
     * 只看指纹会漏掉一个真实漏洞 —— 设备拿自己的私钥自签一张证书，只要公钥与库里那张相同，
     * 指纹就命中、记录也有效，于是被放行；补上链校验后，自签证书因验不过本平台 CA 的公钥而被拒。
     *
     * <p><b>本平台作为上级时恒开</b>，不受 {@code gb35114.verify-upstream-cert-chain} 控制
     * （那个开关只管本平台作为下级时是否校验上级证书链）。
     *
     * <p>不校验有效期：到期是否拦截由 {@code gb35114.reject-expired-cert} 决定，
     * 且该判定已在 {@link #validateAnnouncedDeviceCert} 中完成，此处重复只会产生两条含义重叠的日志。
     *
     * @param gbId         设备国标编码（仅用于拼装可读的失败信息）
     * @param cert         设备自报的证书
     * @param expectedCaId 签发记录上的 CA（可为 null：存量未回填，或证书由 {@link #importPeerCert} 导入）
     * @return 校验通过的证书
     * @throws Gb35114Exception 无法验证，或签发者不具备 CA 资格
     */
    X509Certificate validateDeviceCertChain(String gbId, X509Certificate cert, Integer expectedCaId);

    /**
     * UAC 侧：校验上级平台证书的链（本平台作为下级时）。
     *
     * <p>由 {@code gb35114.verify-upstream-cert-chain} 控制是否注入（默认注入 = 校验）。
     * 标准对平台间认证（7.5）没有要求链校验，但默认仍从严；需要放宽的部署把该项置为
     * {@code false}，即不注入。
     *
     * <p>自签的上级证书同样要求「该证书已作为受信任的 CA 导入一份」：否则开关在自签这个常态下
     * 等于空操作，开了跟没开一样。本平台的信任仍来自「运维显式导入」这一动作。
     *
     * @return 校验通过的证书
     * @throws Gb35114Exception 受信任的 CA 列表里找不到能签发它的证书
     */
    X509Certificate validateUpstreamPlatformCertChain(X509Certificate platformCert);

    /**
     * 说明某设备为何取不到可用的客户端证书（下级设备）。
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

    /**
     * 删除证书，并先解除<b>级联平台</b>对它的绑定。
     *
     * <p>用于「国标级联 → 编辑」页删除本上级绑定的证书：证书此刻仍被本 platform 行按 ID
     * 引用，直接走 {@link #deleteCert(int)} 会被引用守卫拒绝。本方法先把
     * {@code wvp_platform.device_cert_id} / {@code platform_cert_id} 中等于该 ID 的置空，
     * 再执行删除。
     *
     * <p>只解绑级联平台，不动设备的绑定：设备侧那张证书与级联无关，擅自解绑会把一台
     * 正常在用的设备弄成「未配置证书」。设备仍引用时，删除照旧被守卫拒绝并点名。
     */
    void unbindAndDeleteCert(int id);

    /**
     * 把某张证书绑定到某个级联平台（{@code certId} 为 null 表示解绑）。
     *
     * <p>国密接入下「本平台设备证书」与「上级平台证书」都是<b>按上级各一张</b>的，
     * 因此这个归属必须显式记在 {@code wvp_platform} 上。没有它时，运行期只能靠
     * {@link #queryDeviceIdentity(String)} 按国标 ID 反查兜底 —— 兜底在「只有一张候选」时
     * 能用，接入第二个上级就会退化成「拒绝猜测、返回 null」，页面上也无从回显绑的是哪张。
     *
     * <p>只写绑定那一列，不整行更新 platform：见 {@code PlatformMapper.bindDeviceCert} 的说明。
     *
     * @param platformId 级联平台 ID
     * @param type       证书类型，只接受 {@code DEVICE_IDENTITY} 与 {@code TRUSTED_PLATFORM}
     * @param certId     证书 ID；null 表示解绑
     */
    void bindToPlatform(int platformId, String type, Integer certId);
}
