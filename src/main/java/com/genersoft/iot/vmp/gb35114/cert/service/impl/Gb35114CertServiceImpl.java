package com.genersoft.iot.vmp.gb35114.cert.service.impl;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114KeyProtector;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import com.genersoft.iot.vmp.gb28181.bean.Device;
import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.dao.DeviceMapper;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.conf.SipConfig;
import com.genersoft.iot.vmp.utils.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
public class Gb35114CertServiceImpl implements IGb35114CertService {

    private static final DateTimeFormatter CERT_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    @Autowired
    private Gb35114CaMapper caMapper;

    @Autowired
    private Gb35114CertMapper certMapper;

    @Autowired
    private Gb35114Config config;

    /**
     * 反查证书被谁用了，填充瞬态关联字段。
     *
     * <p>直接注入 mapper 而不是 {@code IDeviceService} / {@code IPlatformService}：
     * 那两个 service 会经由 SIP 层间接依赖本 service，注入它们会形成循环依赖。
     * 这里只做只读查询，用 mapper 更贴合。
     */
    @Autowired
    private DeviceMapper deviceMapper;

    @Autowired
    private PlatformMapper platformMapper;

    /**
     * 本平台国标编码（`sip.id`），用于生成证书主题的默认值。
     *
     * <p>用 {@code @Autowired(required = false)}：单元测试里没有 Spring 容器，
     * 缺这个 bean 时退化成「主题留空由调用方给」，而不是让整个 service 装配失败。
     */
    @Autowired(required = false)
    private SipConfig sipConfig;

    /**
     * 启动时一次性回填存量证书的公钥指纹。
     *
     * <p>{@code key_fingerprint} 列是后加的，此前的证书该列为空。指纹要解析 DER 才能算，
     * SQL 里做不了，所以必须由 Java 补 —— 但<b>只在启动时补一次</b>：查询接口是只读的，
     * 让它们在读的时候顺手写库，会让「看一眼列表」变成一次数据库写入，也让并发读之间
     * 产生无谓的写竞争。
     *
     * <p>幂等：只处理该列为空的记录，补过的不再重复计算。失败只记日志，不影响启动 ——
     * 指纹缺失的后果是「设备自报证书按指纹反查落空」，而该路径已有 gb_id + 公钥比对的
     * 兜底，不会因此放行已吊销的证书。
     */
    @jakarta.annotation.PostConstruct
    public void backfillFingerprintsOnce() {
        List<Gb35114Cert> list;
        try {
            list = certMapper.queryAll();
        } catch (Exception e) {
            log.warn("[GB35114] 启动回填公钥指纹时读取证书表失败: {}", e.getMessage());
            return;
        }
        if (list == null || list.isEmpty()) {
            return;
        }
        int filled = 0;
        for (Gb35114Cert cert : list) {
            if (cert.getKeyFingerprint() != null && !cert.getKeyFingerprint().isEmpty()) {
                continue;
            }
            if (cert.getCertPem() == null || cert.getCertPem().isEmpty()) {
                continue; // 待签发记录还没有证书，无指纹可算
            }
            String fp = fingerprintOf(cert.getCertPem());
            if (fp == null) {
                continue;
            }
            try {
                certMapper.updateFingerprint(cert.getId(), fp);
                filled++;
            } catch (Exception e) {
                log.warn("[GB35114] 回填证书 #{} 公钥指纹失败: {}", cert.getId(), e.getMessage());
            }
        }
        if (filled > 0) {
            log.info("[GB35114] 已回填 {} 张存量证书的公钥指纹", filled);
        }
    }

    // ------------------------------------------------------------------
    // CA
    // ------------------------------------------------------------------

    @Override
    public Gb35114Ca generateCa(Gb35114Ca profile, int validityDays) {
        assertNoLocalCa();
        try {
            // 主题留空时补「本平台国标ID_22个0」——根 CA 也是本平台签发的证书身份，
            // 与其它证书用同一套主题格式，不另立命名。表单已默认生成，这里是不依赖前端的兜底。
            if (profile == null) {
                profile = new Gb35114Ca();
            }
            if (profile.getSubjectCn() == null || profile.getSubjectCn().trim().isEmpty()) {
                profile.setSubjectCn(defaultSubjectCn());
            }
            String subjectCn = profile.getSubjectCn();
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore,
                    validityDays > 0 ? validityDays : config.getCertValidityDays());
            // 用完整 DN 生成：与「创建 CSR / 自签生成」走同一个 buildSubject，
            // 界面上收的 C/ST/L/O/OU 才会真的写进证书，而不是收完就丢。
            Gb35114CertUtil.Gb35114Identity identity = Gb35114CertUtil.generateSelfSigned(
                    Gb35114CertUtil.buildSubject(profile.getCountry(), profile.getProvince(),
                            profile.getLocality(), profile.getOrganization(),
                            profile.getOrganizationalUnit(), subjectCn),
                    notBefore, notAfter);
            Gb35114Ca ca = new Gb35114Ca();
            ca.setType(Gb35114Ca.TYPE_LOCAL_CA);
            ca.setSerialNumber(identity.certificate.getSerialNumber().toString(16));
            ca.setCertPem(identity.certPem);
            ca.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), identity.keyPem));
            ca.setNotBefore(CERT_TIME.format(notBefore.toInstant()));
            ca.setNotAfter(CERT_TIME.format(notAfter.toInstant()));
            ca.setRemark(profile.getRemark());
            ca.setCreateTime(DateUtil.getNow());
            // DN 各段取自刚签出的证书，不采信表单原值：表单可能带首尾空格、大小写不一致，
            // 或者留空（导入路径根本没有这些输入）。只要列来自证书，列与 subject_dn 就永远一致。
            fillSubjectFromCert(ca, identity.certificate);
            caMapper.add(ca);
            return ca;
        } catch (Exception e) {
            log.error("[GB35114] 生成根 CA 失败", e);
            throw new RuntimeException("生成根 CA 失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Ca importCa(String type, String certPem, String keyPem, String remark) {
        if (type == null || type.isEmpty() || Gb35114Ca.TYPE_LOCAL_CA.equals(type)) {
            // 本地 CA 只能有一份：导入等价于新建，同样受守卫约束
            assertNoLocalCa();
        }
        try {
            if (type == null || type.isEmpty()) {
                type = Gb35114Ca.TYPE_LOCAL_CA;
            }
            boolean local = Gb35114Ca.TYPE_LOCAL_CA.equals(type);
            if (local && (keyPem == null || keyPem.isEmpty())) {
                throw new IllegalArgumentException("本地 CA 必须提供私钥文件");
            }
            X509Certificate cert = Gb35114CertUtil.loadCertificate(certPem);
            Gb35114Ca ca = new Gb35114Ca();
            ca.setType(type);
            ca.setSerialNumber(cert.getSerialNumber().toString(16));
            ca.setCertPem(certPem);
            // 受信任的 CA 仅存证书，无私钥
            ca.setKeyPem(local ? Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), keyPem) : null);
            ca.setNotBefore(CERT_TIME.format(cert.getNotBefore().toInstant()));
            ca.setNotAfter(CERT_TIME.format(cert.getNotAfter().toInstant()));
            ca.setRemark(remark);
            ca.setCreateTime(DateUtil.getNow());
            // 身份与 DN 各段一律取自证书本身：不由导入者现场编一个别名，也不会出现
            // 「DN 里有 C=CN、country 列却是 NULL」这种列与 subject_dn 打架的情况。
            fillSubjectFromCert(ca, cert);
            caMapper.add(ca);
            return ca;
        } catch (Exception e) {
            log.error("[GB35114] 导入 CA 失败", e);
            throw new RuntimeException("导入 CA 失败: " + e.getMessage(), e);
        }
    }

    @Override
    public List<Gb35114Ca> queryAllCa() {
        return fillCaPlatformRelations(caMapper.queryAll());
    }

    @Override
    public List<Gb35114Ca> queryCaByType(String type) {
        return fillCaPlatformRelations(caMapper.queryByType(type));
    }

    @Override
    public Gb35114Ca queryCa(int id) {
        return caMapper.query(id);
    }

    @Override
    public List<Gb35114Cert> queryCertsByCaId(int caId) {
        return fillRelations(certMapper.queryByCaId(caId));
    }

    @Override
    public void deleteCa(int id) {
        int used = certMapper.countByCaId(id);
        if (used > 0) {
            throw new IllegalArgumentException("该 CA 下仍有 " + used + " 张证书（"
                    + describeCertsByCaId(id) + "），请先删除或改签后再删除 CA");
        }
        caMapper.delete(id);
    }

    /**
     * 用一句话点名某 CA 名下都有哪些证书，供删除被拒时提示。
     *
     * <p>只说「还有 3 张证书」等于把找证书的活全推给用户，而重构后「受信任的 CA」
     * 既能签上级平台证书、也能签下级设备证书，用户光看 CA 页面已经猜不到是哪三张。
     * 这里按类型归类并把国标 ID 带出来，让用户能直接在证书列表里搜到。
     *
     * <p>查询失败不抛异常：这是提示语的配料，拿不到就退回只有张数的原文案，
     * 不能因为拼不出提示而让「拒绝删除」这件事本身失败。
     */
    private String describeCertsByCaId(int caId) {
        try {
            List<Gb35114Cert> certs = certMapper.queryByCaId(caId);
            if (certs == null || certs.isEmpty()) {
                return "";
            }
            Map<String, Integer> byType = new LinkedHashMap<>();
            for (Gb35114Cert c : certs) {
                byType.merge(c.getType() == null ? "未知类型" : c.getType(), 1, Integer::sum);
            }
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Integer> e : byType.entrySet()) {
                if (sb.length() > 0) {
                    sb.append('、');
                }
                sb.append(typeLabel(e.getKey())).append(' ').append(e.getValue()).append(" 张");
            }
            // 顺带点名一张具体证书的国标 ID：用户拿它去证书列表搜一下就能定位，
            // 比按类型归类再自己数更直接。多张时只举第一张（按 id 倒序即最新签发的）。
            Gb35114Cert sample = certs.get(0);
            String sampleId = sample.getGbId() == null || sample.getGbId().isEmpty()
                    ? "#" + sample.getId() : sample.getGbId();
            return sb + "，如 " + sampleId;
        } catch (Exception e) {
            log.warn("[GB35114] 拼装 CA #{} 的关联证书提示失败: {}", caId, e.getMessage());
            return "";
        }
    }

    /** 类型的中文名，供提示语使用；未知取值原样返回。 */
    private static String typeLabel(String type) {
        switch (type) {
            case Gb35114Cert.TYPE_SERVER_IDENTITY:
                return "服务端证书（本平台）";
            case Gb35114Cert.TYPE_DEVICE_IDENTITY:
                return "客户端证书（本平台）";
            case Gb35114Cert.TYPE_ISSUED_DEVICE:
                return "客户端证书（下级设备）";
            case Gb35114Cert.TYPE_TRUSTED_PLATFORM:
                return "服务端证书（上级平台）";
            default:
                return type;
        }
    }

    /**
     * 按签发者反查本平台已留存的 CA。
     *
     * <p>逐个用已导入 CA 的公钥去验证本证书的签名，验得过的那张就是签发者。
     *
     * <p><b>自签证书同样走这条路径</b>，不提前返回。自签证书 S 的签名只能被「签发 S 的那把
     * 私钥所对应的公钥」验过，而签发 S 的就是 S 自己 —— 因此能验过 S 的 CA，其公钥必然与 S
     * 完全相同。这让「同一张证书既作为服务端证书导入、又作为受信任的 CA 导入」时能把两者关联起来
     * （现场 {@code TRUSTED_PLATFORM} 与 {@code TRUSTED_CA} 常常就是同一张自签证书），
     * 进而反查出该 CA 服务于哪个级联平台。
     *
     * <p><b>为什么不会误关联</b>：判定是密码学的 —— 候选 CA 能验过 S 的签名 ⟺ 两者公钥相同。
     * 密钥不同的 CA 验签必然抛异常，同名但密钥不同的 CA 也一样（CA 表只存 CN，按 DN 匹配才会
     * 串台）。要伪造一张「能被某 CA 验过」的证书，必须持有该 CA 的私钥。
     *
     * <p><b>同一把公钥有多条 CA 记录时</b>（同一张 CA 被导入两次，或 CA 证书续期后公钥未变），
     * {@code queryAll()} 按 {@code id DESC} 返回，循环取到的是最新一条。这是确定性的结果，
     * 不是猜测：语义上「由这把密钥签发」对这几条都成立，指向哪一条都不算错。
     *
     * <p>这里刻意<b>不校验 CA 资格</b>（{@code keyCertSign} / {@code basicConstraints}）：
     * {@code caId} 表达的是<b>谱系与展示</b>事实（这张证书的签名出自哪把密钥），不是信任判定。
     * 信任判定由 UAS 侧的设备证书链校验独立承担（见 {@link #validateDeviceCertChain}），
     * 在那里才需要「签发者必须真的是 CA」。混在一起会让「同密钥但不带 keyCertSign 的记录」
     * 关联不上，产生无意义的失败。
     *
     * <p>返回 {@code null} 现在只有一种含义：<b>签发者未导入本平台</b>。
     */
    private Integer resolveIssuerCaId(X509Certificate x509) {
        List<Gb35114Ca> cas;
        try {
            cas = caMapper.queryAll();
        } catch (Exception e) {
            log.warn("[GB35114] 反查证书签发者时读取 CA 表失败: {}", e.getMessage());
            return null;
        }
        if (cas == null || cas.isEmpty()) {
            return null;
        }
        // 先按「签发者 DN」缩小候选，避免对每张 CA 都做一次 SM2 验签。
        // 命中为空时退回全表 —— 见 narrowByIssuerDn 的说明。
        List<Gb35114Ca> narrowed = narrowByIssuerDn(cas, x509);
        List<Gb35114Ca> pool = narrowed.isEmpty() ? cas : narrowed;
        for (Gb35114Ca ca : pool) {
            if (ca.getCertPem() == null || ca.getCertPem().isEmpty()) {
                continue;
            }
            try {
                X509Certificate caCert = Gb35114CertUtil.loadCertificate(ca.getCertPem());
                x509.verify(caCert.getPublicKey());
                return ca.getId();
            } catch (Exception ignored) {
                // 验签不过 = 不是这张 CA 签的，继续试下一张
            }
        }
        return null;
    }

    /**
     * 按「签发者 DN」把候选 CA 缩小到真正可能的那几张，避免逐个做 SM2 验签。
     *
     * <p><b>依据是 X.509 的固有语义，不是启发式</b>：证书的 {@code issuer} 字段必然等于
     * 签发它的那张 CA 的 {@code subject}。本平台的签发路径正是用 CA 证书的 subject 作
     * issuer（{@code buildAndSign} 传的是 {@code caHolder.getSubject()}），外部 CA 签出的
     * 证书同样满足这一条。因此「issuer DN 对不上」的 CA <b>不可能</b>是签发者，可以安全排除。
     *
     * <p>DN 比对用 {@link X500Principal} 而非字符串：同一 DN 的字符串写法可能不同
     * （属性顺序、转义、大小写），{@code X500Principal.equals} 做的是规范化比较。
     * 这正好绕开了「不同 CA 共用 CN」的问题 —— 它比对的是<b>完整 DN</b>，
     * 而 {@code resolveIssuerCaId} 当初拒绝按 CN 匹配正是因为 CN 会重名。
     *
     * <p><b>命中为空时调用方必须退回全表</b>，原因有三：
     * <ul>
     *   <li>存量 CA 记录的 {@code subject_dn} 可能尚未回填（该列是后加的）；</li>
     *   <li>DN 写法差异超出规范化范围时 {@link X500Principal} 也可能判不等；</li>
     *   <li>宁可慢也不能错 —— 缩小候选只允许排除「确定不可能」的，不允许误伤。</li>
     * </ul>
     * 因此这里对 {@code subject_dn} 为空的记录一律<b>保留</b>在候选里。
     */
    private List<Gb35114Ca> narrowByIssuerDn(List<Gb35114Ca> pool, X509Certificate cert) {
        List<Gb35114Ca> hit = new ArrayList<>();
        if (pool == null || pool.isEmpty() || cert == null) {
            return hit;
        }
        String issuer = Gb35114CertUtil.issuerDn(cert);
        for (Gb35114Ca ca : pool) {
            String subject = ca.getSubjectDn();
            if (subject == null || subject.trim().isEmpty()) {
                // 未回填 subject_dn 的存量记录：无从判断，保留候选交由验签裁决。
                hit.add(ca);
                continue;
            }
            if (sameDn(subject, issuer)) {
                hit.add(ca);
            }
        }
        return hit;
    }

    /** DN 规范化比较，解析失败时退回忽略大小写的字符串比较。 */
    private static boolean sameDn(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        try {
            return new X500Principal(a).equals(new X500Principal(b));
        } catch (Exception e) {
            return a.equalsIgnoreCase(b);
        }
    }

    // ------------------------------------------------------------------
    // 本地身份证书
    // ------------------------------------------------------------------

    @Override
    public Gb35114Cert createServerIdentity(Gb35114Cert profile, Integer caId, int validityDays) {
        requireLocalIdentityType(profile.getType());
        // 服务端证书必须由本平台签发：本平台作 UAS 签 sign2，设备侧只需要拿到公钥，
        // 谁签的、是不是自签都不影响验签。客户端证书要交给上级验 sign1，本平台不能签。
        requireLocallyIssuableType(profile.getType());
        // 服务端只保留一组密钥对（见 assertNoActiveServerIdentity）
        assertNoActiveServerIdentity();
        // 主题留空时补「本平台国标ID_22个0」——表单已默认生成，这里是不依赖前端的兜底
        applyDefaultSubjectCn(profile);
        requireValidDeviceCn(profile);
        try {
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            Gb35114CertUtil.Gb35114Identity identity;
            if (caId == null) {
                // 自签：签发者即自身。无 CA 的联调环境可用，但正式环境建议用本地 CA 签，
                // 这样设备侧只需导入一次 CA 证书，换发平台证书时无需重新配置设备。
                identity = Gb35114CertUtil.generateSelfSigned(buildSubject(profile),
                        notBefore, notAfter, keyUsageBits(profile));
            } else {
                Gb35114Ca ca = caMapper.query(caId);
                if (ca == null) {
                    throw new IllegalArgumentException("CA 不存在: " + caId);
                }
                if (!Gb35114Ca.TYPE_LOCAL_CA.equals(ca.getType())) {
                    throw new IllegalArgumentException("只能使用本地 CA 签发证书");
                }
                identity = Gb35114CertUtil.issue(loadCaIdentity(ca), buildSubject(profile),
                        notBefore, notAfter, keyUsageBits(profile));
            }
            return persist(profile, identity, caId, validityDays, notBefore, notAfter);
        } catch (Exception e) {
            log.error("[GB35114] 创建服务端证书失败", e);
            throw new RuntimeException("创建服务端证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert createPendingCsr(Gb35114Cert profile, int validityDays) {
        requireLocalIdentityType(profile.getType());
        // 服务端证书也支持「先出 CSR、再签发」：签发者仍是本平台（本地根 CA 或自签），
        // 与一步创建的差别只是中间多一次 CSR 导出。
        //
        // 唯一性守卫必须在这里也生效：它此前只在 createServerIdentity / importIdentityCert
        // 里调用，CSR 这条路完全没有 —— 不补的话同一类型下会落下多组密钥对，而设备侧
        // 只存得下一把公钥（见 assertNoActiveServerIdentity）。
        // 守卫以 server 为条件：它查的是服务端证书表，无条件调用会让「已有服务端证书」
        // 顺带把设备 CSR 也堵死。
        if (Gb35114Cert.TYPE_SERVER_IDENTITY.equals(profile.getType())) {
            assertNoActiveServerIdentity();
        }
        // 主题留空时补「本平台国标ID_22个0」——表单已默认生成，这里是不依赖前端的兜底
        applyDefaultSubjectCn(profile);
        requireValidDeviceCn(profile);
        try {
            Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(buildSubject(profile));
            Gb35114Cert cert = baseRecord(profile);
            cert.setCsrPem(csr.csrPem);
            cert.setKeyUsage(normalizeKeyUsage(profile));
            // 关键：私钥不再丢弃，加密后与 CSR 存于同一条记录，签发时复用其公钥。
            cert.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), csr.keyPem));
            cert.setCertPem(null);
            cert.setValidityDays(validityDays);
            certMapper.add(cert);
            // 回读一次：hasKey 等列由 SQL 计算，直接返回内存对象会让页面把「私钥已就绪」
            // 的待签发记录显示成「无私钥」，与列表页不一致。
            return reload(cert);
        } catch (Exception e) {
            log.error("[GB35114] 创建证书请求失败", e);
            throw new RuntimeException("创建证书请求失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert completePendingWithCert(int certId, String certPem) {
        try {
            Gb35114Cert cert = certMapper.query(certId);
            if (cert == null) {
                throw new IllegalArgumentException("证书不存在: " + certId);
            }
            requireLocalIdentityType(cert.getType());
            if (cert.getCertPem() != null && !cert.getCertPem().isEmpty()) {
                throw new IllegalStateException("该记录已签发，无需重复回填");
            }
            if (cert.getKeyPem() == null || cert.getKeyPem().isEmpty()) {
                throw new IllegalStateException("该记录无本地私钥，无法回填");
            }
            String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), cert.getKeyPem());
            if (!Gb35114CertUtil.matches(certPem, keyPem)) {
                throw new IllegalArgumentException("证书公钥与本平台留存的私钥不匹配，回填将导致证书无法使用");
            }
            X509Certificate x509 = Gb35114CertUtil.loadCertificate(certPem);
            // 回填的证书通常是上级签发的，其签发者可能已在「受信任的 CA」里留存；
            // 按签名反查一次，把「证书 → 签发 CA → 级联平台」这条链补上。
            certMapper.completeCert(certId, certPem, x509.getSerialNumber().toString(16),
                    CERT_TIME.format(x509.getNotBefore().toInstant()),
                    CERT_TIME.format(x509.getNotAfter().toInstant()),
                    resolveIssuerCaId(x509), cert.getValidityDays(), normalizeKeyUsage(cert),
                    fingerprintOf(x509));
            Gb35114Cert completed = certMapper.queryLite(certId);
            return completed;
        } catch (Exception e) {
            log.error("[GB35114] 回填证书失败", e);
            throw new RuntimeException("回填证书失败: " + e.getMessage(), e);
        }
    }

    /**
     * <b>用本平台签发一张待签发的服务端证书</b>：取 {@link #createPendingCsr} 留下的 CSR 与
     * 加密私钥，由本地 CA 签发（{@code caId} 非空）或自签（{@code caId} 为空），原地回填该记录。
     *
     * <p>与「回填外部签发的证书」（{@link #completePendingWithCert}）并列：那条路的证书由外部
     * 产生，这条路完全在本平台内完成。服务端证书作 UAS 签 sign2，设备侧只需拿到公钥，
     * 谁签的、是不是自签都不影响验签，所以本平台签发即可用。
     *
     * <p><b>为什么原地更新而不是新增一行</b>：该记录已持有加密私钥，且其 ID 可能已被
     * {@code wvp_device.server_cert_id} / {@code wvp_platform.device_cert_id} 引用；
     * 新增一行会让这些引用指向一条永远没有证书的记录。
     *
     * <p><b>为什么复用 {@link #requireLocallyIssuableType}</b>：它把「只有服务端证书能由
     * 本平台签发」这条规则收在一处。若这里另写一套，这条新入口就会变成「用本地 CA 给自己签
     * 客户端证书」的坑 —— 签出的证书接入上级必然被拒，而本平台侧日志一切正常，排查方向跑偏。
     */
    @Override
    public Gb35114Cert signPendingServerIdentity(int certId, Integer caId, int validityDays) {
        // 校验一律放在 try 之外，且用 IllegalArgumentException：
        // 全局异常处理只把 IllegalArgumentException 的消息透给用户（ERROR100 + message），
        // IllegalStateException 会变成一个不带消息的 400；而套进 try 还会被
        // 「签发服务端证书失败:」前缀盖住真正的原因。这几条消息都是写给用户看的处置指引。
        Gb35114Cert cert = certMapper.query(certId);
        if (cert == null) {
            throw new IllegalArgumentException("证书不存在: " + certId);
        }
        requireLocallyIssuableType(cert.getType());
        if (cert.getCertPem() != null && !cert.getCertPem().isEmpty()) {
            throw new IllegalArgumentException("该记录已签发，无需重复签发");
        }
        if (cert.getCsrPem() == null || cert.getCsrPem().isEmpty()) {
            throw new IllegalArgumentException("该记录没有 CSR，无法签发");
        }
        if (cert.getKeyPem() == null || cert.getKeyPem().isEmpty()) {
            throw new IllegalArgumentException("该记录没有本地私钥，无法签发；"
                    + "请改用「回填」导入外部签发的证书");
        }
        Gb35114Ca ca = null;
        if (caId != null) {
            ca = caMapper.query(caId);
            if (ca == null) {
                throw new IllegalArgumentException("CA 不存在: " + caId);
            }
            if (!Gb35114Ca.TYPE_LOCAL_CA.equals(ca.getType())) {
                throw new IllegalArgumentException("只能使用本地 CA 签发证书");
            }
        }
        try {
            String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), cert.getKeyPem());
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            int keyUsage = keyUsageBits(cert);
            Gb35114CertUtil.Gb35114Identity issued;
            if (caId == null) {
                // 自签分支必须复用 CSR 里的公钥，不能新生成密钥对 —— CSR 是按留存私钥生成的，
                // 另起一对会让签出的证书与留存私钥不配对，设备侧验 sign2 必然失败。
                issued = Gb35114CertUtil.selfSignFromCsr(cert.getCsrPem(), keyPem,
                        notBefore, notAfter, keyUsage);
            } else {
                // issueFromCsr 的 subject 与公钥均取自 CSR，调用方无法覆盖 —— 这正是要的不变量
                issued = Gb35114CertUtil.issueFromCsr(loadCaIdentity(ca), cert.getCsrPem(),
                        notBefore, notAfter, keyUsage);
            }
            // 写库前复验配对关系：一旦落库，这张证书与留存的私钥就绑死了，
            // 事后再发现不配对只能重签，而设备侧已经开始用它验 sign2。
            if (!Gb35114CertUtil.matches(issued.certPem, keyPem)) {
                throw new IllegalStateException("签出的证书与本地留存的私钥不配对，已放弃写入");
            }
            certMapper.completeCert(certId, issued.certPem,
                    issued.certificate.getSerialNumber().toString(16),
                    CERT_TIME.format(notBefore.toInstant()), CERT_TIME.format(notAfter.toInstant()),
                    caId, validityDays, normalizeKeyUsage(cert), fingerprintOf(issued.certificate));
            return certMapper.queryLite(certId);
        } catch (Exception e) {
            log.error("[GB35114] 签发服务端证书失败", e);
            throw new RuntimeException("签发服务端证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert importIdentityCert(Gb35114Cert profile, String certPem, String keyPem) {
        requireLocalIdentityType(profile.getType());
        if (Gb35114Cert.TYPE_SERVER_IDENTITY.equals(profile.getType())) {
            // 导入等价于新建一组密钥对，同样受守卫约束（见 assertNoActiveServerIdentity）
            assertNoActiveServerIdentity();
        }
        if (keyPem == null || keyPem.isEmpty()) {
            throw new IllegalArgumentException("本地身份证书必须提供私钥文件");
        }
        if (!Gb35114CertUtil.matches(certPem, keyPem)) {
            throw new IllegalArgumentException("证书与私钥不匹配，请检查文件");
        }
        return persistImported(profile, certPem, keyPem);
    }

    // ------------------------------------------------------------------
    // 客户端证书（下级设备）
    // ------------------------------------------------------------------

    @Override
    public Gb35114Cert issueFromExternalCsr(int caId, String gbId, String remark, String csrPem,
                                            int validityDays, String keyUsage) {
        return issueFromExternalCsr(caId, gbId, remark, csrPem, validityDays, keyUsage, false);
    }

    @Override
    public Gb35114Cert reissueFromCsr(int caId, String gbId, String remark, String csrPem,
                                      int validityDays, String keyUsage) {
        return issueFromExternalCsr(caId, gbId, remark, csrPem, validityDays, keyUsage, true);
    }

    /** 由下级 CSR 签发证书。{@code reuse} 为 true 时先按 CSR 查历史记录并复用。 */
    private Gb35114Cert issueFromExternalCsr(int caId, String gbId, String remark, String csrPem,
                                             int validityDays, String keyUsage, boolean reuse) {
        try {
            Gb35114Ca ca = caMapper.query(caId);
            if (ca == null) {
                throw new IllegalArgumentException("CA 不存在: " + caId);
            }
            if (!Gb35114Ca.TYPE_LOCAL_CA.equals(ca.getType())) {
                throw new IllegalArgumentException("只能使用本地 CA 签发证书");
            }
            Gb35114CertUtil.Gb35114Identity caIdentity = loadCaIdentity(ca);
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issueFromCsr(
                    caIdentity, csrPem, notBefore, notAfter,
                    Gb35114CertUtil.parseKeyUsage(keyUsage, Gb35114CertUtil.KEY_USAGE_ENTITY));

            // 重复签发（续期/补发）：复用同一份 CSR 的历史记录，避免同一 CSR 落多行。
            // 类型过滤不可省：服务端证书的待签发记录里也存着 CSR，不过滤的话这张服务端 CSR
            // 会被按 ISSUED_DEVICE 的语义签掉 —— 证书落成「下级设备」类型、私钥被置空，
            // 服务端证书的私钥记录就此毁掉。类型不符时返回空，走下面的新增分支。
            if (reuse) {
                List<Gb35114Cert> history = certMapper.queryByCsrPem(csrPem.trim(),
                        Gb35114Cert.TYPE_ISSUED_DEVICE);
                if (history != null && !history.isEmpty()) {
                    Gb35114Cert existing = history.get(0);
                    if (gbId == null || gbId.trim().isEmpty()) {
                        gbId = existing.getGbId(); // 沿用原国标 ID
                    }
                    String keyUsageFinal = keyUsage == null || keyUsage.trim().isEmpty()
                            ? "digitalSignature" : keyUsage.trim();
                    certMapper.completeCert(existing.getId(), issued.certPem,
                            issued.certificate.getSerialNumber().toString(16),
                            CERT_TIME.format(notBefore.toInstant()), CERT_TIME.format(notAfter.toInstant()),
                            caId, validityDays, keyUsageFinal, fingerprintOf(issued.certificate));
                    return certMapper.queryLite(existing.getId());
                }
            }

            Gb35114Cert cert = new Gb35114Cert();
            cert.setType(Gb35114Cert.TYPE_ISSUED_DEVICE);
            // 下级国标 ID：调用方未提供时从 CSR 主题 CN 提取（CN 通常即国标编码）
            String effectiveGbId = gbId;
            if (effectiveGbId == null || effectiveGbId.trim().isEmpty()) {
                effectiveGbId = Gb35114CertUtil.csrSubjectCn(csrPem);
            }
            cert.setGbId(effectiveGbId);
            // subject 取自 CSR，调用方不可覆盖，避免 DN 与公钥绑定被篡改
            cert.setSubjectCn(extractCn(issued.certificate));
            cert.setSubjectDn(Gb35114CertUtil.subjectDn(issued.certificate));
            // 密码模块 ID 从 CN 的「设备ID_密码模块ID」后半段解析（附录 A 表 A.1 第 6 项），
            // 单列出来供「设备身份管理」检验项展示三元对应关系。
            cert.setModuleId(moduleIdOf(cert.getSubjectCn()));
            cert.setSerialNumber(issued.certificate.getSerialNumber().toString(16));
            cert.setCaId(caId);
            cert.setCertPem(issued.certPem);
            cert.setKeyPem(null); // 私钥在下级，本平台不持有
            cert.setCsrPem(csrPem.trim());
            // 公钥指纹必须落库：UAS 侧按指纹反查「设备自报的证书是否由本平台保存」，
            // 指纹为空会让反查落空 —— 该证书会被判为「非本平台签发」而拒绝接入。
            cert.setKeyFingerprint(fingerprintOf(issued.certificate));
            cert.setNotBefore(CERT_TIME.format(notBefore.toInstant()));
            cert.setNotAfter(CERT_TIME.format(notAfter.toInstant()));
            cert.setValidityDays(validityDays);
            cert.setKeyUsage(keyUsage == null || keyUsage.trim().isEmpty()
                    ? "digitalSignature" : keyUsage.trim());
            cert.setRevoked(false);
            cert.setRemark(remark);
            cert.setCreateTime(DateUtil.getNow());
            certMapper.add(cert);
            return cert;
        } catch (Exception e) {
            log.error("[GB35114] 由下级 CSR 签发证书失败", e);
            throw new RuntimeException("签发证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert importPeerCert(Gb35114Cert profile, String certPem) {
        // 对端证书仅存公钥，忽略任何传入私钥
        return persistImported(profile, certPem, null);
    }

    // ------------------------------------------------------------------
    // 查询 / 生命周期
    // ------------------------------------------------------------------

    @Override
    public List<Gb35114Cert> queryAllCerts() {
        return fillRelations(certMapper.queryAll());
    }

    @Override
    public List<Gb35114Cert> queryCertsByType(String type) {
        return fillRelations(certMapper.queryByType(type));
    }

    /**
     * 落库后重新读一遍列表列再返回。
     *
     * <p>新增/签发接口返回的是内存里刚拼好的对象，缺少只有 SQL 才产生的派生列
     * （{@code has_key} 是 {@code CASE WHEN} 算出来的），直接返回会让前端看到
     * {@code hasKey=null}，与列表接口的自相矛盾。
     */
    private Gb35114Cert reload(Gb35114Cert cert) {
        if (cert == null || cert.getId() == null) {
            return cert;
        }
        try {
            Gb35114Cert fresh = certMapper.queryLite(cert.getId());
            return fresh == null ? cert : fresh;
        } catch (Exception e) {
            log.warn("[GB35114] 回读证书 #{} 失败: {}", cert.getId(), e.getMessage());
            return cert;
        }
    }

    @Override
    public Gb35114Cert queryCert(int id) {
        return certMapper.queryLite(id);
    }

    @Override
    public List<Gb35114Cert> queryByGbId(String gbId) {
        return fillRelations(certMapper.queryByGbId(gbId));
    }

    @Override
    public Gb35114Cert queryIssuedDeviceCert(String gbId) {
        if (gbId == null || gbId.isEmpty()) {
            return null;
        }
        List<Gb35114Cert> list = certMapper.queryIssuedDeviceCert(gbId);
        if (list == null || list.isEmpty()) {
            return null;
        }
        // 吊销/过期的过滤放在 Java 层，规避 revoked 列在 MySQL/PG/达梦 的布尔类型差异。
        // 列表已按 id 倒序，取第一条仍然有效的证书。
        String now = DateUtil.getNow();
        Gb35114Cert expiredCandidate = null;
        for (Gb35114Cert cert : list) {
            if (Boolean.TRUE.equals(cert.getRevoked())) {
                continue;
            }
            if (isExpired(cert, now)) {
                // 过期是否算「不可用」取决于策略（见 rejectBecauseExpired）。
                // 默认策略下过期证书仍可用，但优先返回未过期的 —— 同一设备可能有新旧两张，
                // 让设备用新的那张，把过期的留作兜底。
                if (expiredCandidate == null) {
                    expiredCandidate = cert;
                }
                continue;
            }
            return cert;
        }
        if (expiredCandidate != null && !config.isRejectExpiredCert()) {
            rejectBecauseExpired(expiredCandidate, now, "设备接入");
            return expiredCandidate;
        }
        return null;
    }

    @Override
    public Gb35114Cert queryActiveServerIdentity() {
        return queryDefaultServerIdentity();
    }

    /**
     * 取当前可用的服务端签名身份。
     *
     * <p><b>服务端只保留一组密钥</b>：设备侧只存得下一把公钥（NanGBD 的
     * {@code ua_set_server_cert} 就是一个全局变量，后写覆盖先写），平台若在多个密钥组
     * 之间挑用，等于悄悄换掉设备信任的公钥，设备验 sign2 必然失败，而平台日志上一切正常
     * —— 故障点会漂到设备侧，极难定位。所以这里<b>绝不跨密钥组回退</b>。
     *
     * <p><b>不存在「选哪一张」的问题</b>：{@code SERVER_IDENTITY} 由后端强制唯一
     * （见 {@link #assertNoActiveServerIdentity}），换发走「同密钥再签」原地更新，
     * 所以该类型下至多一条未吊销记录，取它即可。早期版本用 {@code is_default} 列
     * 在「同密钥对的多张证书」之间挑锚点，现已随唯一性约束一并删除。
     *
     * @return 可用的服务端证书；已吊销、或（严格策略下）已过期时返回 {@code null}
     */
    @Override
    public Gb35114Cert queryDefaultServerIdentity() {
        List<Gb35114Cert> list = certMapper.queryServerIdentities();
        if (list == null || list.isEmpty()) {
            return null;
        }
        // 按 id 倒序，取第一条未吊销的。唯一性约束下这里通常只有一条；
        // 存量数据可能有多条（唯一性守卫是后加的），取最新的一条兼容之。
        for (Gb35114Cert cert : list) {
            if (Boolean.TRUE.equals(cert.getRevoked())) {
                continue;
            }
            // 组内解析：证书不可用时按公钥指纹找同密钥对的兄弟证书。
            // 注意已吊销的证书 resolveUsableServerIdentity 直接返回 null 而不顺延 —— 吊销即停用。
            return resolveUsableServerIdentity(cert.getId());
        }
        return null;
    }

    @Override
    public Gb35114Cert resolveUsableServerIdentity(int certId) {
        Gb35114Cert cert = certMapper.queryLite(certId);
        if (cert == null || !Gb35114Cert.TYPE_SERVER_IDENTITY.equals(cert.getType())) {
            return null;
        }
        // 吊销是对该签名身份「停用」的明确指令，绝不顺延到同组兄弟证书 ——
        // 同组共用私钥，泄露必然整组一起吊销，能顺延就等于吊销无效。
        if (Boolean.TRUE.equals(cert.getRevoked())) {
            return null;
        }
        if (isUsableServerIdentity(cert, DateUtil.getNow())) {
            return cert;
        }
        // 本张已过期（或待签发/缺私钥），但签名身份是密钥对而非证书：
        // 同指纹的兄弟证书只要还有可用的，就能继续代表同一身份，设备无感。
        if (cert.getKeyFingerprint() == null || cert.getKeyFingerprint().isEmpty()) {
            return null;
        }
        for (Gb35114Cert sibling : certMapper.queryServerIdentitiesByFingerprint(cert.getKeyFingerprint())) {
            if (sibling.getId() == certId || Boolean.TRUE.equals(sibling.getRevoked())) {
                continue;
            }
            if (isUsableServerIdentity(sibling, DateUtil.getNow())) {
                log.info("[GB35114] 证书 #{} 不可用，改用同密钥对证书 #{}（指纹 {}）",
                        certId, sibling.getId(), cert.getKeyFingerprint());
                return sibling;
            }
        }
        return null;
    }

    @Override
    public Gb35114Cert queryUsableServerIdentity(Integer certId) {
        if (certId == null) {
            return null;
        }
        Gb35114Cert cert = certMapper.queryLite(certId);
        if (cert == null || !Gb35114Cert.TYPE_SERVER_IDENTITY.equals(cert.getType())) {
            return null;
        }
        return isUsableServerIdentity(cert, DateUtil.getNow()) ? cert : null;
    }

    @Override
    public Gb35114Cert queryDeviceIdentity(String gbId) {
        return resolveByType(Gb35114Cert.TYPE_DEVICE_IDENTITY, gbId, "客户端证书（本平台）");
    }

    @Override
    public Gb35114Cert queryTrustedPlatformCert(String serverGbId) {
        return resolveByType(Gb35114Cert.TYPE_TRUSTED_PLATFORM, serverGbId, "服务端证书（上级平台）");
    }

    /**
     * 按类型 + 国标 ID 解析证书：精确匹配优先，唯一候选兜底，多候选拒绝。
     *
     * <p>DEVICE_IDENTITY / TRUSTED_PLATFORM 这两个类型<b>天然不唯一</b> —— 本平台可以同时
     * 接入多个上级，每个上级各有自己的一张。所以这里不能像 SERVER_IDENTITY 那样「取唯一的一条」，
     * 而要按绑定的国标 ID 区分。
     *
     * <p>匹配不到国标 ID 时<b>只在候选唯一的情况下兜底</b>：多张候选说明运维配了多个上级但
     * 没建立对应关系，此时无论挑哪张都是猜。猜错的代价是用别人的身份去注册（或拿别人的公钥
     * 去验签），对方必然验不过，而本平台日志上一切正常 —— 所以宁可不签名、返回 null 并告警，
     * 让调用方明确报「未配置证书」，也不要静默地挑一张。
     *
     * @param type 证书类型
     * @param gbId    绑定的国标 ID，可为 null/空
     * @param label   日志用中文名
     */
    private Gb35114Cert resolveByType(String type, String gbId, String label) {
        List<Gb35114Cert> all = certMapper.queryByType(type);
        if (all == null || all.isEmpty()) {
            return null;
        }
        // 吊销的绝不参与（列表按 id 倒序，同一 gbId 有多张时取最新的那张）
        // 待签发（只有 CSR 与私钥、certPem 为空）的同样不参与：它还不是一张证书，
        // 既不能用于签名也不能用于验签。放进来会让调用方拿到一条「有私钥但没证书」的记录，
        // 随后在 loadIdentity 里以 StringReader(null) 的 NPE 形式炸掉，报错信息完全指不到
        // 「证书还没签发」这个真实原因。
        List<Gb35114Cert> candidates = new java.util.ArrayList<>();
        for (Gb35114Cert cert : all) {
            if (Boolean.TRUE.equals(cert.getRevoked())) {
                continue;
            }
            if (cert.getCertPem() == null || cert.getCertPem().isEmpty()) {
                continue;
            }
            candidates.add(cert);
        }
        if (candidates.isEmpty()) {
            return null;
        }
        if (gbId != null && !gbId.isEmpty()) {
            for (Gb35114Cert cert : candidates) {
                if (gbId.equals(cert.getGbId())) {
                    return cert;
                }
            }
        }
        if (candidates.size() == 1) {
            return candidates.get(0);
        }
        log.warn("[GB35114] {} 有多张候选（{} 张）但无法按国标 ID {} 定位，拒绝猜测；"
                        + "请在级联平台配置里显式绑定证书",
                label, candidates.size(), gbId == null || gbId.isEmpty() ? "(空)" : gbId);
        return null;
    }

    /**
     * 公钥指纹，取不到时返回 {@code null} 并记日志。
     *
     * <p>指纹是辅助标识（用于判断同组证书可互换），不应因为计算失败而让整条落库回滚。
     */
    private String fingerprintOf(X509Certificate certificate) {
        try {
            return Gb35114CertUtil.publicKeyFingerprint(certificate);
        } catch (Exception e) {
            log.warn("[GB35114] 计算公钥指纹失败: {}", e.getMessage());
            return null;
        }
    }

    /** 公钥指纹（PEM 版），取不到时返回 {@code null} 并记日志。 */
    private String fingerprintOf(String certPem) {
        try {
            return Gb35114CertUtil.publicKeyFingerprint(certPem);
        } catch (Exception e) {
            log.warn("[GB35114] 计算公钥指纹失败: {}", e.getMessage());
            return null;
        }
    }

    /** 服务端证书是否可用：持私钥、已签发、未吊销、未过期。 */
    private boolean isUsableServerIdentity(Gb35114Cert cert, String now) {
        if (Boolean.TRUE.equals(cert.getRevoked())) {
            return false;
        }
        if (cert.getCertPem() == null || cert.getCertPem().isEmpty()) {
            return false;
        }
        if (isExpired(cert, now) && config.isRejectExpiredCert()) {
            // 这里刻意不记日志：本方法在 resolveUsableServerIdentity 的同组兄弟遍历里
            // 会被逐张调用，记日志会让每次注册都刷出一串告警。真正需要告警的场景
            //（出站签名、设备接入判定）由 rejectBecauseExpired 负责。
            return false;
        }
        return Boolean.TRUE.equals(cert.getHasKey());
    }

    /** 该证书是否已过有效期（{@code notAfter} 早于 {@code now}）。 */
    private static boolean isExpired(Gb35114Cert cert, String now) {
        return cert.getNotAfter() != null && cert.getNotAfter().compareTo(now) < 0;
    }

    /**
     * 过期策略下的「是否过期拦截」判定。
     *
     * <p>默认（{@code gb35114.reject-expired-cert=false}）返回 false 并记一次告警 ——
     * 过期只提示不拦截，由运维在证书列表上看到「已过期」后自行决定吊销、删除还是续签。
     * A 级握手既不校验证书链也不校验有效期，设备/上级只拿公钥验签，因此一张刚过期的
     * 证书在协议上仍然可用；按日期直接拒绝会让设备在运维还没反应过来时就被挡在门外。
     *
     * <p>吊销与过期是两回事：吊销不受本策略影响，任何取值下都拒绝。
     *
     * @param cert   待判定的证书
     * @param now    当前时间（服务器本地时区的字符串形式）
     * @param scene  出现该情况时记日志用的场景描述
     * @return true 表示「应当因过期而拒绝」
     */
    private boolean rejectBecauseExpired(Gb35114Cert cert, String now, String scene) {
        if (!isExpired(cert, now)) {
            return false;
        }
        if (config.isRejectExpiredCert()) {
            return true;
        }
        log.warn("[GB35114] {}使用的证书 #{} 已于 {} 过期，当前配置不拒绝过期证书，"
                        + "仍按有效处理；建议在证书管理页吊销后重新颁发",
                scene, cert.getId(), cert.getNotAfter());
        return false;
    }

    @Override
    public X509Certificate loadCert(int id) {
        Gb35114Cert cert = certMapper.query(id);
        if (cert == null) {
            return null;
        }
        // 与 loadIdentity 同理：待签发记录没有证书内容，先给出可读的原因，
        // 而不是让 null 在 loadCertificate 里变成 StringReader(null) 的 NPE。
        if (cert.getCertPem() == null || cert.getCertPem().isEmpty()) {
            throw new IllegalStateException("证书 #" + id + " 类型为 " + cert.getType()
                    + " 尚未签发（无证书内容），不能使用；请先完成签发或回填证书");
        }
        try {
            return Gb35114CertUtil.loadCertificate(cert.getCertPem());
        } catch (Exception e) {
            log.error("[GB35114] 加载证书失败 id={}", id, e);
            throw new RuntimeException("加载证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114CertUtil.Gb35114Identity loadIdentity(int id) {
        Gb35114Cert cert = certMapper.query(id);
        if (cert == null) {
            return null;
        }
        // 本方法是本平台「出站签名」的统一入口（UAS 签 sign2、UAC 签 sign1）。
        // 吊销在这里拦截，而不是在 loadCert 里 —— loadCert 服务于验签路径，
        // 在底层按 revoked 直接拦会让「吊销一张上级平台证书」把级联打黑且丢失上下文；
        // 验签侧的吊销语义由 validateAnnouncedDeviceCert 这类按业务判定的地方表达。
        if (Boolean.TRUE.equals(cert.getRevoked())) {
            log.warn("[GB35114] 证书 #{} 已吊销，拒绝用于本平台签名: type={}, gbId={}",
                    id, cert.getType(), cert.getGbId());
            throw new Gb35114Exception("证书 #" + id + " 已吊销，不能用于本平台签名；"
                    + "请重新签发并回填后使用");
        }
        // 过期只告警不拦截（策略见 rejectBecauseExpired）
        rejectBecauseExpired(cert, DateUtil.getNow(), "出站签名");
        if (cert.getKeyPem() == null || cert.getKeyPem().isEmpty()) {
            throw new IllegalStateException("证书 #" + id + " 类型为 " + cert.getType()
                    + "，本平台不持有私钥，不能用于本平台签名");
        }
        // 待签发记录（只有 CSR 与私钥，证书内容为空）不能用于签名。不在这里拦的话，
        // null 会一路传到 Gb35114CertUtil.loadCertificate 的 new StringReader(pem)，
        // 报成「加载身份失败: Cannot invoke "String.length()" because "s" is null」，
        // 完全看不出真实原因是「证书还没签发」。
        if (cert.getCertPem() == null || cert.getCertPem().isEmpty()) {
            throw new IllegalStateException("证书 #" + id + " 类型为 " + cert.getType()
                    + " 尚未签发（无证书内容），不能用于本平台签名；请先完成签发或回填证书");
        }
        String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), cert.getKeyPem());
        try {
            return Gb35114CertUtil.loadIdentity(cert.getCertPem(), keyPem);
        } catch (Exception e) {
            log.error("[GB35114] 加载身份失败 id={}", id, e);
            throw new RuntimeException("加载身份失败: " + e.getMessage(), e);
        }
    }

    @Override
    public String describeDeviceCertUnavailable(String gbId) {
        if (gbId == null || gbId.isEmpty()) {
            return null;
        }
        List<Gb35114Cert> all = certMapper.queryIssuedDeviceCert(gbId);
        if (all == null || all.isEmpty()) {
            return null; // 本平台从未给该设备签发过
        }
        String now = DateUtil.getNow();
        boolean anyRevoked = false;
        boolean anyUsableButNoKey = false;
        boolean anyExpired = false;
        for (Gb35114Cert c : all) {
            if (Boolean.TRUE.equals(c.getRevoked())) {
                anyRevoked = true;
                continue;
            }
            if (isExpired(c, now)) {
                // 只有「过期即拒绝」的策略下，过期才构成不可用的原因；
                // 默认策略下过期证书仍可接入，此处不该把它说成不可用。
                if (config.isRejectExpiredCert()) {
                    anyExpired = true;
                }
                continue;
            }
            if (c.getCertPem() == null || c.getCertPem().isEmpty()) {
                anyUsableButNoKey = true;
            }
        }
        if (anyRevoked) {
            return "本平台签发给该设备的证书已被吊销（#"
                    + all.get(0).getId() + " 等），需重新签发并换发到设备";
        }
        if (anyUsableButNoKey) {
            return "本平台给该设备留有待签发记录，但尚未签发证书";
        }
        if (anyExpired) {
            return "本平台签发给该设备的证书已全部过期，需续签并换发到设备";
        }
        return null;
    }

    @Override
    public X509Certificate validateAnnouncedDeviceCert(String gbId, X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        String fp;
        try {
            fp = Gb35114CertUtil.publicKeyFingerprint(cert);
        } catch (Exception e) {
            throw new Gb35114Exception("无法计算设备自报证书的公钥指纹: " + e.getMessage());
        }
        List<Gb35114Cert> known = certMapper.queryIssuedDeviceCertsByFingerprint(fp);
        if (known == null || known.isEmpty()) {
            // 指纹查不到记录，有两种可能，必须区分开：
            //   (a) 指纹列尚未回填（存量数据）——按指纹反查会落空，若直接放行则吊销失效；
            //   (b) 本平台确实没签发过这张证书。
            // 用 gb_id 兜底再查一次：命中记录说明是本平台签发过的证书，只是指纹没写上，
            // 此时按记录状态判定。
            // 注意必须用 mapper 的原始查询：service 的 queryIssuedDeviceCert 会过滤掉
            // 已吊销的记录（严格策略下还过滤已过期的），拿它兜底会把「已吊销」变成
            // 「查无此证」进而放行。
            List<Gb35114Cert> byGbId = certMapper.queryIssuedDeviceCert(gbId);
            if (byGbId != null && !byGbId.isEmpty()) {
                // 仅按 gb_id 命中不足以判定：必须比公钥指纹，确认设备出示的确实就是库里那张
                // （否则设备拿任意证书配上该 gb_id 就能绕过）。
                //
                // 一台设备只有一个密钥对，所以这里只可能比中一条记录 —— 逐条遍历只为找出
                // 「哪一条是它的」，不是为了「更新每一条」。比对用的指纹在内存里现算，
                // 不写库：读路径保持只读，存量指纹由迁移脚本一次性回填。
                known = new java.util.ArrayList<>();
                for (Gb35114Cert c : byGbId) {
                    if (c.getCertPem() == null || c.getCertPem().isEmpty()) {
                        continue;
                    }
                    String storedFp = c.getKeyFingerprint();
                    if (storedFp == null || storedFp.isEmpty()) {
                        storedFp = fingerprintOf(c.getCertPem());
                    }
                    if (fp.equals(storedFp)) {
                        known.add(c);
                    }
                }
                if (!known.isEmpty()) {
                    log.info("[GB35114] 设备自报证书命中 {} 的签发记录（指纹列未回填，已按公钥比对确认）", gbId);
                }
            }
        }
        if (known == null || known.isEmpty()) {
            // 本平台没有保存这张证书，因此无从判断其有效性 —— 而「本平台保存且有效」是
            // 接入的前提。放行它意味着：任何持有该设备 gb_id 的人，用一张自己签的证书
            // （A 级握手不校验证书链，自签也验得过）就能冒充该设备接入，且平台侧没有
            // 任何记录可供吊销 —— 出事时连「这台设备是谁签的」都查不到。
            log.warn("[GB35114] 设备自报证书不在本平台签发记录中，拒绝接入: gbId={}, 指纹={}", gbId, fp);
            throw new Gb35114Exception("设备证书非本平台签发，未在本平台保存");
        }
        // 指纹命中的记录里只要有一条是有效的，该证书就仍可接入（同密钥对可能有多张，
        // 例如轮换后新旧并存）；全部命中记录都已吊销才拒绝。
        //
        // 过期是否算「无效」取决于策略：默认不拒绝过期证书，因此过期记录在这里仍算有效
        //（仅记一次告警），只有全部记录都已吊销才拒绝。策略置为拒绝时恢复原有判定。
        String now = DateUtil.getNow();
        boolean rejectExpired = config.isRejectExpiredCert();
        boolean anyUsable = false;
        Gb35114Cert expiredSample = null;
        for (Gb35114Cert c : known) {
            if (Boolean.TRUE.equals(c.getRevoked())) {
                continue;
            }
            if (isExpired(c, now)) {
                if (rejectExpired) {
                    continue;
                }
                if (expiredSample == null) {
                    expiredSample = c;
                }
            }
            anyUsable = true;
            break;
        }
        if (!anyUsable) {
            // 走到这里说明「无任何未吊销记录」，或「全部记录都已过期且策略要求拒绝」
            boolean anyRevoked = false;
            for (Gb35114Cert c : known) {
                if (Boolean.TRUE.equals(c.getRevoked())) {
                    anyRevoked = true;
                    break;
                }
            }
            String why = anyRevoked ? "已被吊销" : "已过期";
            log.warn("[GB35114] 设备自报证书{}，拒绝接入: gbId={}, 指纹={}", why, gbId, fp);
            throw new Gb35114Exception("设备证书" + why);
        }
        if (expiredSample != null) {
            rejectBecauseExpired(expiredSample, now, "设备接入");
        }
        // 链校验放在吊销/过期判定之后：否则「已吊销」会被链校验的消息掩盖，
        // 而两者的处置完全不同（前者要重新签发，后者要核对设备用的是哪张证书）。
        Integer expectedCaId = null;
        for (Gb35114Cert c : known) {
            if (c.getCaId() != null) {
                expectedCaId = c.getCaId();
                break;
            }
        }
        return validateDeviceCertChain(gbId, cert, expectedCaId);
    }

    /**
     * {@inheritDoc}
     *
     * <p>判定顺序：先按签发记录上记着的 CA 验，记不上（存量未回填、或由
     * {@link #importPeerCert} 导入的对端证书）再退回本平台的全部 CA 逐一试。
     * 退回时把本地 CA 排在前面：本平台签发给下级的证书正常都由本地 CA 签发，
     * 先试它能省掉多上级场景下的若干次验签。
     */
    @Override
    public X509Certificate validateDeviceCertChain(String gbId, X509Certificate cert, Integer expectedCaId) {
        if (cert == null) {
            return null;
        }
        // 全局逃生口：现场拿不到 CA 时不再要求「由已导入的 CA 签发」。
        // 放在最前面是有意的 —— 这个开关的语义就是「不要因为 CA 缺失把设备挡在门外」，
        // 因此连「本平台没有任何 CA」这条也不该再拦。指纹反查、吊销、有效期都已在
        // 调用方 validateAnnouncedDeviceCert 完成，不受此处影响。
        if (config.isSkipCertChainVerify()) {
            log.warn("[GB35114] 已配置跳过证书链验证，不再校验设备证书签发者: gbId={}", gbId);
            return cert;
        }
        List<Gb35114Ca> candidates = new ArrayList<>();
        if (expectedCaId != null) {
            Gb35114Ca expected = caMapper.query(expectedCaId);
            if (expected != null) {
                candidates.add(expected);
            }
            // 记录上记着的 CA 查不到（已被删除等）→ 退回全表。
            // deleteCa 会拒绝删除仍被证书引用的 CA，所以这条路径近乎不可达；
            // 留着它是因为「退回」只可能接受确实由某张已导入 CA 签发的证书，
            // 不会放松安全性，却能让一处数据不一致不至于把设备全挡在门外。
        }
        List<Gb35114Ca> all = localAndTrustedCas();
        if (candidates.isEmpty()) {
            candidates.addAll(all);
        }
        if (candidates.isEmpty()) {
            // 没有可用的 CA 就无从判定「证书链是否正确」。这里选择拒绝而非放行：
            // 放行等于让链校验在未配置 CA 的部署里静默失效，而设备接入是本平台
            // 唯一需要它把关的入口。未配 CA 的部署应先建 CA 再接入设备。
            log.warn("[GB35114] 设备自报证书无法做链校验：本平台没有可用的 CA，拒绝接入: gbId={}", gbId);
            throw new Gb35114Exception("本平台未配置任何 CA（本地根 CA 或受信任的 CA），"
                    + "无法验证设备证书链；请先在「CA 证书管理」页生成本地根 CA 或导入受信任的 CA");
        }
        // 缩小候选（按签发者 DN）在 tryChain 内做，避免对每张 CA 都做一次 SM2 验签。
        String lastReason = tryChain(cert, candidates);
        if (lastReason == null) {
            return cert;
        }
        // 记录上记着的那张 CA 验不过时，再用全表试一遍。
        //
        // 为什么需要这一步：validateAnnouncedDeviceCert 只取「第一条命中记录」的 ca_id，
        // 而同一台设备只有一个密钥对、可以先后持有由不同 CA 签发的多张证书（轮换）。
        // 设备出示旧的那张时，记录上记着的却是最新那张的 CA，只试它必然拒绝 ——
        // 而这台设备本身完全合法。
        //
        // 这里只放宽「试哪些 CA」，不放宽「必须由某张已导入 CA 签发」这条判据：
        // 能通过就说明该证书确实由本平台已导入的某张 CA 签发，安全性不变。
        if (expectedCaId != null && !all.isEmpty()) {
            lastReason = tryChain(cert, all);
            if (lastReason == null) {
                return cert;
            }
        }
        log.warn("[GB35114] 设备自报证书链校验失败，拒绝接入: gbId={}, 原因={}", gbId, lastReason);
        throw new Gb35114Exception("设备证书不是由本平台已导入的任何 CA 签发（" + lastReason + "）。"
                + "请核对设备使用的是否为本平台签发的证书；"
                + "若该证书由第三方机构签发，请把签发它的 CA 导入「CA 证书管理 · 受信任的 CA 证书」；"
                + "若确实拿不到签发该证书的 CA，可置 gb35114.skip-cert-chain-verify=true 放行"
                + "（会降低对证书被替换的防护，拿到 CA 后应改回 false）");
    }

    /**
     * 用给定的候选 CA 逐个验链，返回 {@code null} 表示通过，否则返回最后一个失败原因。
     *
     * <p>把「按签发者 DN 缩小 → 逐个验签」这段抽出来，是因为它现在要跑两遍
     * （先试记录上记着的那张 CA，失败后试全表）。两处各写一遍容易改漏一处。
     *
     * <p><b>一个 CA 都没试过时返回失败而不是通过</b>：返回 {@code null} 的语义是「验过了，
     * 通过」，而候选为空或候选的 {@code certPem} 全为空时循环一次都不执行 —— 若就此返回
     * {@code null}，等于把「无从校验」当成「校验通过」，链校验会静默失效。
     * 失败方向要朝拒绝一侧倒。
     */
    private String tryChain(X509Certificate cert, List<Gb35114Ca> candidates) {
        List<Gb35114Ca> narrowed = narrowByIssuerDn(candidates, cert);
        if (!narrowed.isEmpty()) {
            candidates = narrowed;
        }
        String lastReason = null;
        boolean tried = false;
        for (Gb35114Ca ca : candidates) {
            if (ca.getCertPem() == null || ca.getCertPem().isEmpty()) {
                continue;
            }
            tried = true;
            try {
                X509Certificate caCert = Gb35114CertUtil.loadCertificate(ca.getCertPem());
                String reason = Gb35114CertUtil.chainFailureReason(cert, caCert);
                if (reason == null) {
                    return null;
                }
                lastReason = reason;
            } catch (Exception e) {
                lastReason = "读取 CA「" + ca.getSubjectCn() + "」的证书失败: " + e.getMessage();
            }
        }
        if (!tried) {
            return "本平台没有可用于校验的 CA 证书";
        }
        return lastReason;
    }

    /**
     * 本平台可用于验链的全部 CA：本地 CA 排在前面，再接受信任的 CA。
     *
     * <p>本地优先只是省几次 SM2 验签：本平台签发给下级的证书正常都由本地 CA 签发。
     *
     * <p><b>受信任的 CA 一并纳入</b>是本次重构的关键 —— 它的适用范围从「只标识上级平台
     * 证书的签发者」扩到「也能验证第三方机构签发的下级设备证书」。设备证书的判定逻辑
     * 本来就不读 {@code ca.getType()}（只验签名 + CA 资格），所以这里放开候选集即可。
     */
    private List<Gb35114Ca> localAndTrustedCas() {
        List<Gb35114Ca> all = new ArrayList<>();
        try {
            List<Gb35114Ca> locals = caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA);
            if (locals != null) {
                all.addAll(locals);
            }
            List<Gb35114Ca> trusted = caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA);
            if (trusted != null) {
                all.addAll(trusted);
            }
        } catch (Exception e) {
            log.warn("[GB35114] 读取 CA 表失败: {}", e.getMessage());
        }
        return all;
    }

    /**
     * {@inheritDoc}
     *
     * <p>只查「受信任的 CA」（{@code TRUSTED_CA}），不查本地根 CA：本平台作下级时，上级证书
     * 由上级自己的 CA 签发，本地根 CA 与它没有任何关系。
     *
     * <p>注意 {@code TRUSTED_CA} 在设备方向（本平台作上级、验下级设备证书）同样参与候选 ——
     * 见 {@link #localAndTrustedCas()}。两个方向的候选集不同是有意的：作下级时本平台自己的
     * 根 CA 不可能签过上级证书，把它放进候选只是白费一次验签。
     */
    @Override
    public X509Certificate validateUpstreamPlatformCertChain(X509Certificate platformCert) {
        if (platformCert == null) {
            return null;
        }
        // 全局逃生口，同 validateDeviceCertChain：拿不到 CA 时不再要求链成立。
        if (config.isSkipCertChainVerify()) {
            log.warn("[GB35114] 已配置跳过证书链验证，不再校验上级平台证书签发者");
            return platformCert;
        }
        List<Gb35114Ca> cas;
        try {
            cas = caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA);
        } catch (Exception e) {
            log.warn("[GB35114] 校验上级证书链时读取受信任 CA 表失败: {}", e.getMessage());
            return platformCert;
        }
        boolean selfSigned = Gb35114CertUtil.isSelfSigned(platformCert);
        // 同 validateDeviceCertChain：按签发者 DN 缩小候选。自签证书的 issuer 等于自身
        // subject，因此同样能被「同公钥的 CA 记录」命中；命中为空时退回原候选集。
        if (cas != null && !cas.isEmpty()) {
            List<Gb35114Ca> narrowed = narrowByIssuerDn(cas, platformCert);
            if (!narrowed.isEmpty()) {
                cas = narrowed;
            }
        }
        String lastReason = null;
        if (cas != null) {
            for (Gb35114Ca ca : cas) {
                if (ca.getCertPem() == null || ca.getCertPem().isEmpty()) {
                    continue;
                }
                X509Certificate caCert;
                try {
                    caCert = Gb35114CertUtil.loadCertificate(ca.getCertPem());
                } catch (Exception e) {
                    lastReason = "读取 CA「" + ca.getSubjectCn() + "」的证书失败: " + e.getMessage();
                    continue;
                }
                // 自签的上级证书：它自己就是链的根，验签只能由同公钥的证书完成 ——
                // 因此这里要求「受信任的 CA 列表里存在与它同公钥的一条」，即该根已被显式导入。
                // 若只做「自签即放行」，开关在自签这个常态下等于没开。
                if (selfSigned) {
                    if (Gb35114CertUtil.sameKey(platformCert, caCert)) {
                        return platformCert;
                    }
                    continue;
                }
                String reason = Gb35114CertUtil.chainFailureReason(platformCert, caCert);
                if (reason == null) {
                    return platformCert;
                }
                lastReason = reason;
            }
        }
        String hint = selfSigned
                ? "上级证书是自签根证书，「CA 证书管理 · 受信任的 CA 证书」里没有与它同公钥的证书；"
                        + "请把该上级证书也导入这一栏，"
                        + "或关闭 gb35114.verify-upstream-cert-chain"
                : "「CA 证书管理 · 受信任的 CA 证书」里没有能签发它的证书（" + lastReason + "）；"
                        + "请把签发该上级证书的 CA 导入这一栏，"
                        + "或关闭 gb35114.verify-upstream-cert-chain";
        if (!selfSigned) {
            // 自签那一支的处置很明确（把证书本身导入即可），不必再抛逃生口，
            // 否则会把「导入一份证书」这种更安全的做法挤到后面。
            hint += "；若确实拿不到该 CA，可置 gb35114.skip-cert-chain-verify=true 放行"
                    + "（会降低对证书被替换的防护，拿到 CA 后应改回 false）";
        }
        log.warn("[GB35114] 上级平台证书链校验失败，本次级联注册不建立: {}", hint);
        throw new Gb35114Exception(hint);
    }

    @Override
    public void revokeCert(int id) {
        certMapper.updateRevoked(id, true);
    }

    @Override
    public void deleteCert(int id) {
        assertNoCertReference(id);
        // 私钥与 CSR 存于同一条记录，删除记录即一并删除私钥，无需额外级联
        certMapper.delete(id);
    }

    @Override
    public void unbindAndDeleteCert(int id) {
        // 先解绑再删。顺序不能反：反了的话 assertNoCertReference 会把本行算成「仍被引用」
        // 而拒绝删除，用户看到的是「删除失败」，实际只差一步解绑。
        int cleared = platformMapper.clearDeviceCertBinding(id) + platformMapper.clearPlatformCertBinding(id);
        if (cleared > 0) {
            log.info("[GB35114] 删除证书 #{} 前解除了 {} 处级联平台绑定", id, cleared);
        }
        // 解绑后若仍被别的平台或设备引用，assertNoCertReference 会照旧拒绝并点名
        deleteCert(id);
    }

    @Override
    public void bindToPlatform(int platformId, String type, Integer certId) {
        boolean deviceSide = Gb35114Cert.TYPE_DEVICE_IDENTITY.equals(type);
        if (!deviceSide && !Gb35114Cert.TYPE_TRUSTED_PLATFORM.equals(type)) {
            throw new IllegalArgumentException("证书类型 " + type + " 不能绑定到级联平台；"
                    + "只接受 " + Gb35114Cert.TYPE_DEVICE_IDENTITY + "（本平台设备证书）与 "
                    + Gb35114Cert.TYPE_TRUSTED_PLATFORM + "（上级平台证书）");
        }
        Platform platform = platformMapper.query(platformId);
        if (platform == null) {
            throw new IllegalArgumentException("级联平台 #" + platformId + " 不存在");
        }
        if (certId != null) {
            // 类型必须对得上。绑错列不会当场报错，而是等到注册时上级验 sign1 失败 ——
            // 那时本平台日志一切正常，排查很容易跑偏，所以在这里就拦下。
            Gb35114Cert cert = certMapper.queryLite(certId);
            if (cert == null) {
                throw new IllegalArgumentException("证书 #" + certId + " 不存在");
            }
            if (!type.equals(cert.getType())) {
                throw new IllegalArgumentException("证书 #" + certId + " 的类型是 " + cert.getType()
                        + "，不能当作「" + type + "」绑定到级联平台");
            }
            if (Boolean.TRUE.equals(cert.getRevoked())) {
                throw new IllegalArgumentException("证书 #" + certId + " 已吊销，不能绑定到级联平台");
            }
        }
        int updated = deviceSide
                ? platformMapper.bindDeviceCert(platformId, certId)
                : platformMapper.bindPlatformCert(platformId, certId);
        if (updated <= 0) {
            throw new IllegalStateException("绑定失败：级联平台 #" + platformId + " 未更新，请刷新后重试");
        }
        log.info("[GB35114] 级联平台 #{}（{}）{}证书绑定改为 {}",
                platformId, platform.getServerGBId(),
                deviceSide ? "设备" : "上级平台", certId == null ? "（解绑）" : "#" + certId);
        // 状态机缓存的丢弃由控制器统一负责（见 Gb35114CertController#resetPlatformStateMachines）：
        // 本类若反向注入 Gb35114SecurityService 会与它对本类的依赖成环。
    }

    /**
     * 删除前校验证书是否仍被设备/级联平台按 ID 引用，被引用则拒绝删除。
     * <p>这些引用是<b>按 ID</b> 存的（{@code wvp_device.cert_id} / {@code server_cert_id}、
     * {@code wvp_platform.device_cert_id} / {@code platform_cert_id}），删除后立刻悬空。
     * 悬空引用不会当场报错，而是在<b>下一次注册时</b>才暴露：
     * {@code Gb35114SecurityService.resolveServerCertId} 对「设备绑定的证书已不可用」
     * 是<b>直接抛异常拒绝注册</b>（不静默回退到其它证书），设备侧表现为注册被拒 403。
     * 服务端证书被删时尤其危险 —— 设备侧存的是旧公钥，即使重新签发也验不过 sign2。
     *
     * <p>因此这里要求运维<b>先解除绑定</b>（设备编辑页清空「国密服务端证书」、级联编辑页
     * 清空「国密设备证书」），再删除证书。校验失败只记日志并跳过，不让「看一眼能不能删」
     * 变成一次可能抛异常的查询。
     */
    private void assertNoCertReference(int id) {
        List<String> refs = new ArrayList<>();
        try {
            List<Device> devices = deviceMapper.getAll();
            if (devices != null) {
                for (Device d : devices) {
                    if (d.getCertId() != null && d.getCertId() == id) {
                        refs.add("设备「" + d.getName() + "」的国密设备证书");
                    }
                    if (d.getServerCertId() != null && d.getServerCertId() == id) {
                        refs.add("设备「" + d.getName() + "」的国密服务端证书");
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[GB35114] 删除证书 #{} 前校验设备引用失败: {}", id, e.getMessage());
        }
        try {
            List<Platform> platforms = platformMapper.queryAll();
            if (platforms != null) {
                for (Platform p : platforms) {
                    if (p.getDeviceCertId() != null && p.getDeviceCertId() == id) {
                        refs.add("级联平台「" + p.getName() + "」的国密设备证书");
                    }
                    if (p.getPlatformCertId() != null && p.getPlatformCertId() == id) {
                        refs.add("级联平台「" + p.getName() + "」的国密平台证书");
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[GB35114] 删除证书 #{} 前校验级联平台引用失败: {}", id, e.getMessage());
        }
        if (!refs.isEmpty()) {
            throw new IllegalArgumentException("证书 #" + id + " 仍被引用，无法删除："
                    + String.join("、", refs)
                    + "。请先在这些设备/平台的编辑页解除绑定，再删除证书");
        }
    }

    // ------------------------------------------------------------------
    // 内部工具
    // ------------------------------------------------------------------

    /**
     * 默认密钥用途：GB35114 的 sign1/sign2 均为数字签名，
     * 故服务端证书（本平台）与客户端证书（本平台）默认 {@code digitalSignature}。
     */
    private static final int DEFAULT_KEY_USAGE = Gb35114CertUtil.KEY_USAGE_ENTITY;

    /** 默认密钥用途的描述串（落库与展示用）。 */
    private static final String DEFAULT_KEY_USAGE_SPEC = "digitalSignature";

    /** 记录应使用的密钥用途位（用户显式指定优先，否则取默认）。 */
    private static int keyUsageBits(Gb35114Cert c) {
        return Gb35114CertUtil.parseKeyUsage(c.getKeyUsage(), DEFAULT_KEY_USAGE);
    }

    /**
     * 规范化密钥用途描述串：为空时落库为默认值，便于列表展示；
     * 非空时先解析一次，无法识别的取值直接报错，避免签出类型不符的证书。
     */
    private static String normalizeKeyUsage(Gb35114Cert c) {
        if (c.getKeyUsage() == null || c.getKeyUsage().trim().isEmpty()) {
            return DEFAULT_KEY_USAGE_SPEC;
        }
        Gb35114CertUtil.parseKeyUsage(c.getKeyUsage(), DEFAULT_KEY_USAGE);
        return c.getKeyUsage().trim();
    }

    /** 有效期自签发时刻起算。 */
    private static Date expiryFrom(Date notBefore, int validityDays) {
        int days = validityDays > 0 ? validityDays : 3650;
        return new Date(notBefore.getTime() + days * 24L * 3600L * 1000L);
    }

    /**
     * 反查「这张证书给谁用了」，填充 {@link Gb35114Cert} 的瞬态关联字段。
     *
     * <p>关系本身存在业务对象那一侧（{@code wvp_platform.device_cert_id} /
     * {@code platform_cert_id}、{@code wvp_device.cert_id}，以及证书行自己的 {@code gb_id}），
     * 这里只把它反过来呈现给运维看，不写库、不新增表。
     *
     * <p>反查失败（数据库异常等）只记日志并跳过关联，不影响证书列表本身 ——
     * 关联只是展示信息，不该让「看一眼证书」变成一次可能失败的查询。
     */
    private List<Gb35114Cert> fillRelations(List<Gb35114Cert> certs) {
        if (certs == null || certs.isEmpty()) {
            return certs;
        }
        fillDeviceRelations(certs);
        fillPlatformRelations(certs);
        fillIssuerHints(certs);
        return certs;
    }

    /**
     * 填充「签发者」提示字段（瞬态）：{@link Gb35114Cert#issuerDn} 与 {@link Gb35114Cert#selfSigned}。
     *
     * <p>对所有<b>已签发</b>的记录计算。这里不能再按「{@code caId} 为空」来筛选：
     * 自签证书现在也会关联到同公钥的 CA（见 {@link #resolveIssuerCaId}），
     * 于是「有 caId」不再蕴含「非自签」—— 若还按老条件跳过，前端就会把一张自签证书
     * 显示成「由受信任 CA #N 签发」，丢掉「自签」这个关键信息。
     *
     * <p>代价是每行多一次 DER 解析。证书表规模是个位数到几十行，列表查询本就要做若干次
     * 关联查询，这点开销可忽略。
     *
     * <p>解析失败只跳过该行：关联信息是展示用的，不该让整个列表查询失败。
     */
    private void fillIssuerHints(List<Gb35114Cert> certs) {
        for (Gb35114Cert c : certs) {
            if (c.getCertPem() == null || c.getCertPem().isEmpty()) {
                continue;
            }
            try {
                X509Certificate x509 = Gb35114CertUtil.loadCertificate(c.getCertPem());
                c.setIssuerDn(Gb35114CertUtil.issuerDn(x509));
                c.setSelfSigned(Gb35114CertUtil.isSelfSigned(x509));
            } catch (Exception e) {
                log.warn("[GB35114] 解析证书 #{} 的签发者失败: {}", c.getId(), e.getMessage());
            }
        }
    }

    /**
     * 填充受信任的 CA 的「关联平台」（瞬态）。
     *
     * <p>链路由「服务端证书（上级平台）的 {@code ca_id}」串起来：某张 TRUSTED_PLATFORM 证书由本 CA 签发，
     * 而级联平台又绑定了那张证书，说明本 CA 就是该上级平台的 CA。多个受信任的 CA 的 CN 常常
     * 都叫 {@code Root CA}，只有这一列能把它们区分开。
     *
     * <p>本地 CA 不参与：它签的是本平台的证书，不服务于任何上级平台。
     */
    /**
     * 给 CA 列表补上「签发了多少张证书」。
     *
     * <p>逐个 {@code COUNT} 而不是一次查全表再内存分组：CA 的数量是个位数，
     * 几次 count 走主键/索引比把整张证书表拉进内存便宜得多。
     *
     * <p>单张 CA 查询失败不让整个列表失败 —— 计数是辅助信息，
     * 缺了它 CA 列表仍然可用（删除时的引用校验在后端另做，不依赖这里）。
     */
    private void fillCaCertCounts(List<Gb35114Ca> cas) {
        for (Gb35114Ca ca : cas) {
            if (ca.getId() == null) {
                continue;
            }
            try {
                ca.setCertCount(certMapper.countByCaId(ca.getId()));
            } catch (Exception e) {
                log.warn("[GB35114] 统计 CA #{} 的关联证书数失败: {}", ca.getId(), e.getMessage());
            }
        }
    }

    private List<Gb35114Ca> fillCaPlatformRelations(List<Gb35114Ca> cas) {
        if (cas == null || cas.isEmpty()) {
            return cas;
        }
        fillCaCertCounts(cas);
        boolean needed = false;
        for (Gb35114Ca ca : cas) {
            if (Gb35114Ca.TYPE_TRUSTED_CA.equals(ca.getType())) {
                needed = true;
                break;
            }
        }
        if (!needed) {
            return cas;
        }
        List<Gb35114Cert> certs;
        List<Platform> platforms;
        try {
            certs = certMapper.queryByType(Gb35114Cert.TYPE_TRUSTED_PLATFORM);
            platforms = platformMapper.queryAll();
        } catch (Exception e) {
            log.warn("[GB35114] 反查 CA 关联级联平台失败: {}", e.getMessage());
            return cas;
        }
        if (certs == null || certs.isEmpty() || platforms == null || platforms.isEmpty()) {
            return cas;
        }
        for (Gb35114Ca ca : cas) {
            if (!Gb35114Ca.TYPE_TRUSTED_CA.equals(ca.getType())) {
                continue;
            }
            for (Gb35114Cert cert : certs) {
                if (cert.getCaId() == null || !cert.getCaId().equals(ca.getId())) {
                    continue;
                }
                Platform matched = null;
                for (Platform p : platforms) {
                    if (p.getPlatformCertId() != null && p.getPlatformCertId().equals(cert.getId())) {
                        matched = p;
                        break;
                    }
                }
                // 未显式绑定证书时，回退按上级编码匹配（该证书的 gb_id 即上级平台编码）
                if (matched == null && cert.getGbId() != null && !cert.getGbId().isEmpty()) {
                    for (Platform p : platforms) {
                        if (cert.getGbId().equals(p.getServerGBId())) {
                            matched = p;
                            break;
                        }
                    }
                }
                if (matched != null) {
                    ca.setRelatedPlatformName(matched.getName());
                    break;
                }
            }
        }
        return cas;
    }

    /**
     * 客户端证书（下级设备）·{@link Gb35114Cert#TYPE_ISSUED_DEVICE} 按 {@code gb_id} 反查国标设备。
     *
     * <p>证书行的 {@code gb_id} 就是被签发设备的国标编码，与 {@code wvp_device.device_id} 同域，
     * 因此可以一次批量查回，避免逐条查库。
     */
    private void fillDeviceRelations(List<Gb35114Cert> certs) {
        Set<String> gbIds = new HashSet<>();
        for (Gb35114Cert c : certs) {
            if (Gb35114Cert.TYPE_ISSUED_DEVICE.equals(c.getType())
                    && c.getGbId() != null && !c.getGbId().isEmpty()) {
                gbIds.add(c.getGbId());
            }
        }
        if (gbIds.isEmpty()) {
            return;
        }
        Map<String, Device> byDeviceId = new HashMap<>();
        try {
            List<Device> devices = deviceMapper.queryByDeviceIds(new ArrayList<>(gbIds));
            if (devices != null) {
                for (Device d : devices) {
                    if (d.getDeviceId() != null) {
                        byDeviceId.put(d.getDeviceId(), d);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[GB35114] 反查客户端证书（下级设备）关联设备失败: {}", e.getMessage());
            return;
        }
        for (Gb35114Cert c : certs) {
            if (!Gb35114Cert.TYPE_ISSUED_DEVICE.equals(c.getType())) {
                continue;
            }
            Device d = byDeviceId.get(c.getGbId());
            if (d != null) {
                c.setRelatedDeviceId(d.getId());
                c.setRelatedDeviceName(d.getName());
            }
        }
    }

    /**
     * 客户端证书（本平台）与服务端证书（上级平台）按级联平台配置反查关联平台。
     *
     * <p>优先按平台上的显式绑定（{@code device_cert_id} / {@code platform_cert_id}）匹配；
     * 未显式绑定时回退按国标编码匹配 —— 客户端证书（本平台）的 {@code gb_id} 是<b>本平台</b>向上注册的
     * 编码（{@code platform.device_gb_id}），服务端证书（上级平台）的 {@code gb_id} 是<b>上级</b>编码
     * （{@code platform.server_gb_id}）。
     *
     * <p>平台数量是个位数，一次全量查回在内存里过滤即可，不新增「按证书反查平台」的 SQL ——
     * 那需要为 MySQL 与达梦各维护一套语句（见 {@code Gb35114CaMapper} 的双套 {@code databaseId}）。
     */
    private void fillPlatformRelations(List<Gb35114Cert> certs) {
        boolean needed = false;
        for (Gb35114Cert c : certs) {
            String p = c.getType();
            if (Gb35114Cert.TYPE_DEVICE_IDENTITY.equals(p)
                    || Gb35114Cert.TYPE_TRUSTED_PLATFORM.equals(p)) {
                needed = true;
                break;
            }
        }
        if (!needed) {
            return;
        }
        List<Platform> platforms;
        try {
            platforms = platformMapper.queryAll();
        } catch (Exception e) {
            log.warn("[GB35114] 反查证书关联级联平台失败: {}", e.getMessage());
            return;
        }
        if (platforms == null || platforms.isEmpty()) {
            return;
        }
        for (Gb35114Cert c : certs) {
            String type = c.getType();
            boolean isDeviceIdentity = Gb35114Cert.TYPE_DEVICE_IDENTITY.equals(type);
            if (!isDeviceIdentity && !Gb35114Cert.TYPE_TRUSTED_PLATFORM.equals(type)) {
                continue;
            }
            Platform matched = null;
            // 第一轮：平台上的显式证书绑定
            for (Platform p : platforms) {
                Integer bound = isDeviceIdentity ? p.getDeviceCertId() : p.getPlatformCertId();
                if (bound != null && bound.equals(c.getId())) {
                    matched = p;
                    break;
                }
            }
            // 第二轮：未显式绑定，按国标编码匹配
            if (matched == null && c.getGbId() != null && !c.getGbId().isEmpty()) {
                for (Platform p : platforms) {
                    String gbId = isDeviceIdentity ? p.getDeviceGBId() : p.getServerGBId();
                    if (c.getGbId().equals(gbId)) {
                        matched = p;
                        break;
                    }
                }
            }
            if (matched != null) {
                c.setRelatedPlatformId(matched.getId());
                c.setRelatedPlatformName(matched.getName());
            }
        }
    }

    private void requireLocalIdentityType(String type) {
        if (!Gb35114Cert.holdsKey(type)) {
            throw new IllegalArgumentException("类型 " + type + " 不由本平台持有私钥，"
                    + "请使用「由下级 CSR 签发」或「导入对端证书」");
        }
    }

    /**
     * 本平台可否自行签发该类型的证书（自签，或用本地 CA 签）。
     *
     * <p>只有<b>服务端证书（本平台）</b>可以：本平台作 UAS 用它签 sign2，设备侧只需要拿到公钥，
     * 谁签的、是不是自签都不影响验签，因此自签或用本地 CA 签都能用。
     *
     * <p><b>客户端证书（本平台）不行</b>：本平台作 UAC，这张证书要交给<b>上级</b>去验 sign1。
     * 证书之所以能被上级信任，靠的是「上级自己签发过它」这条记录 —— 本平台自签或用本地 CA
     * 签出来的证书，上级那边没有任何记录，接入必然被拒。更麻烦的是失败只出现在上级，
     * 本平台这一侧日志一切正常，排查方向很容易跑偏。
     *
     * <p>所以客户端证书只能走「创建 CSR → 导出交上级签发 → 回填」。
     */
    private void requireLocallyIssuableType(String type) {
        if (!Gb35114Cert.TYPE_SERVER_IDENTITY.equals(type)) {
            throw new IllegalArgumentException("类型 " + type + " 的证书必须由上级签发，"
                    + "本平台不能自签或用本地 CA 签发；请用「创建 CSR」导出请求，"
                    + "待上级签发后回到列表点「回填」");
        }
    }

    /**
     * 本地 CA 全局只允许一份。
     *
     * <p>多份本地 CA 并存时，「新签发的证书由谁签的」取决于建 CA 的时间先后，
     * 而验签方只看签发者 DN —— 运维在列表里看到两个 CN 相似的 CA 时无从判断该用哪个，
     * 删错一个又会让它签发的证书集体失去签发者。
     *
     * <p>轮换路径与密钥对一致：<b>先删旧的再建新的</b>。{@link #deleteCa(int)} 会校验
     * 引用，仍被证书引用的 CA 删不掉，因此不会出现「删了 CA 却留下孤儿证书」。
     * 这里刻意不做「自动覆盖」：覆盖会静默改变已有证书的签发者，与删除前校验引用的
     * 安全语义直接冲突。
     *
     * <p>只约束 {@link Gb35114Ca#TYPE_LOCAL_CA}；受信任的 CA 可有多份（多个上级平台各一份，
     * 第三方签发机构也可能不止一家）。
     */
    private void assertNoLocalCa() {
        List<Gb35114Ca> locals = caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA);
        if (locals == null || locals.isEmpty()) {
            return;
        }
        // 查询按 id 倒序，取到的是最新一份；但真正有意义的是「在用」的那份 ——
        // 提示里点名它能直接告诉运维该处理哪一个。存量的多份 CA 场景下两者可能不同。
        Gb35114Ca exist = null;
        for (Gb35114Ca ca : locals) {
            if (certMapper.countByCaId(ca.getId()) > 0) {
                exist = ca;
                break;
            }
        }
        if (exist == null) {
            exist = locals.get(0);
        }
        throw new IllegalArgumentException("本平台已存在本地 CA #" + exist.getId()
                + "（" + exist.getSubjectCn() + "），本地 CA 只保留一份。"
                + "如需更换请先删除它（删除时会校验是否仍有证书引用），再重新生成或导入");
    }

    /**
     * 服务端证书（本平台）只允许存在一组密钥对。
     *
     * <p>守卫条件是「存在<b>未吊销</b>的 {@link Gb35114Cert#TYPE_SERVER_IDENTITY} 记录」。
     * 多组密钥对并存时，设备绑定的是哪一把公钥要靠指纹分组去猜。
     * {@link #resolveUsableServerIdentity(int)} 虽然保证不跨组回退，但「有两组可选」本身
     * 就是配置错误 —— 运维无从判断设备导入的是哪一组，一旦选错，设备验 sign2 必然失败，
     * 而平台侧日志一切正常（确实签了名，只是用错了身份），故障点漂到设备侧。
     *
     * <p>换发路径是<b>先删除、再重新创建</b>：删除后守卫即失效，可以干净地建新的一组。
     * 新证书是<b>新的密钥对</b>，因此绑定过旧证书的设备（{@code wvp_device.server_cert_id}）
     * 与级联平台（{@code wvp_platform.device_cert_id}）必须重新绑定并导入新的平台证书 ——
     * {@link #deleteCert(int)} 会在删除前校验引用，把这些关系点名拦下，而不是留下悬空 ID
     * 等到设备注册时才以 403 暴露。
     *
     * <p>已吊销的记录不阻塞新建：吊销是对某个签名身份的停用，存量数据里可能留有这类记录，
     * 让它们永久占位会使平台再也建不出服务端证书。
     *
     * <p><b>待签发的记录同样占位，但信息不同</b>：一条只有 CSR、还没证书的记录，它的私钥
     * 已经生成并留存了 —— 允许再建一条就等于同一类型下存在两组密钥对，与「只保留一组」矛盾。
     * 但它与「已有可用服务端证书」的处置完全不同：后者要先删除（会换密钥对），
     * 前者只需把那张待签发的签掉即可。所以这里分成两条信息，各自给出可执行的下一步。
     */
    private void assertNoActiveServerIdentity() {
        List<Gb35114Cert> list = certMapper.queryServerIdentities();
        if (list == null || list.isEmpty()) {
            return;
        }
        for (Gb35114Cert c : list) {
            if (Boolean.TRUE.equals(c.getRevoked())) {
                continue;
            }
            // 用「无证书」而非 isPending() 判断：既无证书又无 CSR 的畸形记录同样无从使用，
            // 也应当走删除导向的处置，而不是被当成一张正常证书去要求「先删除再重建」。
            if (c.getCertPem() == null || c.getCertPem().isEmpty()) {
                throw new IllegalArgumentException("本平台已有一张待签发的服务端证书 #" + c.getId()
                        + "（" + c.getSubjectCn() + "），请先把它签出来"
                        + "（用本地根 CA 签发，或导入外部签发的证书回填），"
                        + "或删除该待签发记录后再创建新的");
            }
            throw new IllegalArgumentException("本平台已有服务端证书 #" + c.getId()
                    + "（" + c.getSubjectCn() + "），服务端只保留一组密钥对。"
                    + "如需更换（含延长有效期、换主题），请先删除该证书再重新创建 —— "
                    + "注意新证书是新的密钥对，绑定过它的设备与级联平台需要重新导入本平台证书");
        }
    }

    private X500Name buildSubject(Gb35114Cert c) {
        return Gb35114CertUtil.buildSubject(c.getCountry(), c.getProvince(), c.getLocality(),
                c.getOrganization(), c.getOrganizationalUnit(), c.getSubjectCn());
    }

    /**
     * 设备证书（本平台作 UAC 接入上级）的主题 CN 合规性兜底。
     *
     * <p>GB 35114—2017 附录 A 表 A.1 第 6 项要求设备证书 CN 为「设备 ID_密码模块 ID」。
     * 前端已按此拼装，但证书一旦签出就固化，事后才发现格式不对只能重签；而 CSR 这一步
     * 恰恰是最便宜的拦截点，所以后端不依赖前端：
     * <ul>
     *   <li>CN 里没有「_」时，视为用户只给了设备 ID —— 允许，但记录里模块 ID 会是空；</li>
     *   <li>「_」之后非空且不是 NULL 时，必须是附录 B 的 22 位十进制。</li>
     * </ul>
     * <p>只校验 {@code DEVICE_IDENTITY}：该格式是<b>附录 A 对设备证书</b>的规定，
     * 而本平台自身证书（服务端 / 根 CA）的主题只是<b>沿用</b>这个形状以便统一
     * （见 {@link #defaultSubjectCn}），并不受附录 A 约束 —— 对它们设卡会把一个
     * 纯命名约定变成硬性要求，用户想给服务端证书起个别的名字都做不到。
     */
    private void requireValidDeviceCn(Gb35114Cert profile) {
        if (!Gb35114Cert.TYPE_DEVICE_IDENTITY.equals(profile.getType())) {
            return;
        }
        Gb35114CertUtil.DeviceIds ids = Gb35114CertUtil.parseDeviceIds(profile.getSubjectCn());
        if (ids == null || ids.moduleId() == null) {
            return;
        }
        if (!Gb35114CertUtil.isValidModuleId(ids.moduleId())) {
            throw new IllegalArgumentException("密码模块 ID 须为 " + Gb35114CertUtil.MODULE_ID_LENGTH
                    + " 位十进制数字（GB 35114—2017 附录 B），当前为：" + ids.moduleId());
        }
    }

    /**
     * 本平台证书主题的默认值：`本平台国标ID_密码模块ID`（附录 A 表 A.1 的格式）。
     *
     * <p>服务端证书、客户端证书、根 CA 三者都是本平台自己签发的身份，主题格式没有理由
     * 各不相同。国标 ID 取 `sip.id`；取不到时用标准的空段写法 `NULL` 占位 ——
     * 与其生成一个格式上说不通的串，不如让「本平台编码没配」这件事在主题里直接可见。
     * 密码模块 ID 取自配置 `gb35114.module-id`（留空即 22 个 0），见
     * {@link Gb35114Config#resolvedModuleId()}。
     *
     * <p>只在调用方<b>没有</b>给出主题时兜底：表单里用户可以按需改写主题
     * （例如接入上级时另编一个编码防冲突），那种情况一律以调用方为准。
     */
    private String defaultSubjectCn() {
        String gbId = sipConfig == null ? null : sipConfig.getId();
        return Gb35114CertUtil.buildDeviceCn(gbId, config.resolvedModuleId());
    }

    /** 主题为空时补默认值，返回是否补过（补过则连同 gbId 一起对齐）。 */
    private boolean applyDefaultSubjectCn(Gb35114Cert profile) {
        if (profile.getSubjectCn() != null && !profile.getSubjectCn().trim().isEmpty()) {
            return false;
        }
        String cn = defaultSubjectCn();
        profile.setSubjectCn(cn);
        Gb35114CertUtil.DeviceIds ids = Gb35114CertUtil.parseDeviceIds(cn);
        if (ids != null && ids.deviceId() != null && !"NULL".equals(ids.deviceId())) {
            profile.setGbId(ids.deviceId());
        }
        return true;
    }

    /** 构造基础记录（不含证书/私钥，供 CSR 待签发使用）。 */
    private Gb35114Cert baseRecord(Gb35114Cert profile) {
        Gb35114Cert cert = new Gb35114Cert();
        cert.setType(profile.getType());
        cert.setGbId(profile.getGbId());
        cert.setSubjectCn(profile.getSubjectCn());
        cert.setSubjectDn(buildSubject(profile).toString());
        // 密码模块 ID 一律从 CN 反解析，不单独采信表单字段：CN 才是写进证书的东西，
        // 列取自 CN 才能保证「列 ↔ 证书」永远一致（同 DN 各段的处理口径）。
        cert.setModuleId(moduleIdOf(profile.getSubjectCn()));
        cert.setCountry(profile.getCountry());
        cert.setProvince(profile.getProvince());
        cert.setLocality(profile.getLocality());
        cert.setOrganization(profile.getOrganization());
        cert.setOrganizationalUnit(profile.getOrganizationalUnit());
        cert.setRevoked(false);
        cert.setRemark(profile.getRemark());
        cert.setCreateTime(DateUtil.getNow());
        return cert;
    }

    /** 落库已签发且本平台持有私钥的记录。 */
    private Gb35114Cert persist(Gb35114Cert profile, Gb35114CertUtil.Gb35114Identity identity,
                                Integer caId, int validityDays, Date notBefore, Date notAfter) {
        Gb35114Cert cert = baseRecord(profile);
        cert.setSerialNumber(identity.certificate.getSerialNumber().toString(16));
        cert.setCaId(caId);
        cert.setCertPem(identity.certPem);
        cert.setSubjectDn(Gb35114CertUtil.subjectDn(identity.certificate));
        cert.setKeyFingerprint(fingerprintOf(identity.certificate));
        cert.setKeyPem(identity.keyPem == null ? null
                : Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), identity.keyPem));
        cert.setNotBefore(CERT_TIME.format(notBefore.toInstant()));
        cert.setNotAfter(CERT_TIME.format(notAfter.toInstant()));
        cert.setValidityDays(validityDays);
        cert.setKeyUsage(normalizeKeyUsage(profile));
        certMapper.add(cert);
        return reload(cert);
    }

    /** 落库导入的证书（私钥可为空，仅对端证书）。 */
    private Gb35114Cert persistImported(Gb35114Cert profile, String certPem, String keyPem) {
        try {
            X509Certificate x509 = Gb35114CertUtil.loadCertificate(certPem);
            // 导入表单只收集类型/国标 ID/文件/备注，主题字段一律取自证书本身
            // （下面的 subjectDn 也直接用证书的 DN，不再采信表单值）。因此必须在
            // 构造记录之前把 CN 补上：baseRecord 内的 buildSubject 要求 CN 非空，
            // 补晚了就会以「CN 不能为空」失败 —— 而那个 CN 随后又会被证书的真实
            // 主题覆盖，等于为一个即时丢弃的中间值卡死了整条导入路径。
            if (profile.getSubjectCn() == null || profile.getSubjectCn().trim().isEmpty()) {
                profile.setSubjectCn(extractCn(x509));
            }
            Gb35114Cert cert = baseRecord(profile);
            // DN 各段统一取自证书本身。baseRecord 是按「表单值」填的，而导入表单根本
            // 不收这五个字段，于是 subject_dn 来自证书、五列来自空表单 —— 同一份数据
            // 存两遍且互相矛盾（现场 #41 的 DN 里有 C=CN，country 列却是 NULL）。
            // 这里连同 subject_dn 一起用证书反解析的结果覆盖，让列与 DN 永远一致。
            Gb35114CertUtil.DnParts dn = Gb35114CertUtil.parseSubject(x509);
            cert.setSubjectCn(dn.commonName() == null ? extractCn(x509) : dn.commonName());
            cert.setSubjectDn(Gb35114CertUtil.subjectDn(x509));
            // 密码模块 ID 同样从证书 CN 解析 —— 导入的可能是别人签发的设备证书，
            // 其 CN 里的密码模块 ID 是真实编码，不能采信表单值。
            cert.setModuleId(moduleIdOf(cert.getSubjectCn()));
            cert.setCountry(dn.country());
            cert.setProvince(dn.province());
            cert.setLocality(dn.locality());
            cert.setOrganization(dn.organization());
            cert.setOrganizationalUnit(dn.organizationalUnit());
            cert.setSerialNumber(x509.getSerialNumber().toString(16));
            cert.setCertPem(certPem);
            // 按签名反查签发 CA：导入的证书若能对上已留存的「受信任的 CA」，
            // 「签发方式」列就能显示它由哪个 CA 签发，进而反查该 CA 服务于哪个级联平台。
            // 查不到不报错 —— 证书本身可用，只是页面显示为「签发者未导入」。
            cert.setCaId(resolveIssuerCaId(x509));
            cert.setKeyFingerprint(Gb35114CertUtil.publicKeyFingerprint(x509));
            cert.setKeyPem(keyPem == null ? null
                    : Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), keyPem));
            cert.setNotBefore(CERT_TIME.format(x509.getNotBefore().toInstant()));
            cert.setNotAfter(CERT_TIME.format(x509.getNotAfter().toInstant()));
            cert.setValidityDays(profile.getValidityDays());
            // 导入的证书类型已固化在证书扩展里，此处仅记录用户填写值供展示
            cert.setKeyUsage(profile.getKeyUsage());
            certMapper.add(cert);
            Gb35114Cert saved = reload(cert);
            attachIssuerWarning(saved, x509);
            return saved;
        } catch (Exception e) {
            log.error("[GB35114] 导入证书失败", e);
            throw new RuntimeException("导入证书失败: " + e.getMessage(), e);
        }
    }

    /**
     * 导入对端证书时，若签发它的 CA 不在本平台，给一条提示（<b>不阻断</b>）。
     *
     * <p>覆盖两类证书：
     * <ul>
     *   <li><b>设备证书（下级设备）</b>：设备接入是本平台按链校验把关的入口
     *       （见 {@link #validateDeviceCertChain}），签发者缺失会在注册时变成拒绝；</li>
     *   <li><b>服务端证书（上级平台）</b>：是否校验由 {@code verify-upstream-cert-chain}
     *       开关控制（默认开）。缺 CA 会导致级联注册被拒，所以这里也提示 ——
     *       与设备证书口径一致，不因为开关可以关掉就不提示。</li>
     * </ul>
     *
     * <p><b>为什么不阻断</b>：「证书先导入、CA 后导入」是合法顺序 —— 对端证书往往先由
     * 第三方机构签好拿来导入，CA 证书可能隔一会儿才拿到。信任判定在注册时实时做，
     * 不依赖导入这一眼；这里拒绝会把一个合法顺序变成错误。
     *
     * <p>提示只在导入响应里返回（瞬态字段），不落库：CA 导入后这条提示即失效，
     * 存进库里反而会变成一个永远显示、又无法消除的假告警。
     */
    private void attachIssuerWarning(Gb35114Cert cert, X509Certificate x509) {
        if (cert == null) {
            return;
        }
        String type = cert.getType();
        boolean deviceCert = Gb35114Cert.TYPE_ISSUED_DEVICE.equals(type);
        boolean peerServerCert = Gb35114Cert.TYPE_TRUSTED_PLATFORM.equals(type);
        if (!deviceCert && !peerServerCert) {
            return;
        }
        if (cert.getCaId() != null) {
            return;
        }
        // 自签的证书不需要 CA —— 它是自己签自己，提示「签发者未导入」只会误导。
        // 上级平台证书自签很常见（尤其只有单个上级、没有上级 CA 的场景）。
        if (Gb35114CertUtil.isSelfSigned(x509)) {
            return;
        }
        String issuer = Gb35114CertUtil.issuerDn(x509);
        log.warn("[GB35114] 导入的{} #{} 的签发者未在本平台留存: issuer={}",
                typeLabel(type), cert.getId(), issuer);
        // 「一张 CA 都没有」与「有候选但都不匹配」的处置完全不同：前者要先导入 CA，
        // 后者说明导入的 CA 不对（或该证书该重新签发）。文案分开，否则零 CA 时
        // 每张证书都会得到一句指向错误方向的建议。
        boolean anyCa = hasAnyCa();
        if (deviceCert) {
            cert.setImportWarning("该证书的签发者（" + issuer + "）尚未导入本平台。"
                    + "设备注册时会做证书链校验，届时不通过将被拒绝接入；"
                    + "请把签发它的 CA 证书导入「CA 证书管理 · 受信任的 CA 证书」一栏");
        } else if (anyCa) {
            cert.setImportWarning("这张证书不是由任何已导入的 CA 签发的。"
                    + "请让上级用你已导入的 CA 重新颁发，或导入签发它的那张 CA。");
        } else {
            cert.setImportWarning("尚未导入任何 CA，无法校验签发链。请先导入上级的 CA。");
        }
    }

    /** 本平台是否已留存任何 CA（读表失败时按「有」处理，避免把读故障说成「一张都没有」）。 */
    private boolean hasAnyCa() {
        try {
            List<Gb35114Ca> cas = caMapper.queryAll();
            return cas != null && !cas.isEmpty();
        } catch (Exception e) {
            log.warn("[GB35114] 判断是否已导入 CA 时读表失败: {}", e.getMessage());
            return true;
        }
    }

    private Gb35114CertUtil.Gb35114Identity loadCaIdentity(Gb35114Ca ca) throws Exception {
        if (ca.getKeyPem() == null || ca.getKeyPem().isEmpty()) {
            throw new IllegalArgumentException("CA「" + ca.getSubjectCn() + "」不含私钥，无法用于签发");
        }
        String caKeyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), ca.getKeyPem());
        return Gb35114CertUtil.loadIdentity(ca.getCertPem(), caKeyPem);
    }

    /**
     * 把证书主题 DN 的各段回填到 CA 记录（CN 与 C/ST/L/O/OU 一并取自证书）。
     *
     * <p>生成与导入两条路径共用，保证两条路径落库的列口径完全一致。
     */
    private void fillSubjectFromCert(Gb35114Ca ca, X509Certificate cert) {
        Gb35114CertUtil.DnParts dn = Gb35114CertUtil.parseSubject(cert);
        ca.setSubjectCn(dn.commonName() == null ? Gb35114CertUtil.subjectDn(cert) : dn.commonName());
        ca.setSubjectDn(Gb35114CertUtil.subjectDn(cert));
        ca.setCountry(dn.country());
        ca.setProvince(dn.province());
        ca.setLocality(dn.locality());
        ca.setOrganization(dn.organization());
        ca.setOrganizationalUnit(dn.organizationalUnit());
    }

    /**
     * 从 CN 取密码模块 ID，CN 为空时返回 null。
     *
     * <p>落库的三条路径（CSR 签发 / 自签与导入 / 由下级 CSR 签发）统一走这里，
     * 保证 module_id 列的口径一致，且都源自写进证书的 CN。
     */
    private String moduleIdOf(String subjectCn) {
        Gb35114CertUtil.DeviceIds ids = Gb35114CertUtil.parseDeviceIds(subjectCn);
        return ids == null ? null : ids.moduleId();
    }

    private String extractCn(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }
}
