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
import com.genersoft.iot.vmp.utils.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
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
    public Gb35114Ca generateCa(String subjectCn, String remark) {
        assertNoLocalCa();
        try {
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, config.getCertValidityDays());
            Gb35114CertUtil.Gb35114Identity identity =
                    Gb35114CertUtil.generateSelfSigned(subjectCn, notBefore, notAfter);
            Gb35114Ca ca = new Gb35114Ca();
            ca.setPurpose(Gb35114Ca.PURPOSE_LOCAL);
            ca.setSubjectCn(subjectCn);
            ca.setSerialNumber(identity.certificate.getSerialNumber().toString(16));
            ca.setCertPem(identity.certPem);
            ca.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), identity.keyPem));
            ca.setNotBefore(CERT_TIME.format(notBefore.toInstant()));
            ca.setNotAfter(CERT_TIME.format(notAfter.toInstant()));
            ca.setRemark(remark);
            ca.setCreateTime(DateUtil.getNow());
            caMapper.add(ca);
            return ca;
        } catch (Exception e) {
            log.error("[GB35114] 生成根 CA 失败", e);
            throw new RuntimeException("生成根 CA 失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Ca importCa(String purpose, String certPem, String keyPem, String remark) {
        if (purpose == null || purpose.isEmpty() || Gb35114Ca.PURPOSE_LOCAL.equals(purpose)) {
            // 本地 CA 只能有一份：导入等价于新建，同样受守卫约束
            assertNoLocalCa();
        }
        try {
            if (purpose == null || purpose.isEmpty()) {
                purpose = Gb35114Ca.PURPOSE_LOCAL;
            }
            boolean local = Gb35114Ca.PURPOSE_LOCAL.equals(purpose);
            if (local && (keyPem == null || keyPem.isEmpty())) {
                throw new IllegalArgumentException("本地 CA 必须提供私钥文件");
            }
            X509Certificate cert = Gb35114CertUtil.loadCertificate(certPem);
            Gb35114Ca ca = new Gb35114Ca();
            ca.setPurpose(purpose);
            // CA 的身份取自证书本身：主题 CN 从证书里读，不由导入者现场编一个别名
            ca.setSubjectCn(extractCn(cert));
            ca.setSerialNumber(cert.getSerialNumber().toString(16));
            ca.setCertPem(certPem);
            // 上级 CA 仅存证书，无私钥
            ca.setKeyPem(local ? Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), keyPem) : null);
            ca.setNotBefore(CERT_TIME.format(cert.getNotBefore().toInstant()));
            ca.setNotAfter(CERT_TIME.format(cert.getNotAfter().toInstant()));
            ca.setRemark(remark);
            ca.setCreateTime(DateUtil.getNow());
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
    public List<Gb35114Ca> queryCaByPurpose(String purpose) {
        return fillCaPlatformRelations(caMapper.queryByPurpose(purpose));
    }

    @Override
    public Gb35114Ca queryCa(int id) {
        return caMapper.query(id);
    }

    @Override
    public void deleteCa(int id) {
        int used = certMapper.countByCaId(id);
        if (used > 0) {
            throw new IllegalArgumentException("该 CA 下仍有 " + used + " 张证书，请先删除或改签后再删除 CA");
        }
        caMapper.delete(id);
    }

    /**
     * 按签发者反查本平台已留存的 CA。
     *
     * <p>自签证书（issuer == subject）返回 {@code null}；否则逐个用已导入 CA 的公钥去验证
     * 本证书的签名，验得过的那张就是签发者。
     *
     * <p><b>为什么不用 issuer DN 去匹配 CA 的 subject_cn</b>：CA 表只存了 CN，
     * 而不同 CA 完全可能同名（厂商默认 CN 常常就是 {@code Root CA}），DN 匹配会串台，
     * 把「由 A 签发」标成「由 B 签发」—— 比不标更糟。验签是密码学判定，不存在歧义。
     * 代价是每个候选算一次 SM2 验签，CA 数量是个位数，可忽略。
     *
     * <p>返回 {@code null} 有<b>两种</b>含义（自签 / 签发者未导入），调用方需用
     * {@link Gb35114CertUtil#isSelfSigned} 自行区分 —— 证书表里 {@code ca_id} 为空的
     * 历史记录也走这条路径，不能一律当成自签。
     */
    private Integer resolveIssuerCaId(X509Certificate x509) {
        if (Gb35114CertUtil.isSelfSigned(x509)) {
            return null;
        }
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
        for (Gb35114Ca ca : cas) {
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

    // ------------------------------------------------------------------
    // 本地身份证书
    // ------------------------------------------------------------------

    @Override
    public Gb35114Cert createPendingCsr(Gb35114Cert profile, int validityDays) {
        requireLocalIdentityPurpose(profile.getPurpose());
        if (Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(profile.getPurpose())) {
            // 服务端只保留一组密钥对（见 assertNoActiveServerIdentity）
            assertNoActiveServerIdentity();
        }
        try {
            Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(buildSubject(profile));
            Gb35114Cert cert = baseRecord(profile);
            cert.setCsrPem(csr.csrPem);
            cert.setKeyUsage(normalizeKeyUsage(profile));
            // 关键：私钥不再丢弃，加密后与 CSR 存于同一条记录，签发时复用其公钥。
            cert.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), csr.keyPem));
            cert.setCertPem(null);
            cert.setValidityDays(validityDays);
            cert.setIsDefault(false);
            certMapper.add(cert);
            return cert;
        } catch (Exception e) {
            log.error("[GB35114] 创建证书请求失败", e);
            throw new RuntimeException("创建证书请求失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert signPendingByCa(int certId, int caId, int validityDays) {
        try {
            Gb35114Cert cert = certMapper.query(certId);
            if (cert == null) {
                throw new IllegalArgumentException("证书不存在: " + certId);
            }
            requireLocalIdentityPurpose(cert.getPurpose());
            // 客户端证书必须由上级签发：本地签出来的上级不认（详见 requireLocallyIssuablePurpose）
            requireLocallyIssuablePurpose(cert.getPurpose());
            if (cert.getCertPem() != null && !cert.getCertPem().isEmpty()) {
                throw new IllegalStateException("该记录已签发，无需重复签发");
            }
            if (cert.getKeyPem() == null || cert.getKeyPem().isEmpty()) {
                throw new IllegalStateException("该记录无本地私钥，无法用本平台 CA 签发");
            }
            Gb35114Ca ca = caMapper.query(caId);
            if (ca == null) {
                throw new IllegalArgumentException("CA 不存在: " + caId);
            }
            if (!Gb35114Ca.PURPOSE_LOCAL.equals(ca.getPurpose())) {
                throw new IllegalArgumentException("只能使用本地 CA 签发证书");
            }
            Gb35114CertUtil.Gb35114Identity caIdentity = loadCaIdentity(ca);
            String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), cert.getKeyPem());
            PublicKey publicKey = Gb35114CertUtil.publicKeyOf(keyPem);

            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            Gb35114CertUtil.Gb35114Identity issued =
                    Gb35114CertUtil.issueWithKey(caIdentity, buildSubject(cert), publicKey,
                            notBefore, notAfter, keyUsageBits(cert));
            certMapper.completeCert(certId, issued.certPem,
                    issued.certificate.getSerialNumber().toString(16),
                    CERT_TIME.format(notBefore.toInstant()), CERT_TIME.format(notAfter.toInstant()),
                    caId, validityDays, normalizeKeyUsage(cert),
                    fingerprintOf(issued.certificate));
            Gb35114Cert signed = certMapper.queryLite(certId);
            claimDefaultIfFirstServerIdentity(signed);
            return signed;
        } catch (Exception e) {
            log.error("[GB35114] 签发待签发证书失败", e);
            throw new RuntimeException("签发失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert completePendingWithCert(int certId, String certPem) {
        try {
            Gb35114Cert cert = certMapper.query(certId);
            if (cert == null) {
                throw new IllegalArgumentException("证书不存在: " + certId);
            }
            requireLocalIdentityPurpose(cert.getPurpose());
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
            // 回填的证书通常是上级签发的，其签发者可能已在「上级 CA」里留存；
            // 按签名反查一次，把「证书 → 签发 CA → 级联平台」这条链补上。
            certMapper.completeCert(certId, certPem, x509.getSerialNumber().toString(16),
                    CERT_TIME.format(x509.getNotBefore().toInstant()),
                    CERT_TIME.format(x509.getNotAfter().toInstant()),
                    resolveIssuerCaId(x509), cert.getValidityDays(), normalizeKeyUsage(cert),
                    fingerprintOf(x509));
            Gb35114Cert completed = certMapper.queryLite(certId);
            claimDefaultIfFirstServerIdentity(completed);
            return completed;
        } catch (Exception e) {
            log.error("[GB35114] 回填证书失败", e);
            throw new RuntimeException("回填证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert generateSelfSigned(Gb35114Cert profile, int validityDays) {
        requireLocalIdentityPurpose(profile.getPurpose());
        // 只有服务端证书能自签：客户端证书要交给上级验 sign1，自签的上级不认
        requireLocallyIssuablePurpose(profile.getPurpose());
        // 服务端只保留一组密钥对（见 assertNoActiveServerIdentity）
        assertNoActiveServerIdentity();
        try {
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            Gb35114CertUtil.Gb35114Identity identity =
                    Gb35114CertUtil.generateSelfSigned(buildSubject(profile), notBefore, notAfter,
                            keyUsageBits(profile));
            return persist(profile, identity, null, validityDays, notBefore, notAfter);
        } catch (Exception e) {
            log.error("[GB35114] 生成自签证书失败", e);
            throw new RuntimeException("生成自签证书失败: " + e.getMessage(), e);
        }
    }

    @Override
    public Gb35114Cert importIdentityCert(Gb35114Cert profile, String certPem, String keyPem) {
        requireLocalIdentityPurpose(profile.getPurpose());
        if (Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(profile.getPurpose())) {
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
    // 下级客户端证书
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
            if (!Gb35114Ca.PURPOSE_LOCAL.equals(ca.getPurpose())) {
                throw new IllegalArgumentException("只能使用本地 CA 签发证书");
            }
            Gb35114CertUtil.Gb35114Identity caIdentity = loadCaIdentity(ca);
            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);
            Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issueFromCsr(
                    caIdentity, csrPem, notBefore, notAfter,
                    Gb35114CertUtil.parseKeyUsage(keyUsage, Gb35114CertUtil.KEY_USAGE_ENTITY));

            // 重复签发（续期/补发）：复用同一份 CSR 的历史记录，避免同一 CSR 落多行
            if (reuse) {
                List<Gb35114Cert> history = certMapper.queryByCsrPem(csrPem.trim());
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
            cert.setPurpose(Gb35114Cert.PURPOSE_ISSUED_DEVICE);
            cert.setType(Gb35114Cert.TYPE_DEVICE);
            // 下级国标 ID：调用方未提供时从 CSR 主题 CN 提取（CN 通常即国标编码）
            String effectiveGbId = gbId;
            if (effectiveGbId == null || effectiveGbId.trim().isEmpty()) {
                effectiveGbId = Gb35114CertUtil.csrSubjectCn(csrPem);
            }
            cert.setGbId(effectiveGbId);
            // subject 取自 CSR，调用方不可覆盖，避免 DN 与公钥绑定被篡改
            cert.setSubjectCn(extractCn(issued.certificate));
            cert.setSubjectDn(Gb35114CertUtil.subjectDn(issued.certificate));
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
    public List<Gb35114Cert> queryCertsByPurpose(String purpose) {
        return fillRelations(certMapper.queryByPurpose(purpose));
    }

    /**
     * 落库后重新读一遍列表列再返回。
     *
     * <p>新增/签发接口返回的是内存里刚拼好的对象，缺少只有 SQL 才产生的派生列
     * （{@code has_key} 是 {@code CASE WHEN} 算出来的、{@code is_default} 可能被
     * {@link #claimDefaultIfFirstServerIdentity} 改过），直接返回会让前端看到
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
     * <p>「多个证书」只允许是<b>同一密钥组内的多张</b>（有效期/签发者/序列号不同），
     * 它们对设备完全等价。因此本方法先在组内选出「锚点」，再用
     * {@link #resolveUsableServerIdentity(int)} 在锚点所在组内找一张真正可用的。
     *
     * <p>锚点优先取<b>被显式标记为默认</b>的那张：它是运维对设备的承诺。从未标记过默认时
     * （例如存量数据）取最新的一张，此时不存在承诺，挑到哪张都不算背信。
     *
     * @return 可用的服务端证书；锚点已吊销、或其所在组内已无可用证书时返回 {@code null}
     */
    @Override
    public Gb35114Cert queryDefaultServerIdentity() {
        Gb35114Cert anchor = queryMarkedDefaultServerIdentity();
        if (anchor == null) {
            List<Gb35114Cert> list = certMapper.queryServerIdentities();
            if (list == null || list.isEmpty()) {
                return null;
            }
            anchor = list.get(0); // 列表按 is_default DESC, id DESC，无标记时即最新一张
        }
        // 组内解析：锚点自身可用就返回它；不可用则找同公钥指纹的兄弟证书。
        // 注意锚点若已吊销，resolveUsableServerIdentity 直接返回 null 而不顺延 —— 吊销即停用。
        return resolveUsableServerIdentity(anchor.getId());
    }

    @Override
    public Gb35114Cert queryMarkedDefaultServerIdentity() {
        for (Gb35114Cert cert : certMapper.queryServerIdentities()) {
            if (Boolean.TRUE.equals(cert.getIsDefault())) {
                return cert;
            }
        }
        return null;
    }

    @Override
    public Gb35114Cert resolveUsableServerIdentity(int certId) {
        Gb35114Cert cert = certMapper.queryLite(certId);
        if (cert == null || !Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(cert.getPurpose())) {
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
        if (cert == null || !Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(cert.getPurpose())) {
            return null;
        }
        return isUsableServerIdentity(cert, DateUtil.getNow()) ? cert : null;
    }

    @Override
    public void setDefaultServerIdentity(int certId) {
        Gb35114Cert cert = certMapper.queryLite(certId);
        if (cert == null) {
            throw new IllegalArgumentException("证书 #" + certId + " 不存在");
        }
        if (!Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(cert.getPurpose())) {
            throw new IllegalArgumentException("证书 #" + certId + " 用途为 " + cert.getPurpose()
                    + "，只有本地服务端证书可以设为默认");
        }
        if (!isUsableServerIdentity(cert, DateUtil.getNow())) {
            throw new IllegalArgumentException("证书 #" + certId
                    + " 不可用（需持有私钥、未吊销、未过期），不能设为默认");
        }
        // 先清后置，保证全局至多一张默认
        certMapper.clearDefault();
        certMapper.markDefault(certId);
    }

    @Override
    public Gb35114Cert reissueServerIdentity(int sourceCertId, Gb35114Cert profile,
                                             Integer caId, int validityDays) {
        try {
            Gb35114Cert source = certMapper.query(sourceCertId);
            if (source == null) {
                throw new IllegalArgumentException("源证书不存在: " + sourceCertId);
            }
            if (!Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(source.getPurpose())) {
                throw new IllegalArgumentException("源证书 #" + sourceCertId + " 用途为 "
                        + source.getPurpose() + "，只有本地服务端证书可以复用密钥对");
            }
            if (source.getKeyPem() == null || source.getKeyPem().isEmpty()) {
                throw new IllegalStateException("源证书 #" + sourceCertId
                        + " 未持有私钥，无法复用其密钥对；请改用「创建 CSR」新建密钥对");
            }
            if (source.getCertPem() == null || source.getCertPem().isEmpty()) {
                throw new IllegalStateException("源证书 #" + sourceCertId + " 尚未签发，无法复用其密钥对");
            }

            // 复用源记录的私钥：解密后原样再加密回新记录，公钥自然与源证书一致。
            String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), source.getKeyPem());
            PublicKey publicKey = Gb35114CertUtil.publicKeyOf(keyPem);

            Date notBefore = new Date();
            Date notAfter = expiryFrom(notBefore, validityDays);

            Gb35114CertUtil.Gb35114Identity issued;
            Integer effectiveCaId = caId;
            if (caId == null) {
                // 自签：签发者即自身，用同一私钥签自己的新证书
                issued = Gb35114CertUtil.selfSignWithKey(buildSubject(profile), publicKey,
                        keyPem, notBefore, notAfter, keyUsageBits(profile));
            } else {
                Gb35114Ca ca = caMapper.query(caId);
                if (ca == null) {
                    throw new IllegalArgumentException("CA 不存在: " + caId);
                }
                if (!Gb35114Ca.PURPOSE_LOCAL.equals(ca.getPurpose())) {
                    throw new IllegalArgumentException("只能使用本地 CA 签发证书");
                }
                issued = Gb35114CertUtil.issueWithKey(loadCaIdentity(ca), buildSubject(profile),
                        publicKey, notBefore, notAfter, keyUsageBits(profile));
            }

            Gb35114Cert cert = baseRecord(profile);
            cert.setPurpose(Gb35114Cert.PURPOSE_SERVER_IDENTITY);
            cert.setType(Gb35114Cert.TYPE_SERVER);
            cert.setSerialNumber(issued.certificate.getSerialNumber().toString(16));
            cert.setCaId(effectiveCaId);
            cert.setCertPem(issued.certPem);
            cert.setSubjectDn(Gb35114CertUtil.subjectDn(issued.certificate));
            // 与源证书同一公钥 → 同一指纹，这是「设备无需重新配置」的依据
            cert.setKeyFingerprint(Gb35114CertUtil.publicKeyFingerprint(issued.certificate));
            cert.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), keyPem));
            cert.setNotBefore(CERT_TIME.format(notBefore.toInstant()));
            cert.setNotAfter(CERT_TIME.format(notAfter.toInstant()));
            cert.setValidityDays(validityDays);
            cert.setKeyUsage(normalizeKeyUsage(profile));
            cert.setIsDefault(false);
            certMapper.add(cert);
            claimDefaultIfFirstServerIdentity(cert);
            log.info("[GB35114] 已复用密钥对签发服务端证书 #{}（源 #{}），公钥指纹={}",
                    cert.getId(), sourceCertId, cert.getKeyFingerprint());
            return reload(cert);
        } catch (Exception e) {
            log.error("[GB35114] 复用密钥对签发服务端证书失败", e);
            throw new RuntimeException("复用密钥对签发失败: " + e.getMessage(), e);
        }
    }

    @Override
    public List<Gb35114Cert> queryServerIdentitiesByFingerprint(String keyFingerprint) {
        if (keyFingerprint == null || keyFingerprint.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        return certMapper.queryServerIdentitiesByFingerprint(keyFingerprint);
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
            log.warn("[GB35114] 证书 #{} 已吊销，拒绝用于本平台签名: purpose={}, gbId={}",
                    id, cert.getPurpose(), cert.getGbId());
            throw new Gb35114Exception("证书 #" + id + " 已吊销，不能用于本平台签名；"
                    + "请重新签发并回填后使用");
        }
        // 过期只告警不拦截（策略见 rejectBecauseExpired）
        rejectBecauseExpired(cert, DateUtil.getNow(), "出站签名");
        if (cert.getKeyPem() == null || cert.getKeyPem().isEmpty()) {
            throw new IllegalStateException("证书 #" + id + " 用途为 " + cert.getPurpose()
                    + "，本平台不持有私钥，不能用于本平台签名");
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
        return cert;
    }

    @Override
    public void revokeCert(int id) {
        certMapper.updateRevoked(id, true);
    }

    @Override
    public void deleteCert(int id) {
        // 私钥与 CSR 存于同一条记录，删除记录即一并删除私钥，无需额外级联
        certMapper.delete(id);
    }

    // ------------------------------------------------------------------
    // 内部工具
    // ------------------------------------------------------------------

    /**
     * 默认密钥用途：GB35114 的 sign1/sign2 均为数字签名，
     * 故本地服务端证书与本地客户端证书默认 {@code digitalSignature}。
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
     * 非空时先解析一次，无法识别的取值直接报错，避免签出用途不符的证书。
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
     * <p>只对<b>已签发但没有 caId</b> 的记录计算 —— 有 caId 的已经能显示成「本地 CA #N」，
     * 待签发的（无 certPem）根本还没有签发者。这两种情况都不需要解析证书，
     * 于是这里也就不用为每一行都做一次 DER 解析。
     *
     * <p>解析失败只跳过该行：关联信息是展示用的，不该让整个列表查询失败。
     */
    private void fillIssuerHints(List<Gb35114Cert> certs) {
        for (Gb35114Cert c : certs) {
            if (c.getCaId() != null || c.getCertPem() == null || c.getCertPem().isEmpty()) {
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
     * 填充上级 CA 的「关联平台」（瞬态）。
     *
     * <p>链路由「上级服务端证书的 {@code ca_id}」串起来：某张 TRUSTED_PLATFORM 证书由本 CA 签发，
     * 而级联平台又绑定了那张证书，说明本 CA 就是该上级平台的 CA。多个上级 CA 的 CN 常常
     * 都叫 {@code Root CA}，只有这一列能把它们区分开。
     *
     * <p>本地 CA 不参与：它签的是本平台的证书，不服务于任何上级平台。
     */
    private List<Gb35114Ca> fillCaPlatformRelations(List<Gb35114Ca> cas) {
        if (cas == null || cas.isEmpty()) {
            return cas;
        }
        boolean needed = false;
        for (Gb35114Ca ca : cas) {
            if (Gb35114Ca.PURPOSE_TRUSTED.equals(ca.getPurpose())) {
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
            certs = certMapper.queryByPurpose(Gb35114Cert.PURPOSE_TRUSTED_PLATFORM);
            platforms = platformMapper.queryAll();
        } catch (Exception e) {
            log.warn("[GB35114] 反查 CA 关联级联平台失败: {}", e.getMessage());
            return cas;
        }
        if (certs == null || certs.isEmpty() || platforms == null || platforms.isEmpty()) {
            return cas;
        }
        for (Gb35114Ca ca : cas) {
            if (!Gb35114Ca.PURPOSE_TRUSTED.equals(ca.getPurpose())) {
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
     * 下级客户端证书（{@link Gb35114Cert#PURPOSE_ISSUED_DEVICE}）按 {@code gb_id} 反查国标设备。
     *
     * <p>证书行的 {@code gb_id} 就是被签发设备的国标编码，与 {@code wvp_device.device_id} 同域，
     * 因此可以一次批量查回，避免逐条查库。
     */
    private void fillDeviceRelations(List<Gb35114Cert> certs) {
        Set<String> gbIds = new HashSet<>();
        for (Gb35114Cert c : certs) {
            if (Gb35114Cert.PURPOSE_ISSUED_DEVICE.equals(c.getPurpose())
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
            log.warn("[GB35114] 反查下级客户端证书关联设备失败: {}", e.getMessage());
            return;
        }
        for (Gb35114Cert c : certs) {
            if (!Gb35114Cert.PURPOSE_ISSUED_DEVICE.equals(c.getPurpose())) {
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
     * 本地客户端证书与上级服务端证书按级联平台配置反查关联平台。
     *
     * <p>优先按平台上的显式绑定（{@code device_cert_id} / {@code platform_cert_id}）匹配；
     * 未显式绑定时回退按国标编码匹配 —— 本地客户端证书的 {@code gb_id} 是<b>本平台</b>向上注册的
     * 编码（{@code platform.device_gb_id}），上级服务端证书的 {@code gb_id} 是<b>上级</b>编码
     * （{@code platform.server_gb_id}）。
     *
     * <p>平台数量是个位数，一次全量查回在内存里过滤即可，不新增「按证书反查平台」的 SQL ——
     * 那需要为 MySQL 与达梦各维护一套语句（见 {@code Gb35114CaMapper} 的双套 {@code databaseId}）。
     */
    private void fillPlatformRelations(List<Gb35114Cert> certs) {
        boolean needed = false;
        for (Gb35114Cert c : certs) {
            String p = c.getPurpose();
            if (Gb35114Cert.PURPOSE_DEVICE_IDENTITY.equals(p)
                    || Gb35114Cert.PURPOSE_TRUSTED_PLATFORM.equals(p)) {
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
            String purpose = c.getPurpose();
            boolean isDeviceIdentity = Gb35114Cert.PURPOSE_DEVICE_IDENTITY.equals(purpose);
            if (!isDeviceIdentity && !Gb35114Cert.PURPOSE_TRUSTED_PLATFORM.equals(purpose)) {
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

    private void requireLocalIdentityPurpose(String purpose) {
        if (!Gb35114Cert.holdsKey(purpose)) {
            throw new IllegalArgumentException("用途 " + purpose + " 不由本平台持有私钥，"
                    + "请使用「由下级 CSR 签发」或「导入对端证书」");
        }
    }

    /**
     * 本平台可否自行签发该用途的证书（自签，或用本地 CA 签）。
     *
     * <p>只有<b>本地服务端证书</b>可以：本平台作 UAS 用它签 sign2，设备侧只需要拿到公钥，
     * 谁签的、是不是自签都不影响验签，因此自签或用本地 CA 签都能用。
     *
     * <p><b>本地客户端证书不行</b>：本平台作 UAC，这张证书要交给<b>上级</b>去验 sign1。
     * 证书之所以能被上级信任，靠的是「上级自己签发过它」这条记录 —— 本平台自签或用本地 CA
     * 签出来的证书，上级那边没有任何记录，接入必然被拒。更麻烦的是失败只出现在上级，
     * 本平台这一侧日志一切正常，排查方向很容易跑偏。
     *
     * <p>所以客户端证书只能走「创建 CSR → 导出交上级签发 → 回填」。
     */
    private void requireLocallyIssuablePurpose(String purpose) {
        if (!Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(purpose)) {
            throw new IllegalArgumentException("用途 " + purpose + " 的证书必须由上级签发，"
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
     * <p>只约束 {@link Gb35114Ca#PURPOSE_LOCAL}；上级 CA 可有多份（多个上级平台各一份）。
     */
    private void assertNoLocalCa() {
        List<Gb35114Ca> locals = caMapper.queryByPurpose(Gb35114Ca.PURPOSE_LOCAL);
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
     * 本地服务端证书只允许存在一组密钥对。
     *
     * <p>守卫条件是「存在<b>未吊销</b>的 {@link Gb35114Cert#PURPOSE_SERVER_IDENTITY} 记录」，
     * 而不是「存在任意一张」。这样做的原因有两层：
     *
     * <p>其一，多组密钥对并存时，设备绑定的是哪一把公钥要靠指纹分组去猜。
     * {@link #resolveUsableServerIdentity(int)} 虽然保证不跨组回退，但「有两组可选」本身
     * 就是配置错误 —— 运维无从判断设备导入的是哪一组，一旦选错，设备验 sign2 必然失败，
     * 而平台侧日志一切正常（确实签了名，只是用错了身份），故障点漂到设备侧。
     *
     * <p>其二，把守卫挂在「未吊销」上，恰好留出了应急通道：密钥泄露或私钥丢失时，
     * 先把该组全部吊销，守卫即失效，可以干净地新建第二组。这正是「吊销」该有的语义 ——
     * 它是对一个签名身份的停用指令，而不是给运维添堵的开关。
     *
     * <p>正常换发（换有效期 / DN / 签发者而不换密钥）走
     * {@link #reissueServerIdentity(int, Gb35114Cert, Integer, int)}，它复用现有密钥对，
     * 不经过本守卫。
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
            throw new IllegalArgumentException("本平台已有服务端证书 #" + c.getId()
                    + "（" + c.getSubjectCn() + "），服务端只保留一组密钥对。"
                    + "如需延长有效期或更换主题，请用「同密钥再签」——它复用现有密钥对，"
                    + "设备无需重新配置；确需更换密钥（如私钥泄露）时，"
                    + "请先吊销该组全部证书，再新建");
        }
    }

    private X500Name buildSubject(Gb35114Cert c) {
        return Gb35114CertUtil.buildSubject(c.getCountry(), c.getProvince(), c.getLocality(),
                c.getOrganization(), c.getOrganizationalUnit(), c.getSubjectCn());
    }

    /** 构造基础记录（不含证书/私钥，供 CSR 待签发使用）。 */
    private Gb35114Cert baseRecord(Gb35114Cert profile) {
        Gb35114Cert cert = new Gb35114Cert();
        cert.setPurpose(profile.getPurpose());
        cert.setType(Gb35114Cert.typeOf(profile.getPurpose()));
        cert.setGbId(profile.getGbId());
        cert.setSubjectCn(profile.getSubjectCn());
        cert.setSubjectDn(buildSubject(profile).toString());
        cert.setCountry(profile.getCountry());
        cert.setProvince(profile.getProvince());
        cert.setLocality(profile.getLocality());
        cert.setOrganization(profile.getOrganization());
        cert.setOrganizationalUnit(profile.getOrganizationalUnit());
        cert.setRevoked(false);
        cert.setIsDefault(false);
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
        cert.setIsDefault(false);
        certMapper.add(cert);
        claimDefaultIfFirstServerIdentity(cert);
        return reload(cert);
    }

    /** 落库导入的证书（私钥可为空，仅对端证书）。 */
    private Gb35114Cert persistImported(Gb35114Cert profile, String certPem, String keyPem) {
        try {
            X509Certificate x509 = Gb35114CertUtil.loadCertificate(certPem);
            // 导入表单只收集用途/国标 ID/文件/备注，主题字段一律取自证书本身
            // （下面的 subjectDn 也直接用证书的 DN，不再采信表单值）。因此必须在
            // 构造记录之前把 CN 补上：baseRecord 内的 buildSubject 要求 CN 非空，
            // 补晚了就会以「CN 不能为空」失败 —— 而那个 CN 随后又会被证书的真实
            // 主题覆盖，等于为一个即时丢弃的中间值卡死了整条导入路径。
            if (profile.getSubjectCn() == null || profile.getSubjectCn().trim().isEmpty()) {
                profile.setSubjectCn(extractCn(x509));
            }
            Gb35114Cert cert = baseRecord(profile);
            cert.setSubjectCn(profile.getSubjectCn());
            cert.setSubjectDn(Gb35114CertUtil.subjectDn(x509));
            cert.setSerialNumber(x509.getSerialNumber().toString(16));
            cert.setCertPem(certPem);
            // 按签名反查签发 CA：导入的上级服务端证书若能对上已留存的「上级 CA」，
            // 「签发方式」列就能显示它由哪个 CA 签发，进而反查该 CA 服务于哪个级联平台。
            // 查不到不报错 —— 证书本身可用，只是页面显示为「签发者未导入」。
            cert.setCaId(resolveIssuerCaId(x509));
            cert.setKeyFingerprint(Gb35114CertUtil.publicKeyFingerprint(x509));
            cert.setKeyPem(keyPem == null ? null
                    : Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), keyPem));
            cert.setNotBefore(CERT_TIME.format(x509.getNotBefore().toInstant()));
            cert.setNotAfter(CERT_TIME.format(x509.getNotAfter().toInstant()));
            cert.setValidityDays(profile.getValidityDays());
            // 导入的证书用途已固化在证书扩展里，此处仅记录用户填写值供展示
            cert.setKeyUsage(profile.getKeyUsage());
            cert.setIsDefault(false);
            certMapper.add(cert);
            claimDefaultIfFirstServerIdentity(cert);
            return reload(cert);
        } catch (Exception e) {
            log.error("[GB35114] 导入证书失败", e);
            throw new RuntimeException("导入证书失败: " + e.getMessage(), e);
        }
    }

    /**
     * 新建的服务端证书若为该用途下的第一张，自动设为默认。
     *
     * <p>只在<b>一张都没有</b>时自动认领，绝不自动顶替已有的默认证书 ——
     * 否则「新增一张证书」又会静默改变签名身份，正是本次改造要消除的隐患。
     */
    private void claimDefaultIfFirstServerIdentity(Gb35114Cert cert) {
        if (!Gb35114Cert.PURPOSE_SERVER_IDENTITY.equals(cert.getPurpose()) || cert.getId() == null) {
            return;
        }
        List<Gb35114Cert> all = certMapper.queryByPurpose(Gb35114Cert.PURPOSE_SERVER_IDENTITY);
        boolean anyDefault = all != null && all.stream()
                .anyMatch(c -> Boolean.TRUE.equals(c.getIsDefault()));
        if (!anyDefault) {
            certMapper.markDefault(cert.getId());
            cert.setIsDefault(true);
            log.info("[GB35114] 服务端证书 #{} 为用途下首张，自动设为默认", cert.getId());
        }
    }

    private Gb35114CertUtil.Gb35114Identity loadCaIdentity(Gb35114Ca ca) throws Exception {
        if (ca.getKeyPem() == null || ca.getKeyPem().isEmpty()) {
            throw new IllegalArgumentException("CA「" + ca.getSubjectCn() + "」不含私钥，无法用于签发");
        }
        String caKeyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(), ca.getKeyPem());
        return Gb35114CertUtil.loadIdentity(ca.getCertPem(), caKeyPem);
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
