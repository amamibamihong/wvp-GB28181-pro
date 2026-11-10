package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

/**
 * 「导入证书时反查签发 CA」（{@code resolveIssuerCaId}）的回归。
 *
 * <p>核心是自签证书的关联：修复前该方法对自签证书<b>提前返回 null</b>，
 * 于是「同一张证书既作为服务端证书导入、又作为上级 CA 导入」时关联不上
 * （现场 {@code #41 TRUSTED_PLATFORM} 的 {@code ca_id} 一直是 NULL）。
 *
 * <p>走 {@link Gb35114CertServiceImpl#importPeerCert} 这个公开入口，
 * 让测试覆盖的是真实落库路径，而不是直接反射调私有方法。
 */
class Gb35114IssuerResolveServiceTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String UPSTREAM_GB_ID = "34020000002000000001";

    private Gb35114CertServiceImpl service;
    private Gb35114CaMapper caMapper;
    private Gb35114CertMapper certMapper;

    /** 按字段名注入（该 service 用字段注入，没有 setter）。 */
    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        caMapper = Mockito.mock(Gb35114CaMapper.class);
        certMapper = Mockito.mock(Gb35114CertMapper.class);
        inject(service, "caMapper", caMapper);
        inject(service, "certMapper", certMapper);
        inject(service, "config", new Gb35114Config());
        // 落库返回自增主键；reload 时 queryLite 返回 null，service 会退回内存对象
        when(certMapper.add(any(Gb35114Cert.class))).thenReturn(1);
        when(certMapper.queryLite(anyInt())).thenReturn(null);
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    private static X500Name name(String cn) {
        return new X500Name("CN=" + cn);
    }

    private static Gb35114Ca ca(int id, String type, Gb35114CertUtil.Gb35114Identity identity) {
        Gb35114Ca record = new Gb35114Ca();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setCertPem(identity.certPem);
        return record;
    }

    private static Gb35114Cert profile() {
        Gb35114Cert p = new Gb35114Cert();
        p.setType(Gb35114Cert.TYPE_TRUSTED_PLATFORM);
        p.setGbId(UPSTREAM_GB_ID);
        return p;
    }

    /**
     * 用给定 CA 的私钥与公钥另签一张<b>只有 {@code basicConstraints CA:TRUE}</b> 的 CA 证书，
     * 模拟外部工具签出的形态（它们通常写 basicConstraints 而不写 keyUsage）。
     *
     * <p>与 {@code Gb35114CertChainTest} 的同名辅助方法构造方式一致 —— 本模块的测试不做
     * 共享基类，需要时各自内联，保持每个测试类可独立读懂。
     */
    private static X509Certificate basicConstraintsOnlyCa(Gb35114CertUtil.Gb35114Identity identity)
            throws Exception {
        X500Name subject = name("BC Only CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, new BigInteger(160, new SecureRandom()), new Date(), later(3650),
                subject, identity.certificate.getPublicKey());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(Gb35114CertUtil.loadPrivateKey(identity.keyPem));
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /** 一张下级设备证书的档案（导入对端证书用）。 */
    private static Gb35114Cert deviceProfile(String gbId) {
        Gb35114Cert p = new Gb35114Cert();
        p.setType(Gb35114Cert.TYPE_ISSUED_DEVICE);
        p.setGbId(gbId);
        return p;
    }

    /**
     * <b>本次修复的核心场景</b>：自签证书 + CA 列表里有同一张证书 → 关联上。
     *
     * <p>修复前这里必然是 null（自签被提前短路）。
     */
    @Test
    void selfSignedCertAssociatesWithIdenticalCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name(UPSTREAM_GB_ID + "_NULL"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);
        assertTrue(Gb35114CertUtil.isSelfSigned(selfSigned.certificate), "前提：这是一张自签证书");

        when(caMapper.queryAll())
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, selfSigned)));

        Gb35114Cert imported = service.importPeerCert(profile(), selfSigned.certPem);
        assertEquals(10, imported.getCaId(), "自签证书必须能关联到同公钥的 CA 记录");
    }

    /** 自签证书 + CA 列表只有别的密钥 → 不关联（不串台）。 */
    @Test
    void selfSignedCertDoesNotAssociateWithUnrelatedCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name(UPSTREAM_GB_ID + "_NULL"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity unrelated = Gb35114CertUtil.generateSelfSigned(
                name("Unrelated CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryAll())
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, unrelated)));

        Gb35114Cert imported = service.importPeerCert(profile(), selfSigned.certPem);
        assertNull(imported.getCaId(), "密钥不同就不能关联");
    }

    /**
     * 同公钥有多条 CA 记录时取 {@code id DESC} 的最新一条 —— 确定性的，不是猜测。
     */
    @Test
    void sameKeyMultipleCaRowsPicksLatest() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        // queryAll 按 id DESC 返回，最新一条排在前面
        when(caMapper.queryAll()).thenReturn(List.of(
                ca(12, Gb35114Ca.TYPE_TRUSTED_CA, selfSigned),
                ca(10, Gb35114Ca.TYPE_TRUSTED_CA, selfSigned)));

        Gb35114Cert imported = service.importPeerCert(profile(), selfSigned.certPem);
        assertEquals(12, imported.getCaId(), "同公钥多行时取最新的那一条");
    }

    /** CA 列表为空 → 不关联，且不报错（证书本身仍可用）。 */
    @Test
    void emptyCaTableLeavesCaIdNull() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryAll()).thenReturn(List.of());

        Gb35114Cert imported = service.importPeerCert(profile(), selfSigned.certPem);
        assertNull(imported.getCaId());
        assertNotNull(imported.getCertPem(), "关联失败不影响证书本身落库");
    }

    /** 读 CA 表抛异常 → 不关联、不抛（导入证书不该因为 CA 表读不到而失败）。 */
    @Test
    void unreadableCaTableDoesNotFailImport() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryAll()).thenThrow(new RuntimeException("db down"));

        Gb35114Cert imported = service.importPeerCert(profile(), selfSigned.certPem);
        assertNull(imported.getCaId());
    }

    /** CA 签发的证书（非自签）行为不变：仍按验签反查。 */
    @Test
    void caIssuedCertStillResolvesIssuer() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCa = Gb35114CertUtil.generateSelfSigned(
                name("Upstream CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                upstreamCa, name(UPSTREAM_GB_ID), new Date(), later(365));

        when(caMapper.queryAll())
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, upstreamCa)));

        Gb35114Cert imported = service.importPeerCert(profile(), upstreamCert.certPem);
        assertEquals(10, imported.getCaId());
    }

    // ------------------------------------------------------------------
    // 受信任的 CA 签发下级设备证书：导入时同样按签名反查
    // ------------------------------------------------------------------

    /**
     * 第三方 CA 签发的<b>设备</b>证书导入后，{@code ca_id} 指向该受信任 CA。
     *
     * <p>{@code resolveIssuerCaId} 全程不区分用途 —— 它只回答「这张证书的签名出自哪把密钥」。
     * 因此受信任的 CA 既能关联上级平台证书，也能关联下级设备证书，无需为设备方向另写一套。
     */
    @Test
    void deviceCertSignedByTrustedCaResolvesIssuer() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name("35020000001320000001"), new Date(), later(365));

        when(caMapper.queryAll())
                .thenReturn(List.of(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted)));

        Gb35114Cert imported = service.importPeerCert(
                deviceProfile("35020000001320000001"), device.certPem);
        assertEquals(20, imported.getCaId(), "设备证书也要能关联到签发它的受信任 CA");
    }

    /**
     * 签发者尚未导入 → {@code ca_id} 为 null，同时带上一条导入提示。
     *
     * <p>决策是「导入时告警、不拦」：证书先导入、CA 后导入是合法顺序，但这个问题不该
     * 拖到设备注册失败才暴露 —— 那时用户面对的是「设备连不上」，而不是「少导了一张 CA」。
     */
    @Test
    void deviceCertWithUnimportedIssuerWarnsWithoutBlocking() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name("35020000001320000001"), new Date(), later(365));

        when(caMapper.queryAll()).thenReturn(List.of());

        Gb35114Cert imported = service.importPeerCert(
                deviceProfile("35020000001320000001"), device.certPem);
        assertNull(imported.getCaId());
        assertNotNull(imported.getCertPem(), "提示不阻断导入，证书仍要落库");
        assertNotNull(imported.getImportWarning(), "应带上「签发者未导入」的提示");
        assertTrue(imported.getImportWarning().contains("受信任的 CA"),
                "提示要指向导入位置，实际: " + imported.getImportWarning());
    }

    /** 自签的设备证书不该被提示「签发者未导入」—— 它自己就是签发者，提示只会误导。 */
    @Test
    void selfSignedDeviceCertCarriesNoIssuerWarning() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("35020000001320000001"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        when(caMapper.queryAll()).thenReturn(List.of());

        Gb35114Cert imported = service.importPeerCert(
                deviceProfile("35020000001320000001"), selfSigned.certPem);
        assertNull(imported.getImportWarning(), "自签设备证书不该有「签发者未导入」提示");
    }

    /**
     * 上级平台证书的签发者没导入时<b>也要提示</b>。
     *
     * <p>早先这里断言「不提示」，理由是上级方向由 {@code verify-upstream-cert-chain} 控制、
     * 默认不校验，提示了是噪音。该理由站不住：开关打开时缺 CA 同样会让级联注册被拒，
     * 而用户是在<b>导入证书的这一刻</b>最该知道这件事。提示不阻断导入，
     * 与设备证书口径一致。
     *
     * <p>本用例覆盖「一张 CA 都没有」的分支：文案要指向「先导入 CA」，
     * 而不是「让上级重新颁发」—— 后者在零 CA 时是错误方向。
     */
    @Test
    void upstreamCertWithoutAnyCaWarnsToImportCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCa = Gb35114CertUtil.generateSelfSigned(
                name("Upstream CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                upstreamCa, name(UPSTREAM_GB_ID), new Date(), later(365));

        when(caMapper.queryAll()).thenReturn(List.of());

        Gb35114Cert imported = service.importPeerCert(profile(), upstreamCert.certPem);
        assertNotNull(imported.getImportWarning(), "上级平台证书的签发者缺失时应提示");
        assertTrue(imported.getImportWarning().contains("尚未导入任何 CA"),
                "零 CA 时应指向「先导入 CA」，实际: " + imported.getImportWarning());
    }

    /**
     * 已导入若干 CA，但没有一张是这张上级证书的签发者 —— 文案要与「零 CA」区分开。
     *
     * <p>两者的处置完全不同：零 CA 是「先去导入」，有候选不匹配是「导入的 CA 不对，
     * 或该让上级重新颁发」。混成一句会让零 CA 的用户被指向错误方向。
     */
    @Test
    void upstreamCertWithUnmatchedCaWarnsToReissue() throws Exception {
        Gb35114CertUtil.Gb35114Identity realIssuer = Gb35114CertUtil.generateSelfSigned(
                name("Real Issuer CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                realIssuer, name(UPSTREAM_GB_ID), new Date(), later(365));

        // 库里有一张 CA，但不是签发这张证书的那张
        Gb35114CertUtil.Gb35114Identity otherCa = Gb35114CertUtil.generateSelfSigned(
                name("Other CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryAll()).thenReturn(List.of(ca(9, Gb35114Ca.TYPE_TRUSTED_CA, otherCa)));

        Gb35114Cert imported = service.importPeerCert(profile(), upstreamCert.certPem);
        assertNotNull(imported.getImportWarning(), "签发者不匹配时应提示");
        assertTrue(imported.getImportWarning().contains("不是由任何已导入的 CA 签发"),
                "有候选但不匹配时文案应指向「重新颁发/导入正确的 CA」，实际: " + imported.getImportWarning());
    }

    /** 上级平台证书能对上已导入的 CA 时，不该有任何提示。 */
    @Test
    void upstreamCertWithMatchedCaCarriesNoWarning() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCa = Gb35114CertUtil.generateSelfSigned(
                name("Upstream CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                upstreamCa, name(UPSTREAM_GB_ID), new Date(), later(365));

        when(caMapper.queryAll()).thenReturn(List.of(ca(3, Gb35114Ca.TYPE_TRUSTED_CA, upstreamCa)));

        Gb35114Cert imported = service.importPeerCert(profile(), upstreamCert.certPem);
        assertNull(imported.getImportWarning(), "签发者已导入时不该提示");
    }

    /**
     * 外部工具签出的 CA（只有 {@code basicConstraints CA:TRUE}，无 keyUsage）
     * 也能解析出发设备证书的签发者 —— 反查只看签名，不看 CA 资格。
     */
    @Test
    void basicConstraintsOnlyCaResolvesIssuer() throws Exception {
        Gb35114CertUtil.Gb35114Identity realCa = Gb35114CertUtil.generateSelfSigned(
                name("External CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                realCa, name("35020000001320000001"), new Date(), later(365));
        X509Certificate bcOnly = basicConstraintsOnlyCa(realCa);

        Gb35114Ca caRecord = new Gb35114Ca();
        caRecord.setId(22);
        caRecord.setType(Gb35114Ca.TYPE_TRUSTED_CA);
        caRecord.setSubjectCn(Gb35114CertUtil.subjectDn(bcOnly));
        caRecord.setCertPem(Gb35114CertUtil.toPem(bcOnly));
        when(caMapper.queryAll()).thenReturn(List.of(caRecord));

        Gb35114Cert imported = service.importPeerCert(
                deviceProfile("35020000001320000001"), device.certPem);
        assertEquals(22, imported.getCaId(),
                "反查只做验签，CA 资格判定不参与关联");
    }
}
