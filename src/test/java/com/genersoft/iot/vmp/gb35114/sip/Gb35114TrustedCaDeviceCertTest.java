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
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * <b>受信任的 CA 也能签发下级设备证书</b> —— 本次重构放宽的那条信任范围。
 *
 * <p>在此之前 {@code TRUSTED_CA} 只服务一个方向：标识上级平台服务端证书的签发者。
 * 现在第三方机构签发的设备证书，只要把该机构的 CA 导入「受信任的 CA 证书」一栏，
 * 设备注册时的链校验就能通过。
 *
 * <p><b>判定逻辑本身没有改动</b>：{@code validateDeviceCertChain} 从不读 {@code ca.getType()}，
 * 只做「验签 + CA 资格」两件事，候选集由 {@code expectedCaId} 决定。所以这里要锁的不是
 * 「新写了什么」，而是「放开候选集之后，该通过的通过、该拒的仍然拒」。
 *
 * <p>同时锁住<b>没有放开的那一半</b>：决策是「导入并绑定后信任」——
 * 「必须按指纹命中本平台记录」这道闸不动。没有记录的自签证书仍然拒绝，
 * 否则任何持有该 gbId 的人都能用一张自签证书冒充设备接入。
 */
class Gb35114TrustedCaDeviceCertTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String DEVICE_ID = "35020000001320000001";

    private Gb35114CertServiceImpl service;
    private Gb35114CaMapper caMapper;
    private Gb35114CertMapper certMapper;

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
        record.setSubjectDn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setCertPem(identity.certPem);
        return record;
    }

    private static Gb35114Cert deviceRecord(int id, Gb35114CertUtil.Gb35114Identity identity)
            throws Exception {
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(Gb35114Cert.TYPE_ISSUED_DEVICE);
        record.setGbId(DEVICE_ID);
        record.setCertPem(identity.certPem);
        record.setKeyFingerprint(Gb35114CertUtil.publicKeyFingerprint(identity.certificate));
        record.setRevoked(false);
        record.setNotBefore("2020-01-01 00:00:00");
        record.setNotAfter("2099-01-01 00:00:00");
        return record;
    }

    /**
     * 用给定 CA 的私钥与公钥另签一张<b>只有 {@code basicConstraints CA:TRUE}</b> 的 CA 证书，
     * 模拟外部工具（openssl 等）签出的形态：它们通常写 basicConstraints 而不写 keyUsage。
     *
     * <p>与 {@code Gb35114CertChainTest} 的同名辅助方法构造方式一致。
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

    /** 一张第三方机构自签的 CA（带 keyCertSign），用来签设备证书。 */
    private static Gb35114CertUtil.Gb35114Identity thirdPartyCa(String cn) throws Exception {
        return Gb35114CertUtil.generateSelfSigned(name(cn), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);
    }

    // ------------------------------------------------------------------
    // 一、受信任的 CA 签发的设备证书可通过
    // ------------------------------------------------------------------

    /**
     * <b>本类最核心的用例</b>：第三方 CA 签发的设备证书，记录上的 {@code ca_id} 指向该 CA → 通过。
     *
     * <p>这是本次放宽的信任范围本身。用测试锁定，不靠推理。
     */
    @Test
    void deviceCertSignedByTrustedCaPasses() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(20)).thenReturn(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted));

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 20));
    }

    /**
     * 签发记录没记 CA（证书先导入、CA 后导入）→ 退回全表，受信任的 CA 同样参与候选。
     *
     * <p>这个导入顺序是合法的，计划里明确要支持，因此兜底候选集必须包含 {@code TRUSTED_CA}。
     */
    @Test
    void trustedCaParticipatesInFallbackWhenNoCaRecorded() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(Collections.emptyList());
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted)));

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, null));
    }

    /**
     * 端到端：{@code validateAnnouncedDeviceCert} 的指纹反查命中后，链校验放行第三方 CA 签发的证书。
     */
    @Test
    void announcedDeviceCertFromTrustedCaPasses() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name(DEVICE_ID), new Date(), later(365));

        Gb35114Cert record = deviceRecord(30, device);
        record.setCaId(20);
        when(certMapper.queryIssuedDeviceCertsByFingerprint(anyString()))
                .thenReturn(List.of(record));
        when(caMapper.query(20)).thenReturn(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted));

        assertSame(device.certificate,
                service.validateAnnouncedDeviceCert(DEVICE_ID, device.certificate));
    }

    // ------------------------------------------------------------------
    // 二、没有放开的那一半：必须命中记录
    // ------------------------------------------------------------------

    /**
     * <b>决策「导入并绑定后信任」的锁</b>：本平台没有该证书的任何记录 → 拒绝，
     * 即使它能链到某张已导入的受信任 CA。
     *
     * <p>放行它等于：任何持有该 gbId 的人，用一张自己签的证书（A 级握手不校验证书链，
     * 自签也验得过）就能冒充该设备接入，且平台侧没有任何记录可供吊销。
     * 「第三方签发」放开的是<b>链</b>判据，不是「必须在本平台留档」这道闸。
     */
    @Test
    void certWithoutAnyRecordIsStillRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name(DEVICE_ID), new Date(), later(365));

        when(certMapper.queryIssuedDeviceCertsByFingerprint(anyString()))
                .thenReturn(Collections.emptyList());
        when(certMapper.queryIssuedDeviceCert(DEVICE_ID)).thenReturn(Collections.emptyList());

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateAnnouncedDeviceCert(DEVICE_ID, device.certificate));
        assertTrue(e.getMessage().contains("未在本平台保存"), "实际: " + e.getMessage());
    }

    /** 记录指向的 CA 并非真正的签发者 → 仍然拒绝（放宽的是「哪些 CA 可试」，不是「谁签的都行」）。 */
    @Test
    void recordPointingAtWrongCaIsStillRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");
        Gb35114CertUtil.Gb35114Identity unrelated = thirdPartyCa("Unrelated CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name(DEVICE_ID), new Date(), later(365));

        // 记录指向 Unrelated，而全表里也只有它 —— 两张 CA 都验不过这张证书
        when(caMapper.query(21)).thenReturn(ca(21, Gb35114Ca.TYPE_TRUSTED_CA, unrelated));
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(Collections.emptyList());
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(21, Gb35114Ca.TYPE_TRUSTED_CA, unrelated)));

        assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, device.certificate, 21));
    }

    // ------------------------------------------------------------------
    // 三、轮换场景：记录上的 CA 已不是当前签发者
    // ------------------------------------------------------------------

    /**
     * 同一密钥对先后有两张证书（旧的本平台 CA 签、新的受信任 CA 签），设备出示<b>旧的</b>那张。
     *
     * <p>{@code validateAnnouncedDeviceCert} 只取第一条命中记录的 {@code ca_id}（按 id 倒序即最新），
     * 而同一台设备只有一个密钥对 —— 于是「记录记的是新证书的 CA，设备出示的是旧证书」。
     * 只试记录上那张 CA 必然拒绝，而这台设备完全合法。
     *
     * <p>修法是把全表兜底从「仅候选集为空时」扩到「循环失败后也走一遍」。这里锁住它。
     */
    @Test
    void rotationAcrossCasIsAcceptedViaFallback() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity trusted = thirdPartyCa("Third Party CA");

        // 设备当前的密钥对来自本地 CA 签发的那张（旧的），记录里记的却是新证书的 CA（受信任的）
        Gb35114CertUtil.Gb35114Identity oldCert = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(20)).thenReturn(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted));
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(9, Gb35114Ca.TYPE_LOCAL_CA, localCa)));
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted)));

        assertSame(oldCert.certificate,
                service.validateDeviceCertChain(DEVICE_ID, oldCert.certificate, 20));
    }

    // ------------------------------------------------------------------
    // 四、外部工具签出的 CA：只带 basicConstraints，不带 keyUsage
    // ------------------------------------------------------------------

    /**
     * 外部工具签出的 CA 常常只写 {@code basicConstraints CA:TRUE}，不写 {@code keyUsage.keyCertSign}
     * （本平台自己的 CA 反过来，只写 keyUsage）。{@code isCaCertificate} 用<b>或</b>语义兼容两者，
     * 这张 CA 也必须能通过设备链校验。
     */
    @Test
    void externalStyleCaWithOnlyBasicConstraintsIsAccepted() throws Exception {
        Gb35114CertUtil.Gb35114Identity realCa = thirdPartyCa("External CA");
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                realCa, name(DEVICE_ID), new Date(), later(365));
        // 同一把 CA 私钥、同一把公钥，另签一张「只有 basicConstraints CA:TRUE」的自签 CA 证书 ——
        // 这正是外部工具签出来的形态。公钥相同，因此它仍能验过 device 的签名。
        X509Certificate caOnlyBasicConstraints = basicConstraintsOnlyCa(realCa);

        Gb35114Ca caRecord = new Gb35114Ca();
        caRecord.setId(22);
        caRecord.setType(Gb35114Ca.TYPE_TRUSTED_CA);
        caRecord.setSubjectCn(Gb35114CertUtil.subjectDn(caOnlyBasicConstraints));
        caRecord.setCertPem(Gb35114CertUtil.toPem(caOnlyBasicConstraints));
        when(caMapper.query(22)).thenReturn(caRecord);

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 22));
    }
}
