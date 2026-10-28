package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * 证书链校验在 service 层的落地：UAS 侧「设备证书是否由本平台 CA 签发」，
 * 与 UAC 侧「上级证书是否由某个已导入的上级 CA 签发」。
 *
 * <p>这里用 Mockito 直接注入三个 mapper/config —— 该 service 没有构造注入，
 * 用反射填字段比拉起 Spring 上下文快得多，也与本模块其余测试
 * 「纯 JUnit、无 Spring」的风格一致（因此不用 {@code ReflectionTestUtils}）。
 */
class Gb35114CertChainServiceTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String DEVICE_ID = "35020000001320000001";

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

    private static Gb35114Cert cert(int id, String type, String gbId,
                                    Gb35114CertUtil.Gb35114Identity identity) throws Exception {
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(type);
        record.setGbId(gbId);
        record.setCertPem(identity.certPem);
        record.setKeyFingerprint(Gb35114CertUtil.publicKeyFingerprint(identity.certificate));
        record.setRevoked(false);
        record.setNotBefore("2020-01-01 00:00:00");
        record.setNotAfter("2099-01-01 00:00:00");
        return record;
    }

    // ------------------------------------------------------------------
    // UAS 侧：validateDeviceCertChain
    // ------------------------------------------------------------------

    /** 由本地 CA 签发、签发记录也记着该 CA → 通过。 */
    @Test
    void deviceCertSignedByLocalCaPasses() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        Gb35114Ca caRecord = ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa);
        when(caMapper.query(8)).thenReturn(caRecord);

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /**
     * <b>本需求最有价值的用例</b>：设备拿自己的私钥自签一张证书，
     * 公钥与库里那张完全相同 —— 指纹反查会命中、记录也有效，因此老的指纹校验会放行。
     * 链校验必须把它拦下。
     */
    @Test
    void selfSignedCertWithSameKeyIsRejectedByChainCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        // 设备用同一把私钥自签（换 issuer/subject 与序列号），公钥不变
        Gb35114CertUtil.Gb35114Identity rogue = Gb35114CertUtil.selfSignWithKey(
                name(DEVICE_ID), issued.certificate.getPublicKey(), issued.keyPem,
                new Date(), later(365), Gb35114CertUtil.KEY_USAGE_ENTITY);

        assertEquals(Gb35114CertUtil.publicKeyFingerprint(issued.certificate),
                Gb35114CertUtil.publicKeyFingerprint(rogue.certificate),
                "前提：两者公钥相同 —— 指纹反查无法区分");

        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa));

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, rogue.certificate, 8));
        assertTrue(e.getMessage().contains("不是由本平台已导入的任何 CA 签发"), "实际: " + e.getMessage());
    }

    /**
     * 签发记录指向的 CA 并非真正的签发者 → 拒绝。
     *
     * <p>本用例的名字曾叫「由上级 CA 签发 → 拒绝」，那是「受信任的 CA 只服务上级方向」时期的
     * 说法。现在受信任的 CA 同样能签下级设备证书（见 {@code Gb35114TrustedCaDeviceCertTest}），
     * 所以关键不在「谁签的」，而在「记录上记的那张 CA 是不是真的签了它」。
     */
    @Test
    void deviceCertSignedByOtherCaThanRecordedIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity foreignCa = Gb35114CertUtil.generateSelfSigned(
                name("Foreign CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                foreignCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa));

        assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /** 签发记录没记 CA（存量未回填）→ 退回全部 CA 逐一试，本地 CA 命中即通过。 */
    @Test
    void missingCaIdFallsBackToAllCas() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa)));
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(Collections.emptyList());

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, null));
    }

    /** 本平台一张 CA 都没有 → 拒绝，且原因点名两栏 CA 都为空。 */
    @Test
    void noCaConfiguredIsRejectedWithActionableReason() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                name("Some CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                ca, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.queryByType(anyString())).thenReturn(Collections.emptyList());

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, device.certificate, null));
        assertTrue(e.getMessage().contains("未配置任何 CA"), "实际: " + e.getMessage());
    }

    /** 签发记录指向的 CA 已被删除（查询返回 null）→ 退回全部 CA，仍能通过。 */
    @Test
    void deletedCaFallsBackInsteadOfReportingNullReason() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(8)).thenReturn(null);
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa)));
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(Collections.emptyList());

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /**
     * 端到端：{@code validateAnnouncedDeviceCert} 在指纹命中、记录未吊销未过期之后，
     * 仍要过链校验。
     */
    @Test
    void announcedDeviceCertStillGoesThroughChainCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));
        Gb35114CertUtil.Gb35114Identity rogue = Gb35114CertUtil.selfSignWithKey(
                name(DEVICE_ID), issued.certificate.getPublicKey(), issued.keyPem,
                new Date(), later(365), Gb35114CertUtil.KEY_USAGE_ENTITY);

        Gb35114Cert record = cert(32, Gb35114Cert.TYPE_ISSUED_DEVICE, DEVICE_ID, issued);
        record.setCaId(8);
        when(certMapper.queryIssuedDeviceCertsByFingerprint(anyString()))
                .thenReturn(List.of(record));
        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa));

        // 正常签发的证书：通过
        assertSame(issued.certificate,
                service.validateAnnouncedDeviceCert(DEVICE_ID, issued.certificate));

        // 同公钥的自签证书：指纹命中，但链校验必须拦下
        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateAnnouncedDeviceCert(DEVICE_ID, rogue.certificate));
        assertTrue(e.getMessage().contains("不是由本平台已导入的任何 CA 签发"), "实际: " + e.getMessage());
    }

    /** 已吊销的记录：错误信息应仍是「已被吊销」，不被链校验的消息盖掉。 */
    @Test
    void revokedRecordReasonSurvivesChainCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        Gb35114Cert record = cert(32, Gb35114Cert.TYPE_ISSUED_DEVICE, DEVICE_ID, issued);
        record.setRevoked(true);
        when(certMapper.queryIssuedDeviceCertsByFingerprint(anyString()))
                .thenReturn(List.of(record));

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateAnnouncedDeviceCert(DEVICE_ID, issued.certificate));
        assertTrue(e.getMessage().contains("已被吊销"), "实际: " + e.getMessage());
    }

    // ------------------------------------------------------------------
    // UAC 侧：validateUpstreamPlatformCertChain
    // ------------------------------------------------------------------

    /** 上级证书由已导入的上级 CA 签发 → 通过。 */
    @Test
    void upstreamCertSignedByImportedCaPasses() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCa = Gb35114CertUtil.generateSelfSigned(
                name("Upstream CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                upstreamCa, name("34020000002000000001"), new Date(), later(365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, upstreamCa)));

        assertSame(upstreamCert.certificate,
                service.validateUpstreamPlatformCertChain(upstreamCert.certificate));
    }

    /** 上级证书的签发者没导入 → 拒绝，且提示要导入哪个。 */
    @Test
    void upstreamCertWithoutImportedCaIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCa = Gb35114CertUtil.generateSelfSigned(
                name("Upstream CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity otherCa = Gb35114CertUtil.generateSelfSigned(
                name("Other CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                upstreamCa, name("34020000002000000001"), new Date(), later(365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, otherCa)));

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(upstreamCert.certificate));
        assertTrue(e.getMessage().contains("受信任的 CA"), "实际: " + e.getMessage());
    }

    /**
     * <b>自签上级证书</b>（现场最常见形态）：该证书本身也作为上级 CA 导入了一份 → 通过。
     */
    @Test
    void selfSignedUpstreamCertAcceptedWhenAlsoImportedAsCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("34020000002000000001_NULL"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, selfSigned)));

        assertSame(selfSigned.certificate,
                service.validateUpstreamPlatformCertChain(selfSigned.certificate));
    }

    /**
     * 自签上级证书、但没作为上级 CA 导入 → 拒绝。
     *
     * <p>若这里放行，开关在自签这个常态下就等于空操作 —— 开了跟没开一样。
     */
    @Test
    void selfSignedUpstreamCertRejectedWhenNotImportedAsCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity selfSigned = Gb35114CertUtil.generateSelfSigned(
                name("34020000002000000001_NULL"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity unrelated = Gb35114CertUtil.generateSelfSigned(
                name("Unrelated CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(10, Gb35114Ca.TYPE_TRUSTED_CA, unrelated)));

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(selfSigned.certificate));
        assertTrue(e.getMessage().contains("自签"), "实际: " + e.getMessage());
    }

    /** 上级 CA 表为空 → 拒绝（开关打开时，未导入 CA 就是没配好）。 */
    @Test
    void upstreamChainRejectedWhenNoTrustedCaAtAll() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstream = Gb35114CertUtil.generateSelfSigned(
                name("Upstream"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(Collections.emptyList());

        assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(upstream.certificate));
    }

    /** 读 CA 表抛异常时不阻断级联：链校验依赖的数据取不到，不应把注册打死。 */
    @Test
    void upstreamChainFailsOpenWhenCaTableUnreadable() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstream = Gb35114CertUtil.generateSelfSigned(
                name("Upstream"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenThrow(new RuntimeException("db down"));

        assertSame(upstream.certificate,
                service.validateUpstreamPlatformCertChain(upstream.certificate));
    }

    /** 上级证书为空 → 直接返回 null，不抛。 */
    @Test
    void nullUpstreamCertIsPassedThrough() {
        assertNull(service.validateUpstreamPlatformCertChain(null));
    }
}
