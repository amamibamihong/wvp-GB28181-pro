package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114KeyProtector;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * 待签发记录（只有 CSR 与私钥、证书列为空）不得进入签名/验签路径。
 *
 * <p>线上事故的形态：某张 {@code DEVICE_IDENTITY} 只建到「待签发」，运维随后去注册上级平台，
 * 证书表解析按「未吊销」筛出它，{@code loadIdentity} 把 {@code null} 送进
 * {@code new StringReader(pem)}，日志报
 * {@code 加载身份失败: Cannot invoke "String.length()" because "s" is null} ——
 * 完全看不出真实原因是「证书还没签发」。本类把三处防线各钉一条。
 */
class Gb35114PendingCertNotSelectableTest {

    private static final String PLATFORM_ID = "34020000002000000001";
    private static final String PEER_ID = "34020000002000000002";

    private Gb35114CertServiceImpl service;
    private Gb35114CertMapper certMapper;
    private Gb35114Config config;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        certMapper = Mockito.mock(Gb35114CertMapper.class);
        config = new Gb35114Config();
        inject(service, "certMapper", certMapper);
        inject(service, "config", config);
    }

    /** 待签发记录：私钥已加密留存，证书列为空。 */
    private Gb35114Cert pendingRecord(int id, String type) throws Exception {
        Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(new X500Name("CN=" + PLATFORM_ID));
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(PLATFORM_ID);
        record.setCsrPem(csr.csrPem);
        record.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), csr.keyPem));
        record.setCertPem(null);
        record.setRevoked(false);
        return record;
    }

    /** 已签发的同一类型记录，用于证明「有待签发也有已签发时选的是已签发那张」。 */
    private Gb35114Cert issuedRecord(int id, String type, String gbId) throws Exception {
        Gb35114CertUtil.Gb35114Identity identity = Gb35114CertUtil.generateSelfSigned(
                new X500Name("CN=" + PLATFORM_ID), new Date(),
                new Date(System.currentTimeMillis() + 3650L * 24 * 3600 * 1000),
                Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(type);
        record.setGbId(gbId);
        record.setSubjectCn(PLATFORM_ID);
        record.setCertPem(identity.certPem);
        record.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), identity.keyPem));
        record.setNotAfter(java.time.format.DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault())
                .format(java.time.Instant.ofEpochMilli(
                        System.currentTimeMillis() + 3650L * 24 * 3600 * 1000)));
        record.setRevoked(false);
        record.setHasKey(true);
        return record;
    }

    /**
     * 只有一条待签发记录时，解析必须返回 null（= 未配置证书），而不是把这条交给调用方。
     *
     * <p>返回 null 的语义在调用方是明确的：「本平台尚未给该上级配客户端证书，跳过签名」；
     * 交给调用方则会一路走到 NPE。
     */
    @Test
    void pendingDeviceIdentityIsNotResolved() throws Exception {
        when(certMapper.queryByType(Gb35114Cert.TYPE_DEVICE_IDENTITY))
                .thenReturn(List.of(pendingRecord(7, Gb35114Cert.TYPE_DEVICE_IDENTITY)));

        assertNull(service.queryDeviceIdentity(PEER_ID),
                "待签发记录没有证书内容，不能作为签名身份被解析出来");
    }

    /** 上级平台证书同理：待签发/仅 CSR 的上级证书不得用于验 sign2。 */
    @Test
    void pendingTrustedPlatformCertIsNotResolved() throws Exception {
        when(certMapper.queryByType(Gb35114Cert.TYPE_TRUSTED_PLATFORM))
                .thenReturn(List.of(pendingRecord(8, Gb35114Cert.TYPE_TRUSTED_PLATFORM)));

        assertNull(service.queryTrustedPlatformCert(PEER_ID));
    }

    /** 待签发与已签发并存时，选中的必须是已签发那张（列表按 id 倒序，待签发的更新）。 */
    @Test
    void issuedCertWinsOverNewerPendingOne() throws Exception {
        Gb35114Cert pending = pendingRecord(20, Gb35114Cert.TYPE_DEVICE_IDENTITY);
        pending.setGbId(PEER_ID);
        Gb35114Cert issued = issuedRecord(19, Gb35114Cert.TYPE_DEVICE_IDENTITY, PEER_ID);
        when(certMapper.queryByType(Gb35114Cert.TYPE_DEVICE_IDENTITY))
                .thenReturn(List.of(pending, issued));

        Gb35114Cert resolved = service.queryDeviceIdentity(PEER_ID);
        assertNotNull(resolved, "应回退到已签发的那张");
        assertEquals(19, resolved.getId());
    }

    /**
     * 直接按 id 加载待签发记录：必须抛出可读的「尚未签发」，而不是 NPE。
     *
     * <p>调用方（{@code uacStateMachine} 等）也会从平台绑定里拿到证书 ID 再 load，
     * 那条链路绕开了 {@code resolveByType}，所以守卫必须在 load 这层也有。
     */
    @Test
    void loadIdentityReportsNotIssuedInsteadOfNpe() throws Exception {
        when(certMapper.query(30)).thenReturn(pendingRecord(30, Gb35114Cert.TYPE_DEVICE_IDENTITY));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> service.loadIdentity(30));
        assertTrue(e.getMessage().contains("尚未签发"), "实际: " + e.getMessage());
        assertFalse(e.getMessage().contains("String.length()"),
                "报错不能停留在 StringReader(null) 的 NPE 文案上");
    }

    /** loadCert 走的是验签路径，同样不能把 null 交给 PEM 解析器。 */
    @Test
    void loadCertReportsNotIssuedInsteadOfNpe() throws Exception {
        when(certMapper.query(31)).thenReturn(pendingRecord(31, Gb35114Cert.TYPE_DEVICE_IDENTITY));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> service.loadCert(31));
        assertTrue(e.getMessage().contains("尚未签发"), "实际: " + e.getMessage());
    }

    /** 底层工具方法本身也要兜住空 PEM —— 它是所有解析路径的公共出口。 */
    @Test
    void utilRejectsNullPemWithReadableMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Gb35114CertUtil.loadCertificate(null));
        assertTrue(e.getMessage().contains("证书内容为空"), "实际: " + e.getMessage());

        IllegalArgumentException e2 = assertThrows(IllegalArgumentException.class,
                () -> Gb35114CertUtil.loadPrivateKey(null));
        assertTrue(e2.getMessage().contains("私钥内容为空"), "实际: " + e2.getMessage());
    }
}
