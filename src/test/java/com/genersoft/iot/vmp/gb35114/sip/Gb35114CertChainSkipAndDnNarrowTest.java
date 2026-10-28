package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
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
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * 两件事的回归：
 *
 * <ol>
 *   <li><b>全局跳过链校验</b>（{@code gb35114.skip-cert-chain-verify}）—— 拿不到 CA 时的
 *       逃生口，默认关闭；打开后不再要求「由已导入的 CA 签发」；</li>
 *   <li><b>按签发者 DN 缩小候选</b> —— 验签前先用 issuer/subject 的 DN 关系排除不可能
 *       的 CA，避免对每张 CA 都做一次 SM2 验签。</li>
 * </ol>
 *
 * <p>第 2 点最要紧的是<b>不能误伤</b>：DN 缩小的前提是「issuer DN 必然等于签发 CA 的
 * subject DN」，这个前提本身可靠（本平台签发时传的就是 CA 证书的 subject），但存量数据
 * 的 {@code subject_dn} 可能为空、DN 写法也可能有差异，因此命中为空时必须退回原候选集。
 * 下面 {@code dnNarrowing*} 一组用例就是把这条钉住。
 */
class Gb35114CertChainSkipAndDnNarrowTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String DEVICE_ID = "35020000001320000001";

    private Gb35114CertServiceImpl service;
    private Gb35114CaMapper caMapper;
    private Gb35114Config config;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        caMapper = Mockito.mock(Gb35114CaMapper.class);
        config = new Gb35114Config();
        inject(service, "caMapper", caMapper);
        inject(service, "certMapper", Mockito.mock(Gb35114CertMapper.class));
        inject(service, "config", config);
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    private static X500Name name(String cn) {
        return new X500Name("CN=" + cn);
    }

    private static Gb35114Ca ca(int id, String type,
                                Gb35114CertUtil.Gb35114Identity identity,
                                boolean fillSubjectDn) {
        Gb35114Ca record = new Gb35114Ca();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(Gb35114CertUtil.subjectDn(identity.certificate));
        if (fillSubjectDn) {
            record.setSubjectDn(Gb35114CertUtil.subjectDn(identity.certificate));
        }
        record.setCertPem(identity.certPem);
        return record;
    }

    // ------------------------------------------------------------------
    // 一、全局跳过链校验
    // ------------------------------------------------------------------

    /**
     * 开关关闭（默认）时，链不成立照样拒绝 —— 先钉住默认行为，
     * 否则「默认验证」这句话没有测试兜底。
     */
    @Test
    void defaultStillVerifiesChain() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity foreignCa = Gb35114CertUtil.generateSelfSigned(
                name("Foreign CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                foreignCa, name(DEVICE_ID), new Date(), later(365));

        assertFalse(config.isSkipCertChainVerify(), "前提：默认必须是验证");
        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, true));

        assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /** 开关打开后，非本平台 CA 签发的设备证书也放行。 */
    @Test
    void skipAllowsDeviceCertNotSignedByOurCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity foreignCa = Gb35114CertUtil.generateSelfSigned(
                name("Foreign CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                foreignCa, name(DEVICE_ID), new Date(), later(365));

        config.setSkipCertChainVerify(true);

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /**
     * 开关打开时，<b>连「本平台一张 CA 都没有」也不该再拦</b>。
     *
     * <p>这条正是开关存在的理由：现场拿不到 CA，如果仍然因为「没配 CA」被挡，
     * 这个逃生口就白开了。
     */
    @Test
    void skipBypassesNoCaConfigured() throws Exception {
        Gb35114CertUtil.Gb35114Identity someCa = Gb35114CertUtil.generateSelfSigned(
                name("Some CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                someCa, name(DEVICE_ID), new Date(), later(365));

        config.setSkipCertChainVerify(true);
        when(caMapper.queryByType(Mockito.anyString())).thenReturn(java.util.Collections.emptyList());

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, null));
    }

    /** 上级方向同样受开关控制：打开后自签且未导入为上级 CA 的证书也放行。 */
    @Test
    void skipAllowsUpstreamCertNotBackedByImportedCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstream = Gb35114CertUtil.generateSelfSigned(
                name("Upstream Platform"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_ENTITY);

        // 先确认默认行为是拒绝
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(java.util.Collections.emptyList());
        assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(upstream.certificate));

        config.setSkipCertChainVerify(true);
        assertSame(upstream.certificate,
                service.validateUpstreamPlatformCertChain(upstream.certificate));
    }

    /** 空证书在任何取值下都返回 null，不受开关影响。 */
    @Test
    void nullCertStaysNullUnderSkip() {
        config.setSkipCertChainVerify(true);
        assertNull(service.validateDeviceCertChain(DEVICE_ID, null, null));
        assertNull(service.validateUpstreamPlatformCertChain(null));
    }

    // ------------------------------------------------------------------
    // 二、按签发者 DN 缩小候选
    // ------------------------------------------------------------------

    /**
     * DN 对得上的 CA 被优先命中 —— 正常路径不受影响。
     * 这里 CA 记录填了 {@code subject_dn}，缩小后仍应通过。
     */
    @Test
    void dnNarrowingKeepsMatchingCa() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, true));

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /**
     * <b>关键</b>：{@code subject_dn} 为空的存量记录必须保留在候选里。
     *
     * <p>该列是后加的，存量 CA 行可能为空。若按「DN 对不上就排除」处理，
     * 这些 CA 会被全部排除，导致设备整批接不进来 —— 而这与「证书是否真的由它签发」
     * 毫无关系。这里构造一条 subject_dn 为空的记录，验证仍能通过。
     */
    @Test
    void dnNarrowingKeepsCaWithBlankSubjectDn() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, false));

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
    }

    /**
     * 缩小后候选为空 → 退回原候选集，不因 DN 写法的细微差异误判。
     *
     * <p>构造一条 subject_dn 与真实 issuer <b>写法不同</b>（但仍是同一把密钥）的记录：
     * 缩小会把它排除、候选变空，此时必须退回全表并由验签裁决 —— 而验签是能过的。
     * 若忘了退回，这张证书就会被误拒。
     */
    @Test
    void dnNarrowingFallsBackWhenNothingMatches() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        Gb35114Ca record = ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, false);
        // 故意写一个与 issuer 不同的 DN：缩小会排除它，从而触发「命中为空退回全表」
        record.setSubjectDn("CN=Completely Different CA");
        when(caMapper.query(8)).thenReturn(record);

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8),
                "DN 缩小命中为空时必须退回全表，否则同一把密钥也会被误拒");
    }

    /**
     * 缩小不得改变「该拒还是拒」的结论。
     *
     * <p>一张由别的 CA 签发的证书，即便把正确的 DN 填进候选集，缩小后仍应拒绝 ——
     * 缩小是性能优化，不是判据。
     */
    @Test
    void dnNarrowingDoesNotLoosenRejection() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity foreignCa = Gb35114CertUtil.generateSelfSigned(
                name("Foreign CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                foreignCa, name(DEVICE_ID), new Date(), later(365));

        // 候选集里放的是 Local CA（与设备证书的签发者无关的那张）
        when(caMapper.query(8)).thenReturn(ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, true));

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> service.validateDeviceCertChain(DEVICE_ID, device.certificate, 8));
        assertTrue(e.getMessage().contains("不是由本平台已导入的任何 CA 签发"), "实际: " + e.getMessage());
    }

    /**
     * 多个 CA 时，DN 缩小应命中正确的那一个。
     *
     * <p>候选集里放两张 CA（一张无关、一张是真正的签发者），缩小后仍须通过 ——
     * 验证缩小是「按 DN 过滤」而不是「取第一个」。
     */
    @Test
    void dnNarrowingPicksRightCaAmongMany() throws Exception {
        Gb35114CertUtil.Gb35114Identity unrelated = Gb35114CertUtil.generateSelfSigned(
                name("Unrelated CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                localCa, name(DEVICE_ID), new Date(), later(365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA)).thenReturn(List.of(
                ca(7, Gb35114Ca.TYPE_LOCAL_CA, unrelated, true),
                ca(8, Gb35114Ca.TYPE_LOCAL_CA, localCa, true)));
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(java.util.Collections.emptyList());

        assertSame(device.certificate,
                service.validateDeviceCertChain(DEVICE_ID, device.certificate, null));
    }
}
