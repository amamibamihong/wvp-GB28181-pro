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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

/**
 * CA 的主题 DN 落库口径。
 *
 * <p>「生成本地根 CA」与其它证书创建入口（创建 CSR / 自签生成）现在收同一套
 * DN 字段（CN + C/ST/L/O/OU），因此必须验证：
 * <ol>
 *   <li>表单填的 C/ST/L/O/OU 真的写进了证书（而不是收完就丢）；</li>
 *   <li>落库的各列由<b>证书反解析</b>得到，与 {@code subject_dn} 永远一致 ——
 *       现场曾出现 {@code #41} 的 DN 里有 {@code C=CN} 而 {@code country} 列是 NULL
 *       这种「同一份数据存两遍且互相矛盾」的情况。</li>
 * </ol>
 */
class Gb35114CaSubjectServiceTest {

    private static final long DAY = 24L * 3600 * 1000;

    private Gb35114CertServiceImpl service;
    private Gb35114CaMapper caMapper;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        caMapper = Mockito.mock(Gb35114CaMapper.class);
        inject(service, "caMapper", caMapper);
        inject(service, "certMapper", Mockito.mock(Gb35114CertMapper.class));
        inject(service, "config", new Gb35114Config());
        // 本地 CA 唯一性守卫：默认「一份都没有」，放行生成
        when(caMapper.queryByType(any())).thenReturn(List.of());
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    /** 构造一份填满 DN 各段的生成档案。 */
    private static Gb35114Ca profile() {
        Gb35114Ca p = new Gb35114Ca();
        p.setSubjectCn("GB35114 Root CA");
        p.setCountry("CN");
        p.setProvince("jiangsu");
        p.setLocality("nanjing");
        p.setOrganization("trendy");
        p.setOrganizationalUnit("vmp");
        p.setRemark("单测");
        return p;
    }

    /** 落库的记录由 ArgumentCaptor 取回 —— add 返回 int，不是回填后的对象。 */
    private Gb35114Ca captured() {
        ArgumentCaptor<Gb35114Ca> captor = ArgumentCaptor.forClass(Gb35114Ca.class);
        Mockito.verify(caMapper).add(captor.capture());
        return captor.getValue();
    }

    /** 表单里填的 C/ST/L/O/OU 必须真的进入签出的证书。 */
    @Test
    void generateWritesFormDnIntoCertificate() throws Exception {
        service.generateCa(profile(), 3650);
        Gb35114Ca ca = captured();

        Gb35114CertUtil.DnParts dn =
                Gb35114CertUtil.parseSubject(Gb35114CertUtil.loadCertificate(ca.getCertPem()));
        assertEquals("CN", dn.country());
        assertEquals("jiangsu", dn.province());
        assertEquals("nanjing", dn.locality());
        assertEquals("trendy", dn.organization());
        assertEquals("vmp", dn.organizationalUnit());
        assertEquals("GB35114 Root CA", dn.commonName());
    }

    /**
     * 落库的各列与 {@code subject_dn} 必须一致 —— 这条是现场那个矛盾的回归。
     *
     * <p>修复前 {@code persistImported} 里 {@code subject_dn} 取自证书、五个列取自
     * 空表单，于是 DN 里有 {@code C=CN} 而 {@code country} 列是 NULL。
     */
    @Test
    void generatedCaColumnsAgreeWithSubjectDn() throws Exception {
        service.generateCa(profile(), 3650);
        Gb35114Ca ca = captured();

        assertTrue(ca.getSubjectDn().contains("C=CN"), "subject_dn 应含国家段: " + ca.getSubjectDn());
        assertTrue(ca.getSubjectDn().contains("ST=jiangsu"));
        assertTrue(ca.getSubjectDn().contains("O=trendy"));

        assertEquals("CN", ca.getCountry(), "country 列必须与 subject_dn 里的 C 段一致");
        assertEquals("jiangsu", ca.getProvince());
        assertEquals("nanjing", ca.getLocality());
        assertEquals("trendy", ca.getOrganization());
        assertEquals("vmp", ca.getOrganizationalUnit());
        assertEquals("GB35114 Root CA", ca.getSubjectCn());
    }

    /** 各列由证书反解析得到：表单值带空格也不会落库成带空格的样子。 */
    @Test
    void columnsComeFromCertificateNotRawForm() throws Exception {
        Gb35114Ca p = profile();
        p.setCountry("  CN  ");
        p.setProvince(" jiangsu ");
        service.generateCa(p, 3650);
        Gb35114Ca ca = captured();

        // buildSubject 内部会 trim，证书里存的是 trim 后的值；列取自证书 → 同样是 trim 后的
        assertEquals("CN", ca.getCountry());
        assertEquals("jiangsu", ca.getProvince());
        assertEquals(ca.getCountry(), Gb35114CertUtil.parseSubject(
                Gb35114CertUtil.loadCertificate(ca.getCertPem())).country());
    }

    /** 有效期参数必须真的生效（修复前那个输入框是死的，永远用全局默认）。 */
    @Test
    void validityDaysTakesEffect() throws Exception {
        service.generateCa(profile(), 365);
        Gb35114Ca ca = captured();

        long spanDays = java.time.Duration.between(
                java.time.LocalDateTime.parse(ca.getNotBefore().replace(' ', 'T')),
                java.time.LocalDateTime.parse(ca.getNotAfter().replace(' ', 'T'))).toDays();
        assertTrue(spanDays >= 364 && spanDays <= 366,
                "应签发约 365 天，实际 " + spanDays + " 天（" + ca.getNotBefore() + " → " + ca.getNotAfter() + "）");
    }

    /** 不传有效期（0）时回退到全局默认，保持既有行为。 */
    @Test
    void zeroValidityFallsBackToGlobalDefault() throws Exception {
        service.generateCa(profile(), 0);
        Gb35114Ca ca = captured();

        long spanDays = java.time.Duration.between(
                java.time.LocalDateTime.parse(ca.getNotBefore().replace(' ', 'T')),
                java.time.LocalDateTime.parse(ca.getNotAfter().replace(' ', 'T'))).toDays();
        assertTrue(spanDays >= 3649, "应回退到默认 3650 天，实际 " + spanDays + " 天");
    }

    /**
     * CN 为空/全空白时补默认主题，而不是报错。
     *
     * <p>根 CA 的主题默认是「本平台国标ID_22个0」。单测里没有 Spring 容器，
     * `sipConfig` 为 null，国标 ID 取不到 —— 此时按标准的空段写法退化成
     * `NULL_22个0`：与其生成一个格式上说不通的串，不如让「本平台编码没配」
     * 这件事在主题里直接可见。
     */
    @Test
    void blankCnFallsBackToDefaultSubject() {
        Gb35114Ca p = profile();
        p.setSubjectCn("   ");
        service.generateCa(p, 3650);
        Gb35114Ca ca = captured();

        assertEquals("NULL_" + Gb35114CertUtil.MODULE_ID_PLACEHOLDER, ca.getSubjectCn(),
                "主题留空时应补默认值，而不是签发一个空 CN 的证书");
    }

    /** 显式填的主题一律以调用方为准，不被默认值覆盖。 */
    @Test
    void explicitCnIsNotOverwrittenByDefault() {
        service.generateCa(profile(), 3650);
        assertEquals("GB35114 Root CA", captured().getSubjectCn());
    }

    /** 导入 CA 时各段也取自证书，且 subject_dn 与各列一致。 */
    @Test
    void importedCaColumnsComeFromCertificate() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                Gb35114CertUtil.buildSubject("CN", "jiangsu", "nanjing", "trendy", "vmp", "Imported CA"),
                new Date(), later(3650));

        service.importCa(Gb35114Ca.TYPE_TRUSTED_CA, ca.certPem, null, "外部 CA");
        Gb35114Ca stored = captured();

        assertEquals("Imported CA", stored.getSubjectCn());
        assertEquals("CN", stored.getCountry());
        assertEquals("jiangsu", stored.getProvince());
        assertEquals("nanjing", stored.getLocality());
        assertEquals("trendy", stored.getOrganization());
        assertEquals("vmp", stored.getOrganizationalUnit());
        assertNotNull(stored.getSubjectDn());
        assertTrue(stored.getSubjectDn().contains("C=CN"));
    }

    /** 导入一张只有 CN 的证书：其余各段为 null，不编造空串。 */
    @Test
    void importedCaWithCnOnlyLeavesOtherPartsNull() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                new X500Name("CN=34020000002000000001_NULL"), new Date(), later(3650),
                Gb35114CertUtil.KEY_USAGE_CA);

        service.importCa(Gb35114Ca.TYPE_TRUSTED_CA, ca.certPem, null, null);
        Gb35114Ca stored = captured();

        assertEquals("34020000002000000001_NULL", stored.getSubjectCn());
        assertNull(stored.getCountry());
        assertNull(stored.getProvince());
        assertNull(stored.getLocality());
        assertNull(stored.getOrganization());
        assertNull(stored.getOrganizationalUnit());
        assertEquals("CN=34020000002000000001_NULL", stored.getSubjectDn());
    }
}
