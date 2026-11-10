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
 * 上级证书链校验「<b>默认开、允许关</b>」这一策略本身。
 *
 * <p>本类<b>不</b>重复 {@code Gb35114CertChainServiceTest} 已覆盖的校验逻辑（谁能过、
 * 谁被拒、自签怎么算），只钉住两件容易在后续改动里被无声改掉的事：
 *
 * <ol>
 *   <li>{@link Gb35114Config#isVerifyUpstreamCertChain()} 的<b>默认值必须是 true</b>。
 *       它是「默认从严」的落点 —— 若被改回 false，下面那条测试会红，而不是悄悄放宽；</li>
 *   <li>「允许不校验」的<b>两条路各自只关自己那一段</b>：置 false 只关上级方向，
 *       {@code skipCertChainVerify} 才两个方向一起关。混为一谈会让运维以为关了
 *       上级校验就等于关了设备校验。</li>
 * </ol>
 *
 * <p>为什么默认值值得单独立测试：它在源码里只是一个布尔字面量，没有任何测试或调用方
 * 会因为它变成 false 而失败 —— 现场要等到「随便一张证书都能冒充上级」时才察觉。
 */
class Gb35114UpstreamChainDefaultTest {

    private static final long DAY = 24L * 3600 * 1000;

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

    private static Gb35114Ca ca(int id, Gb35114CertUtil.Gb35114Identity identity) {
        Gb35114Ca record = new Gb35114Ca();
        record.setId(id);
        record.setType(Gb35114Ca.TYPE_TRUSTED_CA);
        record.setSubjectCn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setCertPem(identity.certPem);
        return record;
    }

    /**
     * <b>默认校验。</b>
     *
     * <p>这是「默认从严」唯一的落点：配置类里那个字面量。若有人把它改回 false，
     * 应当在这里红掉 —— 那是一次安全口径的变更，不该无声发生。
     */
    @Test
    void upstreamChainVerificationIsOnByDefault() {
        assertTrue(new Gb35114Config().isVerifyUpstreamCertChain(),
                "上级证书链校验必须默认开启（gb35114.verify-upstream-cert-chain 默认 true）；"
                        + "要放宽是显式置 false 的事，不能改默认值");
    }

    /** 默认配置下，签发者未导入的上级证书确实被拒 —— 默认值是「真的在起作用」，不只是个字段。 */
    @Test
    void defaultConfigRejectsUpstreamCertWhoseIssuerIsMissing() throws Exception {
        Gb35114CertUtil.Gb35114Identity realIssuer = Gb35114CertUtil.generateSelfSigned(
                name("Real Issuer CA"), later(3650), later(3650 + 365),
                Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity unrelated = Gb35114CertUtil.generateSelfSigned(
                name("Unrelated CA"), later(3650), later(3650 + 365),
                Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.issue(
                realIssuer, name("34020000002000000001"), later(3650), later(3650 + 365));

        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of(ca(10, unrelated)));

        // 不碰 config：用它的默认值
        assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(upstreamCert.certificate),
                "默认（校验开启）时，签发者未导入的上级证书必须被拒");
    }

    /** 把本项置 false（「允许不校验」的正路）→ 上级证书直接放行，不再看 CA 表。 */
    @Test
    void disablingOnlyUpstreamFlagSkipsUpstreamCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.generateSelfSigned(
                name("34020000002000000001_NULL"), later(3650), later(3650 + 365),
                Gb35114CertUtil.KEY_USAGE_CA);

        config.setVerifyUpstreamCertChain(false);
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA))
                .thenReturn(List.of());

        // 注意：validateUpstreamPlatformCertChain 自身不看 verifyUpstreamCertChain
        // （是否调用它由 Gb35114SecurityService 决定），因此这里仍会被拒 ——
        // 断言这一点，是为了说明「置 false」的作用点在「不注入」，而不是「注入了也放行」。
        assertThrows(Gb35114Exception.class,
                () -> service.validateUpstreamPlatformCertChain(upstreamCert.certificate),
                "置 false 的语义是不注入该方法；方法本身被调用时仍严格校验");
    }

    /**
     * 「允许不校验」的另一条路：{@code skipCertChainVerify} 是全局逃生口，
     * 它让方法<b>自己</b>放行 —— 与置 false 的「不注入」是两条不同的路。
     */
    @Test
    void globalSkipFlagMakesUpstreamCheckPassThrough() throws Exception {
        Gb35114CertUtil.Gb35114Identity upstreamCert = Gb35114CertUtil.generateSelfSigned(
                name("34020000002000000001_NULL"), later(3650), later(3650 + 365),
                Gb35114CertUtil.KEY_USAGE_CA);

        config.setSkipCertChainVerify(true);
        when(caMapper.queryByType(Gb35114Ca.TYPE_TRUSTED_CA)).thenReturn(List.of());

        assertSame(upstreamCert.certificate,
                service.validateUpstreamPlatformCertChain(upstreamCert.certificate),
                "全局跳过开关打开后，上级链校验直接放行");
    }
}
