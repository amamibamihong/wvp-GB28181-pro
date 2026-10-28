package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 「按签发者反查 CA」这一机制的验证。
 *
 * <p>导入服务端证书（上级平台）时，平台要靠「谁签的这张证书」把它与已导入的上级 CA 关联起来，
 * 进而反查出它服务于哪个级联平台。这里验证的是判定依据本身：
 * <b>用候选 CA 的公钥去验证书签名</b>，而不是拿 issuer DN 去比对 CA 的 CN。
 *
 * <p>为什么不用 DN 比对：CA 表只存 CN，而不同 CA 完全可能同名（厂商默认 CN 常常就是
 * {@code Root CA}）。DN 比对会串台，把「由 A 签发」标成「由 B 签发」—— 比不标更糟。
 */
class Gb35114IssuerResolveTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String CERT_CN = "35020000003000000001";

    private static Date now() {
        return new Date();
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    private static X500Name caName(String cn) {
        return new X500Name("CN=" + cn);
    }

    /** 自签证书：issuer 与 subject 相同，据此与「签发者未导入」区分开。 */
    @Test
    void selfSignedCertIsRecognized() throws Exception {
        Gb35114CertUtil.Gb35114Identity self = Gb35114CertUtil.generateSelfSigned(
                caName(CERT_CN), now(), later(365), Gb35114CertUtil.KEY_USAGE_ENTITY);

        assertTrue(Gb35114CertUtil.isSelfSigned(self.certificate));
        assertEquals(Gb35114CertUtil.subjectDn(self.certificate),
                Gb35114CertUtil.issuerDn(self.certificate));
    }

    /** CA 签发的证书：issuer 是 CA 的主题，且能用 CA 公钥验过签名。 */
    @Test
    void caIssuedCertVerifiesWithCaPublicKey() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                caName("GB35114 Root CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                ca, caName(CERT_CN), now(), later(365));

        assertFalse(Gb35114CertUtil.isSelfSigned(issued.certificate));
        assertEquals(Gb35114CertUtil.subjectDn(ca.certificate),
                Gb35114CertUtil.issuerDn(issued.certificate));

        // 这就是 resolveIssuerCaId 的判定依据：验得过的那张 CA 才是签发者
        assertDoesNotThrow(() -> issued.certificate.verify(ca.certificate.getPublicKey()),
                "CA 签发的证书必须能被 CA 公钥验过");
    }

    /**
     * 核心断言：两个 <b>同名</b> 的 CA，只有真正签发的那一个能验过。
     *
     * <p>这正是不能按 CN 匹配的原因 —— 两张 CA 的 subject_cn 完全一样，
     * 按 DN 匹配无法区分，而按签名验证能唯一确定。
     */
    @Test
    void sameNameCasAreDistinguishedBySignature() throws Exception {
        Gb35114CertUtil.Gb35114Identity caA = Gb35114CertUtil.generateSelfSigned(
                caName("Root CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity caB = Gb35114CertUtil.generateSelfSigned(
                caName("Root CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        // 前提：两张 CA 的 DN 确实相同，但密钥对不同
        assertEquals(Gb35114CertUtil.subjectDn(caA.certificate),
                Gb35114CertUtil.subjectDn(caB.certificate));
        assertNotEquals(Gb35114CertUtil.publicKeyFingerprint(caA.certificate),
                Gb35114CertUtil.publicKeyFingerprint(caB.certificate));

        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                caA, caName(CERT_CN), now(), later(365));
        X509Certificate cert = issued.certificate;

        assertDoesNotThrow(() -> cert.verify(caA.certificate.getPublicKey()),
                "真签发者必须验得过");
        assertThrows(Exception.class, () -> cert.verify(caB.certificate.getPublicKey()),
                "同名但不是签发者的 CA 必须验不过，否则关联会串台");
    }

    /** 上级 CA 无本地私钥也能参与反查 —— 它只需要公钥。 */
    @Test
    void trustedCaNeedsOnlyPublicKey() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                caName("LiveGBS CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity issued = Gb35114CertUtil.issue(
                ca, caName(CERT_CN), now(), later(365));

        // 模拟「仅导入证书、不导入私钥」：只有 PEM 可用
        X509Certificate caCertOnly = Gb35114CertUtil.loadCertificate(ca.certPem);
        assertDoesNotThrow(() -> issued.certificate.verify(caCertOnly.getPublicKey()));
    }
}
