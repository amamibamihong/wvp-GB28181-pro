package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 服务端证书「复用密钥对」行为的验证。
 *
 * <p>这是「多张服务端证书都能被设备接受」这一需求的技术依据：设备侧只保存一个平台
 * 公钥且不做 CA 链校验，因此只要多张证书的公钥相同（同一密钥对），设备导入其中
 * 任意一张，平台用同组任意一张的私钥签名都能被验过。
 */
class Gb35114CertUtilKeyReuseTest {

    private static final X500Name SUBJECT_A = new X500Name("CN=35020000002000000001");
    private static final X500Name SUBJECT_B = new X500Name("CN=35020000002000000001,O=renewed");
    private static final long DAY = 24L * 3600 * 1000;

    /** 同一密钥对签出的两张证书，公钥必须完全相同（指纹相同）。 */
    @Test
    void reissuedCertSharesPublicKeyAndFingerprint() throws Exception {
        Gb35114CertUtil.Gb35114Identity source = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        PublicKey publicKey = Gb35114CertUtil.publicKeyOf(source.keyPem);
        Gb35114CertUtil.Gb35114Identity renewed = Gb35114CertUtil.selfSignWithKey(
                SUBJECT_B, publicKey, source.keyPem,
                new Date(), new Date(System.currentTimeMillis() + 730 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        // 公钥一致 → 指纹一致 → 设备侧无需重新导入
        assertEquals(Gb35114CertUtil.publicKeyFingerprint(source.certificate),
                Gb35114CertUtil.publicKeyFingerprint(renewed.certificate),
                "复用密钥对签出的证书必须与原证书公钥相同");

        // 但确实是两张不同的证书（序列号、主题不同）
        assertNotEquals(source.certificate.getSerialNumber(), renewed.certificate.getSerialNumber());
        assertNotEquals(source.certificate.getSubjectX500Principal(),
                renewed.certificate.getSubjectX500Principal());
    }

    /**
     * 核心断言：用「源证书的私钥」签名，能被「新证书的公钥」验过 ——
     * 即设备导入任一张都能验签成功。
     */
    @Test
    void signatureVerifiesAcrossSameKeyGroup() throws Exception {
        Gb35114CertUtil.Gb35114Identity source = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114CertUtil.Gb35114Identity renewed = Gb35114CertUtil.selfSignWithKey(
                SUBJECT_B, Gb35114CertUtil.publicKeyOf(source.keyPem), source.keyPem,
                new Date(), new Date(System.currentTimeMillis() + 730 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        byte[] payload = "random1random2deviceidcryptkey".getBytes("UTF-8");
        String signature = Gb35114SmCrypto.sign(
                Gb35114CertUtil.loadPrivateKey(source.keyPem), payload);

        // 设备持有源证书 → 验过
        assertDoesNotThrow(() -> Gb35114SmCrypto.verify(
                        source.certificate.getPublicKey(), payload, signature),
                "源证书公钥应能验证该签名");
        // 设备持有新证书 → 同样验过（这正是「证书可互换」的含义）
        assertDoesNotThrow(() -> Gb35114SmCrypto.verify(
                        renewed.certificate.getPublicKey(), payload, signature),
                "同密钥对的新证书公钥应能验证同一签名");
    }

    /** 用已有私钥生成 CSR：CSR 里的公钥必须等于该私钥的公钥。 */
    @Test
    void csrFromExistingKeyCarriesSamePublicKey() throws Exception {
        Gb35114CertUtil.Gb35114Identity identity = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(
                SUBJECT_B, Gb35114CertUtil.loadPrivateKey(identity.keyPem));

        X509Certificate issued = Gb35114CertUtil.loadCertificate(identity.certPem);
        PublicKey fromCsr = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(Gb35114CertUtil.parseCsr(csr.csrPem).getSubjectPublicKeyInfo());

        assertArrayEquals(fromCsr.getEncoded(), issued.getPublicKey().getEncoded(),
                "复用密钥对生成的 CSR 必须携带同一个公钥");
    }

    /** 未复用密钥对时（普通 generateSelfSigned），两次生成的公钥必须不同。 */
    @Test
    void freshKeyPairsDifferAcrossCertificates() throws Exception {
        Gb35114CertUtil.Gb35114Identity a = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114CertUtil.Gb35114Identity b = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        assertNotEquals(Gb35114CertUtil.publicKeyFingerprint(a.certificate),
                Gb35114CertUtil.publicKeyFingerprint(b.certificate),
                "各自新建密钥对的证书公钥必须不同 —— 这正是「独立密钥对无法互换」的原因");
    }

    /**
     * 负向对照：用无关密钥对的公钥验签必须失败 —— 确保 verify 真的在校验，
     * 而不是恒真。没有这条，上面「两张证书都能验过」的结论就没有说服力。
     */
    @Test
    void unrelatedPublicKeyRejectsSignature() throws Exception {
        Gb35114CertUtil.Gb35114Identity signer = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114CertUtil.Gb35114Identity unrelated = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        byte[] payload = "random1random2deviceidcryptkey".getBytes("UTF-8");
        String signature = Gb35114SmCrypto.sign(
                Gb35114CertUtil.loadPrivateKey(signer.keyPem), payload);

        assertThrows(Exception.class, () -> Gb35114SmCrypto.verify(
                unrelated.certificate.getPublicKey(), payload, signature),
                "无关密钥对的公钥必须验签失败");
    }

    /**
     * 私钥推导出的公钥必须与证书中的公钥逐字节相同（91 字节命名曲线编码）。
     *
     * <p>回归保护：曾用 {@code ECParameterSpec} 内联曲线参数推导，得到 311 字节的
     * 显式参数编码 —— 同一个 EC 点、不同的编码，签出的证书会带非标准形式。
     */
    @Test
    void derivedPublicKeyMatchesCertificateEncoding() throws Exception {
        Gb35114CertUtil.Gb35114Identity identity = Gb35114CertUtil.generateSelfSigned(
                SUBJECT_A, new Date(), new Date(System.currentTimeMillis() + 365 * DAY),
                Gb35114CertUtil.KEY_USAGE_ENTITY);

        PublicKey derived = Gb35114CertUtil.publicKeyOf(identity.keyPem);
        assertArrayEquals(identity.certificate.getPublicKey().getEncoded(), derived.getEncoded(),
                "推导公钥必须与证书公钥编码一致（命名曲线，91 字节）");
        assertEquals(91, derived.getEncoded().length, "SM2 命名曲线公钥编码应为 91 字节");
    }
}
