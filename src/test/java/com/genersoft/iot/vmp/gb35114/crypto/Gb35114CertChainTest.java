package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 单级证书链校验（{@link Gb35114CertUtil#chainFailureReason} 与
 * {@link Gb35114CertUtil#isCaCertificate}）的验证。
 *
 * <p>这层判定同时服务两个方向：本平台作上级（UAS）时验设备证书是否由本平台 CA 签发，
 * 作下级（UAC）时验上级证书是否由某个已导入的上级 CA 签发。
 */
class Gb35114CertChainTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String CERT_CN = "35020000001320000001";

    private static Date now() {
        return new Date();
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    private static X500Name name(String cn) {
        return new X500Name("CN=" + cn);
    }

    /** CA 签发的正常证书：链成立，无失败原因。 */
    @Test
    void caIssuedCertPassesChainCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                ca, name(CERT_CN), now(), later(365));

        assertNull(Gb35114CertUtil.chainFailureReason(leaf.certificate, ca.certificate));
        assertTrue(Gb35114CertUtil.isCaCertificate(ca.certificate));
    }

    /** 由别的密钥签的证书：验签不过，原因里要点出是「不是它签发的」。 */
    @Test
    void certSignedByAnotherKeyFails() throws Exception {
        Gb35114CertUtil.Gb35114Identity realCa = Gb35114CertUtil.generateSelfSigned(
                name("Real CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity otherCa = Gb35114CertUtil.generateSelfSigned(
                name("Other CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                realCa, name(CERT_CN), now(), later(365));

        String reason = Gb35114CertUtil.chainFailureReason(leaf.certificate, otherCa.certificate);
        assertNotNull(reason);
        assertTrue(reason.contains("不是由它签发"), "实际: " + reason);
    }

    /**
     * 同名但密钥不同的 CA 也不能冒充签发者 —— 判定是密码学的，不看 DN。
     *
     * <p>这正是 {@code resolveIssuerCaId} 不用 DN 匹配的理由，这里把它钉在链校验上。
     */
    @Test
    void sameNameDifferentKeyCaCannotImpersonate() throws Exception {
        Gb35114CertUtil.Gb35114Identity caA = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity caB = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        assertEquals(Gb35114CertUtil.subjectDn(caA.certificate),
                Gb35114CertUtil.subjectDn(caB.certificate), "前提：两张 CA 同名");

        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                caA, name(CERT_CN), now(), later(365));

        assertNull(Gb35114CertUtil.chainFailureReason(leaf.certificate, caA.certificate));
        assertNotNull(Gb35114CertUtil.chainFailureReason(leaf.certificate, caB.certificate),
                "同名但不是签发者的 CA 必须验不过");
    }

    /** 签名对得上、但签发者只是终端实体证书（无 CA 资格）→ 必须拒绝。 */
    @Test
    void entityCertWithoutCaQualificationIsRejected() throws Exception {
        // 用实体用途生成自签证书：「签发者」是一张 KEY_USAGE_ENTITY 证书
        Gb35114CertUtil.Gb35114Identity entity = Gb35114CertUtil.generateSelfSigned(
                name("Not a CA"), now(), later(365), Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                entity, name(CERT_CN), now(), later(365));

        // 签名确实验得过 —— 它真的是用这张证书的私钥签的
        assertDoesNotThrow(() -> leaf.certificate.verify(entity.certificate.getPublicKey()));

        assertFalse(Gb35114CertUtil.isCaCertificate(entity.certificate));
        String reason = Gb35114CertUtil.chainFailureReason(leaf.certificate, entity.certificate);
        assertNotNull(reason);
        assertTrue(reason.contains("不具备 CA 资格"), "实际: " + reason);
    }

    /**
     * <b>关键兼容性用例</b>：只有 {@code basicConstraints CA:TRUE}、没有 {@code keyUsage}
     * 的签发者必须被认作 CA。
     *
     * <p>现场那张上级 CA（{@code #10}）就是这种形态（外部工具签发）。若判定只认
     * keyUsage，这类 CA 会被判死。
     */
    @Test
    void caQualificationAcceptsBasicConstraintsOnly() throws Exception {
        Gb35114CertUtil.Gb35114Identity realCa = Gb35114CertUtil.generateSelfSigned(
                name("Real CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                realCa, name(CERT_CN), now(), later(365));

        // 同一把 CA 私钥，另签一张「只有 basicConstraints CA:TRUE」的自签 CA 证书。
        // 公钥相同 → 它能验过 leaf 的签名。
        X509Certificate bcOnlyCa = basicConstraintsOnlyCa(realCa);

        assertTrue(Gb35114CertUtil.isCaCertificate(bcOnlyCa),
                "只有 basicConstraints CA:TRUE 的证书必须被认作 CA");
        assertNull(Gb35114CertUtil.chainFailureReason(leaf.certificate, bcOnlyCa));
    }

    /**
     * <b>关键兼容性用例</b>：本平台自己生成的 CA 只有 {@code keyUsage}（无 basicConstraints），
     * 也必须被认作 CA。
     *
     * <p>{@code Gb35114CertUtil.addKeyUsage} 是生成路径唯一写入的扩展 —— 若链校验硬性要求
     * basicConstraints，UAS 侧一开就把所有设备挡在门外。
     */
    @Test
    void caQualificationAcceptsKeyUsageOnly() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        assertNull(ca.certificate.getExtensionValue(Extension.basicConstraints.getId()),
                "前提：本平台生成的 CA 没有 basicConstraints 扩展");
        assertTrue(Gb35114CertUtil.isCaCertificate(ca.certificate),
                "只有 keyUsage keyCertSign 的证书必须被认作 CA");
    }

    /** 两种扩展都没有 → 不具备 CA 资格。 */
    @Test
    void certWithoutEitherExtensionIsNotCa() throws Exception {
        // KEY_USAGE_ENTITY = digitalSignature，不含 keyCertSign
        Gb35114CertUtil.Gb35114Identity entity = Gb35114CertUtil.generateSelfSigned(
                name("Plain"), now(), later(365), Gb35114CertUtil.KEY_USAGE_ENTITY);
        assertFalse(Gb35114CertUtil.isCaCertificate(entity.certificate));
        assertFalse(Gb35114CertUtil.isCaCertificate(null));
    }

    /**
     * 自签证书作为自己的签发者：验签通过且具备 CA 资格 → 链成立。
     *
     * <p>UAC 侧「自签上级证书」的处理依赖这一点：它自己就是链的根。
     */
    @Test
    void selfSignedCaIsItsOwnIssuer() throws Exception {
        Gb35114CertUtil.Gb35114Identity root = Gb35114CertUtil.generateSelfSigned(
                name("34020000002000000001_NULL"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        assertTrue(Gb35114CertUtil.isSelfSigned(root.certificate));
        assertNull(Gb35114CertUtil.chainFailureReason(root.certificate, root.certificate));
    }

    /** issuer 为空 → 给出明确原因，而不是抛 NPE。 */
    @Test
    void nullIssuerIsReportedNotThrown() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                name("Local CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity leaf = Gb35114CertUtil.issue(
                ca, name(CERT_CN), now(), later(365));

        assertEquals("签发者证书为空", Gb35114CertUtil.chainFailureReason(leaf.certificate, null));
    }

    /** {@code sameKey}：同证书、同密钥不同序列号、不同密钥三种情形。 */
    @Test
    void sameKeyComparesPublicKeysNotCertificates() throws Exception {
        Gb35114CertUtil.Gb35114Identity ca = Gb35114CertUtil.generateSelfSigned(
                name("CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity other = Gb35114CertUtil.generateSelfSigned(
                name("CA"), now(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);

        assertTrue(Gb35114CertUtil.sameKey(ca.certificate, ca.certificate), "同一张证书");
        assertFalse(Gb35114CertUtil.sameKey(ca.certificate, other.certificate), "不同密钥");
        assertFalse(Gb35114CertUtil.sameKey(ca.certificate, null));
        assertFalse(Gb35114CertUtil.sameKey(null, null));

        // 同密钥、不同序列号/有效期：续期后公钥不变，应判为同一身份
        Gb35114CertUtil.Gb35114Identity renewed = Gb35114CertUtil.selfSignWithKey(
                name("CA"), ca.certificate.getPublicKey(), ca.keyPem,
                now(), later(7300), Gb35114CertUtil.KEY_USAGE_CA);
        assertNotEquals(ca.certificate.getSerialNumber(), renewed.certificate.getSerialNumber());
        assertTrue(Gb35114CertUtil.sameKey(ca.certificate, renewed.certificate),
                "同密钥的续期证书必须判为同一身份");
    }

    /** 构造一张「只有 basicConstraints CA:TRUE、无 keyUsage」的证书，公钥取自给定身份。 */
    private static X509Certificate basicConstraintsOnlyCa(Gb35114CertUtil.Gb35114Identity identity)
            throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        // 用原 CA 的私钥签名，公钥用原 CA 的公钥 —— 这样它能验过原 CA 签出的叶子证书
        X500Name subject = name("BC Only CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, new BigInteger(160, new SecureRandom()), now(), later(3650),
                subject, identity.certificate.getPublicKey());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(Gb35114CertUtil.loadPrivateKey(identity.keyPem));
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /** 借 KeyUsage 常量确认扩展语义（避免测试里写死人眼看的位）。 */
    @Test
    void keyUsageConstantsAreAsExpected() {
        assertEquals(KeyUsage.keyCertSign | KeyUsage.cRLSign, Gb35114CertUtil.KEY_USAGE_CA);
        assertEquals(KeyUsage.digitalSignature, Gb35114CertUtil.KEY_USAGE_ENTITY);
    }
}
