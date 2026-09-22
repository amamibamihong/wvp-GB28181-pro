package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * SM2 X.509 证书（GM/T 0015-2012）生成、签发与加载。
 *
 * <p>支持 CA 签发与自签两种模式，私钥以 PKCS#8 PEM 输出；加载支持
 * PKCS#8（{@code PRIVATE KEY}）与 SEC1（{@code EC/SM2 PRIVATE KEY}）私钥。
 */
public final class Gb35114CertUtil {

    private static final String CURVE = "sm2p256v1";
    private static final String SIGN_ALGO = "SM3withSM2";

    private static final SecureRandom RNG = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Gb35114CertUtil() {
    }

    /** 证书 + 私钥的持有对象。 */
    public static final class Gb35114Identity {
        public final X509Certificate certificate;
        public final PrivateKey privateKey;
        public final String certPem;
        public final String keyPem;

        public Gb35114Identity(X509Certificate certificate, PrivateKey privateKey,
                               String certPem, String keyPem) {
            this.certificate = certificate;
            this.privateKey = privateKey;
            this.certPem = certPem;
            this.keyPem = keyPem;
        }

        public PublicKey publicKey() {
            return certificate.getPublicKey();
        }
    }

    /**
     * 公钥指纹：对 SM2 公钥<b>点本身的未压缩编码</b>（{@code 0x04 ‖ X ‖ Y}，65 字节）取 SM3，
     * 返回小写十六进制。
     *
     * <p>刻意不用 {@code SubjectPublicKeyInfo} 整体编码：同一把密钥可能被编成「命名曲线」
     * 或「显式曲线参数」两种形式（长度 91 vs 311 字节），整体编码做摘要会得出不同指纹，
     * 无法判断两张证书是否同一个身份。取点编码则与编码形式无关。
     *
     * <p>用途是判定两张证书是否<b>同一个签名身份</b>——公钥相同则指纹相同。设备侧只
     * 保存一个平台公钥，因此同指纹的证书彼此可互换：设备导入其中任一张，平台用同组
     * 内任一张的私钥签名都能被验过。这也是「证书轮换不打断已配置设备」的依据。
     */
    public static String publicKeyFingerprint(X509Certificate certificate) throws Exception {
        if (certificate == null) {
            return null;
        }
        return publicKeyFingerprint(certificate.getPublicKey());
    }

    /** 公钥指纹（PublicKey 版）。 */
    public static String publicKeyFingerprint(PublicKey publicKey) throws Exception {
        if (publicKey == null) {
            return null;
        }
        byte[] point = ecPointEncoding(publicKey);
        SM3Digest digest = new SM3Digest();
        digest.update(point, 0, point.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        StringBuilder sb = new StringBuilder(out.length * 2);
        for (byte b : out) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** 公钥指纹（PEM 版）。 */
    public static String publicKeyFingerprint(String certPem) throws Exception {
        return publicKeyFingerprint(loadCertificate(certPem));
    }

    /** 取 SM2 公钥点的未压缩编码（{@code 0x04 ‖ X ‖ Y}），与曲线参数编码形式无关。 */
    private static byte[] ecPointEncoding(PublicKey publicKey) throws Exception {
        org.bouncycastle.jce.interfaces.ECPublicKey ecKey =
                (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
        return ecKey.getQ().getEncoded(false);
    }

    /**
     * 用<b>已有私钥</b>生成 CSR：公钥与私钥均取自调用方，不生成新密钥对。
     *
     * <p>用于让「向上级申请的客户端证书」与已有身份共用同一密钥对，或对同一身份
     * 重新提交请求。标准未禁止同一公钥申请不同用途的证书，但服务端/客户端两个
     * 信任方向相反，是否共用应由使用方按自己的安全策略决定。
     *
     * @param subject     证书主题
     * @param privateKey  已有私钥（用于 CSR 自签名）
     */
    public static CsrResult generateCsr(X500Name subject, PrivateKey privateKey) throws Exception {
        if (privateKey == null) {
            throw new IllegalArgumentException("复用密钥对生成 CSR 需要提供私钥");
        }
        PublicKey publicKey = publicKeyOf(privateKey);
        PKCS10CertificationRequestBuilder builder =
                new PKCS10CertificationRequestBuilder(subject,
                        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
        PKCS10CertificationRequest csr = builder.build(signer);
        return new CsrResult(privateKey, toPem(privateKey), toPem(csr));
    }

    /**
     * 由 SM2 私钥推导对应公钥。
     *
     * <p>算法标识用 {@code id-ecPublicKey} + SM2 命名曲线参数（91 字节 SPKI），
     * 与证书里的公钥编码一致。两种错误写法都会出问题：
     * <ul>
     *   <li>直接把算法标识写成 SM2 OID —— BC 的转换器认不出该算法，抛
     *       {@code no such algorithm};</li>
     *   <li>用 {@code ECParameterSpec} 内联曲线参数 —— 编出 311 字节的显式参数形式，
     *       签出的证书带上非标准编码，对端比对公钥时会不一致。</li>
     * </ul>
     */
    public static PublicKey publicKeyOf(PrivateKey key) throws Exception {
        java.security.interfaces.ECPrivateKey priv = (java.security.interfaces.ECPrivateKey) key;
        X9ECParameters params = GMNamedCurves.getByName(CURVE);
        org.bouncycastle.math.ec.ECPoint point = params.getG().multiply(priv.getS()).normalize();
        return new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(new SubjectPublicKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,
                                GMObjectIdentifiers.sm2p256v1),
                        point.getEncoded(false)));
    }

    /** 生成 SM2 密钥对。 */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec(CURVE), RNG);
        return generator.generateKeyPair();
    }

    /**
     * 组装 X500Name，仅加入非空项；CN 必填。
     *
     * <p>顺序遵循 RFC4514 常见书写顺序（C, ST, L, O, OU, CN），BC 内部会按 ASN.1 规范逆序编码。
     */
    public static X500Name buildSubject(String country, String province, String locality,
                                        String organization, String organizationalUnit,
                                        String commonName) {
        if (commonName == null || commonName.trim().isEmpty()) {
            throw new IllegalArgumentException("CN 不能为空");
        }
        List<RDN> rdns = new ArrayList<>();
        addRdn(rdns, BCStyle.C, country);
        addRdn(rdns, BCStyle.ST, province);
        addRdn(rdns, BCStyle.L, locality);
        addRdn(rdns, BCStyle.O, organization);
        addRdn(rdns, BCStyle.OU, organizationalUnit);
        addRdn(rdns, BCStyle.CN, commonName);
        return new X500Name(rdns.toArray(new RDN[0]));
    }

    private static void addRdn(List<RDN> rdns, org.bouncycastle.asn1.ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.trim().isEmpty()) {
            rdns.add(new RDN(oid, BCStyle.INSTANCE.stringToValue(oid, value.trim())));
        }
    }

    /** 取证书主题 DN（RFC2253 形式）。 */
    public static String subjectDn(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName();
    }

    /** 取证书签发者 DN（RFC2253 形式）。 */
    public static String issuerDn(X509Certificate cert) {
        return cert.getIssuerX500Principal().getName();
    }

    /**
     * 证书是否自签（issuer 与 subject 完全相同）。
     *
     * <p>只比对 DN，不做签名验证：这里要回答的是「这张证书是不是自己签的自己」，
     * 用于把「自签」与「由未导入的外部 CA 签发」区分开，而两者都表现为没有 caId。
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
    }

    /**
     * 解析密钥用途扩展描述串为 X.509 KeyUsage 位掩码。
     *
     * <p>支持以 {@code |} 或 {@code ,} 分隔的组合，取值：
     * {@code digitalSignature}（默认）、{@code nonRepudiation}、{@code keyEncipherment}、
     * {@code dataEncipherment}、{@code keyAgreement}、{@code keyCertSign}、{@code cRLSign}。
     * 为空时返回 {@code defaultValue}；无法识别时抛异常而非静默忽略，
     * 避免签出的证书用途与用户预期不符。
     */
    public static int parseKeyUsage(String spec, int defaultValue) {
        if (spec == null || spec.trim().isEmpty()) {
            return defaultValue;
        }
        int bits = 0;
        for (String raw : spec.split("[|,]")) {
            String item = raw.trim();
            if (item.isEmpty()) {
                continue;
            }
            switch (item) {
                case "digitalSignature" -> bits |= KeyUsage.digitalSignature;
                case "nonRepudiation" -> bits |= KeyUsage.nonRepudiation;
                case "keyEncipherment" -> bits |= KeyUsage.keyEncipherment;
                case "dataEncipherment" -> bits |= KeyUsage.dataEncipherment;
                case "keyAgreement" -> bits |= KeyUsage.keyAgreement;
                case "keyCertSign" -> bits |= KeyUsage.keyCertSign;
                case "cRLSign" -> bits |= KeyUsage.cRLSign;
                default -> throw new IllegalArgumentException("无法识别的密钥用途: " + item);
            }
        }
        return bits == 0 ? defaultValue : bits;
    }

    /** CA 证书默认密钥用途：签证书 + 吊销列表。 */
    public static final int KEY_USAGE_CA = KeyUsage.keyCertSign | KeyUsage.cRLSign;
    /** 终端实体证书默认密钥用途：数字签名（GB35114 的 sign1/sign2 即数字签名）。 */
    public static final int KEY_USAGE_ENTITY = KeyUsage.digitalSignature;

    /** 生成 PKCS#10 证书请求（CSR）。持有待签发私钥与 CSR PEM。 */
    public static final class CsrResult {
        public final PrivateKey privateKey;
        public final String keyPem;
        public final String csrPem;

        public CsrResult(PrivateKey privateKey, String keyPem, String csrPem) {
            this.privateKey = privateKey;
            this.keyPem = keyPem;
            this.csrPem = csrPem;
        }
    }

    /**
     * 生成证书请求（CSR）：产出 SM2 密钥对 + PKCS#10 请求，私钥供签发时保留。
     * 签发时用 {@link #issueFromCsr} 完成 CA 侧签发。
     */
    public static CsrResult generateCsr(String subjectCn) throws Exception {
        return generateCsr(new X500Name("CN=" + subjectCn));
    }

    /** 生成证书请求（完整 DN 版本）。 */
    public static CsrResult generateCsr(X500Name subject) throws Exception {
        KeyPair kp = generateKeyPair();
        PKCS10CertificationRequestBuilder builder =
                new PKCS10CertificationRequestBuilder(subject, SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        return new CsrResult(kp.getPrivate(), toPem(kp.getPrivate()), toPem(csr));
    }

    /** 由 CA 用 CSR 签发证书（subject 取自 CSR），返回仅含证书的身份（无私钥）。 */
    public static Gb35114Identity issueFromCsr(Gb35114Identity ca, String csrPem,
                                               Date notBefore, Date notAfter) throws Exception {
        return issueFromCsr(ca, csrPem, notBefore, notAfter, KEY_USAGE_ENTITY);
    }

    /**
     * 由 CA 用 CSR 签发证书，并写入密钥用途扩展。
     *
     * <p>subject 与公钥均取自 CSR，调用方无法覆盖，避免 DN 与公钥的绑定关系被篡改。
     */
    public static Gb35114Identity issueFromCsr(Gb35114Identity ca, String csrPem,
                                               Date notBefore, Date notAfter,
                                               int keyUsage) throws Exception {
        PKCS10CertificationRequest csr = parseCsr(csrPem);
        X500Name subject = csr.getSubject();
        PublicKey publicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());
        X509CertificateHolder caHolder = new X509CertificateHolder(ca.certificate.getEncoded());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caHolder.getSubject(), new BigInteger(160, RNG), notBefore, notAfter,
                subject, publicKey);
        addKeyUsage(builder, keyUsage);
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(ca.privateKey);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
        return new Gb35114Identity(cert, null, toPem(cert), null);
    }

    /** 解析 CSR PEM。 */
    public static PKCS10CertificationRequest parseCsr(String csrPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            }
            throw new IllegalArgumentException("PEM 中未找到 CSR 块");
        }
    }

    /**
     * 从 CSR 中取主题 CN。
     *
     * <p>下级提交的 CSR 里，CN 通常就是其国标编码，用来自动回填「下级国标 ID」，
     * 避免人工再抄一遍。无法解析时返回 {@code null}，由调用方决定是否报错。
     */
    public static String csrSubjectCn(String csrPem) {
        try {
            RDN[] rdns = parseCsr(csrPem).getSubject().getRDNs(BCStyle.CN);
            if (rdns.length == 0) {
                return null;
            }
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        } catch (Exception e) {
            return null;
        }
    }

    /** 从 CSR 中取完整主题 DN（RFC2253 形式），无法解析时返回 {@code null}。 */
    public static String csrSubjectDn(String csrPem) {
        try {
            return parseCsr(csrPem).getSubject().toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** 生成自签 SM2 证书（subject 即 issuer）。 */
    public static Gb35114Identity generateSelfSigned(String subjectCn, Date notBefore, Date notAfter)
            throws Exception {
        return generateSelfSigned(new X500Name("CN=" + subjectCn), notBefore, notAfter, KEY_USAGE_CA);
    }

    /** 生成自签 SM2 证书（完整 DN 版本，subject 即 issuer）。 */
    public static Gb35114Identity generateSelfSigned(X500Name subject, Date notBefore, Date notAfter)
            throws Exception {
        return generateSelfSigned(subject, notBefore, notAfter, KEY_USAGE_CA);
    }

    /** 生成自签 SM2 证书，并写入密钥用途扩展。 */
    public static Gb35114Identity generateSelfSigned(X500Name subject, Date notBefore, Date notAfter,
                                                     int keyUsage) throws Exception {
        KeyPair kp = generateKeyPair();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, new BigInteger(160, RNG), notBefore, notAfter, subject, kp.getPublic());
        addKeyUsage(builder, keyUsage);
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
        return toIdentity(cert, kp.getPrivate());
    }

    /**
     * 用<b>已有密钥对</b>自签一张证书，不生成新密钥对。
     *
     * <p>用于服务端证书轮换：私钥不变，只重签证书（换有效期 / DN / 序列号）。
     * 新证书公钥与源证书一致，设备侧无需重新导入。
     *
     * @param subject    新证书主题
     * @param publicKey  已有公钥（须与 privateKey 配对）
     * @param keyPem     已有私钥 PEM（原样存回新记录）
     */
    public static Gb35114Identity selfSignWithKey(X500Name subject, PublicKey publicKey,
                                                  String keyPem, Date notBefore, Date notAfter,
                                                  int keyUsage) throws Exception {
        PrivateKey privateKey = loadPrivateKey(keyPem);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, new BigInteger(160, RNG), notBefore, notAfter, subject, publicKey);
        addKeyUsage(builder, keyUsage);
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
        return new Gb35114Identity(cert, privateKey, toPem(cert), keyPem);
    }

    /** 用 CA 身份签发一张 SM2 证书。 */
    public static Gb35114Identity issue(Gb35114Identity ca, String subjectCn,
                                        Date notBefore, Date notAfter) throws Exception {
        return issue(ca, new X500Name("CN=" + subjectCn), notBefore, notAfter);
    }

    /** 用 CA 身份签发一张 SM2 证书（完整 DN 版本）。 */
    public static Gb35114Identity issue(Gb35114Identity ca, X500Name subject,
                                        Date notBefore, Date notAfter) throws Exception {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = buildAndSign(ca, subject, kp.getPublic(), notBefore, notAfter, KEY_USAGE_ENTITY);
        return toIdentity(cert, kp.getPrivate());
    }

    /**
     * 用 CA 身份为<b>已存在的公钥</b>签发证书，不生成新密钥对。
     *
     * <p>用于「本地身份证书」场景：私钥已由本平台生成并加密留存，
     * 签发只回填证书，必须复用原公钥，否则签出的证书与留存私钥不配对、无法用于签名。
     */
    public static Gb35114Identity issueWithKey(Gb35114Identity ca, X500Name subject,
                                               PublicKey publicKey,
                                               Date notBefore, Date notAfter) throws Exception {
        return issueWithKey(ca, subject, publicKey, notBefore, notAfter, KEY_USAGE_ENTITY);
    }

    /** 用 CA 身份为已存在的公钥签发证书，并写入密钥用途扩展。 */
    public static Gb35114Identity issueWithKey(Gb35114Identity ca, X500Name subject,
                                               PublicKey publicKey,
                                               Date notBefore, Date notAfter,
                                               int keyUsage) throws Exception {
        X509Certificate cert = buildAndSign(ca, subject, publicKey, notBefore, notAfter, keyUsage);
        return new Gb35114Identity(cert, null, toPem(cert), null);
    }

    /** 写入密钥用途扩展。 */
    private static void addKeyUsage(JcaX509v3CertificateBuilder builder, int keyUsage)
            throws CertIOException {
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
    }

    /** 构造并签名证书（公钥由调用方提供）。 */
    private static X509Certificate buildAndSign(Gb35114Identity ca, X500Name subject,
                                                PublicKey publicKey,
                                                Date notBefore, Date notAfter,
                                                int keyUsage) throws Exception {
        X509CertificateHolder caHolder = new X509CertificateHolder(ca.certificate.getEncoded());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caHolder.getSubject(), new BigInteger(160, RNG), notBefore, notAfter,
                subject, publicKey);
        addKeyUsage(builder, keyUsage);
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(ca.privateKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /** 从 PEM 加载证书（不含私钥）。 */
    public static X509Certificate loadCertificate(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate((X509CertificateHolder) obj);
            }
            throw new IllegalArgumentException("PEM 中未找到证书块");
        }
    }

    /** 从证书 + 私钥 PEM 加载身份。私钥支持 PKCS#8 与 SEC1。 */
    public static Gb35114Identity loadIdentity(String certPem, String keyPem) throws Exception {
        X509Certificate cert = loadCertificate(certPem);
        PrivateKey key = loadPrivateKey(keyPem);
        return new Gb35114Identity(cert, key, certPem, keyPem);
    }

    /** 加载私钥（PKCS#8 或 SEC1 或加密 PKCS#8）。 */
    public static PrivateKey loadPrivateKey(String keyPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(keyPem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (obj instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) obj);
            }
            throw new IllegalArgumentException("PEM 中未找到受支持的私钥块");
        }
    }

    /**
     * 校验证书公钥与私钥是否配对。
     *
     * <p>用于「回填证书」时防止把不匹配的证书填进已留存私钥的记录，
     * 否则签出的证书永远无法用于签名。
     */
    public static boolean matches(String certPem, String keyPem) {
        if (certPem == null || keyPem == null) {
            return false;
        }
        try {
            X509Certificate cert = loadCertificate(certPem);
            PrivateKey key = loadPrivateKey(keyPem);
            java.security.interfaces.ECPublicKey certPub =
                    (java.security.interfaces.ECPublicKey) cert.getPublicKey();
            java.security.interfaces.ECPrivateKey priv =
                    (java.security.interfaces.ECPrivateKey) key;
            // 由私钥标量 d 计算公钥点 d*G，与证书公钥坐标比对
            X9ECParameters params = GMNamedCurves.getByName(CURVE);
            org.bouncycastle.math.ec.ECPoint point = params.getG().multiply(priv.getS()).normalize();
            return point.getAffineXCoord().toBigInteger().equals(certPub.getW().getAffineX())
                    && point.getAffineYCoord().toBigInteger().equals(certPub.getW().getAffineY());
        } catch (Exception e) {
            return false;
        }
    }

    /** 从私钥 PEM 推导公钥。 */
    public static PublicKey publicKeyOf(String keyPem) throws Exception {
        return publicKeyOf(loadPrivateKey(keyPem));
    }

    /** 证书转 PEM。 */
    public static String toPem(Object obj) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
        }
        return sw.toString();
    }

    private static Gb35114Identity toIdentity(X509Certificate cert, PrivateKey key)
            throws Exception {
        return new Gb35114Identity(cert, key, toPem(cert), toPem(key));
    }
}
