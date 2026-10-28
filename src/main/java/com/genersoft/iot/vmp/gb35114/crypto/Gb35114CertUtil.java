package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
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
     * <p>类型是判定两张证书是否<b>同一个签名身份</b>——公钥相同则指纹相同。设备侧只
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
     * 重新提交请求。标准未禁止同一公钥申请不同类型的证书，但服务端/客户端两个
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

    private static void addRdn(List<RDN> rdns, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.trim().isEmpty()) {
            rdns.add(new RDN(oid, BCStyle.INSTANCE.stringToValue(oid, value.trim())));
        }
    }

    /**
     * 主题 DN 的分段解析结果，字段与证书档案的各列一一对应，缺失段为 {@code null}。
     */
    public record DnParts(String country, String province, String locality,
                          String organization, String organizationalUnit, String commonName) {
    }

    /**
     * 从证书主题 DN 解析出各段（C/ST/L/O/OU/CN）。
     *
     * <p>与 {@link #buildSubject} 互逆。用它把「证书里真实写着的 DN」拆回各列，
     * 而不是采信调用方传进来的表单值 —— 表单值可能带首尾空格、大小写不同，或者
     * 干脆是空的（导入路径就没有这些输入）。只要列取自证书本身，列与
     * {@code subject_dn} 就永远一致，不会出现「DN 里有 C=CN、country 列却是 NULL」。
     *
     * <p>同一属性出现多次时取第一个，够用于展示与回填。
     */
    public static DnParts parseSubject(X509Certificate cert) {
        X500Name name = new X500Name(cert.getSubjectX500Principal().getName());
        return new DnParts(
                firstRdn(name, BCStyle.C), firstRdn(name, BCStyle.ST), firstRdn(name, BCStyle.L),
                firstRdn(name, BCStyle.O), firstRdn(name, BCStyle.OU), firstRdn(name, BCStyle.CN));
    }

    /** 取某个属性的首个取值，没有则返回 null。 */
    private static String firstRdn(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0) {
            return null;
        }
        try {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        } catch (Exception e) {
            return null;
        }
    }

    /** 取证书主题 DN（RFC2253 形式）。 */
    public static String subjectDn(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName();
    }

    /**
     * GB 35114—2017 附录 A 表 A.1 第 6 项「设备标识（CN）」的解析结果。
     *
     * <p>标准规定的 CN 格式为「<b>设备 ID_密码模块 ID</b>」，以「_」分隔，
     * 某个 ID 为空时该位置写 {@code NULL}。密码模块 ID 是 22 位十进制编码
     * （附录 B：产品型号 4 + 类型 2 + 生产日期 8 + 批次 3 + 序号 5）。
     */
    public record DeviceIds(String deviceId, String moduleId) {
    }

    /** 密码模块 ID 的位数（GB 35114—2017 附录 B：五码段共 22 位十进制数字）。 */
    public static final int MODULE_ID_LENGTH = 22;

    /**
     * 无密码模块时 CN 里密码模块 ID 位置的默认占位：22 个 0。
     *
     * <p>标准允许该 ID 为空时写 {@code NULL}；本平台默认填全 0 而非 {@code NULL}，
     * 是因为「长度对但取值为 0」比「写 NULL」更能通过「码段长度符合附录 B」的形式核对，
     * 同时明确表达「本平台无硬件密码模块」这一事实。用户可在表单里改成真实编码。
     */
    public static final String MODULE_ID_PLACEHOLDER = "0".repeat(MODULE_ID_LENGTH);

    /**
     * 从设备证书 CN 解析出设备 ID 与密码模块 ID。
     *
     * <p>兼容两种形态：
     * <ul>
     *   <li>标准格式 {@code 设备ID_密码模块ID} —— 拆成两段；</li>
     *   <li>只有设备 ID（本平台历史默认值，或平台证书）—— 密码模块 ID 为 {@code null}。</li>
     * </ul>
     * 密码模块 ID 位置写 {@code NULL}（标准规定的空值写法）时同样返回 {@code null}。
     *
     * @return 解析结果；{@code cn} 为空时返回 {@code null}
     */
    public static DeviceIds parseDeviceIds(String cn) {
        if (cn == null || cn.trim().isEmpty()) {
            return null;
        }
        String value = cn.trim();
        int sep = value.indexOf('_');
        if (sep < 0) {
            // 无分隔符：只有设备 ID（或平台证书的任意 CN）
            return new DeviceIds(value, null);
        }
        String deviceId = value.substring(0, sep).trim();
        String moduleId = value.substring(sep + 1).trim();
        if (moduleId.isEmpty() || "NULL".equalsIgnoreCase(moduleId)) {
            moduleId = null;
        }
        return new DeviceIds(deviceId.isEmpty() ? null : deviceId, moduleId);
    }

    /**
     * 按附录 A 表 A.1 拼装设备证书的 CN：{@code 设备ID_密码模块ID}。
     *
     * <p>任一段为空时写 {@code NULL}（标准规定的空值写法）。
     */
    public static String buildDeviceCn(String deviceId, String moduleId) {
        String d = (deviceId == null || deviceId.trim().isEmpty()) ? "NULL" : deviceId.trim();
        String m = (moduleId == null || moduleId.trim().isEmpty()) ? "NULL" : moduleId.trim();
        return d + "_" + m;
    }

    /** 密码模块 ID 是否符合附录 B 的形态（22 位十进制数字）。空值不算违规，返回 false。 */
    public static boolean isValidModuleId(String moduleId) {
        if (moduleId == null || moduleId.isEmpty()) {
            return false;
        }
        if (moduleId.length() != MODULE_ID_LENGTH) {
            return false;
        }
        for (int i = 0; i < moduleId.length(); i++) {
            if (!Character.isDigit(moduleId.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /** 取证书签发者 DN（RFC2253 形式）。 */
    public static String issuerDn(X509Certificate cert) {
        return cert.getIssuerX500Principal().getName();
    }

    /**
     * 证书是否自签（issuer 与 subject 完全相同）。
     *
     * <p>只比对 DN，不做签名验证：这里要回答的是「这张证书是不是自己签的自己」，
     * 用于在展示层区分「自签」与「由未导入的外部 CA 签发」这两种情况。
     *
     * <p>注意它<b>不再是</b>「{@code caId} 为空」的解释依据：反查签发者时自签证书同样
     * 走验签路径，能关联到「同一张证书已作为 CA 导入」的那条记录，因此 {@code caId}
     * 为空现在只表示「签发者未导入本平台」。
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
    }

    /**
     * 单级证书链校验：判定 {@code leaf} 是否由 {@code issuer} 签发。
     *
     * <p>通过返回 {@code null}；不通过返回可直接呈现给运维的中文原因。
     *
     * <p>判定分两步，顺序不可颠倒：
     * <ol>
     *   <li><b>验签</b>：{@code leaf.verify(issuer.getPublicKey())}。这是权威判定 ——
     *       只有真正签发 {@code leaf} 的那把私钥所对应的公钥才验得过。刻意<b>不比对
     *       issuer/subject DN</b>：厂商证书的属性顺序与空格差异会造成假阴性，把合法证书
     *       判死；而 DN 相同的两张 CA 也完全可能密钥不同
     *       （见 {@code Gb35114IssuerResolveTest#sameNameCasAreDistinguishedBySignature}），
     *       按 DN 判定反而会串台。</li>
     *   <li><b>CA 资格</b>：见 {@link #isCaCertificate}。验签通过只说明「密钥对得上」，
     *       不代表这张证书被授权去签别的证书。</li>
     * </ol>
     *
     * <p><b>不查有效期与吊销</b>：到期是否拦截是运维策略（{@code gb35114.reject-expired-cert}），
     * 吊销由证书记录本身承担，二者都不属于「链是否正确」这一判定。
     */
    public static String chainFailureReason(X509Certificate leaf, X509Certificate issuer) {
        if (issuer == null) {
            return "签发者证书为空";
        }
        String issuerName = commonNameOf(issuer);
        try {
            leaf.verify(issuer.getPublicKey());
        } catch (Exception e) {
            return "证书签名无法用「" + issuerName + "」的公钥验证：该证书不是由它签发的"
                    + "（可能由其它 CA 签发，或证书已被篡改）";
        }
        if (!isCaCertificate(issuer)) {
            return "「" + issuerName + "」不具备 CA 资格（keyUsage 缺少 keyCertSign，"
                    + "且 basicConstraints 未置 CA），不能作为签发者";
        }
        return null;
    }

    /**
     * 该证书是否具备 CA 资格。
     *
     * <p>判定为「{@code basicConstraints} 置了 CA <b>或</b> {@code keyUsage} 含
     * {@code keyCertSign}」—— 两者<b>取或</b>，不是取与。
     *
     * <p>为什么必须取或：<b>本平台自己生成的 CA 只写 keyUsage，没有 basicConstraints</b>
     * （{@code generateSelfSigned} / {@code buildAndSign} 仅通过 {@code addKeyUsage}
     * 写入 keyUsage 扩展）。若硬性要求 basicConstraints CA:TRUE，本平台的本地 CA 会被判为
     * 不具备资格，UAS 侧链校验一开就把所有设备挡在门外。反过来，OpenSSL、厂商工具签出的
     * CA 常常只有 basicConstraints 而没有 keyUsage，所以也不能只认 keyUsage。
     */
    public static boolean isCaCertificate(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            BasicConstraints bc = BasicConstraints.fromExtensions(holder.getExtensions());
            if (bc != null && bc.isCA()) {
                return true;
            }
            KeyUsage ku = KeyUsage.fromExtensions(holder.getExtensions());
            return ku != null && ku.hasUsages(KeyUsage.keyCertSign);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 两张证书是否持有同一把公钥。
     *
     * <p>同密钥即同一签名身份，与证书序列号、DN、公钥编码形式都无关。用于判定
     * 「这张证书是不是就是那张 CA」（自签根作为自己的锚）——自签证书的签名只能被
     * 与它公钥相同的证书验过，因此这是唯一可靠的同一性判定。
     */
    public static boolean sameKey(X509Certificate a, X509Certificate b) {
        if (a == null || b == null) {
            return false;
        }
        try {
            return publicKeyFingerprint(a).equals(publicKeyFingerprint(b));
        } catch (Exception e) {
            return false;
        }
    }

    /** 取证书主题的 CN，取不到时退回完整 DN。仅用于拼装可读的提示文本。 */
    private static String commonNameOf(X509Certificate cert) {
        try {
            RDN[] rdns = new X500Name(cert.getSubjectX500Principal().getName()).getRDNs(BCStyle.CN);
            if (rdns.length > 0) {
                return IETFUtils.valueToString(rdns[0].getFirst().getValue());
            }
        } catch (Exception ignored) {
            // 落到完整 DN
        }
        return subjectDn(cert);
    }

    /**
     * 解析密钥用途扩展描述串为 X.509 KeyUsage 位掩码。
     *
     * <p>支持以 {@code |} 或 {@code ,} 分隔的组合，取值：
     * {@code digitalSignature}（默认）、{@code nonRepudiation}、{@code keyEncipherment}、
     * {@code dataEncipherment}、{@code keyAgreement}、{@code keyCertSign}、{@code cRLSign}。
     * 为空时返回 {@code defaultValue}；无法识别时抛异常而非静默忽略，
     * 避免签出的证书类型与用户预期不符。
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

    /**
     * 用 CSR 里的主题与公钥<b>自签</b>一张证书，不生成新密钥对。
     *
     * <p>用于「服务端证书（本平台）先出 CSR、再由本平台自签」：私钥在
     * {@link #generateCsr(X500Name)} 那一步就已加密留存，签发必须复用 CSR 的公钥 ——
     * 若另生成密钥对，签出的证书与留存的私钥不配对，设备侧验 sign2 必然失败。
     * issuer 与 subject 相同（自签的固有含义）。
     *
     * <p>{@code keyPem} 只用于签名，不被校验是否与 CSR 公钥配对 —— 配对的把关由调用方
     * 用 {@link #matches(String, String)} 在写库前完成。
     *
     * @param csrPem    CSR（主题与公钥的来源，调用方无法覆盖）
     * @param keyPem    已留存的私钥 PEM
     */
    public static Gb35114Identity selfSignFromCsr(String csrPem, String keyPem,
                                                  Date notBefore, Date notAfter,
                                                  int keyUsage) throws Exception {
        PKCS10CertificationRequest csr = parseCsr(csrPem);
        PublicKey publicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());
        return selfSignWithKey(csr.getSubject(), publicKey, keyPem, notBefore, notAfter, keyUsage);
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
     * 用 CA 身份签发一张 SM2 证书，并写入密钥用途扩展。
     *
     * <p>与 {@link #issueWithKey} 的区别是<b>自己生成密钥对</b>，返回的身份里带着私钥
     * （{@code keyPem}），供本平台加密留存 —— 「一步创建」正是靠它省掉
     * 「先建 CSR 存私钥、再签发」这两步。
     */
    public static Gb35114Identity issue(Gb35114Identity ca, X500Name subject,
                                        Date notBefore, Date notAfter, int keyUsage) throws Exception {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = buildAndSign(ca, subject, kp.getPublic(), notBefore, notAfter, keyUsage);
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
