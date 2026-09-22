package com.genersoft.iot.vmp.gb35114.crypto;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

/**
 * GB35114 A 级的 SM2/SM3 密码原语，线格式逐字节对齐 gb28181-rs 的
 * {@code security35114::crypto}：
 * <ul>
 *   <li>SM2 签名/验签：默认 UID {@code 1234567812345678}（GM/T 0003），签名输出 base64(DER)</li>
 *   <li>VKEK 信封：SM2 加密，{@code C1‖C3‖C2} 顺序（GM/T 0009 / GB/T 32918.4）</li>
 *   <li>SM3 摘要</li>
 * </ul>
 */
public final class Gb35114SmCrypto {

    /** GM/T 0003 默认 SM2 用户标识，与 Rust {@code DEFAULT_UID} 一致。 */
    public static final String DEFAULT_UID = "1234567812345678";

    private static final X9ECParameters X9 = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(X9.getCurve(), X9.getG(), X9.getN(), X9.getH());

    private static final SecureRandom RNG = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Gb35114SmCrypto() {
    }

    /** 生成 n 字节密码学安全随机数。 */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    /** 生成 n 字节随机数并 base64 编码（random1/random2 的线格式）。 */
    public static String randomB64(int n) {
        return Base64.getEncoder().encodeToString(randomBytes(n));
    }

    /** 生成 SM2 密钥对（轻量级 BC 表示，供证书签发使用）。 */
    public static AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(DOMAIN, RNG));
        return generator.generateKeyPair();
    }

    /** SM3 摘要，对多段字节按序拼接后计算。 */
    public static byte[] sm3(byte[]... chunks) {
        SM3Digest digest = new SM3Digest();
        for (byte[] chunk : chunks) {
            digest.update(chunk, 0, chunk.length);
        }
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /** UTF-8 便捷封装。 */
    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * SM2 签名（默认 UID），返回 base64 编码的 DER 签名。
     */
    public static String sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
        ECPrivateKeyParameters params = privateKeyParams(privateKey);
        SM2Signer signer = new SM2Signer(StandardDSAEncoding.INSTANCE);
        signer.init(true, new ParametersWithRandom(params, RNG));
        signer.update(payload, 0, payload.length);
        try {
            return Base64.getEncoder().encodeToString(signer.generateSignature());
        } catch (CryptoException e) {
            throw new GeneralSecurityException("SM2 sign failed", e);
        }
    }

    /**
     * SM2 验签（默认 UID）。签名不合法时抛出 {@link GeneralSecurityException}。
     */
    public static void verify(PublicKey publicKey, byte[] payload, String sigB64)
            throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(sigB64);
        ECPublicKeyParameters params = publicKeyParams(publicKey);
        SM2Signer signer = new SM2Signer(StandardDSAEncoding.INSTANCE);
        signer.init(false, params);
        signer.update(payload, 0, payload.length);
        if (!signer.verifySignature(der)) {
            throw new GeneralSecurityException("SM2 signature verification failed");
        }
    }

    /**
     * 将 VKEK 封到设备公钥下：SM2 C1C3C2 加密，返回 base64 编码的 <b>DER</b> 信封。
     *
     * <p>线格式必须是 DER 的 {@code SM2Ciphertext}：
     * {@code SEQUENCE { INTEGER x, INTEGER y, OCTET STRING C3, OCTET STRING C2 }}。
     * BouncyCastle 低层 {@link SM2Engine} 输出的是<b>裸</b> {@code C1‖C3‖C2}，
     * 而设备端（OpenSSL {@code SM2_decrypt}、gmsm、Rust 参考实现的 {@code encrypt_der}）
     * 都按 DER 解析，裸输出会让设备解不开 cryptkey、注册直接失败。
     * 这里补上 DER 封装，与 {@code interop_fixtures} 的黄金值同格式。
     */
    public static String encryptVkek(PublicKey publicKey, byte[] vkek) throws GeneralSecurityException {
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(true, new ParametersWithRandom(publicKeyParams(publicKey), RNG));
        try {
            byte[] enc = engine.processBlock(vkek, 0, vkek.length);
            return Base64.getEncoder().encodeToString(toDerCiphertext(enc));
        } catch (InvalidCipherTextException e) {
            throw new GeneralSecurityException("SM2 encrypt failed", e);
        } catch (IOException e) {
            throw new GeneralSecurityException("SM2 ciphertext DER encode failed", e);
        }
    }

    /** 裸 {@code C1(65)‖C3(32)‖C2(n)} 打包成 DER 的 SM2Ciphertext。 */
    private static byte[] toDerCiphertext(byte[] raw) throws IOException {
        if (raw.length < 97 || raw[0] != 0x04) {
            // 不是预期的裸格式，原样返回（交由对端报错），避免静默产出错误线格式
            return raw;
        }
        byte[] x = Arrays.copyOfRange(raw, 1, 33);
        byte[] y = Arrays.copyOfRange(raw, 33, 65);
        byte[] c3 = Arrays.copyOfRange(raw, 65, 97);
        byte[] c2 = Arrays.copyOfRange(raw, 97, raw.length);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(new BigInteger(1, x)));
        v.add(new ASN1Integer(new BigInteger(1, y)));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * DER 的 SM2Ciphertext 还原为裸 {@code C1‖C3‖C2}；已是裸格式则原样返回。
     *
     * <p>C1 的 x / y 在 DER 里是 INTEGER，长度不固定：最高字节 ≥ 0x80 时前面补
     * {@code 0x00} 防止被当成负数，最高字节为 0 时又会被省掉。因此必须<b>归一化到
     * 定长 32 字节</b>，不能直接拿 DER 里读到的字节数当坐标长度。
     *
     * <p>此处曾经写成 {@code if (x.length > 32) return in}，而
     * {@code getPositiveValue().toByteArray()} 对「最高位为 1 的 32 字节坐标」会再补一个
     * {@code 0x00} 变成 33 字节 —— 于是约一半的密文（x、y 各自概率 1/2）被判为「不是预期
     * 格式」，函数原样返回 DER 字节，{@link #decryptVkek} 再拿 DER 去喂只认裸格式的
     * {@code SM2Engine}，必然失败。现场表现是 cryptkey <b>随机</b>解不开、握手时通时断，
     * 与证书、平台配置都无关，极易被误判成对端问题。
     */
    private static byte[] fromDerCiphertext(byte[] in) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(in);
            if (seq.size() != 4) {
                return in;
            }
            byte[] x = normalizeCoordinate((ASN1Integer) seq.getObjectAt(0));
            byte[] y = normalizeCoordinate((ASN1Integer) seq.getObjectAt(1));
            byte[] c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            byte[] c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
            if (x == null || y == null || c3.length != 32) {
                return in;
            }
            byte[] out = new byte[65 + c3.length + c2.length];
            out[0] = 0x04;
            System.arraycopy(x, 0, out, 1, 32);
            System.arraycopy(y, 0, out, 33, 32);
            System.arraycopy(c3, 0, out, 65, c3.length);
            System.arraycopy(c2, 0, out, 65 + c3.length, c2.length);
            return out;
        } catch (RuntimeException e) {
            return in;
        }
    }

    /**
     * 把 DER INTEGER 里的一个坐标归一化成定长 32 字节（大端、左补零）。
     *
     * @return 32 字节坐标；数值超出 32 字节（不是 SM2 坐标）时返回 {@code null}
     */
    private static byte[] normalizeCoordinate(ASN1Integer value) {
        byte[] raw = value.getPositiveValue().toByteArray();
        int start = 0;
        while (start < raw.length - 1 && raw[start] == 0) {
            start++;
        }
        int len = raw.length - start;
        if (len > 32) {
            return null;
        }
        byte[] out = new byte[32];
        System.arraycopy(raw, start, out, 32 - len, len);
        return out;
    }

    /**
     * 用私钥打开 cryptkey 信封，返回协商出的 VKEK。
     * 同时接受 DER（标准/设备）与裸 C1C3C2（兼容早期实现）两种线格式。
     *
     * <p><b>两种线格式的 C1 都得容忍省略的前导零。</b>SM2 密文的 C1 是「无符号 32 字节
     * 整数」，但 DER 编码把 x/y 写成 INTEGER，最高位为 1 时补 {@code 0x00}、最高字节为 0 时
     * 又被省掉，于是同一份密文长度会在 113~117 字节之间浮动。BouncyCastle 的
     * {@code SM2Engine} 只认<b>定长 65 字节</b>的 C1，长度差一点就静默解密失败 ——
     * 而现场表现极具迷惑性：握手看似跑完（对端 200 OK、回 401 也正常），本端却<b>随机</b>
     * 地「有时能解、有时不能」，且失败率与密钥、平台都无关。
     *
     * <p>原先这里只在 {@code x.length <= 32} 时才补齐，可 {@code getPositiveValue()}
     * 在最高字节为 0 时（例如 x = 0x00 12 34 …）返回值可能只有 31 字节，甚至更短，
     * 补位后仍不足 32 —— 于是那部分密文永远解不开。下面改为<b>无条件左补零到 32 字节</b>，
     * 并把任何异常统一转成可读的 {@link GeneralSecurityException}，不再让
     * {@code SM2 decrypt failed} 这种没头没尾的消息出现在日志里。
     */
    public static byte[] decryptVkek(PrivateKey privateKey, String cryptkeyB64)
            throws GeneralSecurityException {
        byte[] enc = fromDerCiphertext(Base64.getDecoder().decode(cryptkeyB64));
        if (enc.length < 97 || enc[0] != 0x04) {
            throw new GeneralSecurityException("cryptkey 不是合法的 SM2 密文（长度 "
                    + enc.length + "，未解析出 C1C3C2）");
        }
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(false, privateKeyParams(privateKey));
        try {
            return engine.processBlock(enc, 0, enc.length);
        } catch (InvalidCipherTextException e) {
            throw new GeneralSecurityException("SM2 解 cryptkey 失败：" + e.getMessage(), e);
        }
    }

    static ECPublicKeyParameters publicKeyParams(PublicKey key) throws GeneralSecurityException {
        return (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(key);
    }

    static ECPrivateKeyParameters privateKeyParams(PrivateKey key) throws GeneralSecurityException {
        return (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(key);
    }
}
