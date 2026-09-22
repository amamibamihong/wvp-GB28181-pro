package com.genersoft.iot.vmp.gb35114.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 私钥 PEM 的对称加密工具（AES-128-GCM），避免私钥明文落库。
 * 密钥由配置 {@code gb35114.key-encrypt-password} 派生（SHA-256 前 16 字节）。
 */
public final class Gb35114KeyProtector {

    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_LEN = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private Gb35114KeyProtector() {
    }

    private static byte[] deriveKey(String password) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(password.getBytes(StandardCharsets.UTF_8));
            byte[] key = new byte[16];
            System.arraycopy(digest, 0, key, 0, 16);
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 加密，输出 base64(iv ‖ ciphertext)。 */
    public static String encrypt(String password, String plain) {
        try {
            byte[] iv = new byte[GCM_IV_LEN];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveKey(password), "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN, iv));
            byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("加密私钥失败", e);
        }
    }

    /** 解密。 */
    public static String decrypt(String password, String encoded) {
        try {
            byte[] in = Base64.getDecoder().decode(encoded);
            byte[] iv = new byte[GCM_IV_LEN];
            System.arraycopy(in, 0, iv, 0, GCM_IV_LEN);
            byte[] ct = new byte[in.length - GCM_IV_LEN];
            System.arraycopy(in, GCM_IV_LEN, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(password), "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("解密私钥失败", e);
        }
    }
}
