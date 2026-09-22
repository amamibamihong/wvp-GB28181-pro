package com.genersoft.iot.vmp.gb35114.crypto;

import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SM2/SM3 密码原语测试：签名/验签回环、VKEK 信封回环、错误分支，
 * 以及对齐 gb28181-rs {@code crypto.rs} 的 SM3 Note 摘要 golden 值。
 */
class Gb35114SmCryptoTest {

    @Test
    void signVerifyRoundtrip() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        byte[] payload = "random2random1serverid".getBytes();
        String sig = Gb35114SmCrypto.sign(kp.getPrivate(), payload);
        assertNotNull(sig);
        Gb35114SmCrypto.verify(kp.getPublic(), payload, sig); // 不抛即通过
    }

    @Test
    void signVerifyRejectsWrongKey() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        KeyPair other = Gb35114CertUtil.generateKeyPair();
        byte[] payload = "data".getBytes();
        String sig = Gb35114SmCrypto.sign(kp.getPrivate(), payload);
        assertThrows(GeneralSecurityException.class,
                () -> Gb35114SmCrypto.verify(other.getPublic(), payload, sig));
    }

    @Test
    void signVerifyRejectsTamperedPayload() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        byte[] payload = "data".getBytes();
        String sig = Gb35114SmCrypto.sign(kp.getPrivate(), payload);
        assertThrows(GeneralSecurityException.class,
                () -> Gb35114SmCrypto.verify(kp.getPublic(), "DATA".getBytes(), sig));
    }

    @Test
    void vkekEnvelopeRoundtrip() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        byte[] vkek = Gb35114SmCrypto.randomBytes(16);
        String cryptKey = Gb35114SmCrypto.encryptVkek(kp.getPublic(), vkek);
        byte[] opened = Gb35114SmCrypto.decryptVkek(kp.getPrivate(), cryptKey);
        assertArrayEquals(vkek, opened);
    }

    @Test
    void vkekEnvelopeRejectsWrongKey() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        KeyPair other = Gb35114CertUtil.generateKeyPair();
        byte[] vkek = Gb35114SmCrypto.randomBytes(16);
        String cryptKey = Gb35114SmCrypto.encryptVkek(kp.getPublic(), vkek);
        assertThrows(GeneralSecurityException.class,
                () -> Gb35114SmCrypto.decryptVkek(other.getPrivate(), cryptKey));
    }

    @Test
    void decryptRejectsIllegalBase64() throws Exception {
        KeyPair kp = Gb35114CertUtil.generateKeyPair();
        assertThrows(Exception.class,
                () -> Gb35114SmCrypto.decryptVkek(kp.getPrivate(), "not-base64!!"));
    }

    @Test
    void sm3DigestMatchesRustGoldenRawVkek() {
        // 取自 gb28181-rs integrity.rs digest_payload_vkek_raw_golden。
        String method = "MESSAGE";
        String from = "<sip:34020000001320000001@3402000000>;tag=1465468922";
        String to = "<sip:34020000002000000001@3402000000>";
        String callId = "1465470512602@192.168.1.100";
        String date = "2024-01-31T14:40:49.583";
        byte[] vkek = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        String body = "<?xml version=\"1.0\"?>\r\n<Notify>\r\n<CmdType>Keepalive</CmdType>\r\n"
                + "<SN>1</SN>\r\n<DeviceID>34020000001320000001</DeviceID>\r\n"
                + "<Status>OK</Status>\r\n</Notify>\r\n";

        byte[] digest = Gb35114HeaderUtil.digestPayload(method, from, to, callId, date, vkek, body);
        assertEquals(
                "95b9b4c1ff6900fb5b7981049ab4a6b017b1d917108b4db59762e3a82cad4210",
                hex(digest));
    }

    @Test
    void randomB64HasExpectedLength() {
        assertEquals(24, Gb35114SmCrypto.randomB64(16).length()); // 16 字节 → 24 字符 base64
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
