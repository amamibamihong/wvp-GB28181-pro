package com.genersoft.iot.vmp.gb35114.crypto;

import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GB35114 头构建/解析 golden 测试，golden 值直接取自 gb28181-rs
 * {@code security35114::headers} 与 {@code security35114::integrity} 的测试常量，
 * 确保 Java 与 Rust 逐字节一致。
 */
class Gb35114HeaderUtilTest {

    private static final String GOLDEN_RANDOM1 = "PRAIIbutDbd5x/NKsbwwYw==";
    private static final String GOLDEN_RANDOM2 = "F4InuQewuMMqYPy1ItBdhQ==";
    private static final String GOLDEN_SERVER = "34020000002000000001";
    private static final String GOLDEN_DEVICE = "34020000001320000001";
    private static final String GOLDEN_SIGN1 =
            "MEUCIQD/9gP8olHM0TeLj0MxBRw3C8tQKFMMRgUupnyD4xXTTwIhAJvXxvTEDXj8Yk5qjHwujzUjpYpxxCGq7Zz0tKzhhJUU";
    private static final String GOLDEN_SIGN2 =
            "MEUCIQDzvGhJCuxmH/3NNtLNnrXIUOxYkYB7j8/3Th1LvjZHggIgD/nd9RbpEd6neZTuXDsIbNzydyS8WarbN1p6nHD5pHk=";
    private static final String GOLDEN_CRYPT = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWQ==";

    @Test
    void capabilityHeaderGolden() {
        assertEquals(
                "Capability algorithm=\"A:SM2;H:SM3;S:SM4/OFB/PKCS5;SI:SM3-SM2\", keyversion=\"2019-08-06T05:31:39\"",
                Gb35114HeaderUtil.buildCapabilityAuthorization("2019-08-06T05:31:39", ""));
    }

    @Test
    void capabilityHeaderWithCertRoundtrip() {
        String certPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        String built = Gb35114HeaderUtil.buildCapabilityAuthorization("t", certPem);
        assertTrue(built.contains(", cnonce=\"devicecert:LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"));

        Gb35114HeaderUtil.CapabilityAnnouncement ann =
                Gb35114HeaderUtil.parseCapabilityAuthorization(built);
        assertEquals(certPem, ann.deviceCertPem);
    }

    @Test
    void parseChallengeRejectsDigest() {
        assertThrows(Gb35114Exception.class, () ->
                Gb35114HeaderUtil.parseChallenge("Digest realm=\"3402000000\", nonce=\"abc\""));
        assertThrows(Gb35114Exception.class, () ->
                Gb35114HeaderUtil.parseChallenge("Unidirection algorithm=\"A:SM2\""));
    }

    @Test
    void authAuthorizationUnidirectionGolden() {
        Gb35114HeaderUtil.Challenge ch = new Gb35114HeaderUtil.Challenge(
                Gb35114HeaderUtil.Mode.Unidirection, "", GOLDEN_RANDOM1);
        assertEquals(
                "Unidirection random1=\"" + GOLDEN_RANDOM1 + "\", random2=\"" + GOLDEN_RANDOM2
                        + "\", serverid=\"" + GOLDEN_SERVER + "\", sign1=\"" + GOLDEN_SIGN1
                        + "\", algorithm=\"A:SM2;H:SM3;S:SM4/OFB/PKCS5;SI:SM3-SM2\"",
                Gb35114HeaderUtil.buildAuthAuthorization(ch, GOLDEN_RANDOM2, GOLDEN_SERVER, "", GOLDEN_SIGN1));
    }

    @Test
    void authAuthorizationBidirectionGoldenAndRoundtrip() {
        Gb35114HeaderUtil.Challenge ch = new Gb35114HeaderUtil.Challenge(
                Gb35114HeaderUtil.Mode.Bidirection, "", GOLDEN_RANDOM1);
        String built = Gb35114HeaderUtil.buildAuthAuthorization(
                ch, GOLDEN_RANDOM2, GOLDEN_SERVER, GOLDEN_DEVICE, GOLDEN_SIGN1);
        assertTrue(built.startsWith("Bidirection random1="));
        assertTrue(built.contains("deviceid=\"" + GOLDEN_DEVICE + "\""));

        Gb35114HeaderUtil.AuthAuthorization aa = Gb35114HeaderUtil.parseAuthAuthorization(built);
        assertEquals(Gb35114HeaderUtil.Mode.Bidirection, aa.mode);
        assertEquals(GOLDEN_RANDOM1, aa.random1);
        assertEquals(GOLDEN_RANDOM2, aa.random2);
        assertEquals(GOLDEN_SERVER, aa.serverId);
        assertEquals(GOLDEN_DEVICE, aa.deviceId);
        assertEquals(GOLDEN_SIGN1, aa.sign1);
    }

    @Test
    void securityInfoBidirectionGoldenRoundtrip() {
        Gb35114HeaderUtil.SecurityInfo si = new Gb35114HeaderUtil.SecurityInfo();
        si.mode = Gb35114HeaderUtil.Mode.Bidirection;
        si.algorithm = Gb35114HeaderUtil.CAPABILITY_ALGORITHM;
        si.random1 = GOLDEN_RANDOM1;
        si.random2 = GOLDEN_RANDOM2;
        si.deviceId = GOLDEN_DEVICE;
        si.serverId = GOLDEN_SERVER;
        si.cryptKey = GOLDEN_CRYPT;
        si.sign2 = GOLDEN_SIGN2;

        String built = Gb35114HeaderUtil.buildSecurityInfo(si);
        assertEquals(
                "Bidirection algorithm=\"A:SM2;H:SM3;S:SM4/OFB/PKCS5;SI:SM3-SM2\",random1=\"" + GOLDEN_RANDOM1
                        + "\",random2=\"" + GOLDEN_RANDOM2 + "\",deviceid=\"" + GOLDEN_DEVICE
                        + "\",serverid=\"" + GOLDEN_SERVER + "\",cryptkey=\"" + GOLDEN_CRYPT
                        + "\",sign2=\"" + GOLDEN_SIGN2 + "\"",
                built);

        Gb35114HeaderUtil.SecurityInfo parsed = Gb35114HeaderUtil.parseSecurityInfo(built);
        assertEquals(Gb35114HeaderUtil.Mode.Bidirection, parsed.mode);
        assertEquals(GOLDEN_DEVICE, parsed.deviceId);
        assertEquals(GOLDEN_SIGN2, parsed.sign2);
    }

    @Test
    void securityInfoUnidirectionGolden() {
        Gb35114HeaderUtil.SecurityInfo si = Gb35114HeaderUtil.parseSecurityInfo(
                "Unidirection cryptkey=\"" + GOLDEN_CRYPT + "\", algorithm=\"A:SM2;H:SM3\"");
        assertEquals(Gb35114HeaderUtil.Mode.Unidirection, si.mode);
        assertEquals(GOLDEN_CRYPT, si.cryptKey);
    }
}
