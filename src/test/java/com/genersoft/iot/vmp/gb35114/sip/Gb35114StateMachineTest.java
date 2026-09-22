package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UAS×UAC 状态机回环测试，对照 gb28181-rs platform.rs 的测试矩阵：
 * 握手、双方 VKEK 一致、Note 篡改检测、stale random1 拒绝、幂等重传、
 * 未知证书拒绝。
 */
class Gb35114StateMachineTest {

    private static final String SERVER_ID = "34020000002000000001";
    private static final String DEVICE_ID = "34020000001320000001";

    private static Gb35114CertUtil.Gb35114Identity identity(String cn) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        return Gb35114CertUtil.generateSelfSigned(cn, notBefore, notAfter);
    }

    @Test
    void loopbackBidirectionHandshake() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        platform.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);

        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        // 1. Capability 宣告 → 401 challenge
        String capability = device.initialAuthorization();
        assertTrue(capability.startsWith("Capability algorithm="));
        String www = platform.challenge(DEVICE_ID, capability);
        assertTrue(www.startsWith("Bidirection "));

        // 2. sign1 → SecurityInfo
        String auth = device.authorizeWithChallenge(www);
        assertTrue(auth.startsWith("Bidirection "));
        String securityInfo = platform.verifyRegister(DEVICE_ID, auth);
        assertTrue(securityInfo.startsWith("Bidirection "));

        // 3. 解开 cryptkey + 验 sign2
        device.verifyOk(securityInfo);

        // 4. 双方 VKEK 一致
        assertArrayEquals(platform.vkek(DEVICE_ID), device.vkek());
        assertEquals(16, device.vkek().length);
    }

    @Test
    void loopbackUnidirectionHandshake() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        // 平台无身份 → Unidirection
        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, null);
        platform.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);

        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);

        String www = platform.challenge(DEVICE_ID, device.initialAuthorization());
        assertTrue(www.startsWith("Unidirection "));
        String auth = device.authorizeWithChallenge(www);
        String securityInfo = platform.verifyRegister(DEVICE_ID, auth);
        assertTrue(securityInfo.startsWith("Unidirection "));
        device.verifyOk(securityInfo);
        assertArrayEquals(platform.vkek(DEVICE_ID), device.vkek());
    }

    @Test
    void idempotentRetransmitReturnsSameSecurityInfo() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        platform.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        String www = platform.challenge(DEVICE_ID, device.initialAuthorization());
        String auth = device.authorizeWithChallenge(www);
        String first = platform.verifyRegister(DEVICE_ID, auth);
        String second = platform.verifyRegister(DEVICE_ID, auth);
        assertEquals(first, second);
    }

    @Test
    void staleRandom1Rejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        platform.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        String www1 = platform.challenge(DEVICE_ID, device.initialAuthorization());
        String auth1 = device.authorizeWithChallenge(www1);

        // 新 challenge 覆盖 random1，旧 auth 的回显 random1 失配。
        String www2 = platform.challenge(DEVICE_ID, device.initialAuthorization());
        assertNotEquals(www1, www2);
        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> platform.verifyRegister(DEVICE_ID, auth1));
        assertTrue(e.getMessage().contains("challenge mismatch"));
    }

    @Test
    void unknownDeviceCertRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        // 平台无证书来源（不预置、不设置 certProvider、cnonce 为空）。
        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        String www = platform.challenge(DEVICE_ID, device.initialAuthorization());
        String auth = device.authorizeWithChallenge(www);
        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> platform.verifyRegister(DEVICE_ID, auth));
        assertTrue(e.getMessage().contains("device cert"));
    }

    @Test
    void noteTamperDetection() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114PlatformStateMachine platform =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        platform.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine device = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        String www = platform.challenge(DEVICE_ID, device.initialAuthorization());
        String auth = device.authorizeWithChallenge(www);
        String securityInfo = platform.verifyRegister(DEVICE_ID, auth);
        device.verifyOk(securityInfo);
        byte[] vkek = device.vkek();

        String method = "MESSAGE";
        String from = "<sip:" + DEVICE_ID + "@3402000000>;tag=1";
        String to = "<sip:" + SERVER_ID + "@3402000000>";
        String callId = "abc@192.168.1.50";
        String body = "<Notify><CmdType>Keepalive</CmdType></Notify>";

        String[] dateNote = new Gb35114NoteService().buildNote(method, from, to, callId,
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), vkek);
        String note = dateNote[1];
        String date = dateNote[0];

        // 合法：验签通过
        new Gb35114NoteService().verifyNote(note, method, from, to, callId, date,
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), vkek);

        // 篡改 body：验签失败
        Gb35114Exception e = assertThrows(Gb35114Exception.class, () ->
                new Gb35114NoteService().verifyNote(
                        note, method, from, to, callId, date,
                        (body + "x").getBytes(java.nio.charset.StandardCharsets.UTF_8), vkek));
        assertTrue(e.getMessage().contains("mismatch"));
    }

    @Test
    void noteHeaderBuildParseVerify() throws Exception {
        String method = "MESSAGE";
        String from = "<sip:34020000001320000001@3402000000>;tag=1465468922";
        String to = "<sip:34020000002000000001@3402000000>";
        String callId = "1465470512602@192.168.1.100";
        String date = "2024-01-31T14:40:49.583";
        byte[] vkek = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        String body = "<?xml version=\"1.0\"?>\r\n<Notify>\r\n<CmdType>Keepalive</CmdType>\r\n"
                + "<SN>1</SN>\r\n<DeviceID>34020000001320000001</DeviceID>\r\n"
                + "<Status>OK</Status>\r\n</Notify>\r\n";

        String note = Gb35114HeaderUtil.buildNoteHeader(method, from, to, callId, date, vkek, body);
        assertTrue(note.startsWith("Digest nonce=\""));
        assertTrue(note.endsWith("\",algorithm=SM3"));

        String[] parsed = Gb35114HeaderUtil.parseNoteHeader(note);
        assertEquals("SM3", parsed[1]);
        assertFalse(parsed[0].isEmpty());

        Gb35114HeaderUtil.verifyNoteHeader(note, method, from, to, callId, date, vkek, body);
    }
}
