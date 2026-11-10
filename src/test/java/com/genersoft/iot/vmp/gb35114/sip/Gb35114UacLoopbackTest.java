package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 本平台作为<b>下级平台（UAC）</b>向国密上级注册的链路测试。
 *
 * <p>与 {@link Gb35114StateMachineTest} 的分工：那个类验证状态机<b>内核</b>
 * （直接调用 {@code challenge} / {@code authorizeWithChallenge} / {@code verifyRegister}）；
 * 本类验证<b>外壳</b>——即 SIP 命令层与响应处理层实际拿到的
 * <b>header 字符串</b>能否正确往返，以及协商出的 VKEK 是否真正落入
 * {@link Gb35114VkekCache}（出站 Note 加签的唯一数据来源）。
 *
 * <p>之所以单独覆盖这一层：2026-09 现场级联国密握手未建立，
 * 根因就落在外壳（401 的 scheme 判定与 VKEK 落缓存），而当时的内核测试全绿。
 */
class Gb35114UacLoopbackTest {

    private static final String SERVER_ID = "35020000003000000001"; // 上级平台编码
    private static final String DEVICE_ID = "35020000002000000001"; // 本平台（作为下级）编码

    private static Gb35114CertUtil.Gb35114Identity identity(String cn) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        return Gb35114CertUtil.generateSelfSigned(cn, notBefore, notAfter);
    }

    /**
     * 完整 C.3 往返：Capability → Bidirection 401 → sign1 → SecurityInfo → VKEK 落缓存。
     *
     * <p>模拟 {@code RegisterResponseProcessor} 在 200 分支所做的两件事：
     * 校验 SecurityInfo、把 VKEK 写入缓存（按<b>上级平台编码</b>索引）。
     * 随后验证出站加签能按该索引取到 VKEK——这正是现场缺失的那一环。
     */
    @Test
    void uacHandshakeCachesVkekUnderPlatformId() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        // 上级：作为 UAS，用本平台的设备证书验 sign1
        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);

        // 本平台：作为 UAC
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        // ① 首包：Capability 宣告
        String capability = local.initialAuthorization();
        assertTrue(capability.startsWith("Capability algorithm="),
                "首包必须是 Capability 宣告，实际: " + capability);
        assertTrue(capability.contains("A:SM2") && capability.contains("H:SM3")
                        && capability.contains("SI:SM3-SM2"),
                "Capability 必须宣告 SM2/SM3/SM3-SM2，实际: " + capability);

        // ② 上级 401：WWW-Authenticate 必须是 Bidirection
        String www = upstream.challenge(DEVICE_ID, capability);
        assertTrue(www.startsWith("Bidirection "),
                "上级应回 Bidirection 挑战，实际: " + www);

        // SIP 层的实际数据流：header 字符串 → 解析出 scheme。
        // 这是 SIPCommanderForPlatform 判定走国密分支还是 Digest 分支的依据。
        assertEquals("Bidirection", Gb35114SipHeaders.schemeOf(www),
                "scheme 必须能被解析为 Bidirection，否则会落入 Digest 降级分支");

        // ③ 本平台应答：Authorization 必须是 Bidirection 且含 sign1
        String authorization = local.authorizeWithChallenge(www);
        assertTrue(authorization.startsWith("Bidirection "),
                "应答必须是 Bidirection，实际: " + authorization);
        assertTrue(authorization.contains("sign1=\"") && authorization.contains("random2=\""),
                "应答必须含 sign1 与 random2");
        assertEquals("Bidirection", Gb35114SipHeaders.schemeOf(authorization));
        assertEquals(Gb35114HeaderUtil.Mode.Bidirection, local.mode(),
                "mode 必须被设置为 Bidirection（否则 verifyOk 会抛异常）");

        // ④ 上级 200：SecurityInfo
        String securityInfo = upstream.verifyRegister(DEVICE_ID, authorization);
        assertTrue(securityInfo.startsWith("Bidirection "),
                "SecurityInfo 必须携带 Bidirection，实际: " + securityInfo);

        // ⑤ 本平台处理 200：校验 SecurityInfo 并落 VKEK（复现 RegisterResponseProcessor 的逻辑）
        local.verifyOk(securityInfo);
        assertNotNull(local.vkek(), "verifyOk 后必须解出 VKEK");

        Gb35114VkekCache cache = new Gb35114VkekCache();
        cache.put(SERVER_ID, local.vkek());

        // ⑥ 关键断言：出站加签按「上级平台编码」能取到 VKEK
        byte[] cached = cache.get(SERVER_ID);
        assertNotNull(cached, "必须能按上级平台编码取到 VKEK——这是出站加签的前提");
        assertArrayEquals(local.vkek(), cached);
        assertArrayEquals(upstream.vkek(DEVICE_ID), cached,
                "本平台与上级协商出的 VKEK 必须一致");
        assertEquals(16, cached.length, "VKEK 应为 16 字节");
    }

    /**
     * 反向：401 的 scheme 是 Digest（非国密）时，{@code parseChallenge} 必须拒绝，
     * 而不是解析出一个 mode 为空/错误的 Challenge 继续往下走。
     *
     * <p>现场上级回的就是 Digest，若此处不拒绝，会掩盖「国密未生效」的事实。
     */
    @Test
    void digestChallengeIsNotParsedAsGb35114() throws Exception {
        String digestWww = "Digest realm=\"3502000000\",qop=\"auth\","
                + "nonce=\"86534178c243b693cc3edfbe6c8c8f6d\"";

        assertEquals("Digest", Gb35114SipHeaders.schemeOf(digestWww),
                "Digest 挑战的 scheme 必须是 Digest——SIPCommanderForPlatform 依此判定不走国密分支");

        // 走国密解析路径必须失败（Digest 不是 GB35114 的 scheme），
        // 不能静默产出一个半成品 Challenge
        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> Gb35114HeaderUtil.parseChallenge(digestWww),
                "Digest 挑战不是国密挑战，解析必须抛异常");
        assertTrue(e.getMessage().contains("not a GB35114 header"),
                "异常信息应说明不是国密头，实际: " + e.getMessage());
    }

    /**
     * 未完成握手时 VKEK 缺失，缓存查询应返回 null（对应出站加签的「未找到 VKEK」分支）。
     */
    @Test
    void vkekCacheReturnsNullBeforeHandshake() {
        Gb35114VkekCache cache = new Gb35114VkekCache();
        assertNull(cache.get(SERVER_ID), "未协商时应返回 null");
        assertFalse(cache.contains(SERVER_ID));
    }

    /**
     * 单向认证（registerWay=4）路径同样应能协商出 VKEK。
     */
    @Test
    void uacUnidirectionHandshakeCachesVkek() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        // 上级无平台身份 → 回 Unidirection
        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, null);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);

        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        assertTrue(www.startsWith("Unidirection "), "实际: " + www);
        assertEquals("Unidirection", Gb35114SipHeaders.schemeOf(www));

        String authorization = local.authorizeWithChallenge(www);
        String securityInfo = upstream.verifyRegister(DEVICE_ID, authorization);
        local.verifyOk(securityInfo);

        Gb35114VkekCache cache = new Gb35114VkekCache();
        cache.put(SERVER_ID, local.vkek());
        assertNotNull(cache.get(SERVER_ID));
        assertArrayEquals(upstream.vkek(DEVICE_ID), cache.get(SERVER_ID));
    }

    /**
     * 首包必须能被上级解析出 algorithm（用于协商），且 keyversion 非空时原样回显。
     */
    @Test
    void capabilityRoundTripsThroughParser() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);

        String capability = local.initialAuthorization();
        Gb35114HeaderUtil.CapabilityAnnouncement ann =
                Gb35114HeaderUtil.parseCapabilityAuthorization(capability);

        assertEquals(Gb35114HeaderUtil.CAPABILITY_ALGORITHM, ann.algorithm,
                "解析出的 algorithm 应与常量一致");
        assertNotNull(ann.keyVersion);
        assertFalse(ann.keyVersion.isEmpty(), "keyversion 不应为空");
    }
}
