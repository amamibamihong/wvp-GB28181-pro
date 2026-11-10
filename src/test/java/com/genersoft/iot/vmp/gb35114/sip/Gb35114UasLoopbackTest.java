package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 本平台作为<b>上级平台（UAS）</b>受理国密注册的链路测试。
 *
 * <p>与 {@link Gb35114StateMachineTest} 的分工：那个类通过
 * {@link Gb35114PlatformStateMachine#provisionDeviceCert} <b>预置</b>设备证书，
 * 验证的是状态机内核的密码学正确性。但生产路径<b>不走预置</b>——
 * {@code Gb35114SecurityService#platformStateMachine} 注入的是
 * {@code certProvider}（查证书库）与 {@code certValidator}（吊销/过期校验），
 * 另有 Capability 首包自报证书（{@code cnonce}）这条独立入口。
 * 本类覆盖这三条生产路径——它们此前零测试覆盖。
 */
class Gb35114UasLoopbackTest {

    private static final String SERVER_ID = "35020000002000000001"; // 本平台（作为上级）编码
    private static final String DEVICE_ID = "35020000001320000001"; // 下级设备编码

    private static Gb35114CertUtil.Gb35114Identity identity(String cn) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        return Gb35114CertUtil.generateSelfSigned(cn, notBefore, notAfter);
    }

    /** 已过期但结构合法的证书：用于验证过期策略确实由 certValidator 表达。 */
    private static Gb35114CertUtil.Gb35114Identity expiredIdentity(String cn) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 400L * 24 * 3600 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() - 30L * 24 * 3600 * 1000);
        return Gb35114CertUtil.generateSelfSigned(cn, notBefore, notAfter);
    }

    /** 走完一次完整注册往返，返回 UAS 侧的 SecurityInfo。 */
    private static String handshake(Gb35114PlatformStateMachine uas,
                                    Gb35114CertUtil.Gb35114Identity deviceIdentity,
                                    X509Certificate platformCert) {
        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, platformCert, DEVICE_ID, SERVER_ID, null);
        String www = uas.challenge(DEVICE_ID, uac.initialAuthorization());
        return uas.verifyRegister(DEVICE_ID, uac.authorizeWithChallenge(www));
    }

    /**
     * 生产路径①：设备证书来自 {@code certProvider}（数据库查询），非预置。
     *
     * <p>这是设备正常注册时真正走的分支。{@code provisionedCerts} 为空，
     * 证书必须由 provider 提供，否则注册会被拒。
     */
    @Test
    void deviceCertResolvedFromProvider() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        // 刻意不调用 provisionDeviceCert —— 只配 provider，复现生产装配
        uas.setCertProvider(deviceId -> DEVICE_ID.equals(deviceId)
                ? deviceIdentity.certificate : null);

        String securityInfo = handshake(uas, deviceIdentity, platformIdentity.certificate);
        assertTrue(securityInfo.startsWith("Bidirection "), "实际: " + securityInfo);

        byte[] vkek = uas.vkek(DEVICE_ID);
        assertNotNull(vkek, "provider 提供证书后必须协商出 VKEK");
        assertEquals(16, vkek.length);
    }

    /**
     * 生产路径②：provider 查不到证书（本平台从未签发）→ 必须拒绝，且错误信息可行动。
     */
    @Test
    void deviceCertAbsentFromProviderIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> null); // 库中无该设备证书
        uas.setCertUnavailableReason(deviceId -> "本平台未给该设备签发过客户端证书");

        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        String www = uas.challenge(DEVICE_ID, uac.initialAuthorization());
        String auth = uac.authorizeWithChallenge(www);

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> uas.verifyRegister(DEVICE_ID, auth));
        assertTrue(e.getMessage().contains("device cert"),
                "错误应指向设备证书，实际: " + e.getMessage());
        assertTrue(e.getMessage().contains("未给该设备签发过"),
                "应给出可行动的原因说明，实际: " + e.getMessage());
    }

    /**
     * 生产路径③：Capability 首包自报证书（{@code cnonce=devicecert:...}）。
     *
     * <p>设备在首包携带自己的证书，平台解析后存入 session。此路径下即便 provider
     * 返回 null，也应能用自报证书验签——这是标准允许的设备侧能力。
     */
    @Test
    void announcedCertFromCapabilityIsAccepted() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> null); // provider 不提供，只能靠自报

        // 构造带 cnonce 的 Capability 首包
        String certPem = pemOf(deviceIdentity.certificate);
        String capability = Gb35114HeaderUtil.buildCapabilityAuthorization(
                Gb35114HeaderUtil.buildDate(java.time.Instant.now()), certPem);
        assertTrue(capability.contains("cnonce=\"devicecert:"),
                "Capability 应携带自报证书，实际: " + capability);

        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        String www = uas.challenge(DEVICE_ID, capability);
        String auth = uac.authorizeWithChallenge(www);

        String securityInfo = uas.verifyRegister(DEVICE_ID, auth);
        assertTrue(securityInfo.startsWith("Bidirection "),
                "自报证书路径应能完成握手，实际: " + securityInfo);
        assertNotNull(uas.vkek(DEVICE_ID));
    }

    /**
     * 生产路径④：{@code certValidator} 是吊销/过期的唯一执行点。
     *
     * <p>provider 返回证书后仍要过 validator。这里模拟「已吊销」：validator 抛异常，
     * 注册必须被拒——否则持一张已吊销的旧证书自报即可重新接入。
     */
    @Test
    void certValidatorRejectionBlocksRegistration() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> deviceIdentity.certificate);
        uas.setCertValidator((deviceId, cert) -> {
            throw new Gb35114Exception("证书 #9 已吊销，不能用于设备接入");
        });

        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        String www = uas.challenge(DEVICE_ID, uac.initialAuthorization());
        String auth = uac.authorizeWithChallenge(www);

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> uas.verifyRegister(DEVICE_ID, auth));
        assertTrue(e.getMessage().contains("已吊销"), "实际: " + e.getMessage());
    }

    /**
     * 过期证书：validator 放行时应能注册成功（对应默认策略「过期只提示不拦截」）。
     *
     * <p>过期是否拦截是运维策略而非协议要求，由 validator 表达；状态机本身不应
     * 内置任何过期判断。这里验证状态机不自行拦截。
     */
    @Test
    void expiredCertPassesWhenValidatorAllows() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity expiredDevice = expiredIdentity("expired-device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> expiredDevice.certificate);
        // 默认策略：放行（真实实现里会 log.warn 后返回原证书）
        uas.setCertValidator((deviceId, cert) -> cert);

        String securityInfo = handshake(uas, expiredDevice, platformIdentity.certificate);
        assertTrue(securityInfo.startsWith("Bidirection "),
                "validator 放行时过期证书应能完成握手，实际: " + securityInfo);
    }

    /**
     * 未知设备自报证书且 provider 也查不到 → 错误信息应能区分
     * 「从未签发过」与「签发过但已吊销/过期」。
     */
    @Test
    void unknownAnnouncedCertGivesActionableReason() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity rogueIdentity = identity("rogue-device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> null);
        uas.setCertValidator((deviceId, cert) -> {
            throw new Gb35114Exception("证书 #9 已吊销");
        });

        String capability = Gb35114HeaderUtil.buildCapabilityAuthorization(
                Gb35114HeaderUtil.buildDate(java.time.Instant.now()),
                pemOf(rogueIdentity.certificate));
        String www = uas.challenge(DEVICE_ID, capability);

        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                rogueIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        String auth = uac.authorizeWithChallenge(www);

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> uas.verifyRegister(DEVICE_ID, auth));
        assertTrue(e.getMessage().contains("已吊销"),
                "应把 validator 的具体原因透出，而非笼统的 device cert，实际: " + e.getMessage());
    }

    /** 单向认证（上级无平台身份）在 provider 路径下同样成立。 */
    @Test
    void unidirectionViaProvider() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, null); // 无平台身份 → Unidirection
        uas.setCertProvider(deviceId -> deviceIdentity.certificate);

        assertEquals(Gb35114HeaderUtil.Mode.Unidirection, uas.mode());

        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);
        String www = uas.challenge(DEVICE_ID, uac.initialAuthorization());
        assertTrue(www.startsWith("Unidirection "), "实际: " + www);

        String securityInfo = uas.verifyRegister(DEVICE_ID, uac.authorizeWithChallenge(www));
        assertTrue(securityInfo.startsWith("Unidirection "), "实际: " + securityInfo);
        assertNotNull(uas.vkek(DEVICE_ID));
    }

    /**
     * <b>本次改动的核心场景</b>：平台<b>有</b>签名身份，但按设备配置回单向挑战。
     *
     * <p>GB 35114—2017 6.4.2 要求平台对设备「进行单向设备身份认证<b>或者</b>双向设备身份认证」，
     * 43026 表 A.1 序号 6、7 是并列的必测项。改动前 mode 只由「平台有无签名身份」决定，
     * 而正常部署必有服务端证书 → 恒回 Bidirection → 单向流程不可达、C.2.1 做不出来。
     *
     * <p>本用例固定住新语义：<b>身份齐备的平台也能发 Unidirection</b>，
     * 且此时 200 OK 不带 sign2（单向只证明设备身份，平台不向设备证明自己）。
     */
    @Test
    void platformWithIdentityCanStillChallengeUnidirection() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        // 平台身份齐备 —— 旧逻辑下这里必然回 Bidirection
        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        uas.setCertProvider(deviceId -> deviceIdentity.certificate);
        assertEquals(Gb35114HeaderUtil.Mode.Bidirection, uas.mode(),
                "平台默认方案仍是 Bidirection");

        // 设备配置为单向（register_way=4）→ 调用方显式要求 Unidirection
        String www = uas.challenge(DEVICE_ID, uacCapability(deviceIdentity),
                Gb35114HeaderUtil.Mode.Unidirection);
        assertTrue(www.startsWith("Unidirection "),
                "身份齐备的平台也必须能发单向挑战，实际: " + www);

        // 设备按单向应答（平台证书可为 null —— 单向不需要验 sign2）
        Gb35114DeviceStateMachine uac = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);
        String auth = uac.authorizeWithChallenge(www);
        assertTrue(auth.startsWith("Unidirection "), "实际: " + auth);

        String securityInfo = uas.verifyRegister(DEVICE_ID, auth);
        assertTrue(securityInfo.startsWith("Unidirection "), "实际: " + securityInfo);
        assertFalse(securityInfo.contains("sign2="),
                "单向认证的 SecurityInfo 不应含 sign2，实际: " + securityInfo);

        uac.verifyOk(securityInfo);
        assertNotNull(uac.vkek(), "单向也应协商出 VKEK");
        assertArrayEquals(uas.vkek(DEVICE_ID), uac.vkek(), "双方 VKEK 必须一致");
    }

    /**
     * 反向保护：设备配置为双向、但平台没有签名身份时，必须<b>明确失败</b>，
     * 而不是发出一个做不完的 Bidirection 挑战（那会在 verifyRegister 才炸，
     * 错误信息指向设备证书，让人误判方向）。
     */
    @Test
    void bidirectionWithoutPlatformIdentityFailsFast() throws Exception {
        Gb35114PlatformStateMachine uas =
                new Gb35114PlatformStateMachine(SERVER_ID, null); // 无签名身份

        Gb35114Exception e = assertThrows(Gb35114Exception.class,
                () -> uas.challenge(DEVICE_ID, null, Gb35114HeaderUtil.Mode.Bidirection),
                "无签名身份时不应发出双向挑战");
        assertTrue(e.getMessage().contains("Bidirection requires a platform identity"),
                "实际: " + e.getMessage());
    }

    /** 构造带设备证书的 Capability 首包。 */
    private static String uacCapability(Gb35114CertUtil.Gb35114Identity deviceIdentity) throws Exception {
        return Gb35114HeaderUtil.buildCapabilityAuthorization(
                Gb35114HeaderUtil.buildDate(java.time.Instant.now()),
                pemOf(deviceIdentity.certificate));
    }

    private static String pemOf(X509Certificate cert) throws Exception {
        String b64 = java.util.Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }
}
