package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UAC 侧「上级平台证书链校验」这一钩子的行为。
 *
 * <p>{@code Gb35114DeviceStateMachine} 是纯协议内核，不读配置也不碰数据库；
 * 链校验由 {@code Gb35114SecurityService} 按
 * {@code gb35114.verify-upstream-cert-chain} 决定是否注入 —— 与 UAS 侧用
 * {@code certValidator} 注入吊销/过期判定的做法一致。本类钉住这条边界：
 * <b>不注入即不校验</b>（默认零影响），注入后失败必须让握手失败且不落 VKEK。
 */
class Gb35114UacChainHookTest {

    private static final String SERVER_ID = "35020000003000000001";
    private static final String DEVICE_ID = "35020000002000000001";

    private static Gb35114CertUtil.Gb35114Identity identity(String cn) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        return Gb35114CertUtil.generateSelfSigned(cn, notBefore, notAfter);
    }

    /** 走完一次 C.3 往返，返回 UAC 侧状态机（已 verifyOk）。 */
    private static Gb35114DeviceStateMachine roundTrip(
            Gb35114CertUtil.Gb35114Identity deviceIdentity,
            Gb35114CertUtil.Gb35114Identity platformIdentity) {
        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        String securityInfo = upstream.verifyRegister(DEVICE_ID, auth);
        local.verifyOk(securityInfo);
        return local;
    }

    /**
     * 未注入 validator（= 配置关）→ 不校验，握手照常完成。
     *
     * <p>这是默认部署的行为，必须零影响。
     */
    @Test
    void withoutValidatorHandshakeSucceeds() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");

        Gb35114DeviceStateMachine local = roundTrip(deviceIdentity, platformIdentity);

        assertNotNull(local.vkek(), "未注入链校验时握手必须照常完成");
        assertEquals(16, local.vkek().length);
    }

    /** 注入且放行 → 握手完成，VKEK 正常协商。 */
    @Test
    void validatorAllowingLetsHandshakeThrough() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");

        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);

        AtomicInteger calls = new AtomicInteger();
        local.setPlatformCertValidator(cert -> {
            calls.incrementAndGet();
            return cert;
        });

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        local.verifyOk(upstream.verifyRegister(DEVICE_ID, auth));

        assertEquals(1, calls.get(), "validator 应被调用一次");
        assertNotNull(local.vkek());
    }

    /**
     * 注入且拒绝 → 抛 {@code Gb35114Exception}，且 VKEK 不落。
     *
     * <p>{@code RegisterResponseProcessor} 会捕获该异常并记 warn，本次注册不建立 ——
     * 这正是「链不成立时不能把 VKEK 装进缓存」的保障。
     */
    @Test
    void validatorRejectingFailsHandshakeWithoutVkek() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");

        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        local.setPlatformCertValidator(cert -> {
            throw new Gb35114Exception("上级证书是自签根证书，「CA 证书管理 · 受信任的 CA 证书」里没有与它同公钥的证书");
        });

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        String securityInfo = upstream.verifyRegister(DEVICE_ID, auth);

        Gb35114Exception e = assertThrows(Gb35114Exception.class, () -> local.verifyOk(securityInfo));
        assertTrue(e.getMessage().contains("受信任的 CA"), "实际: " + e.getMessage());
        assertNull(local.vkek(), "校验失败时不得协商出 VKEK");
    }

    /**
     * 单向认证不涉及上级证书 → validator 不被调用。
     *
     * <p>单向只证明设备身份，平台不向设备证明自己，因此没有「上级证书」可校验。
     */
    @Test
    void unidirectionNeverInvokesValidator() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");

        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, null);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, null, DEVICE_ID, SERVER_ID, null);

        AtomicInteger calls = new AtomicInteger();
        local.setPlatformCertValidator(cert -> {
            calls.incrementAndGet();
            return cert;
        });

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        local.verifyOk(upstream.verifyRegister(DEVICE_ID, auth));

        assertEquals(0, calls.get(), "单向认证没有上级证书可校验");
        assertNotNull(local.vkek(), "单向握手仍应协商出 VKEK");
    }

    /**
     * 链校验先于 sign2 验签：链不成立时不应进入验签分支。
     *
     * <p>顺序上先确认「这把公钥的归属」，再谈「这个签名对不对」——
     * 反过来的话，一张公钥归属未确认的证书只要签名自洽就能通过验签这一步。
     */
    @Test
    void chainCheckRunsBeforeSign2Verification() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        Gb35114CertUtil.Gb35114Identity otherPlatform = identity("other-platform");

        // 上级实际用 platformIdentity 签 sign2，但本平台配置的是 otherPlatform 的证书
        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, otherPlatform.certificate, DEVICE_ID, SERVER_ID, null);

        AtomicInteger chainCalls = new AtomicInteger();
        local.setPlatformCertValidator(cert -> {
            chainCalls.incrementAndGet();
            throw new Gb35114Exception("链校验不通过");
        });

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        String securityInfo = upstream.verifyRegister(DEVICE_ID, auth);

        Gb35114Exception e = assertThrows(Gb35114Exception.class, () -> local.verifyOk(securityInfo));
        assertEquals(1, chainCalls.get(), "链校验必须被调用");
        assertTrue(e.getMessage().contains("链校验不通过"),
                "应报链校验的原因，而不是 sign2 验签失败 —— 实际: " + e.getMessage());
    }

    /** setter 接受 null：等价于关闭校验，不应抛 NPE。 */
    @Test
    void nullValidatorDisablesCheck() throws Exception {
        Gb35114CertUtil.Gb35114Identity deviceIdentity = identity("device");
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");

        Gb35114PlatformStateMachine upstream =
                new Gb35114PlatformStateMachine(SERVER_ID, platformIdentity);
        upstream.provisionDeviceCert(DEVICE_ID, deviceIdentity.certificate);
        Gb35114DeviceStateMachine local = new Gb35114DeviceStateMachine(
                deviceIdentity, platformIdentity.certificate, DEVICE_ID, SERVER_ID, null);
        local.setPlatformCertValidator(null);

        String www = upstream.challenge(DEVICE_ID, local.initialAuthorization());
        String auth = local.authorizeWithChallenge(www);
        local.verifyOk(upstream.verifyRegister(DEVICE_ID, auth));

        assertNotNull(local.vkek());
    }

    /** 编译器提示：X509Certificate 在签名里被用到（保持 import 有意义）。 */
    @Test
    void validatorSignatureUsesX509Certificate() throws Exception {
        Gb35114CertUtil.Gb35114Identity platformIdentity = identity("platform");
        java.util.function.Function<X509Certificate, X509Certificate> f = c -> c;
        assertSame(platformIdentity.certificate, f.apply(platformIdentity.certificate));
    }
}
