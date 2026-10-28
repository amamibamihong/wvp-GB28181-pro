package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114SmCrypto;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.Challenge;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.Mode;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.SecurityInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * 设备侧（UAC）GB35114 A 级 REGISTER 状态机，对齐 gb28181-rs 的
 * {@code security35114::authenticator::Authenticator}。用于本平台作为下级
 * 向上级平台注册。
 */
public class Gb35114DeviceStateMachine {

    private static final Logger log = LoggerFactory.getLogger(Gb35114DeviceStateMachine.class);

    private final Gb35114CertUtil.Gb35114Identity deviceIdentity; // 本平台的设备 SM2 身份
    private final X509Certificate platformCert;                   // 上级平台签名证书（验 sign2）
    private final String deviceId;
    private final String serverId;
    private final String keyVersion;

    private Mode mode;
    private String random1;
    private String random2;
    private byte[] vkek;

    /**
     * 上级平台证书的最后一道校验（链校验，可为空；为空表示不校验）。
     *
     * <p>由 {@code Gb35114SecurityService#uacStateMachine} 按
     * {@code gb35114.verify-upstream-cert-chain} 决定是否注入 —— 状态机本身不读配置，
     * 也不碰数据库，与 UAS 侧用 {@code certValidator} 注入吊销/过期判定的做法一致。
     */
    private java.util.function.Function<X509Certificate, X509Certificate> platformCertValidator;

    public void setPlatformCertValidator(
            java.util.function.Function<X509Certificate, X509Certificate> platformCertValidator) {
        this.platformCertValidator = platformCertValidator;
    }

    public Gb35114DeviceStateMachine(Gb35114CertUtil.Gb35114Identity deviceIdentity,
                                     X509Certificate platformCert,
                                     String deviceId, String serverId, String keyVersion) {
        if (deviceId == null || deviceId.isEmpty() || serverId == null || serverId.isEmpty()) {
            throw new Gb35114Exception("device_id and server_id are required");
        }
        this.deviceIdentity = deviceIdentity;
        this.platformCert = platformCert;
        this.deviceId = deviceId;
        this.serverId = serverId;
        this.keyVersion = keyVersion != null ? keyVersion
                : Gb35114HeaderUtil.buildDate(Instant.now());
    }

    /** 首包 REGISTER 的 Capability 宣告头。 */
    public String initialAuthorization() {
        return Gb35114HeaderUtil.buildCapabilityAuthorization(keyVersion, "");
    }

    /** 已协商的方案（收到挑战前为 {@code null}）。 */
    public Mode mode() {
        return mode;
    }

    /** 协商出的 VKEK，握手完成前为 {@code null}。 */
    public byte[] vkek() {
        return vkek;
    }

    /**
     * 响应 401 挑战：抽取 random2、签名，返回重发 REGISTER 的 Authorization 头。
     */
    public String authorizeWithChallenge(String wwwAuthenticate) {
        Challenge ch = Gb35114HeaderUtil.parseChallenge(wwwAuthenticate);
        String r2 = Gb35114SmCrypto.randomB64(16);
        byte[] payload = Gb35114HeaderUtil.signAuthPayload(ch.random1, r2, serverId);
        String sign1;
        try {
            sign1 = Gb35114SmCrypto.sign(deviceIdentity.privateKey, payload);
        } catch (Exception e) {
            throw new Gb35114Exception("security35114: signing challenge", e);
        }
        this.mode = ch.mode;
        this.random1 = ch.random1;
        this.random2 = r2;
        return Gb35114HeaderUtil.buildAuthAuthorization(ch, r2, serverId, deviceId, sign1);
    }

    /**
     * 校验 200 OK 的 SecurityInfo：解开 cryptkey 得 VKEK，Bidirection 时验 sign2。
     */
    public void verifyOk(String securityInfo) {
        if (mode == null) {
            throw new Gb35114Exception("SecurityInfo received before a challenge was answered");
        }
        SecurityInfo si = Gb35114HeaderUtil.parseSecurityInfo(securityInfo);
        byte[] v;
        try {
            v = Gb35114SmCrypto.decryptVkek(deviceIdentity.privateKey, si.cryptKey);
        } catch (Exception e) {
            throw new Gb35114Exception("security35114: opening cryptkey", e);
        }
        if (si.mode == Mode.Bidirection) {
            if (platformCert == null) {
                throw new Gb35114Exception("Bidirection requires platform_cert to verify sign2");
            }
            // 链校验（可选，由配置决定是否注入）放在验签之前：链不成立时，后面的
            // sign2 验签即使过了也只说明「这把公钥签的」，而公钥本身的归属尚未确认。
            if (platformCertValidator != null) {
                platformCertValidator.apply(platformCert);
            }
            if (!si.random1.equals(random1) || !si.random2.equals(random2)
                    || !si.deviceId.equals(deviceId)) {
                throw new Gb35114Exception("SecurityInfo handshake fields do not match this handshake");
            }
            // serverid 允许缺失：部分平台（如 LiveGBS）在 200 OK 里不回它。它不携带新信息
            // ——本次 REGISTER 的目的地已唯一确定平台编码，缺省即「就是它」；对端回了则必须一致。
            if (!si.serverId.isEmpty() && !si.serverId.equals(serverId)) {
                throw new Gb35114Exception("SecurityInfo serverid does not match this handshake");
            }
            byte[] payload = Gb35114HeaderUtil.sign2Payload(si.random1, si.random2, si.deviceId, si.cryptKey);
            try {
                Gb35114SmCrypto.verify(platformCert.getPublicKey(), payload, si.sign2);
            } catch (Exception e) {
                throw new Gb35114Exception("security35114: verifying sign2", e);
            }
        }
        this.vkek = v;
    }

    /** 本平台的设备 ID（UAC 角色下即向上级注册的编码）。 */
    public String deviceId() {
        return deviceId;
    }

    /** 上级平台 ID。 */
    public String serverId() {
        return serverId;
    }
}
