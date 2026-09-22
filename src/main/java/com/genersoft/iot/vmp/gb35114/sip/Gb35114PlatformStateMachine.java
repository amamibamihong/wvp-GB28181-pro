package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114SmCrypto;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.AuthAuthorization;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.Challenge;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.Mode;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil.SecurityInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 平台侧（UAS）GB35114 A 级 REGISTER 状态机，对齐 gb28181-rs 的
 * {@code security35114::platform::Platform}。
 *
 * <pre>
 * REGISTER  (Authorization: Capability …)          device → platform
 * 401       (WWW-Authenticate: … random1="…")      platform → device   challenge
 * REGISTER  (Authorization: Unidirection/Bidirection … sign1="…")
 * 200 OK    (SecurityInfo: cryptkey [, sign2])     platform → device   verifyRegister
 * </pre>
 *
 * <p>并发安全：会话按设备 ID 索引。设备重注册期间旧 VKEK 继续可验；
 * 对 SIP-over-UDP 重传的已完成 REGISTER 幂等返回同一 SecurityInfo。
 */
public class Gb35114PlatformStateMachine {

    private static final Logger log = LoggerFactory.getLogger(Gb35114PlatformStateMachine.class);

    /** 平台侧会话。 */
    private static final class Session {
        Mode mode;
        String random1;
        X509Certificate announcedCert;
        byte[] vkek;
        String lastAuth;
        String lastSecurityInfo;
        /** 由本次 Capability 协商出的算法串，200 OK 的 SecurityInfo 必须与之一致。 */
        String negotiatedAlgorithm;
    }

    private final String serverId;
    private final Gb35114CertUtil.Gb35114Identity identity; // 平台 SM2 签名身份（Bidirection 用）
    private final Mode mode; // 固定方案（identity 存在则为 Bidirection，否则 Unidirection）
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, X509Certificate> provisionedCerts = new ConcurrentHashMap<>();

    /** 动态设备证书来源（如数据库），provisionedCerts 未命中时兜底。 */
    private Function<String, X509Certificate> certProvider;

    /**
     * 选定设备证书后的最后一道校验（可空）。
     *
     * <p>设备会在 Capability 的 cnonce 里自报证书，这条路径不过数据库，因此
     * 「已吊销 / 已过期」必须在这里补校验 —— 否则一台被吊销的摄像头只要自报旧证书
     * 就能重新接入，吊销形同虚设。实现方返回校验通过的证书，不通过则抛异常。
     */
    private java.util.function.BiFunction<String, X509Certificate, X509Certificate> certValidator;

    public Gb35114PlatformStateMachine(String serverId, Gb35114CertUtil.Gb35114Identity identity) {
        if (serverId == null || serverId.isEmpty()) {
            throw new Gb35114Exception("server_id is required");
        }
        this.serverId = serverId;
        this.identity = identity;
        this.mode = identity != null ? Mode.Bidirection : Mode.Unidirection;
    }

    public String serverId() {
        return serverId;
    }

    public Mode mode() {
        return mode;
    }

    /** 预置一台设备的受信证书。 */
    public void provisionDeviceCert(String deviceId, X509Certificate cert) {
        provisionedCerts.put(deviceId, cert);
    }

    /** 设置动态证书来源（如从证书管理服务查询）。 */
    public void setCertProvider(Function<String, X509Certificate> provider) {
        this.certProvider = provider;
    }

    /**
     * 说明某设备为何取不到受信证书（供日志给出可行动的原因）。
     * 与 {@link #certProvider} 同源，由 {@link com.genersoft.iot.vmp.gb35114.sip.Gb35114SecurityService} 注入。
     */
    private Function<String, String> certUnavailableReason;

    /** 设置「取不到设备证书」的原因说明器。 */
    public void setCertUnavailableReason(Function<String, String> reason) {
        this.certUnavailableReason = reason;
    }

    /** 设置设备证书的最后一道校验（吊销 / 过期），对所有来源的证书生效。 */
    public void setCertValidator(
            java.util.function.BiFunction<String, X509Certificate, X509Certificate> validator) {
        this.certValidator = validator;
    }

    /** 取不到设备证书时的可行动错误（区分「没签发过」与「已吊销/过期」）。 */
    private String deviceCertError(String deviceId) {
        if (certUnavailableReason != null) {
            try {
                String why = certUnavailableReason.apply(deviceId);
                if (why != null && !why.isEmpty()) {
                    return "security35114: device cert (" + why + ")";
                }
            } catch (Exception ignored) {
                // 诊断失败不影响拒绝本身
            }
        }
        return "security35114: device cert (本平台未给该设备签发过客户端证书)";
    }

    /**
     * 为「设备自报了证书但取不到受信证书」生成可区分的原因描述。
     *
     * <p>走 {@link #certValidator} 同一来源（证书服务）的只读查询，不改变校验语义，
     * 只为把日志从含糊的 "device cert" 变成运维能直接行动的信息。
     */
    private String describeRejectedDeviceCert(String deviceId, X509Certificate announced) {
        try {
            // 校验器对「已吊销/已过期」会抛异常，异常消息即为准确原因；
            // 不抛则说明证书本身可接入，问题在于它不属于该设备（deviceId 不匹配）。
            if (certValidator != null) {
                certValidator.apply(deviceId, announced);
            }
            return "security35114: device cert (证书有效，但与本平台签发给 " + deviceId + " 的证书不匹配)";
        } catch (Exception e) {
            return "security35114: device cert (" + e.getMessage() + ")";
        }
    }

    /**
     * 记录 Capability 宣告（解析可选的 cnonce 设备证书），并为该设备生成
     * random1 挑战，返回 401 的完整 WWW-Authenticate 头值。
     */
    public String challenge(String deviceId, String capabilityAuthorization) {
        String random1 = Gb35114SmCrypto.randomB64(16);

        X509Certificate announcedCert = null;
        String announcedAlgorithm = null;
        if (capabilityAuthorization != null && !capabilityAuthorization.isEmpty()) {
            try {
                Gb35114HeaderUtil.CapabilityAnnouncement ann =
                        Gb35114HeaderUtil.parseCapabilityAuthorization(capabilityAuthorization);
                announcedAlgorithm = ann.algorithm;
                if (!ann.deviceCertPem.isEmpty()) {
                    announcedCert = Gb35114CertUtil.loadCertificate(ann.deviceCertPem);
                }
            } catch (Exception e) {
                log.warn("[GB35114] 解析 Capability 宣告失败，忽略 cnonce 证书: {}", e.getMessage());
            }
        }

        Session session = sessions.computeIfAbsent(deviceId, k -> new Session());
        String negotiated = Gb35114HeaderUtil.negotiateAlgorithm(announcedAlgorithm);
        synchronized (session) {
            session.mode = mode;
            session.random1 = random1;
            session.lastAuth = null;
            session.lastSecurityInfo = null;
            session.negotiatedAlgorithm = negotiated;
            if (announcedCert != null) {
                session.announcedCert = announcedCert;
            }
        }
        // 挑战里的 algorithm 必须是「从设备上报能力中选出的」结果（标准 §C.3 b)），
        // 只回内置的 A:SM2;H:SM3 会让协商结果与设备预期不符。
        return Gb35114HeaderUtil.buildChallenge(mode, random1, announcedAlgorithm);
    }

    /**
     * 校验重发 REGISTER 的 Authorization，协商 VKEK 并封到设备公钥（cryptkey），
     * Bidirection 时签名 sign2，返回 200 OK 的完整 SecurityInfo 头值。
     */
    public String verifyRegister(String deviceId, String authorization) {
        AuthAuthorization aa = Gb35114HeaderUtil.parseAuthAuthorization(authorization);

        Session session = sessions.get(deviceId);
        if (session == null) {
            throw error(Gb35114PlatformError.NO_CHALLENGE);
        }
        synchronized (session) {
            if (authorization.equals(session.lastAuth)) {
                return session.lastSecurityInfo; // 幂等重传
            }
            if (session.random1 == null || !session.random1.equals(aa.random1)) {
                throw error(Gb35114PlatformError.CHALLENGE_MISMATCH);
            }
            if (aa.mode != session.mode) {
                throw new Gb35114Exception("Authorization scheme " + aa.mode
                        + " does not answer the " + session.mode + " challenge");
            }
            if (!serverId.equals(aa.serverId)) {
                throw error(Gb35114PlatformError.SERVER_ID_MISMATCH);
            }
            if (!aa.deviceId.isEmpty() && !aa.deviceId.equals(deviceId)) {
                throw new Gb35114Exception("Authorization deviceid " + aa.deviceId
                        + " does not match the registering device " + deviceId);
            }

            X509Certificate cert = provisionedCerts.get(deviceId);
            if (cert == null && session.announcedCert != null) {
                cert = session.announcedCert;
            }
            if (cert == null && certProvider != null) {
                cert = certProvider.apply(deviceId);
            }
            // 设备自报了证书却取不到受信证书：可能是「本平台从未签发过这张」，也可能是
            // 「签发过但已吊销/过期」——后者由 certProvider 过滤掉了，若只报 DEVICE_CERT
            // 会让人误以为是没配证书。这里问一次原因，给出可区分的提示。
            if (cert == null && session.announcedCert != null) {
                throw new Gb35114Exception(describeRejectedDeviceCert(deviceId, session.announcedCert));
            }
            if (cert == null) {
                throw new Gb35114Exception(deviceCertError(deviceId));
            }
            // 无论证书来自预置、设备自报还是数据库，都必须过吊销/过期校验。
            // 自报路径尤其关键：设备持一张已被吊销的旧证书自报即可绕过数据库过滤。
            if (certValidator != null) {
                cert = certValidator.apply(deviceId, cert);
            }

            byte[] payload = Gb35114HeaderUtil.signAuthPayload(aa.random1, aa.random2, aa.serverId);
            try {
                Gb35114SmCrypto.verify(cert.getPublicKey(), payload, aa.sign1);
            } catch (Exception e) {
                throw new Gb35114Exception("security35114: verifying sign1", e);
            }

            byte[] vkek = Gb35114SmCrypto.randomBytes(16);
            String cryptKey;
            try {
                cryptKey = Gb35114SmCrypto.encryptVkek(cert.getPublicKey(), vkek);
            } catch (Exception e) {
                throw new Gb35114Exception("security35114: sealing VKEK", e);
            }

            SecurityInfo si = new SecurityInfo();
            si.mode = aa.mode;
            // 与 401 挑战里协商出的算法串保持一致：设备会拿它比对本次会话的能力，
            // 回内置默认值（少了设备通告的 S 段条目）会被判为协商不一致。
            si.algorithm = session.negotiatedAlgorithm != null
                    ? session.negotiatedAlgorithm : Gb35114HeaderUtil.CAPABILITY_ALGORITHM;
            si.cryptKey = cryptKey;
            if (aa.mode == Mode.Bidirection) {
                if (identity == null) {
                    throw new Gb35114Exception("Bidirection requires an identity");
                }
                si.random1 = aa.random1;
                si.random2 = aa.random2;
                si.deviceId = deviceId;
                si.serverId = serverId;
                byte[] sign2Payload = Gb35114HeaderUtil.sign2Payload(
                        aa.random1, aa.random2, deviceId, cryptKey);
                try {
                    si.sign2 = Gb35114SmCrypto.sign(identity.privateKey, sign2Payload);
                } catch (Exception e) {
                    throw new Gb35114Exception("security35114: signing sign2", e);
                }
            }

            String securityInfo = Gb35114HeaderUtil.buildSecurityInfo(si);
            session.vkek = vkek;
            session.lastAuth = authorization;
            session.lastSecurityInfo = securityInfo;
            return securityInfo;
        }
    }

    /** 返回该设备协商出的 VKEK，未完成握手返回 {@code null}。 */
    public byte[] vkek(String deviceId) {
        Session session = sessions.get(deviceId);
        return session == null ? null : session.vkek;
    }

    private Gb35114Exception error(Gb35114PlatformError err) {
        return new Gb35114Exception("security35114: " + err.name().toLowerCase().replace('_', ' '));
    }
}
