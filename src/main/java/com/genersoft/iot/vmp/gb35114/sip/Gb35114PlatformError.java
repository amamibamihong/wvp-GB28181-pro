package com.genersoft.iot.vmp.gb35114.sip;

/**
 * 平台侧（UAS）国密注册状态机的失败模式，映射到 4xx 响应，对齐
 * gb28181-rs {@code security35114::platform::PlatformError}。
 */
public enum Gb35114PlatformError {
    /** verifyRegister 到达时该设备没有待验证的 challenge。 */
    NO_CHALLENGE,
    /** Authorization 回显的 random1 与待验证 challenge 不一致（重放/伪造）。 */
    CHALLENGE_MISMATCH,
    /** 没有该设备的受信证书（既非预置也非 Capability cnonce 宣告）。 */
    DEVICE_CERT,
    /** 设备为不同的 SIP server ID 签名。 */
    SERVER_ID_MISMATCH,
    /** 该设备未完成握手（无 VKEK）。 */
    NO_SESSION
}
