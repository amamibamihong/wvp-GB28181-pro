package com.genersoft.iot.vmp.gb35114.sip;

/**
 * VKEK 更新周期的服务端上限。
 *
 * <p>GB 35114—2017 <b>6.14.3</b>：「视频密钥加密密钥 VKEK 更新周期不大于 1 天。」
 * GB/T 43026—2023 <b>7.13</b> 表 13 序号 1 把它列为必测项，判定准则 a) 是
 * 「身份注册认证时间间隔符合 GB 35114—2017 中 6.14 的规定」，测试方法是
 * 「查看受测设备与测试平台间<b>身份注册认证时间间隔的配置</b>」——即直接查配置值，
 * 不看运行时行为。
 *
 * <p><b>为什么「VKEK 更新周期」在本实现里等于「注册周期」</b>：VKEK 只在注册握手时
 * 生成（{@code Gb35114PlatformStateMachine#verifyRegister}），此后不随控制信令轮换，
 * 也没有独立的定时更新。因此让注册周期 ≤ 1 天，是当前实现满足 6.14.3 的唯一手段。
 *
 * <p><b>两个方向都要卡</b>：
 * <ul>
 *   <li><b>UAS</b>（设备注册到本平台）：设备请求的 {@code Expires} 超过上限时，
 *       200 OK 里回一个被压到上限的值，设备据此提前重注册，从而刷新 VKEK。
 *       设备侧对 200 OK 的 {@code Expires} 是采信的，这是标准机制；</li>
 *   <li><b>UAC</b>（本平台注册到上级）：本平台发出的 {@code Expires} 由
 *       {@code wvp_platform.expires} 决定，故在保存上级时就把该列钳到上限内。</li>
 * </ul>
 *
 * <p>本类只做钳制，不做校验抛错 —— 上限是协议硬指标，遇到超限的存量配置或对端请求时
 * 压到合规值即可继续工作，拒绝反而会让原本能跑的接入断掉。调用方负责在真的发生钳制时
 * 记一条日志，让「谁在超限」变成运维可见的事实。
 */
public final class Gb35114VkekPeriod {

    /** GB 35114—2017 6.14.3：VKEK 更新周期不大于 1 天。 */
    public static final int MAX_SECONDS = 24 * 60 * 60;

    private Gb35114VkekPeriod() {
    }

    /**
     * 把请求的周期钳到 {@link #MAX_SECONDS} 以内。
     *
     * <p>非正数原样返回：{@code 0} 在注册语义里表示<b>注销</b>，不是「周期为 0」，
     * 不该被改写成一个正数（那会把注销变成注册）。负数同理视为非法值，交由调用方处置。
     */
    public static int clamp(int requested) {
        if (requested <= 0) {
            return requested;
        }
        return Math.min(requested, MAX_SECONDS);
    }

    /** 该值是否超限、需要钳制。 */
    public static boolean exceeds(int requested) {
        return requested > MAX_SECONDS;
    }
}
