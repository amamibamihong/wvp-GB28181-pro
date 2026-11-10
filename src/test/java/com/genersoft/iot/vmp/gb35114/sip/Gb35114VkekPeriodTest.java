package com.genersoft.iot.vmp.gb35114.sip;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * VKEK 更新周期上限（GB 35114—2017 6.14.3：「视频密钥加密密钥 VKEK 更新周期不大于 1 天」）。
 *
 * <p>本实现里 VKEK 只在注册握手时生成，所以「注册周期」就是「VKEK 更新周期」。
 * GB/T 43026—2023 §7.13 表 13 序号 1 把它列为必测项，且测试方法是「查看配置」——
 * 因此这里测的是钳制逻辑本身，而不是运行时的刷新行为。
 */
class Gb35114VkekPeriodTest {

    private static final int ONE_DAY = 24 * 60 * 60;

    /** 上限就是 1 天 —— 这是规范给的数，改了这里就等于改了合规基线。 */
    @Test
    void maxIsExactlyOneDay() {
        assertEquals(ONE_DAY, Gb35114VkekPeriod.MAX_SECONDS);
    }

    /** 恰好等于 1 天不钳制：规范是「不大于」，边界值本身合规。 */
    @Test
    void exactlyOneDayIsAccepted() {
        assertEquals(ONE_DAY, Gb35114VkekPeriod.clamp(ONE_DAY));
        assertFalse(Gb35114VkekPeriod.exceeds(ONE_DAY));
    }

    /** 超一秒就钳 —— 上限是硬的，没有容差。 */
    @Test
    void oneSecondOverIsClamped() {
        assertEquals(ONE_DAY, Gb35114VkekPeriod.clamp(ONE_DAY + 1));
        assertTrue(Gb35114VkekPeriod.exceeds(ONE_DAY + 1));
    }

    /** 常见的超限配置：一周 / 一个月，都压到 1 天。 */
    @Test
    void commonOverLimitValuesAreClamped() {
        assertEquals(ONE_DAY, Gb35114VkekPeriod.clamp(7 * ONE_DAY));
        assertEquals(ONE_DAY, Gb35114VkekPeriod.clamp(30 * ONE_DAY));
        assertEquals(ONE_DAY, Gb35114VkekPeriod.clamp(Integer.MAX_VALUE));
    }

    /** 合规值原样返回，包括默认的 3600 与 0 以外的短周期。 */
    @Test
    void compliantValuesPassThrough() {
        assertEquals(3600, Gb35114VkekPeriod.clamp(3600));
        assertEquals(1, Gb35114VkekPeriod.clamp(1));
        assertEquals(60, Gb35114VkekPeriod.clamp(60));
        assertFalse(Gb35114VkekPeriod.exceeds(3600));
    }

    /**
     * {@code 0} 是「注销」而不是「周期为 0」，必须原样穿过。
     * 若被钳成正数，注销请求会变成一次注册 —— 设备下线不掉。
     */
    @Test
    void zeroMeansUnregisterAndIsNotRewritten() {
        assertEquals(0, Gb35114VkekPeriod.clamp(0));
        assertFalse(Gb35114VkekPeriod.exceeds(0));
    }

    /** 负数视为非法值原样返回，交由调用方处置，不在这里悄悄改成合规值。 */
    @Test
    void negativePassesThroughForCallerToHandle() {
        assertEquals(-5, Gb35114VkekPeriod.clamp(-5));
        assertFalse(Gb35114VkekPeriod.exceeds(-5));
    }
}
