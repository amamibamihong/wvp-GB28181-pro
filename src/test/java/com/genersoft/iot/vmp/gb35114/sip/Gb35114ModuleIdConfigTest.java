package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 密码模块 ID 配置项的解析语义（GB 35114—2017 附录 A 表 A.1 第 6 项 / 附录 B）。
 *
 * <p>覆盖三件事：留空回默认全 0、填了就用填的（含前后空白）、填错<b>原样下发</b>。
 * 最后一条是刻意的：静默改写成合规值会让「配置写错了」这件事在页面上看不出来。
 */
class Gb35114ModuleIdConfigTest {

    private static final String PLACEHOLDER = "0".repeat(22);

    @Test
    void blankFallsBackToPlaceholder() {
        Gb35114Config config = new Gb35114Config();
        config.setModuleId("");
        assertEquals(PLACEHOLDER, config.resolvedModuleId());
    }

    @Test
    void nullFallsBackToPlaceholder() {
        Gb35114Config config = new Gb35114Config();
        config.setModuleId(null);
        assertEquals(PLACEHOLDER, config.resolvedModuleId());
    }

    @Test
    void whitespaceOnlyFallsBackToPlaceholder() {
        Gb35114Config config = new Gb35114Config();
        config.setModuleId("   ");
        assertEquals(PLACEHOLDER, config.resolvedModuleId());
    }

    @Test
    void defaultFieldValueIsPlaceholder() {
        // 出厂状态（yml 里没写这一项）就该是全 0，不需要运维额外配置才能用
        assertEquals(PLACEHOLDER, new Gb35114Config().resolvedModuleId());
    }

    @Test
    void configuredValueIsUsedAsIs() {
        Gb35114Config config = new Gb35114Config();
        config.setModuleId("1234567890123456789012");
        assertEquals("1234567890123456789012", config.resolvedModuleId());
    }

    @Test
    void surroundingWhitespaceIsTrimmed() {
        // yml 里手写 `module-id: 1234... ` 很容易带上尾空格，不该因此变成非法值
        Gb35114Config config = new Gb35114Config();
        config.setModuleId("  1234567890123456789012  ");
        assertEquals("1234567890123456789012", config.resolvedModuleId());
    }

    @Test
    void invalidValueIsPassedThroughNotRewritten() {
        // 位数不对时原样下发，由页面提示 —— 换掉会掩盖配置错误
        Gb35114Config config = new Gb35114Config();
        config.setModuleId("123");
        assertEquals("123", config.resolvedModuleId());
        assertFalse(config.resolvedModuleId().matches("\\d{22}"));
    }

    @Test
    void resolvedValueIsAlwaysNonBlank() {
        // 页面直接拿它拼主题，返回空串会让 CN 变成「GBID_」这种说不通的形状
        for (String v : new String[]{null, "", "  ", "abc"}) {
            Gb35114Config config = new Gb35114Config();
            config.setModuleId(v);
            assertTrue(config.resolvedModuleId().length() > 0, "配置值 " + v + " 解析后为空");
        }
    }
}
