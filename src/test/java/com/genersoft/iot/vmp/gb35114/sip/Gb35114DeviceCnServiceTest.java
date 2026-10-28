package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * 设备证书主题 CN 的格式约束（GB 35114—2017 附录 A 表 A.1 第 6 项 + 附录 B）。
 *
 * <p>表 A.1 要求设备证书的 CN 为「<b>设备 ID_密码模块 ID</b>」，ID 间以「_」分隔，
 * 某段为空时值为「NULL」；附录 B 规定密码模块 ID 是 22 位十进制。本平台没有硬件
 * 密码模块，因此默认全 0 由用户按需改写。
 *
 * <p>这里验证的是<b>后端兜底</b>：前端已按同一规则拼装 CN，但证书一经签出即固化，
 * 事后发现格式不对只能重签，而 CSR 是最便宜的拦截点 —— 所以后端不依赖前端。
 * 同时要保证「不填密码模块 ID」不被误伤：那正是标准里 NULL 的合法写法。
 */
class Gb35114DeviceCnServiceTest {

    private static final String GB_ID = "34020000002000000001";
    private static final String MODULE_ZERO = "0".repeat(22);
    /** 现场真实设备证书 #32 里的密码模块 ID（附录 B 合规样例）。 */
    private static final String MODULE_REAL = "1717012020050159164420";

    private Gb35114CertServiceImpl service;
    private Gb35114CertMapper certMapper;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        certMapper = Mockito.mock(Gb35114CertMapper.class);
        inject(service, "certMapper", certMapper);
        inject(service, "caMapper", Mockito.mock(Gb35114CaMapper.class));
        inject(service, "config", new Gb35114Config());
        // 服务端密钥对守卫只对 SERVER_IDENTITY 生效，设备证书这条路径不查；
        // 但 CSR 落库前的其它查询统一给空结果，避免 mock 返回 null 引发 NPE。
        when(certMapper.queryServerIdentities()).thenReturn(List.of());
    }

    private static Gb35114Cert profile(String cn) {
        Gb35114Cert p = new Gb35114Cert();
        p.setType(Gb35114Cert.TYPE_DEVICE_IDENTITY);
        p.setGbId(GB_ID);
        p.setSubjectCn(cn);
        p.setCountry("CN");
        p.setRemark("单测");
        return p;
    }

    private Gb35114Cert captured() {
        ArgumentCaptor<Gb35114Cert> captor = ArgumentCaptor.forClass(Gb35114Cert.class);
        Mockito.verify(certMapper).add(captor.capture());
        return captor.getValue();
    }

    /** 合规 CN（设备ID_全 0 密码模块ID）应放行，且模块 ID 列由 CN 反解析得到。 */
    @Test
    void zeroModuleIdIsAcceptedAndParsedIntoColumn() {
        service.createPendingCsr(profile(GB_ID + "_" + MODULE_ZERO), 3650);
        Gb35114Cert cert = captured();

        assertEquals(GB_ID + "_" + MODULE_ZERO, cert.getSubjectCn());
        assertEquals(MODULE_ZERO, cert.getModuleId(), "module_id 列应取自 CN 的后半段");
        assertNotNull(cert.getCsrPem(), "CSR 应已生成");
    }

    /** 现场真实设备的模块 ID（22 位、非全 0）同样放行。 */
    @Test
    void realModuleIdIsAccepted() {
        service.createPendingCsr(profile(GB_ID + "_" + MODULE_REAL), 3650);
        assertEquals(MODULE_REAL, captured().getModuleId());
    }

    /** 只写设备 ID（无「_」）不拦 —— 记录里模块 ID 为空，等价于标准里的 NULL。 */
    @Test
    void cnWithoutModuleIdIsAccepted() {
        service.createPendingCsr(profile(GB_ID), 3650);
        Gb35114Cert cert = captured();

        assertEquals(GB_ID, cert.getSubjectCn());
        assertNull(cert.getModuleId());
    }

    /** 标准里的 NULL 写法：模块 ID 段显式为 NULL 时不算模块 ID。 */
    @Test
    void explicitNullModuleIdIsAccepted() {
        service.createPendingCsr(profile(GB_ID + "_NULL"), 3650);
        assertNull(captured().getModuleId());
    }

    /** 位数不对的模块 ID 必须拦下 —— 签出去就固化了，只能在 CSR 这步拒绝。 */
    @Test
    void shortModuleIdIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.createPendingCsr(profile(GB_ID + "_123"), 3650));
        assertTrue(e.getMessage().contains("22"), "报错应点明位数要求: " + e.getMessage());
    }

    /** 含非数字的模块 ID 必须拦下。 */
    @Test
    void nonNumericModuleIdIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> service.createPendingCsr(profile(GB_ID + "_171701202005015916442X"), 3650));
    }

    /** 校验发生在生成密钥之前：非法 CN 不应留下任何落库记录。 */
    @Test
    void rejectedCnLeavesNoRecord() {
        assertThrows(IllegalArgumentException.class,
                () -> service.createPendingCsr(profile(GB_ID + "_123"), 3650));
        Mockito.verify(certMapper, Mockito.never()).add(any());
    }

    /**
     * 平台自身的服务端证书不受附录 A 约束：CN 里带「_」也不该被当成设备证书校验。
     *
     * <p>走的是「一步创建」而不是 CSR：这条路径与 CN 格式校验无关，最短。
     * 服务端证书现在也支持 CSR（见 {@code Gb35114ServerCsrServiceTest}），
     * 但那条路同样不受附录 A 约束 —— {@code requireValidDeviceCn} 只看 DEVICE_IDENTITY。
     */
    @Test
    void serverIdentityCnIsNotSubjectToDeviceFormat() {
        Gb35114Cert p = profile(GB_ID + "_not-a-module-id");
        p.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        service.createServerIdentity(p, null, 3650);
        assertEquals(GB_ID + "_not-a-module-id", captured().getSubjectCn());
    }

    /**
     * 主题留空时补默认值 —— 服务端证书的一步创建也走同一套兜底。
     *
     * <p>单测里没有 Spring 容器，`sipConfig` 为 null，国标 ID 取不到，
     * 于是退化成 `NULL_22个0`（标准的空段写法）。重点是<b>不报错、不签发空 CN</b>。
     */
    @Test
    void blankSubjectFallsBackToDefaultForServerIdentity() {
        Gb35114Cert p = profile(null);
        p.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        service.createServerIdentity(p, null, 3650);
        Gb35114Cert cert = captured();

        assertEquals("NULL_" + MODULE_ZERO, cert.getSubjectCn());
        assertEquals(MODULE_ZERO, cert.getModuleId(), "默认主题里的模块 ID 也应被解析出来");
    }

    /** 显式给的主题不被默认值覆盖（表单默认生成后用户又改过的情况）。 */
    @Test
    void explicitSubjectIsNotOverwritten() {
        Gb35114Cert p = profile(null);
        p.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        p.setSubjectCn("my-own-name");
        service.createServerIdentity(p, null, 3650);
        assertEquals("my-own-name", captured().getSubjectCn());
    }

    /** 拼装工具本身：空段按标准写成 NULL。 */
    @Test
    void buildDeviceCnUsesNullForEmptyParts() {
        assertEquals("NULL_NULL", Gb35114CertUtil.buildDeviceCn(null, null));
        assertEquals(GB_ID + "_NULL", Gb35114CertUtil.buildDeviceCn(GB_ID, null));
        assertEquals("NULL_" + MODULE_ZERO, Gb35114CertUtil.buildDeviceCn("", MODULE_ZERO));
    }
}
