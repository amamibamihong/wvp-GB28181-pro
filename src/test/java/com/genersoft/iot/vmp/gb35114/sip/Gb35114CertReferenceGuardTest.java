package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb28181.bean.Device;
import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.dao.DeviceMapper;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * 删除证书前的引用守卫（{@code assertNoCertReference}）。
 *
 * <p>证书被引用是按 <b>ID</b> 存的（{@code wvp_device.cert_id} / {@code server_cert_id}、
 * {@code wvp_platform.device_cert_id} / {@code platform_cert_id}），删除后引用立刻悬空。
 * 悬空不会当场报错，而是在<b>下一次设备注册</b>时才暴露成 403
 * （{@code resolveServerCertId} 对「绑定的证书不可用」是直接拒绝，不静默回退）。
 *
 * <p>因此删除必须前置拦截，并且要<b>点名</b>是哪个设备/平台在引用 ——
 * 只说「被引用」会让运维在一堆设备里翻找。
 */
class Gb35114CertReferenceGuardTest {

    private static final int CERT_ID = 41;

    private Gb35114CertServiceImpl service;
    private Gb35114CertMapper certMapper;
    private DeviceMapper deviceMapper;
    private PlatformMapper platformMapper;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        certMapper = Mockito.mock(Gb35114CertMapper.class);
        deviceMapper = Mockito.mock(DeviceMapper.class);
        platformMapper = Mockito.mock(PlatformMapper.class);
        inject(service, "certMapper", certMapper);
        inject(service, "caMapper", Mockito.mock(Gb35114CaMapper.class));
        inject(service, "deviceMapper", deviceMapper);
        inject(service, "platformMapper", platformMapper);
        inject(service, "config", new Gb35114Config());
        when(deviceMapper.getAll()).thenReturn(List.of());
        when(platformMapper.queryAll()).thenReturn(List.of());
    }

    private static Device device(String name, Integer certId, Integer serverCertId) {
        Device d = new Device();
        d.setName(name);
        d.setCertId(certId);
        d.setServerCertId(serverCertId);
        return d;
    }

    private static Platform platform(String name, Integer deviceCertId, Integer platformCertId) {
        Platform p = new Platform();
        p.setName(name);
        p.setDeviceCertId(deviceCertId);
        p.setPlatformCertId(platformCertId);
        return p;
    }

    /** 无人引用时删除放行。 */
    @Test
    void deleteSucceedsWhenNotReferenced() {
        service.deleteCert(CERT_ID);
        Mockito.verify(certMapper).delete(CERT_ID);
    }

    /** 设备按「国密服务端证书」绑定时拒绝删除，且点名设备。 */
    @Test
    void deviceServerCertBindingBlocksDelete() {
        when(deviceMapper.getAll()).thenReturn(List.of(device("门口球机", null, CERT_ID)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCert(CERT_ID));

        assertTrue(e.getMessage().contains("门口球机"), "报错应点名设备: " + e.getMessage());
        assertTrue(e.getMessage().contains("服务端证书"), "报错应说明绑定的是哪一类: " + e.getMessage());
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }

    /** 设备按「国密设备证书」绑定同样拦截。 */
    @Test
    void deviceCertBindingBlocksDelete() {
        when(deviceMapper.getAll()).thenReturn(List.of(device("枪机", CERT_ID, null)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCert(CERT_ID));
        assertTrue(e.getMessage().contains("枪机"), e.getMessage());
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }

    /** 级联平台的两种绑定都要拦下（这是存量 #41 的真实形态）。 */
    @Test
    void platformBindingBlocksDelete() {
        when(platformMapper.queryAll())
                .thenReturn(List.of(platform("上级平台A", CERT_ID, CERT_ID)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCert(CERT_ID));
        assertTrue(e.getMessage().contains("上级平台A"), e.getMessage());
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }

    /** 一处引用都没有的行（绑的是别的 id）不阻塞删除。 */
    @Test
    void otherBindingsDoNotBlockDelete() {
        when(deviceMapper.getAll()).thenReturn(List.of(device("设备", CERT_ID + 1, null)));
        when(platformMapper.queryAll()).thenReturn(List.of(platform("平台", null, CERT_ID + 2)));

        service.deleteCert(CERT_ID);
        Mockito.verify(certMapper).delete(CERT_ID);
    }

    /**
     * 查询本身失败时不能把「删除」变成一次必然失败的调用。
     *
     * <p>守卫是「顺手多看一眼」，不该因为设备表读不到就拒绝删除 ——
     * 否则一个与证书无关的数据库故障会连带把证书管理页锁死。
     */
    @Test
    void queryFailureDoesNotBlockDelete() {
        when(deviceMapper.getAll()).thenThrow(new RuntimeException("db down"));
        when(platformMapper.queryAll()).thenThrow(new RuntimeException("db down"));

        service.deleteCert(CERT_ID);
        Mockito.verify(certMapper).delete(CERT_ID);
    }

    /** 多台设备同时引用时报错应把它们都列出来，而不是只报第一个。 */
    @Test
    void allReferencesAreListed() {
        when(deviceMapper.getAll()).thenReturn(List.of(
                device("设备甲", null, CERT_ID),
                device("设备乙", null, CERT_ID)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCert(CERT_ID));
        assertTrue(e.getMessage().contains("设备甲"), e.getMessage());
        assertTrue(e.getMessage().contains("设备乙"), e.getMessage());
    }

    /**
     * 守卫对<b>所有</b>证书一视同仁，不看用途。
     *
     * <p>这是有意的：对端证书（上级平台证书、下级设备证书）被级联/设备绑定时，
     * 删除同样会让引用悬空 —— 而且 {@code deleteCert} 连查都不查这条记录，
     * 直接扫引用，因此不可能出现「按用途跳过校验」的漏洞。
     */
    @Test
    void guardIsIndependentOfCertType() {
        when(platformMapper.queryAll()).thenReturn(List.of(platform("上级", null, CERT_ID)));

        assertThrows(IllegalArgumentException.class, () -> service.deleteCert(CERT_ID));
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }
}
