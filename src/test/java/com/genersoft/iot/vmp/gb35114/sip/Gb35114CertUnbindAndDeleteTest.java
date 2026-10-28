package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb28181.bean.Device;
import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.dao.DeviceMapper;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

/**
 * 「删除并解绑」（{@code unbindAndDeleteCert}）—— 编辑页删自己证书的那条路径。
 *
 * <p>与 {@link Gb35114CertReferenceGuardTest} 覆盖的 {@code deleteCert} 不同：级联编辑页
 * 删证书时，证书正被<b>本</b> platform 行按 ID 引用，直接删必被守卫拒绝。本方法先把
 * {@code wvp_platform.device_cert_id} / {@code platform_cert_id} 中等于该 ID 的置空，
 * 再走删除。
 *
 * <p>两条边界必须守住：
 * <ol>
 *   <li><b>只解绑级联平台，不动设备</b>：设备侧那张证书与级联无关，擅自解绑会把一台
 *       正常在用的设备弄成「未配置证书」，下一次注册直接 403；</li>
 *   <li><b>仍被别的平台/设备引用时照旧拒绝并点名</b>：解绑只是撤掉「本行」的引用，
 *       不是无条件放行。</li>
 * </ol>
 */
class Gb35114CertUnbindAndDeleteTest {

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
        // 守卫读的是解绑「之后」的状态：解绑后本行已不再引用，故 queryAll 返回空
        when(platformMapper.queryAll()).thenReturn(List.of());
    }

    private static Platform platform(String name, Integer deviceCertId, Integer platformCertId) {
        Platform p = new Platform();
        p.setName(name);
        p.setDeviceCertId(deviceCertId);
        p.setPlatformCertId(platformCertId);
        return p;
    }

    private static Device device(String name, Integer certId, Integer serverCertId) {
        Device d = new Device();
        d.setName(name);
        d.setCertId(certId);
        d.setServerCertId(serverCertId);
        return d;
    }

    /** 正常路径：两个引用列都清，然后删除。顺序不能反。 */
    @Test
    void clearsBothPlatformBindingsThenDeletes() {
        when(platformMapper.clearDeviceCertBinding(CERT_ID)).thenReturn(1);
        when(platformMapper.clearPlatformCertBinding(CERT_ID)).thenReturn(0);

        service.unbindAndDeleteCert(CERT_ID);

        InOrder order = inOrder(platformMapper, certMapper);
        order.verify(platformMapper).clearDeviceCertBinding(CERT_ID);
        order.verify(platformMapper).clearPlatformCertBinding(CERT_ID);
        // 解绑必须发生在守卫查询之前，否则守卫看到的是解绑前的状态、照样拒绝
        order.verify(platformMapper).queryAll();
        order.verify(certMapper).delete(CERT_ID);
        order.verifyNoMoreInteractions();
    }

    /** 一处都没绑定时照样删得掉 —— 解绑是幂等的，不该因为「没解除到」而中止。 */
    @Test
    void deletesEvenWhenNothingWasBound() {
        when(platformMapper.clearDeviceCertBinding(CERT_ID)).thenReturn(0);
        when(platformMapper.clearPlatformCertBinding(CERT_ID)).thenReturn(0);

        service.unbindAndDeleteCert(CERT_ID);

        Mockito.verify(certMapper).delete(CERT_ID);
    }

    /**
     * 解绑后仍被<b>别的</b>平台引用 → 拒绝，并点名那个平台。
     * 这是「两个上级共用一张证书」的存量数据场景。
     */
    @Test
    void stillReferencedByAnotherPlatformIsRejectedAndNamed() {
        when(platformMapper.clearDeviceCertBinding(CERT_ID)).thenReturn(0);
        when(platformMapper.clearPlatformCertBinding(CERT_ID)).thenReturn(0);
        when(platformMapper.queryAll()).thenReturn(List.of(
                platform("上级乙", CERT_ID, null)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.unbindAndDeleteCert(CERT_ID));

        assertTrue(e.getMessage().contains("上级乙"), "应点名引用者，实际: " + e.getMessage());
        assertTrue(e.getMessage().contains("国密设备证书"), "应说明是哪个槽，实际: " + e.getMessage());
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }

    /**
     * 解绑<b>只</b>碰级联平台，不碰设备：设备仍按 ID 引用时照旧拒绝。
     * 否则「在级联编辑页删证书」会顺手把一台在用设备弄成未配置证书。
     */
    @Test
    void deviceReferenceIsNotUnboundAndStillBlocksDelete() {
        when(platformMapper.clearDeviceCertBinding(CERT_ID)).thenReturn(0);
        when(platformMapper.clearPlatformCertBinding(CERT_ID)).thenReturn(0);
        when(deviceMapper.getAll()).thenReturn(List.of(
                device("门口球机", null, CERT_ID)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.unbindAndDeleteCert(CERT_ID));

        assertTrue(e.getMessage().contains("门口球机"), "应点名设备，实际: " + e.getMessage());
        assertTrue(e.getMessage().contains("国密服务端证书"), "应说明是哪个槽，实际: " + e.getMessage());
        Mockito.verify(certMapper, Mockito.never()).delete(CERT_ID);
    }

    /**
     * 两个槽指向同一张证书时，两次解绑都要发生（SQL 各清各的列），只删一次。
     */
    @Test
    void sameCertInBothSlotsIsUnboundTwiceAndDeletedOnce() {
        when(platformMapper.clearDeviceCertBinding(CERT_ID)).thenReturn(1);
        when(platformMapper.clearPlatformCertBinding(CERT_ID)).thenReturn(1);

        service.unbindAndDeleteCert(CERT_ID);

        Mockito.verify(platformMapper).clearDeviceCertBinding(CERT_ID);
        Mockito.verify(platformMapper).clearPlatformCertBinding(CERT_ID);
        Mockito.verify(certMapper, Mockito.times(1)).delete(CERT_ID);
    }
}
