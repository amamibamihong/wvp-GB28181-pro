package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.dao.DeviceMapper;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 把证书绑定到级联平台（{@code bindToPlatform}）。
 *
 * <p>要守住的是「国密接入下，证书归属必须显式落在 {@code wvp_platform} 上」这件事。
 * 没有它时运行期只能靠 {@code queryDeviceIdentity} 按国标 ID 反查兜底，而兜底在接入
 * 第二个上级时会退化成「拒绝猜测、返回 null」—— 页面上也就无从回显绑的是哪张。
 *
 * <p>三处必须拦下、且都必须<b>在写库之前</b>拦下：
 * <ol>
 *   <li>证书类型与要绑的槽对不上 —— 绑错列不会当场报错，而是等到注册时上级验 sign1 失败，
 *       那时本平台日志一切正常，排查容易跑偏；</li>
 *   <li>证书已吊销；</li>
 *   <li>类型不是这两个槽之一（比如拿服务端证书去绑）。</li>
 * </ol>
 */
class Gb35114CertBindToPlatformTest {

    private static final int PLATFORM_ID = 1;
    private static final int CERT_ID = 61;

    private Gb35114CertServiceImpl service;
    private Gb35114CertMapper certMapper;
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
        platformMapper = Mockito.mock(PlatformMapper.class);
        inject(service, "certMapper", certMapper);
        inject(service, "caMapper", Mockito.mock(Gb35114CaMapper.class));
        inject(service, "deviceMapper", Mockito.mock(DeviceMapper.class));
        inject(service, "platformMapper", platformMapper);
        inject(service, "config", new Gb35114Config());

        Platform platform = new Platform();
        platform.setId(PLATFORM_ID);
        platform.setServerGBId("34020000002000000001");
        when(platformMapper.query(PLATFORM_ID)).thenReturn(platform);
        when(platformMapper.bindDeviceCert(eq(PLATFORM_ID), any())).thenReturn(1);
        when(platformMapper.bindPlatformCert(eq(PLATFORM_ID), any())).thenReturn(1);
    }

    private static Gb35114Cert cert(String type, boolean revoked) {
        Gb35114Cert c = new Gb35114Cert();
        c.setId(CERT_ID);
        c.setType(type);
        c.setRevoked(revoked);
        return c;
    }

    /** 正常路径：类型对得上就写对应的那一列。 */
    @Test
    void bindsDeviceIdentityToDeviceColumn() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(cert(Gb35114Cert.TYPE_DEVICE_IDENTITY, false));

        service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID);

        verify(platformMapper).bindDeviceCert(PLATFORM_ID, CERT_ID);
        // 绝不能顺手把另一个槽也写了 —— 两个槽是独立的
        verify(platformMapper, never()).bindPlatformCert(anyInt(), any());
    }

    @Test
    void bindsTrustedPlatformToPlatformColumn() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(cert(Gb35114Cert.TYPE_TRUSTED_PLATFORM, false));

        service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_TRUSTED_PLATFORM, CERT_ID);

        verify(platformMapper).bindPlatformCert(PLATFORM_ID, CERT_ID);
        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
    }

    /** certId 为 null 是「解绑」，不该去查证书表。 */
    @Test
    void nullCertIdUnbindsWithoutLookingUpCert() {
        service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, null);

        verify(platformMapper).bindDeviceCert(PLATFORM_ID, null);
        verify(certMapper, never()).queryLite(anyInt());
    }

    /** 类型对不上：拦下，且一个字节都不写库。 */
    @Test
    void mismatchedTypeIsRejectedBeforeWriting() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(cert(Gb35114Cert.TYPE_TRUSTED_PLATFORM, false));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID));

        assertTrue(e.getMessage().contains("TRUSTED_PLATFORM"), "应说明实际类型，实际: " + e.getMessage());
        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
        verify(platformMapper, never()).bindPlatformCert(anyInt(), any());
    }

    /** 已吊销的证书不参与绑定：它在下一次注册时本就会被拒。 */
    @Test
    void revokedCertIsRejectedBeforeWriting() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(cert(Gb35114Cert.TYPE_DEVICE_IDENTITY, true));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID));

        assertTrue(e.getMessage().contains("吊销"), "应说明已吊销，实际: " + e.getMessage());
        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
    }

    /** 证书不存在：拦下。 */
    @Test
    void missingCertIsRejected() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(null);

        assertThrows(IllegalArgumentException.class,
                () -> service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID));

        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
    }

    /** 平台不存在：拦下，不写库。 */
    @Test
    void missingPlatformIsRejected() {
        when(platformMapper.query(PLATFORM_ID)).thenReturn(null);

        assertThrows(IllegalArgumentException.class,
                () -> service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID));

        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
    }

    /** 不属于这两个槽的类型（如本平台服务端证书、下级设备证书）不能绑到级联平台。 */
    @Test
    void otherCertTypesCannotBeBoundToPlatform() {
        for (String type : new String[]{Gb35114Cert.TYPE_SERVER_IDENTITY, Gb35114Cert.TYPE_ISSUED_DEVICE}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> service.bindToPlatform(PLATFORM_ID, type, CERT_ID), type + " 不该被接受");
            assertTrue(e.getMessage().contains("不能绑定"), "实际: " + e.getMessage());
        }
        verify(platformMapper, never()).bindDeviceCert(anyInt(), any());
        verify(platformMapper, never()).bindPlatformCert(anyInt(), any());
    }

    /** 影响行数为 0（平台被并发删掉等）必须报错，不能静默当成功 —— 前端据此提示绑定失败。 */
    @Test
    void zeroAffectedRowsIsAnError() {
        when(certMapper.queryLite(CERT_ID)).thenReturn(cert(Gb35114Cert.TYPE_DEVICE_IDENTITY, false));
        when(platformMapper.bindDeviceCert(eq(PLATFORM_ID), any())).thenReturn(0);

        assertThrows(IllegalStateException.class,
                () -> service.bindToPlatform(PLATFORM_ID, Gb35114Cert.TYPE_DEVICE_IDENTITY, CERT_ID));
    }
}
