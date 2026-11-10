package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.conf.UserSetting;
import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.bean.SubscribeHolder;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.gb28181.service.impl.PlatformServiceImpl;
import com.genersoft.iot.vmp.gb28181.task.platformStatus.PlatformStatusTaskRunner;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

/**
 * 删除级联平台时，连带删除它绑定的 GB35114 证书。
 *
 * <p>绑定关系存在 {@code wvp_platform.device_cert_id} / {@code platform_cert_id} 两个裸外键上，
 * 平台行一删，证书就再没有归属 —— 留着只会在「国密证书管理」页堆成看不出用途的孤儿记录。
 *
 * <p>三件事必须成立：
 * <ol>
 *   <li><b>顺序</b>：先删 platform 行，再删证书。反过来的话
 *       {@code assertNoCertReference} 会把本行算成「仍被引用」而拒绝，每张都删不掉，
 *       而删平台看起来还「成功」了 —— 静默的半个操作；</li>
 *   <li><b>删不掉不影响删平台</b>：存量数据里可能两个上级指向同一张证书，先删的那个
 *       会被守卫拒绝。这是正确的判定，但不该把已经成功的「删平台」一起回滚；</li>
 *   <li><b>模块缺席不炸</b>：{@code gb35114CertService} 是 {@code @Autowired(required=false)}，
 *       未引入 GB35114 时为 null，此时整体跳过而不是 NPE。</li>
 * </ol>
 */
class Gb35114PlatformDeleteCascadeTest {

    private static final int PLATFORM_ID = 7;
    private static final int DEVICE_CERT_ID = 101;
    private static final int PLATFORM_CERT_ID = 202;

    private PlatformServiceImpl service;
    private PlatformMapper platformMapper;
    private PlatformStatusTaskRunner statusTaskRunner;
    private IGb35114CertService certService;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new PlatformServiceImpl();
        platformMapper = Mockito.mock(PlatformMapper.class);
        statusTaskRunner = Mockito.mock(PlatformStatusTaskRunner.class);
        certService = Mockito.mock(IGb35114CertService.class);

        UserSetting userSetting = new UserSetting();
        userSetting.setServerId("server-1");

        inject(service, "platformMapper", platformMapper);
        inject(service, "statusTaskRunner", statusTaskRunner);
        inject(service, "subscribeHolder", Mockito.mock(SubscribeHolder.class));
        inject(service, "userSetting", userSetting);
        inject(service, "gb35114CertService", certService);
    }

    /**
     * 构造一个「本节点所属」的平台行 —— 只有 serverId 相同才走本地删除分支，
     * 否则会经 redisRpcService 转发到别的节点（那是另一条路径）。
     */
    private Platform platform(Integer deviceCertId, Integer platformCertId) {
        Platform p = new Platform();
        p.setId(PLATFORM_ID);
        p.setName("上级甲");
        p.setServerGBId("34010000002000000001");
        p.setServerId("server-1");
        p.setDeviceCertId(deviceCertId);
        p.setPlatformCertId(platformCertId);
        return p;
    }

    private void givenPlatform(Platform p) {
        when(platformMapper.query(PLATFORM_ID)).thenReturn(p);
        when(statusTaskRunner.containsRegister(anyString())).thenReturn(false);
    }

    /** 两张证书都绑了 —— 都要删，且必须发生在 platform 行删除之后。 */
    @Test
    void deletesBothBoundCertsAfterPlatformRow() {
        givenPlatform(platform(DEVICE_CERT_ID, PLATFORM_CERT_ID));

        assertTrue(service.delete(PLATFORM_ID));

        InOrder order = inOrder(platformMapper, certService);
        order.verify(platformMapper).query(PLATFORM_ID);
        order.verify(platformMapper).delete(PLATFORM_ID);
        order.verify(certService).deleteCert(DEVICE_CERT_ID);
        order.verify(certService).deleteCert(PLATFORM_CERT_ID);
        order.verifyNoMoreInteractions();
    }

    /** 只绑了一张时，只删那一张，不去碰另一张（id 恰好相同也要按字段分别判断）。 */
    @Test
    void deletesOnlyTheBoundOne() {
        givenPlatform(platform(DEVICE_CERT_ID, null));

        assertTrue(service.delete(PLATFORM_ID));

        verify(certService).deleteCert(DEVICE_CERT_ID);
        verify(certService, never()).deleteCert(PLATFORM_CERT_ID);
        verify(certService, times(1)).deleteCert(anyInt());
    }

    /** 两张都没绑 —— 一次都不该调用删除。 */
    @Test
    void noBindingMeansNoCertDeletion() {
        givenPlatform(platform(null, null));

        assertTrue(service.delete(PLATFORM_ID));

        verifyNoInteractions(certService);
    }

    /**
     * 某张证书删不掉（例如还被别的上级引用）时，删平台<b>仍然成功</b>，
     * 另一张照常删。
     */
    @Test
    void certDeletionFailureDoesNotFailPlatformDeletion() {
        givenPlatform(platform(DEVICE_CERT_ID, PLATFORM_CERT_ID));
        doThrow(new IllegalArgumentException("证书 #" + DEVICE_CERT_ID + " 仍被引用，无法删除"))
                .when(certService).deleteCert(DEVICE_CERT_ID);

        assertTrue(service.delete(PLATFORM_ID), "一张证书删不掉不该让删平台失败");

        verify(certService).deleteCert(DEVICE_CERT_ID);
        verify(certService).deleteCert(PLATFORM_CERT_ID);
        verify(platformMapper).delete(PLATFORM_ID);
    }

    /** GB35114 模块缺席（服务为 null）时整体跳过，不 NPE。 */
    @Test
    void absentCertServiceIsSkipped() throws Exception {
        inject(service, "gb35114CertService", null);
        givenPlatform(platform(DEVICE_CERT_ID, PLATFORM_CERT_ID));

        assertTrue(service.delete(PLATFORM_ID));
        verify(platformMapper).delete(PLATFORM_ID);
    }

    /**
     * 两个字段指向<b>同一张</b>证书时不重复删：第二次会因「记录已不存在」或守卫判定而失败，
     * 但那只是噪音日志，不该冒泡。
     */
    @Test
    void sameCertBoundToBothFieldsIsTolerated() {
        givenPlatform(platform(DEVICE_CERT_ID, DEVICE_CERT_ID));
        doThrow(new IllegalArgumentException("证书已不存在"))
                .when(certService).deleteCert(DEVICE_CERT_ID);

        assertTrue(service.delete(PLATFORM_ID));
        verify(certService, times(2)).deleteCert(DEVICE_CERT_ID);
    }
}
