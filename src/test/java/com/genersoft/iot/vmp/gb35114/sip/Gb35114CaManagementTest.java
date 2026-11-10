package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CA 证书管理的两条约束：
 *
 * <ol>
 *   <li><b>本地根 CA 全局唯一</b> —— 生成与导入 LOCAL_CA 都受同一条守卫约束，
 *       但受信任的 CA 不受影响（多个上级平台各一份，第三方签发机构也可能不止一家）；</li>
 *   <li><b>被证书引用的 CA 删不掉</b>，且拒绝时要点名是哪些证书在占位。</li>
 * </ol>
 *
 * <p>第 2 点的信息在本次重构后变得更要紧：受信任的 CA 现在既能签上级平台证书、
 * 也能签下级设备证书，「这张 CA 还在不在用」光看 CA 列表已经判断不出来了。
 */
class Gb35114CaManagementTest {

    private static final long DAY = 24L * 3600 * 1000;

    private Gb35114CertServiceImpl service;
    private Gb35114CaMapper caMapper;
    private Gb35114CertMapper certMapper;
    private Gb35114Config config;

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Gb35114CertServiceImpl();
        caMapper = Mockito.mock(Gb35114CaMapper.class);
        certMapper = Mockito.mock(Gb35114CertMapper.class);
        config = new Gb35114Config();
        inject(service, "caMapper", caMapper);
        inject(service, "certMapper", certMapper);
        inject(service, "config", config);
    }

    private static Date later(int days) {
        return new Date(System.currentTimeMillis() + days * DAY);
    }

    private static X500Name name(String cn) {
        return new X500Name("CN=" + cn);
    }

    private static Gb35114Ca ca(int id, String type, Gb35114CertUtil.Gb35114Identity identity) {
        Gb35114Ca record = new Gb35114Ca();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setCertPem(identity.certPem);
        return record;
    }

    private static Gb35114Cert cert(int id, String type, String gbId,
                                    Gb35114CertUtil.Gb35114Identity identity) {
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(type);
        record.setGbId(gbId);
        record.setCertPem(identity.certPem);
        record.setRevoked(false);
        return record;
    }

    // ------------------------------------------------------------------
    // 一、本地根 CA 唯一
    // ------------------------------------------------------------------

    /** 已有本地根 CA → 再生成一张被拒，且不写库。 */
    @Test
    void generateSecondLocalCaIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(1, Gb35114Ca.TYPE_LOCAL_CA, existing)));
        when(certMapper.countByCaId(1)).thenReturn(0);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.generateCa(new Gb35114Ca(), 3650));
        assertTrue(e.getMessage().contains("只保留一份"), "实际: " + e.getMessage());
        verify(caMapper, never()).add(any());
    }

    /** 已有本地根 CA → 导入 LOCAL_CA 同样被拒（导入等价于新建）。 */
    @Test
    void importSecondLocalCaIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity incoming = Gb35114CertUtil.generateSelfSigned(
                name("Another Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(1, Gb35114Ca.TYPE_LOCAL_CA, existing)));
        when(certMapper.countByCaId(1)).thenReturn(0);

        assertThrows(IllegalArgumentException.class,
                () -> service.importCa(Gb35114Ca.TYPE_LOCAL_CA, incoming.certPem,
                        incoming.keyPem, null));
        verify(caMapper, never()).add(any());
    }

    /**
     * <b>守卫的用途作用域</b>：已有本地根 CA 时，导入<b>受信任的 CA</b> 仍须允许。
     *
     * <p>这两栏是独立的：本地根 CA 唯一是「本平台自己只能有一个签发身份」，
     * 而受信任的 CA 是「本平台认哪些外部签发者」，天然可以有多份。
     * 若守卫不看用途，第二栏就永远建不起来。
     */
    @Test
    void importTrustedCaAllowedEvenWhenLocalCaExists() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity thirdParty = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA))
                .thenReturn(List.of(ca(1, Gb35114Ca.TYPE_LOCAL_CA, existing)));

        service.importCa(Gb35114Ca.TYPE_TRUSTED_CA, thirdParty.certPem, null, "第三方");

        verify(caMapper).add(any());
        // 受信任的 CA 不该去查本地 CA 表 —— 查了说明守卫没做用途门控
        verify(caMapper, never()).queryByType(Gb35114Ca.TYPE_LOCAL_CA);
    }

    /**
     * 本地 CA 必须带私钥 —— 没有私钥就签不了证书，导入时就要拦住。
     *
     * <p>这里断言的是「消息里带『私钥』」而非具体的异常类型：{@code importCa} 把校验放在
     * try 内（既有写法），会被包一层 RuntimeException；全局异常处理对未匹配的异常
     * 也会把 message 透给用户，所以对用户而言这条提示照样可见。要紧的是它不被吞掉。
     */
    @Test
    void importLocalCaWithoutKeyIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity incoming = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryByType(Gb35114Ca.TYPE_LOCAL_CA)).thenReturn(List.of());

        RuntimeException e = assertThrows(RuntimeException.class,
                () -> service.importCa(Gb35114Ca.TYPE_LOCAL_CA, incoming.certPem, null, null));
        assertTrue(e.getMessage().contains("私钥"), "实际: " + e.getMessage());
        verify(caMapper, never()).add(any());
    }

    // ------------------------------------------------------------------
    // 二、被引用的 CA 删不掉，且点名占位者
    // ------------------------------------------------------------------

    /** 有证书引用 → 拒绝删除，且不调 delete。 */
    @Test
    void deleteReferencedCaIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name("35020000001320000001"), new Date(), later(365));
        when(certMapper.countByCaId(20)).thenReturn(1);
        when(certMapper.queryByCaId(20)).thenReturn(
                List.of(cert(30, Gb35114Cert.TYPE_ISSUED_DEVICE, "35020000001320000001", device)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCa(20));
        assertTrue(e.getMessage().contains("1 张证书"), "实际: " + e.getMessage());
        verify(caMapper, never()).delete(anyInt());
    }

    /**
     * 拒绝删除时的信息必须<b>点名是哪些证书</b>，不能只说「还有 3 张」。
     *
     * <p>重构后受信任的 CA 既能签上级平台证书、也能签下级设备证书，用户光看 CA 页面
     * 已经猜不到是哪几张；只说张数等于把找证书的活全推回给用户。
     */
    @Test
    void deleteRejectionNamesTheOffendingCerts() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity devA = Gb35114CertUtil.issue(
                trusted, name("35020000001320000001"), new Date(), later(365));
        Gb35114CertUtil.Gb35114Identity devB = Gb35114CertUtil.issue(
                trusted, name("35020000001320000002"), new Date(), later(365));
        when(certMapper.countByCaId(20)).thenReturn(2);
        when(certMapper.queryByCaId(20)).thenReturn(List.of(
                cert(31, Gb35114Cert.TYPE_ISSUED_DEVICE, "35020000001320000002", devB),
                cert(30, Gb35114Cert.TYPE_ISSUED_DEVICE, "35020000001320000001", devA)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCa(20));
        String msg = e.getMessage();
        assertTrue(msg.contains("客户端证书（下级设备）"), "应点名用途，实际: " + msg);
        assertTrue(msg.contains("35020000001320000002"),
                "应举一张具体证书的国标 ID，用户据此可搜到，实际: " + msg);
    }

    /** 未被引用 → 允许删除。 */
    @Test
    void deleteUnreferencedCaSucceeds() {
        when(certMapper.countByCaId(20)).thenReturn(0);

        service.deleteCa(20);

        verify(caMapper).delete(20);
    }

    /** 提示拼装失败不该让「拒绝删除」本身失败 —— 拿不到清单就退回只有张数的文案。 */
    @Test
    void deleteRejectionSurvivesCertListFailure() {
        when(certMapper.countByCaId(20)).thenReturn(3);
        when(certMapper.queryByCaId(20)).thenThrow(new RuntimeException("库连接断了"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.deleteCa(20));
        assertTrue(e.getMessage().contains("3 张证书"), "实际: " + e.getMessage());
        verify(caMapper, never()).delete(anyInt());
    }

    // ------------------------------------------------------------------
    // 三、CA → 证书的反向关联
    // ------------------------------------------------------------------

    /** CA 列表补上「关联证书数」，供页面显示。 */
    @Test
    void caListCarriesCertCount() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryAll()).thenReturn(List.of(
                ca(1, Gb35114Ca.TYPE_LOCAL_CA, localCa),
                ca(20, Gb35114Ca.TYPE_TRUSTED_CA, trusted)));
        when(certMapper.countByCaId(1)).thenReturn(3);
        when(certMapper.countByCaId(20)).thenReturn(1);

        List<Gb35114Ca> cas = service.queryAllCa();

        assertEquals(3, cas.get(0).getCertCount());
        assertEquals(1, cas.get(1).getCertCount());
    }

    /** 单张 CA 的计数查询失败不影响列表其余项 —— 计数是辅助信息。 */
    @Test
    void certCountFailureDoesNotBreakCaList() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        when(caMapper.queryAll()).thenReturn(List.of(ca(1, Gb35114Ca.TYPE_LOCAL_CA, localCa)));
        when(certMapper.countByCaId(1)).thenThrow(new RuntimeException("库连接断了"));

        List<Gb35114Ca> cas = service.queryAllCa();

        assertEquals(1, cas.size());
        assertNull(cas.get(0).getCertCount(), "拿不到计数就留空，不该让整个列表失败");
    }

    /** 点开某张 CA → 返回它签发的证书清单。 */
    @Test
    void queryCertsByCaIdReturnsIssuedCerts() throws Exception {
        Gb35114CertUtil.Gb35114Identity trusted = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114CertUtil.Gb35114Identity device = Gb35114CertUtil.issue(
                trusted, name("35020000001320000001"), new Date(), later(365));
        when(certMapper.queryByCaId(20)).thenReturn(
                List.of(cert(30, Gb35114Cert.TYPE_ISSUED_DEVICE, "35020000001320000001", device)));

        List<Gb35114Cert> certs = service.queryCertsByCaId(20);

        assertEquals(1, certs.size());
        assertEquals(30, certs.get(0).getId());
        // 关联对象由 fillRelations 补齐，页面据此显示「给谁用了」
        assertNotNull(certs.get(0).getIssuerDn());
    }
}
