package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CaMapper;
import com.genersoft.iot.vmp.gb35114.cert.dao.Gb35114CertMapper;
import com.genersoft.iot.vmp.gb35114.cert.service.impl.Gb35114CertServiceImpl;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114KeyProtector;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 服务端证书的 CSR 路径：先出 CSR，再由本平台签发（本地根 CA 或自签）。
 *
 * <p>这条路径与既有的两条并存：
 * <ul>
 *   <li>{@code createServerIdentity} —— 一步生成并当场签发；</li>
 *   <li>{@code createPendingCsr} + {@code signPendingServerIdentity} —— 先出 CSR 再签（本类）；</li>
 *   <li>{@code importIdentityCert} —— 导入外部签发的证书回填。</li>
 * </ul>
 *
 * <p>三条路都必须落在同一条约束下：<b>服务端证书全局只保留一组密钥对</b>。本类把这条钉住 ——
 * 尤其是「守卫必须以 server 为条件」，否则有了服务端证书就再也建不出设备 CSR。
 */
class Gb35114ServerCsrServiceTest {

    private static final long DAY = 24L * 3600 * 1000;
    private static final String PLATFORM_ID = "34020000002000000001";

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

    /**
     * 一张 CA 记录。{@code keyPem} 必须带上 —— {@code loadCaIdentity} 见到空私钥会直接拒绝签发，
     * 而「用本地 CA 签」正是这些用例要走的路径。CA 私钥同样以密文形式落库。
     */
    private Gb35114Ca ca(int id, String type, Gb35114CertUtil.Gb35114Identity identity) {
        Gb35114Ca record = new Gb35114Ca();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setSubjectDn(Gb35114CertUtil.subjectDn(identity.certificate));
        record.setCertPem(identity.certPem);
        if (identity.keyPem != null) {
            record.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(),
                    identity.keyPem));
        }
        return record;
    }

    /**
     * 让 mock 的 {@code add} 像真库一样回填自增主键。
     *
     * <p>{@code createPendingCsr} 落库后会 {@code reload(cert)}，而 {@code reload} 在 id 为 null
     * 时直接返回原对象 —— 不模拟主键回填，返回的就永远是内存里那条没 id 的记录。
     */
    private void stubAddAssigningId(int id) {
        when(certMapper.add(any())).thenAnswer(inv -> {
            ((Gb35114Cert) inv.getArgument(0)).setId(id);
            return 1;
        });
    }

    /** 一张「已有服务端证书」的记录，用来触发唯一性守卫。 */
    private static Gb35114Cert serverRecord(int id, Gb35114CertUtil.Gb35114Identity identity)
            throws Exception {
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        record.setSubjectCn(PLATFORM_ID + "_" + "0".repeat(22));
        record.setCertPem(identity.certPem);
        record.setRevoked(false);
        return record;
    }

    private Gb35114Cert profile(String type) {
        Gb35114Cert p = new Gb35114Cert();
        p.setType(type);
        p.setSubjectCn(PLATFORM_ID + "_" + "0".repeat(22));
        return p;
    }

    /**
     * 待签发记录：CSR 与加密私钥都在，证书列为空 —— 正是 {@code createPendingCsr} 的产物。
     */
    private Gb35114Cert pendingRecord(int id, String type) throws Exception {
        Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(
                name(PLATFORM_ID + "_" + "0".repeat(22)));
        Gb35114Cert record = new Gb35114Cert();
        record.setId(id);
        record.setType(type);
        record.setSubjectCn(PLATFORM_ID + "_" + "0".repeat(22));
        record.setCsrPem(csr.csrPem);
        record.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), csr.keyPem));
        record.setCertPem(null);
        record.setValidityDays(3650);
        record.setRevoked(false);
        return record;
    }

    // ------------------------------------------------------------------
    // 一、createPendingCsr：服务端用途不再被拒，且守卫以 server 为条件
    // ------------------------------------------------------------------

    /**
     * 服务端证书可以走 CSR 路径 —— 这是本次放开的入口。
     *
     * <p>捕获 {@code add} 的入参核对：用途/类型正确、CSR 与私钥都落了、证书列为空。
     * 私钥必须落库，否则后面 {@code signPendingServerIdentity} 无从复用 CSR 里的公钥。
     */
    @Test
    void serverCsrCanBeCreatedAndKeepsPrivateKey() throws Exception {
        when(certMapper.queryServerIdentities()).thenReturn(Collections.emptyList());

        Gb35114Cert created = service.createPendingCsr(
                profile(Gb35114Cert.TYPE_SERVER_IDENTITY), 3650);

        ArgumentCaptor<Gb35114Cert> captor = ArgumentCaptor.forClass(Gb35114Cert.class);
        verify(certMapper).add(captor.capture());
        Gb35114Cert saved = captor.getValue();
        assertEquals(Gb35114Cert.TYPE_SERVER_IDENTITY, saved.getType());
        assertNotNull(saved.getCsrPem(), "必须落下 CSR");
        assertNotNull(saved.getKeyPem(), "私钥必须加密留存，否则签发时无法复用 CSR 的公钥");
        assertNull(saved.getCertPem(), "待签发记录的证书列必须为空");
        assertNotNull(created);
    }

    /** 已有可用服务端证书 → 拒绝建新的服务端 CSR，且不写库。 */
    @Test
    void serverCsrBlockedWhenServerIdentityExists() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name(PLATFORM_ID), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_ENTITY);
        when(certMapper.queryServerIdentities()).thenReturn(List.of(serverRecord(40, existing)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.createPendingCsr(profile(Gb35114Cert.TYPE_SERVER_IDENTITY), 3650));
        assertTrue(e.getMessage().contains("只保留一组密钥对"), "实际: " + e.getMessage());
        verify(certMapper, never()).add(any());
    }

    /**
     * 待签发的服务端记录同样阻塞新建，但给出的处置与「已签发」不同：它只需被签出来。
     *
     * <p>这条信息必须可操作 —— 用户面对一条只有 CSR 的记录，若提示他「请先删除该证书」，
     * 他会以为要丢掉刚生成的密钥对。三个出口（签发 / 回填 / 删除）都应在信息里点名。
     */
    @Test
    void pendingServerIdentityBlocksWithActionableMessage() throws Exception {
        Gb35114CertUtil.CsrResult csr = Gb35114CertUtil.generateCsr(name(PLATFORM_ID));
        Gb35114Cert pending = new Gb35114Cert();
        pending.setId(41);
        pending.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        pending.setSubjectCn(PLATFORM_ID);
        pending.setCsrPem(csr.csrPem);
        pending.setKeyPem(Gb35114KeyProtector.encrypt(config.getKeyEncryptPassword(), csr.keyPem));
        pending.setCertPem(null);
        when(certMapper.queryServerIdentities()).thenReturn(List.of(pending));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.createPendingCsr(profile(Gb35114Cert.TYPE_SERVER_IDENTITY), 3650));
        String msg = e.getMessage();
        assertTrue(msg.contains("#41"), "应点名是哪一条，实际: " + msg);
        assertTrue(msg.contains("签出来") || msg.contains("签发"), "应给出「签出来」这个出口，实际: " + msg);
        assertTrue(msg.contains("删除"), "应给出「删除」这个出口，实际: " + msg);
        verify(certMapper, never()).add(any());
    }

    /** 已吊销的服务端记录不占位 —— 否则存量数据会让平台再也建不出服务端证书。 */
    @Test
    void revokedServerIdentityDoesNotBlock() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name(PLATFORM_ID), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114Cert revoked = serverRecord(42, existing);
        revoked.setRevoked(true);
        when(certMapper.queryServerIdentities()).thenReturn(List.of(revoked));

        service.createPendingCsr(profile(Gb35114Cert.TYPE_SERVER_IDENTITY), 3650);

        verify(certMapper).add(any());
    }

    /**
     * <b>守卫必须以 server 为条件</b>：已有服务端证书时，<b>设备</b> CSR 仍要能建。
     *
     * <p>{@code assertNoActiveServerIdentity} 查的是服务端证书表。若在 {@code createPendingCsr}
     * 里无条件调用它，有服务端证书的部署就再也建不出客户端证书（本平台）的 CSR ——
     * 而那是接入上级的必经步骤，等于把整个 UAC 方向堵死。
     */
    @Test
    void deviceCsrUnaffectedByExistingServerIdentity() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name(PLATFORM_ID), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_ENTITY);
        when(certMapper.queryServerIdentities()).thenReturn(List.of(serverRecord(40, existing)));

        service.createPendingCsr(profile(Gb35114Cert.TYPE_DEVICE_IDENTITY), 3650);

        verify(certMapper).add(any());
        // 设备用途不该去查服务端证书表 —— 查了说明守卫没做用途门控
        verify(certMapper, never()).queryServerIdentities();
    }

    /** 服务端 CSR 的返回值必须回读一次：否则 hasKey 为 null，页面会显示成「无私钥」。 */
    @Test
    void serverCsrReturnsReloadedRecord() throws Exception {
        when(certMapper.queryServerIdentities()).thenReturn(Collections.emptyList());
        stubAddAssigningId(77);
        Gb35114Cert fresh = new Gb35114Cert();
        fresh.setId(77);
        fresh.setType(Gb35114Cert.TYPE_SERVER_IDENTITY);
        fresh.setHasKey(true);
        when(certMapper.queryLite(anyInt())).thenReturn(fresh);

        Gb35114Cert created = service.createPendingCsr(
                profile(Gb35114Cert.TYPE_SERVER_IDENTITY), 3650);

        assertEquals(77, created.getId());
        assertEquals(Boolean.TRUE, created.getHasKey(),
                "必须返回回读后的记录，否则页面把「私钥已就绪」显示成「无私钥」");
    }

    // ------------------------------------------------------------------
    // 二、signPendingServerIdentity
    // ------------------------------------------------------------------

    /** 用本地根 CA 签发：签出的证书与留存私钥配对，issuer 就是该 CA。 */
    @Test
    void signWithLocalCaProducesPairedCert() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114Cert pending = pendingRecord(50, Gb35114Cert.TYPE_SERVER_IDENTITY);
        when(certMapper.query(50)).thenReturn(pending);
        when(caMapper.query(9)).thenReturn(ca(9, Gb35114Ca.TYPE_LOCAL_CA, localCa));

        service.signPendingServerIdentity(50, 9, 3650);

        ArgumentCaptor<String> pem = ArgumentCaptor.forClass(String.class);
        verify(certMapper).completeCert(eq(50), pem.capture(), anyString(), anyString(), anyString(),
                eq(9), eq((Integer) 3650), anyString(), anyString());
        String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(),
                pending.getKeyPem());
        assertTrue(Gb35114CertUtil.matches(pem.getValue(), keyPem),
                "签出的证书必须与留存的私钥配对，否则设备侧验 sign2 必然失败");
        X509Certificate issued = Gb35114CertUtil.loadCertificate(pem.getValue());
        assertEquals(Gb35114CertUtil.subjectDn(localCa.certificate),
                Gb35114CertUtil.issuerDn(issued), "issuer 必须是那张本地 CA");
    }

    /** {@code caId} 为空 → 自签，且仍与留存私钥配对（复用 CSR 里的公钥，不新生成密钥对）。 */
    @Test
    void signWithoutCaIdIsSelfSignedAndStillPaired() throws Exception {
        Gb35114Cert pending = pendingRecord(51, Gb35114Cert.TYPE_SERVER_IDENTITY);
        when(certMapper.query(51)).thenReturn(pending);

        service.signPendingServerIdentity(51, null, 3650);

        ArgumentCaptor<String> pem = ArgumentCaptor.forClass(String.class);
        verify(certMapper).completeCert(eq(51), pem.capture(), anyString(), anyString(), anyString(),
                eq((Integer) null), eq((Integer) 3650), anyString(), anyString());
        String keyPem = Gb35114KeyProtector.decrypt(config.getKeyEncryptPassword(),
                pending.getKeyPem());
        assertTrue(Gb35114CertUtil.matches(pem.getValue(), keyPem),
                "自签分支若新生成密钥对，签出的证书就与留存私钥不配对了");
        X509Certificate issued = Gb35114CertUtil.loadCertificate(pem.getValue());
        assertTrue(Gb35114CertUtil.isSelfSigned(issued));
    }

    /**
     * 只接受服务端用途 —— 这条挡的是「用本地根 CA 给自己签客户端证书」。
     *
     * <p>签出来的证书接入上级必然被拒（上级那边没有签发记录），而本平台侧日志一切正常，
     * 排查方向很容易跑偏。复用 {@code requireLocallyIssuableType} 正是为此。
     */
    @Test
    void signingDeviceIdentityIsRejected() throws Exception {
        Gb35114Cert pending = pendingRecord(52, Gb35114Cert.TYPE_DEVICE_IDENTITY);
        when(certMapper.query(52)).thenReturn(pending);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.signPendingServerIdentity(52, null, 3650));
        assertTrue(e.getMessage().contains("必须由上级签发"), "实际: " + e.getMessage());
        verify(certMapper, never()).completeCert(anyInt(), anyString(), anyString(), anyString(),
                anyString(), any(), anyInt(), anyString(), anyString());
    }

    /** 已签发的记录不能重复签发。 */
    @Test
    void signingAlreadyIssuedRecordIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity existing = Gb35114CertUtil.generateSelfSigned(
                name(PLATFORM_ID), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_ENTITY);
        Gb35114Cert done = pendingRecord(53, Gb35114Cert.TYPE_SERVER_IDENTITY);
        done.setCertPem(existing.certPem);
        when(certMapper.query(53)).thenReturn(done);

        assertThrows(IllegalArgumentException.class,
                () -> service.signPendingServerIdentity(53, null, 3650));
        verify(certMapper, never()).completeCert(anyInt(), anyString(), anyString(), anyString(),
                anyString(), any(), anyInt(), anyString(), anyString());
    }

    /** 受信任的 CA 不能用来签发 —— 它只有公钥，本平台没有它的私钥。 */
    @Test
    void signingWithTrustedCaIsRejected() throws Exception {
        Gb35114CertUtil.Gb35114Identity foreign = Gb35114CertUtil.generateSelfSigned(
                name("Third Party CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114Cert pending = pendingRecord(54, Gb35114Cert.TYPE_SERVER_IDENTITY);
        when(certMapper.query(54)).thenReturn(pending);
        when(caMapper.query(11)).thenReturn(ca(11, Gb35114Ca.TYPE_TRUSTED_CA, foreign));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.signPendingServerIdentity(54, 11, 3650));
        assertTrue(e.getMessage().contains("只能使用本地 CA"), "实际: " + e.getMessage());
        verify(certMapper, never()).completeCert(anyInt(), anyString(), anyString(), anyString(),
                anyString(), any(), anyInt(), anyString(), anyString());
    }

    /**
     * 没有留存私钥的记录拒绝签发，且不写库。
     *
     * <p>无本地私钥就无法复用 CSR 里的公钥 —— 签出的证书会与设备侧持有的私钥不配对。
     * 这种情况该走「回填」（导入外部签发的证书），错误信息里点名。
     */
    @Test
    void signingWithoutLocalKeyIsRejected() throws Exception {
        Gb35114Cert pending = pendingRecord(55, Gb35114Cert.TYPE_SERVER_IDENTITY);
        pending.setKeyPem(null);
        when(certMapper.query(55)).thenReturn(pending);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.signPendingServerIdentity(55, null, 3650));
        assertTrue(e.getMessage().contains("回填"), "应指向「回填」这条出口，实际: " + e.getMessage());
        verify(certMapper, never()).completeCert(anyInt(), anyString(), anyString(), anyString(),
                anyString(), any(), anyInt(), anyString(), anyString());
    }

    /** 记录不存在时给出可读错误，而不是 NPE。 */
    @Test
    void signingMissingRecordIsRejected() {
        when(certMapper.query(56)).thenReturn(null);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> service.signPendingServerIdentity(56, null, 3650));
        assertTrue(e.getMessage().contains("证书不存在"), "实际: " + e.getMessage());
    }

    // ------------------------------------------------------------------
    // 三、reissueFromCsr 的用途过滤
    // ------------------------------------------------------------------

    /**
     * <b>「由下级 CSR 签发」不得复用服务端证书的待签发记录</b>。
     *
     * <p>{@code queryByCsrPem} 原先只按 CSR 内容匹配、无用途过滤。一张服务端 CSR 会被这条
     * 路径找到并按 {@code ISSUED_DEVICE} 的语义签掉：证书落成「下级设备」用途、私钥被置空，
     * 服务端证书的私钥记录就此毁掉。用途过滤把这条堵上 —— 查不到历史就落新行，原记录不动。
     */
    @Test
    void reissueDoesNotReuseServerCsrRecord() throws Exception {
        Gb35114CertUtil.Gb35114Identity localCa = Gb35114CertUtil.generateSelfSigned(
                name("Local Root CA"), new Date(), later(3650), Gb35114CertUtil.KEY_USAGE_CA);
        Gb35114Cert pending = pendingRecord(60, Gb35114Cert.TYPE_SERVER_IDENTITY);
        when(caMapper.query(9)).thenReturn(ca(9, Gb35114Ca.TYPE_LOCAL_CA, localCa));
        // 用途过滤后查不到 ISSUED_DEVICE 的历史记录
        when(certMapper.queryByCsrPem(anyString(), eq(Gb35114Cert.TYPE_ISSUED_DEVICE)))
                .thenReturn(Collections.emptyList());

        service.reissueFromCsr(9, "35020000001320000001", null, pending.getCsrPem(), 365,
                "digitalSignature");

        // 必须落新行，且原待签发记录不得被改写
        verify(certMapper).add(any());
        verify(certMapper, never()).completeCert(eq(60), anyString(), anyString(), anyString(),
                anyString(), any(), anyInt(), anyString(), anyString());
    }
}
