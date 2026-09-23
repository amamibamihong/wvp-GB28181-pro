package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GB35114 安全门面，串联平台侧（UAS）与设备侧（UAC）状态机、证书服务与 VKEK 缓存。
 *
 * <ul>
 *   <li>UAS：本平台作为平台，收下级设备的国密证书注册（{@link Gb35114PlatformStateMachine}）。</li>
 *   <li>UAC：本平台作为下级，向上级平台的国密证书注册（{@link Gb35114DeviceStateMachine}）。</li>
 * </ul>
 */
@Component
public class Gb35114SecurityService {

    private static final Logger log = LoggerFactory.getLogger(Gb35114SecurityService.class);

    @Autowired
    private Gb35114Config config;

    @Autowired
    private IGb35114CertService certService;

    @Autowired
    private Gb35114VkekCache vkekCache;

    /**
     * UAS 平台侧状态机，按「服务器证书 ID」索引。
     *
     * <p>平台可以并存多张服务端证书，不同设备信任的可能是不同的那一张：签 sign2 的
     * 私钥必须与设备配置时导入的公钥配对，否则设备验签失败并拒绝对后续信令服务。
     * 因此状态机不能是单例，必须按证书分实例，一台设备一个签名身份。
     *
     * <p>key 为 {@code serverid|certId}；certId 为 0 表示无身份（Unidirection 退化）。
     */
    private final Map<String, Gb35114PlatformStateMachine> platformStateMachines = new ConcurrentHashMap<>();

    /** UAC 设备侧状态机，按上级平台 serverGBId 索引。 */
    private final Map<String, Gb35114DeviceStateMachine> deviceStateMachines = new ConcurrentHashMap<>();

    /** 国密是否可用（总开关 + 证书配置齐全）。 */
    public boolean isEnabled() {
        return config.isEnabled();
    }

    /**
     * 获取 UAS 平台侧状态机（按设备实际信任的证书选择签名身份）。
     *
     * <p>证书选择优先级：
     * <ol>
     *   <li>{@code certId} —— 调用方传入的<b>设备级绑定</b>（{@code wvp_device.server_cert_id}）；</li>
     *   <li>证书表中<b>唯一的</b>那张 {@code SERVER_IDENTITY}（由后端唯一性约束保证无歧义）。</li>
     * </ol>
     *
     * <p>用哪张证书<b>不再由配置文件指定</b>：{@code gb35114.server-cert-id} 这类写法把数据库主键
     * 写死在 yml 里，证书一旦重建（ID 自增不回退）配置就指向不存在的行，且只在设备注册时才暴露。
     * 现在证书的存在与唯一性都由数据库保证，配置只管开关与策略。
     *
     * <p>都取不到时退化为 Unidirection —— 此时无法签发 sign2，要求导入服务端 CA
     * 的摄像头会注册失败。
     *
     * @param certId 该设备绑定的服务器证书 ID，可为 null
     */
    public Gb35114PlatformStateMachine platformStateMachine(String nodeId, String sipId, Integer certId) {
        Integer resolved = resolveServerCertId(certId);
        // 国密握手中校验的 serverid 是平台国标编码（sip.id），节点标识变化不影响协议，
        // 但 state machine 持有 serverId，两者任一变化都需要重建。
        String stateMachineKey = sipId != null && !sipId.isEmpty() ? sipId : nodeId;
        String mapKey = stateMachineKey + "|" + resolved;
        return platformStateMachines.computeIfAbsent(mapKey, k -> {
            Gb35114CertUtil.Gb35114Identity identity = null;
            if (resolved != null) {
                // 加载失败不降级：降级成 Unidirection 会让本该被拒的设备静默注册成功，
                // 而设备侧仍期待 Bidirection 的 sign2，双方对认证等级的认知就此错开。
                identity = certService.loadIdentity(resolved);
            }
            Gb35114PlatformStateMachine machine = new Gb35114PlatformStateMachine(stateMachineKey, identity);
            // 动态设备证书来源：只信任本平台签发给下级的、未吊销且未过期的下级客户端证书
            machine.setCertProvider(deviceId -> {
                Gb35114Cert cert = certService.queryIssuedDeviceCert(deviceId);
                return cert == null ? null : certService.loadCert(cert.getId());
            });
            // 设备在 Capability 自报的证书不过数据库，必须按公钥指纹反查吊销状态，
            // 否则持一张已吊销的旧证书自报即可重新接入。
            machine.setCertValidator(certService::validateAnnouncedDeviceCert);
            // 取不到证书时给出可行动的原因（未签发 / 已吊销 / 已过期），
            // 避免只报 "device cert" 让人误判为没配证书。
            machine.setCertUnavailableReason(certService::describeDeviceCertUnavailable);
            log.info("[GB35114] UAS 状态机已初始化，serverid={}，模式={}，服务器证书={}",
                    stateMachineKey, machine.mode(), resolved == null ? "无" : ("#" + resolved));
            return machine;
        });
    }

    /** 兼容旧调用：不指定设备级绑定时按证书表中的服务端证书选择。 */
    public Gb35114PlatformStateMachine platformStateMachine(String nodeId, String sipId) {
        return platformStateMachine(nodeId, sipId, null);
    }

    /**
     * 丢弃某个平台编码下的全部 UAS 状态机。
     *
     * <p>证书新增/吊销/删除后调用：状态机持有签名身份与已协商的 VKEK，
     * 换证书后必须重建，否则会继续用旧私钥签 sign2。
     */
    public void invalidatePlatformStateMachines(String sipId) {
        String prefix = sipId + "|";
        platformStateMachines.keySet().removeIf(k -> k.startsWith(prefix));
    }

    /** 丢弃全部 UAS 状态机（证书集发生变动、无法定位受影响平台时使用）。 */
    public void invalidateAllPlatformStateMachines() {
        platformStateMachines.clear();
    }

    /**
     * 丢弃全部证书相关的状态机缓存：UAS（平台侧）与 UAC（设备侧）都清。
     *
     * <p>证书集变动后<b>两侧都要清</b>：UAS 侧缓存签 sign2 的身份，UAC 侧缓存签 sign1 的
     * 身份与已协商的 VKEK。而「同密钥再签」是<b>原地更新</b>（证书 ID 不变），
     * 复合键 {@code serverId|deviceCertId|platformCertId} 因此不变，
     * 只清 UAS 侧会让 UAC 侧继续用换发前的旧证书。
     */
    public void invalidateAllCertStateMachines() {
        platformStateMachines.clear();
        deviceStateMachines.clear();
    }

    /**
     * 解析本次注册应使用的服务器证书 ID。
     *
     * <p>优先级：<b>设备级绑定 &gt; 证书表中唯一的那张 SERVER_IDENTITY</b>。
     * 不再有「全局配置」这一层 —— 见 {@link #platformStateMachine} 的说明。
     *
     * <p><b>两条路径共用同一条规则：在「指定的那张证书所属的密钥组」内解析可用的证书。</b>
     * 因为签名身份的本质是<b>密钥对</b>而非证书 —— 设备只存公钥，同一密钥对签出的多张
     * 证书（有效期不同、签发者不同、序列号不同）对设备完全等价。所以指定的证书过期时，
     * 只要同组还有可用证书就继续用，设备无需重新配置；同组全过期才拒绝。
     *
     * <p>唯一不参与顺延的是<b>吊销</b> —— 见
     * {@link IGb35114CertService#resolveUsableServerIdentity(int)}。
     *
     * <p>顺延<b>绝不跨密钥组</b>：那等于悄悄换掉设备信任的公钥，设备验 sign2 必然失败，
     * 且平台日志上一切正常（确实签了名，只是用错了身份），故障点会漂到设备侧。
     *
     * @throws Gb35114Exception 指定的证书已吊销、用途不符，或同组内已无可用证书
     */
    private Integer resolveServerCertId(Integer deviceBoundCertId) {
        if (deviceBoundCertId != null) {
            Gb35114Cert resolved = certService.resolveUsableServerIdentity(deviceBoundCertId);
            if (resolved == null) {
                throw new Gb35114Exception("设备绑定的服务器证书 #" + deviceBoundCertId
                        + " 已不可用（已吊销 / 已过期），且同密钥组内无可用证书，拒绝注册");
            }
            return resolved.getId();
        }
        // 未绑定：用证书表中唯一的那张服务端证书。SERVER_IDENTITY 由后端强制唯一
        // （见 assertNoActiveServerIdentity），换发走「同密钥再签」原地更新，不新增行，
        // 因此这里不存在「选哪张」的歧义，也无需 is_default 标记。
        Gb35114Cert active = certService.queryDefaultServerIdentity();
        return active == null ? null : active.getId();
    }

    /**
     * 获取（或创建）UAC 设备侧状态机，用于本平台向上级平台注册。
     *
     * @param deviceIdentity 本平台作为下级注册的设备身份
     * @param platformCert   上级平台签名证书（Bidirection 验 sign2，可为 null）
     * @param deviceId       本平台向上注册的国标编码
     * @param serverId       上级平台国标编码
     */
    public Gb35114DeviceStateMachine deviceStateMachine(Gb35114CertUtil.Gb35114Identity deviceIdentity,
                                                       X509Certificate platformCert,
                                                       String deviceId, String serverId) {
        return deviceStateMachine(deviceIdentity, platformCert, deviceId, serverId, null, null);
    }

    private Gb35114DeviceStateMachine deviceStateMachine(Gb35114CertUtil.Gb35114Identity deviceIdentity,
                                                        X509Certificate platformCert,
                                                        String deviceId, String serverId,
                                                        Integer deviceCertId, Integer platformCertId) {
        // 证书配置变化时按复合 key 重建，避免复用旧证书签出的握手状态。
        String key = serverId + "|" + deviceCertId + "|" + platformCertId;
        return deviceStateMachines.computeIfAbsent(key,
                k -> new Gb35114DeviceStateMachine(deviceIdentity, platformCert, deviceId, serverId, null));
    }

    /** 移除某个上级平台的 UAC 状态机（注销/下线时）。 */
    public void removeDeviceStateMachine(String serverId) {
        deviceStateMachines.keySet().removeIf(k -> k.startsWith(serverId + "|"));
    }

    /**
     * 加载本平台作为下级注册用的设备身份（本地客户端证书，DEVICE_IDENTITY）。
     *
     * <p>该用途<b>不唯一</b>（可接入多个上级），按 {@code gbId} 解析；解析不到时返回
     * {@code null}，由调用方给出「未配置证书」的明确报错 —— 详见
     * {@link IGb35114CertService#queryDeviceIdentity(String)}。
     */
    public Gb35114CertUtil.Gb35114Identity loadDeviceIdentity() {
        return loadDeviceIdentityByPlatform(null);
    }

    /**
     * 按上级平台国标编码加载本平台的设备身份，{@code null} 表示未配置或有歧义。
     *
     * @param serverGbId 上级平台国标编码；为空时仅在候选唯一的情况下取用
     */
    public Gb35114CertUtil.Gb35114Identity loadDeviceIdentityByPlatform(String serverGbId) {
        Gb35114Cert cert = certService.queryDeviceIdentity(serverGbId);
        return cert == null ? null : certService.loadIdentity(cert.getId());
    }

    /**
     * 加载上级平台证书（TRUSTED_PLATFORM，仅公钥，用于验 sign2）。
     *
     * <p>同样不唯一（多个上级各有各的），按上级国标编码解析；解析不到返回 {@code null}。
     */
    public X509Certificate loadPlatformCert() {
        return loadPlatformCertByServer(null);
    }

    /**
     * 按上级平台国标编码加载其签名证书，{@code null} 表示未导入或有歧义。
     *
     * @param serverGbId 上级平台国标编码；为空时仅在候选唯一的情况下取用
     */
    public X509Certificate loadPlatformCertByServer(String serverGbId) {
        Gb35114Cert cert = certService.queryTrustedPlatformCert(serverGbId);
        return cert == null ? null : certService.loadCert(cert.getId());
    }

    /**
     * 获取（或创建）本平台作为下级的 UAC 状态机，按上级平台国标编码解析证书。
     * 解析不到设备证书（无法签 sign1）时返回 {@code null}。
     */
    public Gb35114DeviceStateMachine uacStateMachine(String deviceId, String serverId) {
        return uacStateMachine(deviceId, serverId, null, null);
    }

    /**
     * 获取（或创建）本平台作为下级的 UAC 状态机。
     *
     * <p>证书优先取<b>上级平台（per-platform）配置</b>（{@code wvp_platform.device_cert_id} /
     * {@code platform_cert_id}，调用方从 {@code parentPlatform} 传入），未配置时<b>从证书表按
     * 上级国标编码解析</b>。这支撑「一个下级平台接入多个上级」：每个上级绑自己的那张证书，
     * 互不干扰；没绑定时只要该用途只有一张也能跑起来。
     *
     * <p>不再回退 {@code gb35114.device-cert-id} 这类全局配置 —— 全局只能容纳一个上级，
     * 接入第二个时要么改配置影响第一个，要么解析出错，且配置里写数据库主键在证书重建后悬空。
     *
     * @param deviceId       本平台向上注册的国标编码
     * @param serverId       上级平台国标编码
     * @param deviceCertId   本平台设备证书 ID（可为 null，回退按 serverId 解析）
     * @param platformCertId 上级平台证书 ID（可为 null，回退按 serverId 解析）
     */
    public Gb35114DeviceStateMachine uacStateMachine(String deviceId, String serverId,
                                                     Integer deviceCertId, Integer platformCertId) {
        Integer effectiveDeviceCertId = deviceCertId != null
                ? deviceCertId
                : idOf(certService.queryDeviceIdentity(serverId));
        Gb35114CertUtil.Gb35114Identity identity = loadDeviceIdentity(effectiveDeviceCertId);
        if (identity == null) {
            return null;
        }
        Integer effectivePlatformCertId = platformCertId != null
                ? platformCertId
                : idOf(certService.queryTrustedPlatformCert(serverId));
        X509Certificate platformCert = loadPlatformCert(effectivePlatformCertId);
        return deviceStateMachine(identity, platformCert, deviceId, serverId,
                effectiveDeviceCertId, effectivePlatformCertId);
    }

    /** 按证书 ID 加载设备身份，null 表示无。 */
    public Gb35114CertUtil.Gb35114Identity loadDeviceIdentity(Integer certId) {
        if (certId == null) {
            return null;
        }
        return certService.loadIdentity(certId);
    }

    /** 按证书 ID 加载上级平台证书，null 表示无。 */
    public X509Certificate loadPlatformCert(Integer certId) {
        if (certId == null) {
            return null;
        }
        return certService.loadCert(certId);
    }

    private static Integer idOf(Gb35114Cert cert) {
        return cert == null ? null : cert.getId();
    }
}
