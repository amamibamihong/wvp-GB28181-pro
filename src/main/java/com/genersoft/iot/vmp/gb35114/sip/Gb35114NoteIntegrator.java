package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb28181.bean.Device;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import gov.nist.javax.sip.message.SIPMessage;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.sip.header.CallIdHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.Header;
import javax.sip.header.ToHeader;
import javax.sip.message.Request;

import javax.sip.address.SipURI;
import javax.sip.address.URI;

/**
 * 把 GB35114 的 Note 完整性认证接到 wvp 的两个集中点：
 * <ul>
 *   <li>出站：{@link #decorateOutgoing}（由 SIPSender 调用），对非 REGISTER 请求按
 *       对端国标 ID 查 VKEK，命中则注入 Date + Note。</li>
 *   <li>入站：{@link #verifyIncoming}（由 SIPProcessorObserver 调用），对带 Note 的
 *       非 REGISTER 请求验签，失败返回 false 以回 403。</li>
 * </ul>
 *
 * <p>对端 ID 的判定：出站取 To 头 URI 的 user（设备或上级平台编码），入站取 From 头
 * URI 的 user——两者都进同一 {@link Gb35114VkekCache}，天然覆盖 UAS/UAC 两种角色。
 */
@Component
public class Gb35114NoteIntegrator {

    private static final Logger log = LoggerFactory.getLogger(Gb35114NoteIntegrator.class);

    @Autowired
    private Gb35114Config config;

    @Autowired
    private Gb35114VkekCache vkekCache;

    @Autowired
    private Gb35114NoteService noteService;

    /**
     * 按通道国标编码反查设备的服务。
     *
     * <p>用 {@link ObjectProvider} 延迟获取而非直接 {@code @Autowired}：
     * {@code IDeviceService → ISIPCommander → SipLayer → SIPProcessorObserver →
     * Gb35114NoteIntegrator}，直接注入会形成 Bean 循环依赖，导致应用启动失败。
     * 这里只在真正需要反查时才向容器要一次。
     */
    @Autowired
    private org.springframework.beans.factory.ObjectProvider<
            com.genersoft.iot.vmp.gb28181.service.IDeviceService> deviceServiceProvider;

    /** 把 YAML 里的 Note 参数应用到无状态的 {@link Gb35114HeaderUtil}（启动与热更新各一次）。 */
    @PostConstruct
    public void applyConfig() {
        Gb35114HeaderUtil.setVkekDigestForm(config.getNote().getVkekForm());
        log.info("[GB35114] Note 认证参数：enabled={}，VKEK 拼接形式={}",
                config.getNote().isEnabled(), Gb35114HeaderUtil.vkekDigestForm());
    }

    /** 出站加签：仅对非 REGISTER 且已协商 VKEK 的请求注入 Date + Note。 */
    public void decorateOutgoing(javax.sip.message.Message message) {
        if (!config.isEnabled() || !config.getNote().isEnabled() || !(message instanceof Request)) {
            return;
        }
        Request request = (Request) message;
        if (Request.REGISTER.equals(request.getMethod())) {
            return;
        }
        String peerId = uriUser(request.getHeader(ToHeader.NAME));
        if (peerId == null) {
            return;
        }
        byte[] vkek = vkekCache.get(peerId);
        if (vkek == null) {
            // To 头指向的是「通道」而非「设备」时（INVITE/点播等针对通道的信令就是这样，
            // 如 To: <sip:34020000001320000001@…>，而 VKEK 是注册时按设备编码
            // 35020000001320000001 协商并缓存的），直接查必然落空。
            //
            // 这里若静默返回，请求就会以「无 Note」的形式发出 —— 设备按 A 级要求校验
            // 完整性，一律回 403，表现为「注册成功、目录能拿到，但一点播就 Forbidden」。
            // 因此按通道反查其所属设备，用设备的 VKEK 加签。
            String ownerId = deviceIdOfChannel(peerId);
            if (ownerId != null) {
                vkek = vkekCache.get(ownerId);
                if (vkek != null) {
                    peerId = ownerId;
                }
            }
        }
        if (vkek == null) {
            // 真的没协商过（例如设备尚未完成 Bidirection 握手）：不静默，留痕便于定位。
            log.warn("[GB35114] 出站加签跳过 method={}, to={}：未找到该对端的 VKEK",
                    request.getMethod(), peerId);
            return;
        }

        String method = request.getMethod();
        String from = Gb35114SipHeaders.value(request.getHeader(FromHeader.NAME));
        String to = Gb35114SipHeaders.value(request.getHeader(ToHeader.NAME));
        String callId = ((CallIdHeader) request.getHeader(CallIdHeader.NAME)).getCallId();
        // 消息体必须用原始字节：MANSCDP 常声明 encoding="GB2312"，转字符串会破坏非 ASCII 字节。
        byte[] body = request.getRawContent();

        String[] dateNote = noteService.buildNote(method, from, to, callId, body, vkek);
        Gb35114SipHeaders.addRawHeader(message, "Date", dateNote[0]);
        Gb35114SipHeaders.addRawHeader(message, "Note", dateNote[1]);
        // 现场联调定位用：把参与摘要的各段原样打出来，便于与对端回包离线复算比对。
        log.info("[GB35114] 出站加签 method={}, callId={}, date={}, vkek={}, from={}, to={}, body={}",
                method, callId, dateNote[0], toHex(vkek), from, to,
                body == null ? "" : new String(body, java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 入站验签。返回 {@code false} 表示应拒绝（回 403）。无 Note 的请求放行
     * （兼容混跑 Digest 平台）；Note 存在但验签失败则拒绝。
     */
    public boolean verifyIncoming(Request request) {
        if (!config.isEnabled() || !config.getNote().isEnabled()
                || Request.REGISTER.equals(request.getMethod())) {
            return true;
        }
        String note = Gb35114SipHeaders.rawHeaderValue(request, "Note");
        if (note == null && request instanceof SIPMessage) {
            // 值里含空格等字符时也可能落到 unrecognizedHeaders
            note = Gb35114SipHeaders.unparsedHeaderValue((SIPMessage) request, "Note");
        }
        if (note == null || note.isEmpty()) {
            return true;
        }

        String peerId = uriUser(request.getHeader(FromHeader.NAME));
        String method = request.getMethod();
        String from = Gb35114SipHeaders.value(request.getHeader(FromHeader.NAME));
        String to = Gb35114SipHeaders.value(request.getHeader(ToHeader.NAME));
        String callId = ((CallIdHeader) request.getHeader(CallIdHeader.NAME)).getCallId();
        // 消息体必须用原始字节：MANSCDP 常声明 encoding="GB2312"，转字符串会破坏非 ASCII 字节。
        byte[] body = request.getRawContent();

        // ISO8601 的 Date 会被标准 DateParser 拒收、落到 unrecognizedHeaders，需单独取。
        String date = Gb35114SipHeaders.rawHeaderValue(request, "Date");
        if (date == null && request instanceof SIPMessage) {
            date = Gb35114SipHeaders.unparsedHeaderValue((SIPMessage) request, "Date");
        }

        byte[] vkek = peerId == null ? null : vkekCache.get(peerId);
        try {
            noteService.verifyNote(note, method, from, to, callId, date, body, vkek);
            return true;
        } catch (Gb35114Exception e) {
            log.warn("[GB35114] 入站 Note 验签失败, peer={}, method={}, date={}: {}",
                    peerId, method, date, e.getMessage());
            return false;
        }
    }

    /**
     * 按「通道国标编码」反查其所属设备编码。
     *
     * <p>点播类信令的 To 头指向通道（{@code <sip:34020000001320000001@…>}），
     * 而 VKEK 是注册时按设备编码协商的，两者对不上。查不到时返回 {@code null}，
     * 由调用方按「未协商」处理。
     */
    private String deviceIdOfChannel(String channelId) {
        try {
            com.genersoft.iot.vmp.gb28181.service.IDeviceService deviceService =
                    deviceServiceProvider.getIfAvailable();
            if (deviceService == null) {
                return null;
            }
            Device device = deviceService.getDeviceBySourceChannelDeviceId(channelId);
            return device == null ? null : device.getDeviceId();
        } catch (Exception e) {
            // 反查失败不影响加签本身：当作没找到，由上层记日志跳过。
            log.debug("[GB35114] 按通道反查设备失败 channelId={}: {}", channelId, e.getMessage());
            return null;
        }
    }

    /** 从 From/To 头取 URI 的 user（国标编码）。 */
    private static String uriUser(Header header) {
        if (header == null) {
            return null;
        }
        try {
            URI uri = null;
            if (header instanceof FromHeader) {
                uri = ((FromHeader) header).getAddress().getURI();
            } else if (header instanceof ToHeader) {
                uri = ((ToHeader) header).getAddress().getURI();
            }
            if (uri instanceof SipURI) {
                return ((SipURI) uri).getUser();
            }
        } catch (Exception ignored) {
            // 头缺失或结构异常时视为无法判定对端，交给上层跳过/放行。
        }
        return null;
    }
}
