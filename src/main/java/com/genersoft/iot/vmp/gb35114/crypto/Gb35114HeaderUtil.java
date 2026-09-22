package com.genersoft.iot.vmp.gb35114.crypto;

import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GB35114 A 级 SIP 头构建与解析，线格式逐字节对齐 gb28181-rs 的
 * {@code security35114::headers} 与 {@code security35114::integrity}。
 *
 * <p>三个认证头：
 * <ul>
 *   <li>{@code Authorization: Capability/Unidirection/Bidirection}（设备 → 平台）</li>
 *   <li>{@code WWW-Authenticate: Unidirection/Bidirection}（401 挑战）</li>
 *   <li>{@code SecurityInfo: Unidirection/Bidirection}（200 OK 结果）</li>
 * </ul>
 */
public final class Gb35114HeaderUtil {

    /** 算法能力串，与 Rust {@code CAPABILITY_ALGORITHM} 一致。 */
    public static final String CAPABILITY_ALGORITHM = "A:SM2;H:SM3;S:SM4/OFB/PKCS5;SI:SM3-SM2";

    /**
     * GB35114 的 Date 头（ISO8601、无时区后缀）。
     *
     * <p>用<b>服务器本地时区</b>渲染（不写死 UTC）：标准只要求「Date 精确到秒」，
     * 未规定时区，现场按本地时间生成更符合运维直觉。
     *
     * <p>注意时区<b>不影响摘要校验</b>——Note 的摘要输入用的是线上的 Date 原字符串，
     * 收录端原样取回即可，因此两端时区不同不会导致验签失败。时区只影响「新鲜度」
     * 这一个判断，见 {@link #dateCandidates(String)}：入站按本地时区与 UTC 两种解释
     * 取其一命中即可，不要求对端与我们同时区。
     */
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS")
                    .withLocale(Locale.ROOT)
                    .withZone(ZoneId.systemDefault());

    /** 秒精度变体：设备侧通常只精确到秒。 */
    private static final DateTimeFormatter DATE_FORMAT_SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
                    .withLocale(Locale.ROOT)
                    .withZone(ZoneId.systemDefault());

    private Gb35114HeaderUtil() {
    }

    /** 认证方案。 */
    public enum Mode {
        Unidirection,
        Bidirection;

        public String asStr() {
            return name();
        }

        public static Mode fromStr(String s) {
            for (Mode m : values()) {
                if (m.name().equals(s)) {
                    return m;
                }
            }
            return null;
        }
    }

    /** 401 挑战头解析结果。 */
    public static final class Challenge {
        public final Mode mode;
        public final String algorithm;
        public final String random1;

        public Challenge(Mode mode, String algorithm, String random1) {
            this.mode = mode;
            this.algorithm = algorithm;
            this.random1 = random1;
        }
    }

    /** Capability 宣告解析结果。 */
    public static final class CapabilityAnnouncement {
        public final String algorithm;
        public final String keyVersion;
        public final String deviceCertPem;

        public CapabilityAnnouncement(String algorithm, String keyVersion, String deviceCertPem) {
            this.algorithm = algorithm;
            this.keyVersion = keyVersion;
            this.deviceCertPem = deviceCertPem;
        }
    }

    /** 已认证 REGISTER 的 Authorization 解析结果。 */
    public static final class AuthAuthorization {
        public final Mode mode;
        public final String random1;
        public final String random2;
        public final String serverId;
        public final String deviceId;
        public final String sign1;
        public final String algorithm;

        public AuthAuthorization(Mode mode, String random1, String random2, String serverId,
                                 String deviceId, String sign1, String algorithm) {
            this.mode = mode;
            this.random1 = random1;
            this.random2 = random2;
            this.serverId = serverId;
            this.deviceId = deviceId;
            this.sign1 = sign1;
            this.algorithm = algorithm;
        }
    }

    /** SecurityInfo 头解析/构建结果。 */
    public static final class SecurityInfo {
        public Mode mode;
        public String algorithm;
        public String random1;
        public String random2;
        public String deviceId;
        public String serverId;
        public String cryptKey;
        public String sign2;

        public SecurityInfo() {
        }
    }

    // ------------------------------------------------------------------
    // Capability / Challenge / Authorization / SecurityInfo
    // ------------------------------------------------------------------

    /** 构建首包 REGISTER 的 Capability 宣告头。 */
    public static String buildCapabilityAuthorization(String keyVersion, String certPem) {
        StringBuilder out = new StringBuilder();
        out.append("Capability algorithm=\"").append(CAPABILITY_ALGORITHM)
                .append("\", keyversion=\"").append(keyVersion).append("\"");
        if (certPem != null && !certPem.isEmpty()) {
            out.append(", cnonce=\"devicecert:")
                    .append(Base64.getEncoder().encodeToString(certPem.getBytes(StandardCharsets.UTF_8)))
                    .append("\"");
        }
        return out.toString();
    }

    /** 解析首包 REGISTER 的 Capability 宣告头。 */
    public static CapabilityAnnouncement parseCapabilityAuthorization(String authorization) {
        String[] scheme = splitScheme(authorization);
        if (!"Capability".equals(scheme[0])) {
            throw new Gb35114Exception("not a GB35114 Capability announcement: " + authorization);
        }
        ParamMap params = parseParams(scheme[1]);
        String algorithm = params.get("algorithm");
        if (algorithm.isEmpty()) {
            throw new Gb35114Exception("Capability announcement missing algorithm");
        }
        String cnonce = params.get("cnonce");
        String deviceCertPem = "";
        if (cnonce.startsWith("devicecert:")) {
            deviceCertPem = new String(Base64.getDecoder().decode(cnonce.substring("devicecert:".length())),
                    StandardCharsets.UTF_8);
        }
        return new CapabilityAnnouncement(algorithm, params.get("keyversion"), deviceCertPem);
    }

    /** 构建 401 的 WWW-Authenticate 挑战头（平台侧）。 */
    public static String buildChallenge(Mode mode, String random1) {
        return buildChallenge(mode, random1, null);
    }

    /**
     * 构建 401 的 WWW-Authenticate 挑战头（平台侧）。
     *
     * <p>标准 §C.3 b) 要求 {@code algorithm} 是「SIP 服务器从设备上报的安全能力算法中
     * 选择获得」的结果，且明确包含<b>非对称、杂凑、对称</b>三段（用分号分隔）。设备在
     * Capability 里通告的算法串往往还带 S/SI 段，只回 {@code A:SM2;H:SM3} 会让协商结果
     * 与设备预期不一致，部分设备（如海康）会因此在后续信令上拒绝服务。
     *
     * @param deviceCapability 设备 Capability 里上报的算法串，为 null/空时退回内置默认值
     */
    public static String buildChallenge(Mode mode, String random1, String deviceCapability) {
        return mode.asStr() + " algorithm=\"" + negotiateAlgorithm(deviceCapability)
                + "\", random1=\"" + random1 + "\"";
    }

    /**
     * 从设备上报的能力串中选出本次会话使用的算法。
     *
     * <p>按 A / H / S / SI 四段逐段取设备通告的值：我们实际只会用到 SM2+SM3，但 S/SI
     * 段是设备声明的「支持能力」，标准要求挑战里体现出来，缺段会被判为协商失败。
     * 设备未通告的段用内置默认值补齐。
     */
    public static String negotiateAlgorithm(String deviceCapability) {
        if (deviceCapability == null || deviceCapability.trim().isEmpty()) {
            return CAPABILITY_ALGORITHM;
        }
        Map<String, String> announced = new HashMap<>();
        for (String part : deviceCapability.split(";")) {
            int colon = part.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            announced.put(part.substring(0, colon).trim().toUpperCase(Locale.ROOT),
                    part.substring(colon + 1).trim());
        }
        // 顺序固定为 A/H/S/SI：标准按此顺序描述，设备也按此解析
        String[] sections = {"A", "H", "S", "SI"};
        List<String> chosen = new ArrayList<>(sections.length);
        for (String section : sections) {
            String value = announced.get(section);
            if (value != null && !value.isEmpty()) {
                chosen.add(section + ":" + value);
            }
        }
        if (chosen.isEmpty()) {
            return CAPABILITY_ALGORITHM;
        }
        // 缺段时用默认值补齐，避免出现只有 A 段的挑战
        Map<String, String> defaults = new HashMap<>();
        for (String part : CAPABILITY_ALGORITHM.split(";")) {
            int colon = part.indexOf(':');
            if (colon > 0) {
                defaults.put(part.substring(0, colon).trim().toUpperCase(Locale.ROOT),
                        part.substring(colon + 1).trim());
            }
        }
        List<String> merged = new ArrayList<>(sections.length);
        for (String section : sections) {
            String value = announced.get(section);
            if (value == null || value.isEmpty()) {
                value = defaults.get(section);
            }
            if (value != null && !value.isEmpty()) {
                merged.add(section + ":" + value);
            }
        }
        return String.join(";", merged);
    }

    /** 解析 401 的 WWW-Authenticate 挑战头。 */
    public static Challenge parseChallenge(String wwwAuthenticate) {
        String[] scheme = splitScheme(wwwAuthenticate);
        Mode mode = parseMode(scheme[0], wwwAuthenticate);
        ParamMap params = parseParams(scheme[1]);
        String random1 = params.get("random1");
        if (random1.isEmpty()) {
            throw new Gb35114Exception(scheme[0] + " challenge missing random1");
        }
        return new Challenge(mode, params.get("algorithm"), random1);
    }

    /** 构建已认证 REGISTER 的 Authorization 头（设备侧）。 */
    public static String buildAuthAuthorization(Challenge ch, String random2, String serverId,
                                                String deviceId, String sign1) {
        StringBuilder out = new StringBuilder();
        out.append(ch.mode.asStr()).append(" random1=\"").append(ch.random1)
                .append("\", random2=\"").append(random2)
                .append("\", serverid=\"").append(serverId).append("\"");
        if (ch.mode == Mode.Bidirection) {
            out.append(", deviceid=\"").append(deviceId).append("\"");
        }
        out.append(", sign1=\"").append(sign1)
                .append("\", algorithm=\"").append(CAPABILITY_ALGORITHM).append("\"");
        return out.toString();
    }

    /** 解析已认证 REGISTER 的 Authorization 头（平台侧）。 */
    public static AuthAuthorization parseAuthAuthorization(String authorization) {
        String[] scheme = splitScheme(authorization);
        Mode mode = parseMode(scheme[0], authorization);
        ParamMap params = parseParams(scheme[1]);
        AuthAuthorization aa = new AuthAuthorization(
                mode,
                params.get("random1"),
                params.get("random2"),
                params.get("serverid"),
                params.get("deviceid"),
                params.get("sign1"),
                params.get("algorithm"));
        if (aa.random1.isEmpty() || aa.random2.isEmpty() || aa.serverId.isEmpty() || aa.sign1.isEmpty()) {
            throw new Gb35114Exception(mode.asStr() + " Authorization missing fields (random1, random2, serverid, sign1)");
        }
        if (mode == Mode.Bidirection && aa.deviceId.isEmpty()) {
            throw new Gb35114Exception("Bidirection Authorization missing deviceid");
        }
        return aa;
    }

    /**
     * 解析 200 OK 的 SecurityInfo 头。
     *
     * <p>{@code serverid} 按<b>可选</b>处理：标准里 Bidirection 该回它，但并非所有平台都回
     * ——实测 LiveGBS（{@code User-Agent: LiveGBS v260911}）只回
     * {@code random1/random2/deviceid/cryptkey/sign2/algorithm}，据此硬判「缺字段」会把一次
     * 成功的握手判成失败：VKEK 就此丢弃，后续所有信令（心跳、目录、点播）都以无 Note 的形式
     * 发出，被对端一律回 403，而日志上只留一句「SecurityInfo missing fields」。
     *
     * <p>放宽是安全的：本次 REGISTER 的目的地已经唯一确定了平台编码，缺省即「就是它」；
     * 真正的身份凭据是 {@code sign2}（由对端平台私钥签出，用本端为该平台保存的证书验），
     * 少了这个冗余字段并不削弱验证。字段若回了，仍须与本端期望值一致 —— 该比对在
     * {@code Gb35114DeviceStateMachine#verifyOk} 里做。
     */
    public static SecurityInfo parseSecurityInfo(String header) {
        String[] scheme = splitScheme(header);
        Mode mode = parseMode(scheme[0], header);
        ParamMap params = parseParams(scheme[1]);
        SecurityInfo si = new SecurityInfo();
        si.mode = mode;
        si.algorithm = params.get("algorithm");
        si.random1 = params.get("random1");
        si.random2 = params.get("random2");
        si.deviceId = params.get("deviceid");
        si.serverId = params.get("serverid");
        si.cryptKey = params.get("cryptkey");
        si.sign2 = params.get("sign2");
        if (si.cryptKey.isEmpty()) {
            throw new Gb35114Exception(mode.asStr() + " SecurityInfo missing cryptkey");
        }
        if (mode == Mode.Bidirection
                && (si.random1.isEmpty() || si.random2.isEmpty() || si.deviceId.isEmpty()
                || si.sign2.isEmpty())) {
            throw new Gb35114Exception(
                    "Bidirection SecurityInfo missing fields (random1, random2, deviceid, sign2)");
        }
        return si;
    }

    /**
     * sign1 的签名载荷：{@code random2 ‖ random1 ‖ serverid}。
     * 默认采用 base64 字符串直连（对齐 Rust {@code RandomEncoding::ConcatWireStrings}）。
     */
    public static byte[] signAuthPayload(String random1, String random2, String serverId) {
        return Gb35114SmCrypto.utf8(random2 + random1 + serverId);
    }

    /**
     * sign2 的签名载荷：{@code random1 ‖ random2 ‖ deviceid ‖ cryptkey}，
     * 默认 R1R2 顺序（对齐 Rust {@code Sign2Order::R1R2}）。
     */
    public static byte[] sign2Payload(String random1, String random2, String deviceId, String cryptKey) {
        return Gb35114SmCrypto.utf8(random1 + random2 + deviceId + cryptKey);
    }

    /** 渲染 SecurityInfo 头值（平台侧）。 */
    public static String buildSecurityInfo(SecurityInfo si) {
        if (si.mode == Mode.Unidirection) {
            return "Unidirection cryptkey=\"" + si.cryptKey + "\", algorithm=\"" + si.algorithm + "\"";
        }
        return "Bidirection algorithm=\"" + si.algorithm + "\",random1=\"" + si.random1
                + "\",random2=\"" + si.random2 + "\",deviceid=\"" + si.deviceId
                + "\",serverid=\"" + si.serverId + "\",cryptkey=\"" + si.cryptKey
                + "\",sign2=\"" + si.sign2 + "\"";
    }

    // ------------------------------------------------------------------
    // Note / Date（对齐 integrity.rs）
    // ------------------------------------------------------------------

    /** 渲染 GB35114 Date 头（ISO8601 毫秒、服务器本地时区）。 */
    public static String buildDate(Instant t) {
        return DATE_FORMAT.format(t);
    }

    /**
     * 当前时间的 Date 头。
     *
     * <p><b>截断到秒</b>（毫秒恒为 {@code .000}）：标准 C.4.1 明文规定
     * 「Date 精确到秒」，而且不少设备收到 Date 后会先解析成时间、再按自己的格式
     * 重新渲染一次来计算摘要——若我们发的是 {@code .588} 这类非零毫秒，
     * 对端重渲染成 {@code .000}，摘要输入就对不上，表现为对端一律回 4xx。
     * 发 {@code .000} 时「原样拼接」与「解析后重渲染」结果恒等，两种实现都能过。
     */
    public static String buildDateNow() {
        return buildDate(Instant.now().truncatedTo(ChronoUnit.SECONDS));
    }

    /**
     * 把一个线上的 Date 字符串解析成若干可能的 epoch 毫秒，供新鲜度判断使用。
     *
     * <p>该字段不带时区后缀，对端可能按本地时间也可能按 UTC 口径生成，标准也未规定；
     * 这里把「两种精度 × 两种时区」的解释都列出来，调用方只要有一个落在允许窗口内
     * 就算新鲜——因此<b>不要求客户端与服务端时区一致</b>。
     */
    public static List<Long> dateCandidates(String date) {
        List<Long> out = new ArrayList<>(4);
        if (date == null || date.isEmpty()) {
            return out;
        }
        DateTimeFormatter millis = DATE_FORMAT.withLocale(Locale.ROOT);
        DateTimeFormatter seconds = DATE_FORMAT_SECONDS.withLocale(Locale.ROOT);
        for (DateTimeFormatter fmt : new DateTimeFormatter[]{millis, seconds}) {
            for (ZoneId zone : new ZoneId[]{ZoneId.systemDefault(), ZoneOffset.UTC}) {
                try {
                    long epoch = Instant.from(fmt.withZone(zone).parse(date)).toEpochMilli();
                    if (!out.contains(epoch)) {
                        out.add(epoch);
                    }
                } catch (RuntimeException ignored) {
                    // 该「精度 × 时区」组合不适用，换下一种解释
                }
            }
        }
        return out;
    }

    /** 解析 Date 头，取首选（本地时区、毫秒精度）解释；不可解析时抛异常。 */
    public static long parseDate(String date) {
        List<Long> candidates = dateCandidates(date);
        if (candidates.isEmpty()) {
            throw new Gb35114Exception("malformed GB35114 Date header: " + date);
        }
        return candidates.get(0);
    }

    /** VKEK 在 Note 摘要输入中的拼接形式。 */
    private static volatile String vkekDigestForm = "raw";

    /**
     * 设置 VKEK 在 Note 摘要输入中的拼接形式：{@code raw}（16 字节原文，默认）、
     * {@code base64}、{@code hex}。
     *
     * <p>标准原文是「密钥」，未规定文本形式；本文按原文拼接以对齐 Rust 参考实现。
     * 若现场设备对摘要校验不通过，可切换此项逐一排除（出站加签与入站验签共用）。
     */
    public static void setVkekDigestForm(String form) {
        vkekDigestForm = form == null || form.isEmpty() ? "raw" : form.toLowerCase(Locale.ROOT);
    }

    public static String vkekDigestForm() {
        return vkekDigestForm;
    }

    /** 按当前配置把 VKEK 渲染为摘要输入的一段。 */
    private static byte[] vkekDigestBytes(byte[] vkek) {
        if (vkek == null) {
            return new byte[0];
        }
        switch (vkekDigestForm) {
            case "base64":
                return Gb35114SmCrypto.utf8(Base64.getEncoder().encodeToString(vkek));
            case "hex":
                StringBuilder sb = new StringBuilder(vkek.length * 2);
                for (byte b : vkek) {
                    sb.append(String.format("%02x", b));
                }
                return Gb35114SmCrypto.utf8(sb.toString());
            default:
                return vkek;
        }
    }

    /**
     * 计算 Note 头摘要输入：{@code METHOD ‖ From ‖ To ‖ Call-ID ‖ Date ‖ VKEK ‖ body}，
     * 无分隔符直连（对齐 Rust {@code digest_payload}）。
     *
     * <p>消息体按<b>原始字节</b>参与运算：MANSCDP 常声明 {@code encoding="GB2312"}，
     * 用字符串往返会破坏非 ASCII 字节，导致与对端算出不同的摘要。
     */
    public static byte[] digestPayload(String method, String from, String to, String callId,
                                       String date, byte[] vkek, byte[] body) {
        return Gb35114SmCrypto.sm3(
                Gb35114SmCrypto.utf8(method),
                Gb35114SmCrypto.utf8(from == null ? "" : from),
                Gb35114SmCrypto.utf8(to == null ? "" : to),
                Gb35114SmCrypto.utf8(callId == null ? "" : callId),
                Gb35114SmCrypto.utf8(date == null ? "" : date),
                vkekDigestBytes(vkek),
                body == null ? new byte[0] : body);
    }

    /** 计算 Note 头摘要输入（消息体按 UTF-8 文本处理）。 */
    public static byte[] digestPayload(String method, String from, String to, String callId,
                                       String date, byte[] vkek, String body) {
        return digestPayload(method, from, to, callId, date, vkek,
                Gb35114SmCrypto.utf8(body == null ? "" : body));
    }

    /** 构建 Note 头：{@code Digest nonce="<b64 SM3>",algorithm=SM3}。 */
    public static String buildNoteHeader(String method, String from, String to, String callId,
                                         String date, byte[] vkek, byte[] body) {
        byte[] digest = digestPayload(method, from, to, callId, date, vkek, body);
        return "Digest nonce=\"" + Base64.getEncoder().encodeToString(digest) + "\",algorithm=SM3";
    }

    /** 构建 Note 头（消息体按 UTF-8 文本处理）。 */
    public static String buildNoteHeader(String method, String from, String to, String callId,
                                         String date, byte[] vkek, String body) {
        return buildNoteHeader(method, from, to, callId, date, vkek,
                Gb35114SmCrypto.utf8(body == null ? "" : body));
    }

    /**
     * 解析 Note 头，返回 {@code [nonce, algorithm]}。
     *
     * <p>线格式不统一：标准与 Rust 侧写 {@code nonce="…",algorithm=SM3}（逗号分隔），
     * 而现场设备（海康）写 {@code nonce="…" algorithm=SM3}（空格分隔）。
     * 这里按「参数名=值」逐个抓取，两种写法都能识别，不再依赖逗号。
     */
    public static String[] parseNoteHeader(String note) {
        String trimmed = note == null ? "" : note.trim();
        if (!trimmed.regionMatches(true, 0, "Digest", 0, "Digest".length())) {
            throw new Gb35114Exception("not a Digest Note header: " + note);
        }
        String nonce = paramValue(trimmed, "nonce");
        String algorithm = paramValue(trimmed, "algorithm");
        if (nonce == null || nonce.isEmpty()) {
            throw new Gb35114Exception("Note header missing nonce: " + note);
        }
        if (algorithm == null || algorithm.isEmpty()) {
            throw new Gb35114Exception("Note header missing algorithm: " + note);
        }
        return new String[]{nonce, algorithm};
    }

    /** 抓取 {@code key="value"} 或 {@code key=value} 的值，找不到返回 null。 */
    private static String paramValue(String header, String key) {
        Matcher m = Pattern.compile("(?i)(?:^|[\\s,;])" + Pattern.quote(key) + "\\s*=\\s*\"([^\"]*)\"")
                .matcher(header);
        if (m.find()) {
            return m.group(1);
        }
        Matcher bare = Pattern.compile("(?i)(?:^|[\\s,;])" + Pattern.quote(key) + "\\s*=\\s*([^\\s,;]+)")
                .matcher(header);
        return bare.find() ? bare.group(1) : null;
    }

    /** 验 Note 头，不符抛 {@link Gb35114Exception}。 */
    public static void verifyNoteHeader(String note, String method, String from, String to,
                                        String callId, String date, byte[] vkek, byte[] body) {
        String[] parsed = parseNoteHeader(note);
        if (!"SM3".equalsIgnoreCase(parsed[1])) {
            throw new Gb35114Exception("unsupported Note algorithm " + parsed[1] + " (want SM3)");
        }
        byte[] want = Base64.getDecoder().decode(parsed[0]);
        byte[] got = digestPayload(method, from, to, callId, date, vkek, body);
        if (!constantTimeEquals(want, got)) {
            throw new Gb35114Exception("Note digest mismatch");
        }
    }

    /** 详见 {@link #verifyNoteHeader(String, String, String, String, String, byte[], byte[])}。 */
    public static void verifyNoteHeader(String note, String method, String from, String to,
                                        String callId, String date, byte[] vkek, String body) {
        verifyNoteHeader(note, method, from, to, callId, date, vkek,
                Gb35114SmCrypto.utf8(body == null ? "" : body));
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return r == 0;
    }

    // ------------------------------------------------------------------
    // 解析辅助
    // ------------------------------------------------------------------

    /** 拆分 {@code "Scheme rest"}。 */
    private static String[] splitScheme(String header) {
        String trimmed = header.trim();
        int i = trimmed.indexOf(' ');
        if (i < 0) {
            return new String[]{trimmed, ""};
        }
        return new String[]{trimmed.substring(0, i), trimmed.substring(i + 1).trim()};
    }

    private static Mode parseMode(String scheme, String header) {
        Mode mode = Mode.fromStr(scheme);
        if (mode == null) {
            throw new Gb35114Exception("not a GB35114 header: " + header);
        }
        return mode;
    }

    /** 极简参数解析器，支持 {@code key="value"} 与 {@code key=value}，逗号分隔。 */
    private static ParamMap parseParams(String s) {
        ParamMap map = new ParamMap();
        int i = 0;
        int n = s.length();
        while (i < n) {
            while (i < n && (s.charAt(i) == ',' || s.charAt(i) == ' ')) {
                i++;
            }
            if (i >= n) {
                break;
            }
            int keyStart = i;
            while (i < n) {
                char c = s.charAt(i);
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
                    i++;
                } else {
                    break;
                }
            }
            if (i == keyStart || i >= n || s.charAt(i) != '=') {
                break;
            }
            String key = s.substring(keyStart, i).toLowerCase(Locale.ROOT);
            i++; // '='
            String value;
            if (i < n && s.charAt(i) == '"') {
                i++;
                int start = i;
                while (i < n && s.charAt(i) != '"') {
                    i++;
                }
                value = s.substring(start, i);
                if (i < n) {
                    i++;
                }
            } else {
                int start = i;
                while (i < n && s.charAt(i) != ',' && s.charAt(i) != ' ') {
                    i++;
                }
                value = s.substring(start, i);
            }
            map.put(key, value);
        }
        return map;
    }

    /** 简单的键值对容器，避免引入额外依赖。 */
    private static final class ParamMap {
        private final java.util.Map<String, String> map = new java.util.HashMap<>();

        void put(String k, String v) {
            map.put(k, v);
        }

        String get(String k) {
            return Objects.requireNonNullElse(map.get(k), "");
        }
    }
}
