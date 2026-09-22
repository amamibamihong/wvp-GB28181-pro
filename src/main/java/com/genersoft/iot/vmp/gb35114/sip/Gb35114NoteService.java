package com.genersoft.iot.vmp.gb35114.sip;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114HeaderUtil;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * 控制信令 Note 认证服务，对齐 gb28181-rs 的 {@code security35114::integrity}。
 *
 * <p>Note 摘要输入 = {@code METHOD ‖ From ‖ To ‖ Call-ID ‖ Date ‖ VKEK ‖ body}；
 * 摘要里用的 Date 是线上的原字符串。入站验签把 Date 按「本地时区/UTC + 秒/毫秒」
 * 多种解释逐一比对，只要解释后的时间落在 ±5 分钟新鲜度窗口内就通过，
 * 因此<b>不要求客户端与服务端时区一致</b>，也容忍设备 Date 只精确到秒。
 */
@Component
public class Gb35114NoteService {

    /** 新鲜度窗口，与 Rust {@code NOTE_FRESHNESS_WINDOW} 一致。 */
    public static final Duration FRESHNESS_WINDOW = Duration.ofMinutes(5);

    /** 出站加签：返回 {@code [date, note]}。 */
    public String[] buildNote(String method, String from, String to, String callId,
                              byte[] body, byte[] vkek) {
        String date = Gb35114HeaderUtil.buildDateNow();
        String note = Gb35114HeaderUtil.buildNoteHeader(method, from, to, callId, date, vkek, body);
        return new String[]{date, note};
    }

    /** 入站验签：不符抛 {@link Gb35114Exception}。 */
    public void verifyNote(String note, String method, String from, String to, String callId,
                           String date, byte[] body, byte[] vkek) {
        if (note == null || note.isEmpty()) {
            return; // 无 Note 的请求放行（兼容混跑 Digest 平台）
        }
        if (vkek == null) {
            throw new Gb35114Exception("incoming Note before the handshake completed");
        }
        List<Long> stamps = Gb35114HeaderUtil.dateCandidates(date);
        boolean fresh = false;
        long now = Instant.now().toEpochMilli();
        for (Long stamp : stamps) {
            if (Math.abs(now - stamp) <= FRESHNESS_WINDOW.toMillis()) {
                fresh = true;
                break;
            }
        }
        if (!fresh) {
            throw new Gb35114Exception("incoming Note Date outside the freshness window");
        }
        Gb35114HeaderUtil.verifyNoteHeader(note, method, from, to, callId, date, vkek, body);
    }
}
