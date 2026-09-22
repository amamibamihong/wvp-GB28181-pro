package com.genersoft.iot.vmp.gb35114.sip;

import gov.nist.javax.sip.header.ExtensionHeaderImpl;
import gov.nist.javax.sip.message.SIPMessage;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.header.Header;
import javax.sip.header.HeaderFactory;
import javax.sip.message.Message;
import java.nio.charset.StandardCharsets;
import java.util.ListIterator;

/**
 * GB35114 头在 JAIN-SIP 上的读写桥接。
 *
 * <p>关键结论（对 JAIN-SIP 1.3.0 反编译 + 实测确认）：
 * <ul>
 *   <li>{@code Note} / {@code SecurityInfo} 不在 {@code ParserFactory} 表里，
 *       入站落为 {@link ExtensionHeaderImpl}，原始值经 {@link #rawHeaderValue} 取回。</li>
 *   <li>GB35114 的 {@code Date} 是 ISO8601 毫秒（无星期/无时区），标准 {@code DateParser}
 *       需要 RFC1123 星期几，入站解析失败会经 {@code ParseExceptionListener} 落到
 *       {@code unrecognizedHeaders}，经 {@link #unparsedHeaderValue} 取回。</li>
 *   <li>{@code Authorization}（Capability/Unidirection/Bidirection）走标准
 *       {@code AuthorizationParser}，scheme 与各参数可经 getScheme/getParameter 读取。</li>
 *   <li>出站统一用原始 {@link ExtensionHeaderImpl} 追加，值原样落线，逐字节对齐 Rust golden。</li>
 * </ul>
 */
public final class Gb35114SipHeaders {

    private Gb35114SipHeaders() {
    }

    /** 新建一个 HeaderFactory（jain-sip 非线程安全，按需新建）。 */
    public static HeaderFactory headerFactory() {
        try {
            return SipFactory.getInstance().createHeaderFactory();
        } catch (PeerUnavailableException e) {
            throw new Gb35114Exception("unable to create HeaderFactory", e);
        }
    }

    /** 以「原始扩展头」形式写入 GB35114 头（Date/Note/SecurityInfo/Authorization…），值原样落线。 */
    public static void addRawHeader(Message message, String name, String value) {
        ExtensionHeaderImpl header = new ExtensionHeaderImpl();
        header.setName(name);
        header.setValue(value);
        message.setHeader(header);
    }

    /** 取某头的原始值（去掉「Name: 」前缀），支持 ExtensionHeaderImpl 与标准头。 */
    public static String value(Header header) {
        if (header == null) {
            return null;
        }
        if (header instanceof ExtensionHeaderImpl) {
            return ((ExtensionHeaderImpl) header).getHeaderValue();
        }
        return stripName(header.toString(), header.getName());
    }

    /** 从消息中取某头的原始值（SecurityInfo/Note/Authorization），不存在返回 null。 */
    public static String rawHeaderValue(Message message, String name) {
        return value(message.getHeader(name));
    }

    /** 取解析失败落到 {@code unrecognizedHeaders} 的原始头值（如 ISO8601 Date）。 */
    public static String unparsedHeaderValue(SIPMessage message, String name) {
        ListIterator<String> it = message.getUnrecognizedHeaders();
        if (it == null) {
            return null;
        }
        String prefix = name + ":";
        while (it.hasNext()) {
            String line = it.next();
            if (line.regionMatches(true, 0, prefix, 0, prefix.length())) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    /** 优先取扩展头原始值，其次标准头；不存在返回 null。 */
    public static String headerStringValue(Message message, String name) {
        return value(message.getHeader(name));
    }

    /** 消息体原始字节按 UTF-8 解码（Note 摘要输入），无体返回空串。 */
    public static String bodyString(Message message) {
        byte[] raw = message.getRawContent();
        if (raw == null || raw.length == 0) {
            return "";
        }
        return new String(raw, StandardCharsets.UTF_8);
    }

    /** 取头值的 scheme（首 token），如 Authorization 的 Capability/Unidirection/Bidirection/Digest。 */
    public static String schemeOf(String headerValue) {
        if (headerValue == null) {
            return "";
        }
        String t = headerValue.trim();
        int i = t.indexOf(' ');
        return i < 0 ? t : t.substring(0, i);
    }

    private static String stripName(String encoded, String name) {
        if (encoded == null) {
            return null;
        }
        String prefix = name + ":";
        if (encoded.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return encoded.substring(prefix.length()).trim();
        }
        return encoded;
    }
}
