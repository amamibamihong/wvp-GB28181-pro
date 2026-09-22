package com.genersoft.iot.vmp.gb35114.conf;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * GB35114 国密配置，映射 {@code gb35114:} 段。
 */
@Component
@ConfigurationProperties(prefix = "gb35114", ignoreInvalidFields = true)
@Order(0)
@Data
public class Gb35114Config {

    /** 国密总开关。 */
    private boolean enabled = false;

    /** 本平台作为下级向上级注册时使用的设备证书 ID（关联 wvp_gb35114_cert）。 */
    private Integer deviceCertId;

    /** 本平台作为平台（UAS）使用的服务器证书 ID（关联 wvp_gb35114_cert）。 */
    private Integer serverCertId;

    /** 本平台受信的上级平台证书 ID（验 sign2）。 */
    private Integer platformCertId;

    /** 私钥落地加密的对称密钥（至少 16 字节，AES）。 */
    private String keyEncryptPassword = "wvp-gb35114-default";

    /** 证书默认有效期（天）。 */
    private int certValidityDays = 3650;

    /**
     * 是否拒绝已过期的证书。
     *
     * <p>默认 {@code false}：过期<b>只提示不拦截</b> —— 证书列表照常标出「已过期」，
     * 由运维看到后决定吊销、删除还是重新颁发。
     *
     * <p>之所以把「到期是否拒绝」做成策略而非硬编码：A 级握手既不校验证书链也不校验
     * 有效期，设备/上级只拿公钥验签。因此一张刚过期几小时的证书在协议上仍然可用，
     * 而按日期直接拒绝会让设备在运维还没反应过来时就被挡在门外，且现场只能翻日志
     * 才看得出原因。需要严格合规的部署再把此项置为 {@code true}。
     *
     * <p>注意：<b>吊销不受本开关影响</b> —— 吊销是运维对该身份的明确停用指令，
     * 任何取值下都拒绝。
     */
    private boolean rejectExpiredCert = false;

    /**
     * 目录同步前等待的毫秒数，用于规避国密握手与查询之间的时序竞争。
     *
     * <p>设备回 200 OK 后还要解密 cryptkey、装载 VKEK，紧接着到达的查询会被它按
     * 「密钥未就绪」拒绝（403）。留出余量可让设备先完成握手收尾。0 表示不等待。
     */
    private long syncDelayMs = 0;

    /** 控制信令 Note 认证参数。 */
    private Note note = new Note();

    /**
     * Note（带密钥杂凑）参数。
     *
     * <p>各厂商实现对标准的落地细节不一致，现场排查时可逐项开关/切换做二分定位，
     * 不必改代码重新发版。
     */
    @Data
    public static class Note {
        /**
         * 是否启用 Note 加签/验签。关闭后既不给对端加 Note，也不校验对端的 Note。
         * 用于判定「对端 4xx 是否由 Note 引起」。
         */
        private boolean enabled = true;

        /**
         * VKEK 参与摘要时的拼接形式：{@code raw}（16 字节原文）/ {@code base64} / {@code hex}。
         * 标准只写「密钥」，未规定文本形式，各厂商实现不一。
         */
        private String vkekForm = "raw";
    }
}
