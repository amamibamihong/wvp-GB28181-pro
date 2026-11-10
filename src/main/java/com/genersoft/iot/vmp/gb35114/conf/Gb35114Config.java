package com.genersoft.iot.vmp.gb35114.conf;

import com.genersoft.iot.vmp.gb35114.crypto.Gb35114CertUtil;
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

    /**
     * 私钥落地加密的对称密钥（至少 16 字节，AES）。
     */
    private String keyEncryptPassword = "wvp-gb35114-default";

    /** 证书默认有效期（天）。 */
    private int certValidityDays = 3650;

    /**
     * 本平台证书主题里使用的<b>密码模块 ID</b>，22 位十进制数字，默认 22 个 0。
     *
     * <p>GB 35114—2017 附录 A 表 A.1 第 6 项规定证书主题 CN 为
     * 「设备ID_密码模块ID」，附录 B 规定密码模块 ID 为 22 位十进制数字。
     *
     * <p>本平台没有硬件密码模块，故默认全 0 占位。做成配置项是因为这个值最终由
     * <b>运维/检测机构</b>按现场实际（如已备案的密码模块编号）决定，不该写死在代码或
     * 页面里 —— 检测时要能拿出「主题里的模块 ID 与备案一致」这个事实。
     *
     * <p>留空即用默认的 22 个 0；填了非法值（非 22 位数字）时<b>不静默改写</b>，
     * 而是原样下发、由页面提示 —— 配置写错应当立刻可见，而不是被悄悄替换成合规值。
     */
    private String moduleId = "";

    /**
     * 实际使用的密码模块 ID：配置为空即用默认的 22 个 0。
     *
     * <p>放在配置类上而不是 Controller 里，是因为「留空等于全 0」是本配置项的语义，
     * 凡是读它的地方都该拿到同一个答案 —— 散在各个调用点各兜一次底，早晚会兜出分歧。
     *
     * <p>不做「非法值就改写成全 0」的静默兜底 —— 配置里写错了应当让页面照原样提示，
     * 否则运维改了个错值、页面上却显示合规，反而查不出问题。合法性由
     * {@code Gb35114CertUtil.isValidModuleId} 判定，调用方按需自行校验。
     */
    public String resolvedModuleId() {
        if (moduleId == null || moduleId.trim().isEmpty()) {
            return Gb35114CertUtil.MODULE_ID_PLACEHOLDER;
        }
        return moduleId.trim();
    }

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
     * 本平台作为<b>下级（UAC）</b>时，是否校验上级平台证书的链（默认 {@code true}，校验）。
     *
     * <p>校验内容是「上级平台证书（{@code TRUSTED_PLATFORM}，用于验 sign2）是否由某个已导入的
     * 受信任的 CA（{@code TRUSTED_CA}）签发」。<b>只管这一个方向</b> —— 本平台作为上级（UAS）时，
     * 对设备证书的链校验<b>恒开</b>，不受本项控制（GB/T 43026—2023 附录 B 表 B.1 序号 6/7
     * 要求 7.4 设备身份认证「需验证证书链是否正确」，而序号 8/9 的 7.5 平台间认证没有这条要求）。
     *
     * <p><b>为什么默认 true</b>：默认从严 —— 上级证书必须能落到一张已导入的 CA 上，
     * 否则「随便一张证书都能冒充上级」这个口子就一直是开的。标准对 7.5 虽未强制，
     * 但不强制的意思是「可以关」，不是「应当关」。
     *
     * <p><b>现场「上级证书」与「受信任的 CA」常常是同一张自签证书</b>（很多上级平台只发一张
     * 证书，要求下级把它既当服务端证书导入、又当 CA 导入）。自签证书走的是「受信任的 CA
     * 列表里存在与它同公钥的一条」这条判据，所以<b>把该证书本身也在「CA 证书管理 ·
     * 受信任的 CA 证书」里导入一份即可</b>，不必真去要一张独立 CA。
     *
     * <p><b>不校验的两种办法</b>（本项即「允许不校验」的开关）：
     * <ul>
     *   <li>把本项置为 {@code false} —— <b>只关上级方向</b>，设备方向的链校验照旧恒开。推荐；</li>
     *   <li>{@link #skipCertChainVerify} —— 全局逃生口，两个方向一起关，仅在拿不到 CA 时用。</li>
     * </ul>
     *
     * <p><b>打开时（即默认状态下）的现场检查清单</b>：
     * <ul>
     *   <li>自签的上级证书：把它本身在「CA 证书管理 · 受信任的 CA 证书」里也导入一份；</li>
     *   <li>非自签的上级证书：导入签发它的那张 CA。</li>
     * </ul>
     * 只导入了 {@code TRUSTED_PLATFORM} 而未导入 {@code TRUSTED_CA} 时，级联会断，
     * 且失败信息只出现在本平台的 warn 日志里（{@code RegisterResponseProcessor} 会
     * 吞掉该异常），现场不容易察觉 —— 编辑页的常驻告警与列表页「签发者未导入」标记
     * 就是为了把这个原因摆到台面上。
     *
     * <p>改动本项后需重启（或在证书管理页触发一次证书状态机失效）：UAC 状态机在构造时
     * 读取本项一次，之后被缓存复用。
     */
    private boolean verifyUpstreamCertChain = true;

    /**
     * 是否<b>跳过证书链签名验证</b>（默认 {@code false}，即验证）。
     *
     * <p>现场可能<b>拿不到 CA</b>：上级平台只发一张证书、不给签发它的 CA；设备由厂商工具
     * 签发，CA 不外流；或 CA 已停用/丢失，无法补齐。此时链校验会让设备或级联平台<b>全部
     * 无法接入</b>，而本平台并没有办法自行补出那张 CA。本项提供一个显式的全局逃生口。
     *
     * <p><b>置为 {@code true} 时跳过的是「签名是否由某张已导入 CA 签发」这一步</b>，
     * 具体是：
     * <ul>
     *   <li>UAS 侧 {@code validateDeviceCertChain}：不再要求设备证书由已导入的 CA 签发；</li>
     *   <li>UAC 侧 {@code validateUpstreamPlatformCertChain}：不再要求上级证书由受信任的 CA 签发。</li>
     * </ul>
     *
     * <p><b>不跳过</b>的部分（这些是独立的安全判据，与本开关无关）：
     * <ul>
     *   <li>设备证书的<b>指纹反查</b> —— 仍要求命中本平台 {@code ISSUED_DEVICE} 签发记录，
     *       因此「本平台没签发过的证书」依然接不进来；</li>
     *   <li><b>吊销</b>判定；</li>
     *   <li><b>有效期</b>判定（是否拒绝由 {@link #rejectExpiredCert} 单独控制）；</li>
     *   <li>握手本身的 SM2 验签（{@code sign1}/{@code sign2}）—— 那是协议层，
     *       与「证书链」是两回事，本开关<b>不</b>影响它。</li>
     * </ul>
     *
     * <p>换言之：打开后信任依据从「链成立」退化为「本平台签发记录存在（设备方向）」
     * 或「对端自报的证书可直接使用（上级方向）」。这是<b>可用性优先</b>的取舍，
     * 会降低对「证书被替换」的防护，<b>仅在拿不到 CA 时使用</b>，并应记录在案。
     */
    private boolean skipCertChainVerify = false;

    /**
     * 设备接入的认证方式：{@code Bidirection}（双向，默认）或 {@code Unidirection}（单向）。
     *
     * <p>GB 35114—2017 6.4.2：「管理平台应对<b>所有接入的 FDWSF</b> 进行单向设备身份认证
     * <b>或者</b>双向设备身份认证」—— 主语是「所有接入的 FDWSF」，两种方式二选一，
     * 是<b>平台级设置</b>，故做成全局配置而非逐台设备配置。
     *
     * <p>该值决定 401 挑战里 {@code WWW-Authenticate} 的 scheme，设备按收到的 scheme 应答
     * （C.2.1.2 c) / C.2.2.2 c)）。两者的差别只在<b>平台是否向设备证明自己</b>：
     * <ul>
     *   <li>{@code Bidirection}：平台验 sign1 <b>且</b>签 sign2；需要平台签名证书。</li>
     *   <li>{@code Unidirection}：平台只验 sign1，200 OK 不含 sign2；
     *       <b>不需要</b>平台签名证书，也无需向设备下发任何平台证书/CA。</li>
     * </ul>
     *
     * <p>43026 表 A.1 序号 6（单向）、7（双向）为并列必测项，测试时切换本配置分别验证。
     * 切换后需重启（或调用 {@code Gb35114SecurityService#invalidateAllPlatformStateMachines}）
     * 使已建状态机按新方案重建。
     */
    private String authMode = "Bidirection";

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
