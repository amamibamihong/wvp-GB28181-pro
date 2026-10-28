package com.genersoft.iot.vmp.gb35114.cert.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

/**
 * GB35114 根 CA 记录。
 *
 * <p>按类型分成两栏，与页面「CA 证书管理」的两栏一一对应：
 * <ul>
 *   <li>{@link #TYPE_LOCAL_CA} <b>本地根 CA</b>：私钥在本平台，用于签发证书。
 *       全局只保留一份（见 {@code assertNoLocalCa}），因此不需要导入 —— 生成即得；</li>
 *   <li>{@link #TYPE_TRUSTED_CA} <b>受信任的 CA</b>：仅公钥，需从外部导入。它表达的是
 *       「这张 CA 签发的证书，本平台认」。两个方向都适用：
 *       <ul>
 *         <li>本平台作下级（UAC）时，验证<b>上级平台的服务端证书</b> —— 导入上级证书时按
 *             issuer 反查它，把「证书 → CA → 级联平台」串起来；</li>
 *         <li>本平台作上级（UAS）时，验证<b>下级设备自带的客户端证书</b> —— 设备证书由第三方
 *             机构签发时，把该机构的 CA 导入这里，设备注册时的链校验就能通过。</li>
 *       </ul>
 *   </li>
 * </ul>
 *
 * <p><b>关联不校验链</b>：把证书与它的签发 CA 关联起来靠的是「用候选 CA 公钥验签」，
 * 只表达谱系事实，不要求候选具备 CA 资格，也不查有效期。信任判定是另一回事 ——
 * 由证书链校验承担：本平台作上级（UAS）时对设备证书恒开，作下级（UAC）时由
 * {@code gb35114.verify-upstream-cert-chain} 控制（默认开）。
 *
 * <p><b>信任是实时判定的</b>：导入 CA 不给任何证书「打上可信标记」，注册时每次现读 CA 表、
 * 现做验签。删掉 CA，它立刻不再授予信任。
 */
@Data
@Schema(description = "GB35114 根 CA")
public class Gb35114Ca {

    /** 本地根 CA（私钥在本平台，用于签发；全局唯一，不需导入）。 */
    public static final String TYPE_LOCAL_CA = "LOCAL_CA";
    /** 受信任的 CA（仅公钥，需导入；用于验证上级平台证书与第三方签发的下级设备证书）。 */
    public static final String TYPE_TRUSTED_CA = "TRUSTED_CA";

    @Schema(description = "主键ID")
    private Integer id;

    @Schema(description = "类型：LOCAL_CA-本地根CA，TRUSTED_CA-受信任的CA")
    private String type;

    @Schema(description = "主题 DN（CN）")
    private String subjectCn;

    @Schema(description = "完整主题 DN（RFC2253）")
    private String subjectDn;

    @Schema(description = "国家 C")
    private String country;

    @Schema(description = "省份 ST")
    private String province;

    @Schema(description = "城市 L")
    private String locality;

    @Schema(description = "组织 O")
    private String organization;

    @Schema(description = "组织单位 OU")
    private String organizationalUnit;

    @Schema(description = "序列号")
    private String serialNumber;

    @Schema(description = "证书 PEM")
    private String certPem;

    /** 私钥 PEM（对称加密存储）。永不下发前端。 */
    @JsonIgnore
    private String keyPem;

    @Schema(description = "生效时间")
    private String notBefore;

    @Schema(description = "失效时间")
    private String notAfter;

    @Schema(description = "备注")
    private String remark;

    @Schema(description = "创建时间")
    private String createTime;

    /** 本平台是否持有该 CA 私钥（瞬态，由列表查询计算，不落库）。 */
    private Boolean hasKey;

    /**
     * 该 CA 被哪个上级平台使用（瞬态，由列表查询计算，不落库）。
     *
     * <p>链路由「服务端证书（上级平台）的 ca_id」串起来：某张 TRUSTED_PLATFORM 证书由本 CA 签发，
     * 而级联平台又绑定了那张证书，说明本 CA 就是该上级平台的 CA。
     * 多个受信任的 CA 的 CN 常常都叫 Root CA，只有这一列能把它们区分开。
     */
    private String relatedPlatformName;

    /**
     * 该 CA 签发的证书张数（瞬态，由列表查询计算，不落库）。
     *
     * <p>与 {@code deleteCa} 的引用校验同源（{@code countByCaId}）。列出来是因为
     * 「受信任的 CA」既能签上级平台证书、也能签下级设备证书之后，「这张 CA 还有没有在用」
     * 光看 CA 列表已经判断不出来了；删除被拒时也要能一眼看到是哪些证书在占位。
     */
    private Integer certCount;

    /**
     * 该 CA 签发的证书清单（瞬态，仅按 ID 单查时填充，不落库）。
     *
     * <p>列表查询不填这一项：CA 多、证书多时会把列表响应撑大，而列表只需要
     * {@link #certCount} 一个数。点开某张 CA 时才按需拉取。
     */
    private List<Gb35114Cert> relatedCerts;
}
