package com.genersoft.iot.vmp.gb35114.cert.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * GB35114 根 CA 记录。
 *
 * <p>按用途区分：
 * <ul>
 *   <li>{@link #PURPOSE_LOCAL} 本地 CA：私钥在本平台，用于签发证书；</li>
 *   <li>{@link #PURPOSE_TRUSTED} 上级 CA：仅公钥，作为上级服务端证书的签发者留存 ——
 *       导入上级证书时按 issuer 反查它，从而把「证书 → CA → 级联平台」串起来。</li>
 * </ul>
 *
 * <p><b>不做证书链校验</b>：A 级握手不验证书链与有效期，本平台也不实现 PKIX 路径构建，
 * 上级 CA 只用于标识签发者，不参与「是否信任」的判定。
 */
@Data
@Schema(description = "GB35114 根 CA")
public class Gb35114Ca {

    /** 本地 CA（私钥在本平台，用于签发）。 */
    public static final String PURPOSE_LOCAL = "LOCAL_CA";
    /** 上级 CA（仅公钥，用于标识上级服务端证书的签发者）。 */
    public static final String PURPOSE_TRUSTED = "TRUSTED_CA";

    @Schema(description = "主键ID")
    private Integer id;

    @Schema(description = "用途：LOCAL_CA-本地CA，TRUSTED_CA-上级CA")
    private String purpose;

    @Schema(description = "主题 DN（CN）")
    private String subjectCn;

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
     * <p>链路由「上级服务端证书的 ca_id」串起来：某张 TRUSTED_PLATFORM 证书由本 CA 签发，
     * 而级联平台又绑定了那张证书，说明本 CA 就是该上级平台的 CA。
     * 多个上级 CA 的 CN 常常都叫 Root CA，只有这一列能把它们区分开。
     */
    private String relatedPlatformName;
}
