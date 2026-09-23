package com.genersoft.iot.vmp.gb35114.cert.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * GB35114 证书记录。
 *
 * <p>证书按<b>用途</b>（{@link #purpose}）区分，而非仅按服务器/设备区分：
 * <ul>
 *   <li>{@link #PURPOSE_SERVER_IDENTITY} 本地服务端证书：本平台作 UAS，签 sign2，私钥在本平台；</li>
 *   <li>{@link #PURPOSE_DEVICE_IDENTITY} 本地客户端证书：本平台作 UAC，签 sign1，私钥在本平台（通常上级颁发）；</li>
 *   <li>{@link #PURPOSE_ISSUED_DEVICE} 下级客户端证书：签发给下级设备/平台，私钥不在本平台；</li>
 *   <li>{@link #PURPOSE_TRUSTED_PLATFORM} 上级服务端证书：仅公钥，用于验 sign2。</li>
 * </ul>
 *
 * <p>{@link #keyPem} 为私钥密文，仅本平台自持私钥的证书才有，且<b>永不下发到前端</b>
 * （{@code @JsonIgnore}），列表以 {@link #hasKey} 布尔表示"本平台是否持有私钥"。
 */
@Data
@Schema(description = "GB35114 证书")
public class Gb35114Cert {

    /** 本地服务端证书（UAS，签 sign2）。 */
    public static final String PURPOSE_SERVER_IDENTITY = "SERVER_IDENTITY";
    /** 本地客户端证书（UAC，签 sign1，通常上级颁发）。 */
    public static final String PURPOSE_DEVICE_IDENTITY = "DEVICE_IDENTITY";
    /** 下级客户端证书（签发给下级，私钥交付下级）。 */
    public static final String PURPOSE_ISSUED_DEVICE = "ISSUED_DEVICE";
    /** 上级服务端证书（仅公钥，验 sign2）。 */
    public static final String PURPOSE_TRUSTED_PLATFORM = "TRUSTED_PLATFORM";

    /** 服务器证书。 */
    public static final int TYPE_SERVER = 1;
    /** 设备（客户端）证书。 */
    public static final int TYPE_DEVICE = 2;

    @Schema(description = "主键ID")
    private Integer id;

    @Schema(description = "证书用途")
    private String purpose;

    @Schema(description = "证书类型：1-服务器证书，2-设备证书（由用途派生，兼容旧字段）")
    private Integer type;

    @Schema(description = "关联国标 ID（设备编号或平台编号）")
    private String gbId;

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

    @Schema(description = "签发 CA 的 ID，null 表示自签")
    private Integer caId;

    @Schema(description = "证书 PEM")
    private String certPem;

    /**
     * 私钥 PEM（对称加密存储）。
     * 永不下发前端；仅本平台自持私钥的证书（本地服务端/本地客户端）有值。
     */
    @JsonIgnore
    private String keyPem;

    /** 待签发记录对应的 CSR PEM（私钥与 CSR 同记录关联，删除时一并删除）。 */
    private String csrPem;

    @Schema(description = "生效时间")
    private String notBefore;

    @Schema(description = "失效时间")
    private String notAfter;

    @Schema(description = "本次签发的有效期天数（快照）")
    private Integer validityDays;

    /**
     * 密钥用途扩展（X.509 KeyUsage），形如 {@code digitalSignature} 或
     * {@code digitalSignature|nonRepudiation}；为空时按证书用途取默认值。
     */
    @Schema(description = "密钥用途扩展，如 digitalSignature、keyCertSign|cRLSign")
    private String keyUsage;

    @Schema(description = "是否已吊销")
    private Boolean revoked;

    /**
     * 公钥指纹（SM3，十六进制）。
     *
     * <p>指纹相同 = 同一个 SM2 签名身份。设备侧只保存一个平台公钥，因此<b>同指纹的
     * 服务端证书彼此可互换</b>：设备导入其中任意一张，平台用同组内任意一张的私钥签
     * sign2 都能被验过。这也是证书轮换（换有效期/DN/签发者而不换密钥）不打断已配置
     * 设备的依据。
     */
    @Schema(description = "公钥指纹（SM3）；相同表示同一个签名身份，可互换")
    private String keyFingerprint;

    @Schema(description = "备注")
    private String remark;

    @Schema(description = "创建时间")
    private String createTime;

    /** 本平台是否持有该证书私钥（瞬态，由列表查询计算，不落库）。 */
    private Boolean hasKey;

    // ------------------------------------------------------------------
    // 关联对象（瞬态，由列表查询反查填充，不落库）
    //
    // 关系本身存在业务对象那一侧（wvp_platform.device_cert_id / platform_cert_id、
    // wvp_device.cert_id / server_cert_id，以及证书行的 gb_id），这里只是把它反过来
    // 呈现给运维看：「这张证书给谁用了」。不新增表、不新增列。
    // ------------------------------------------------------------------

    /** 关联的国标设备主键（仅 ISSUED_DEVICE：本平台为该设备签发的下级客户端证书）。 */
    @Schema(description = "关联的国标设备主键（瞬态）")
    private Integer relatedDeviceId;

    /** 关联的国标设备名称（仅 ISSUED_DEVICE）。 */
    @Schema(description = "关联的国标设备名称（瞬态）")
    private String relatedDeviceName;

    /** 关联的级联平台主键（DEVICE_IDENTITY / TRUSTED_PLATFORM：该上级平台绑定的证书）。 */
    @Schema(description = "关联的级联平台主键（瞬态）")
    private Integer relatedPlatformId;

    /** 关联的级联平台名称（DEVICE_IDENTITY / TRUSTED_PLATFORM）。 */
    @Schema(description = "关联的级联平台名称（瞬态）")
    private String relatedPlatformName;

    /**
     * 证书自身的签发者 DN（瞬态，由列表查询从 certPem 现算，不落库）。
     *
     * <p>用于区分「自签」与「签发者未导入」这两种都表现为 {@code caId == null} 的情况 ——
     * 前者 issuer == subject，后者 issuer 是某个本平台没留存的外部 CA。两者对运维的含义
     * 完全不同（前者正常，后者说明该导入的 CA 还没导入），只靠 {@code caId} 区分不了。
     */
    @Schema(description = "签发者 DN（瞬态）")
    private String issuerDn;

    /** 证书是否自签（issuer == subject，瞬态）。 */
    @Schema(description = "是否自签（瞬态）")
    private Boolean selfSigned;

    /** 是否尚未签发（有 CSR 无证书）。 */
    public boolean isPending() {
        return (certPem == null || certPem.isEmpty()) && csrPem != null && !csrPem.isEmpty();
    }

    /** 由用途派生兼容的 type 值。 */
    public static int typeOf(String purpose) {
        if (PURPOSE_SERVER_IDENTITY.equals(purpose) || PURPOSE_TRUSTED_PLATFORM.equals(purpose)) {
            return TYPE_SERVER;
        }
        return TYPE_DEVICE;
    }

    /** 该用途是否由本平台持有私钥。 */
    public static boolean holdsKey(String purpose) {
        return PURPOSE_SERVER_IDENTITY.equals(purpose) || PURPOSE_DEVICE_IDENTITY.equals(purpose);
    }
}
