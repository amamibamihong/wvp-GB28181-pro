package com.genersoft.iot.vmp.gb35114.cert.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * GB35114 证书记录。
 *
 * <p>证书按<b>类型</b>（{@link #type}）区分，而非仅按服务器/设备区分：
 * <ul>
 *   <li>{@link #TYPE_SERVER_IDENTITY} 服务端证书（本平台）：本平台作 UAS，签 sign2，私钥在本平台；</li>
 *   <li>{@link #TYPE_DEVICE_IDENTITY} 客户端证书（本平台）：本平台作 UAC，签 sign1，私钥在本平台（通常上级颁发）；</li>
 *   <li>{@link #TYPE_ISSUED_DEVICE} 客户端证书（下级设备）：签发给下级设备/平台，私钥不在本平台；</li>
 *   <li>{@link #TYPE_TRUSTED_PLATFORM} 服务端证书（上级平台）：仅公钥，用于验 sign2。</li>
 * </ul>
 *
 * <p>{@link #keyPem} 为私钥密文，仅本平台自持私钥的证书才有，且<b>永不下发到前端</b>
 * （{@code @JsonIgnore}），列表以 {@link #hasKey} 布尔表示"本平台是否持有私钥"。
 */
@Data
@Schema(description = "GB35114 证书")
public class Gb35114Cert {

    /** 服务端证书（本平台）·UAS，签 sign2）。 */
    public static final String TYPE_SERVER_IDENTITY = "SERVER_IDENTITY";
    /** 客户端证书（本平台）·UAC，签 sign1，通常上级颁发）。 */
    public static final String TYPE_DEVICE_IDENTITY = "DEVICE_IDENTITY";
    /** 客户端证书（下级设备）·签发给下级，私钥交付下级）。 */
    public static final String TYPE_ISSUED_DEVICE = "ISSUED_DEVICE";
    /** 服务端证书（上级平台）·仅公钥，验 sign2）。 */
    public static final String TYPE_TRUSTED_PLATFORM = "TRUSTED_PLATFORM";

    @Schema(description = "主键ID")
    private Integer id;

    /**
     * 证书类型（四个取值见上面的 {@code TYPE_*} 常量）。
     *
     * <p>该列<b>取代</b>了历史上的 {@code purpose varchar} + {@code type integer} 两列：
     * 后者只是前者的派生投影（写 2 处、读 0 处），而且<b>有损</b> ——
     * {@link #TYPE_SERVER_IDENTITY}（本平台作 UAS）与 {@link #TYPE_TRUSTED_PLATFORM}
     * （上级平台作 UAS）方向相反却同落成 1。现在一个概念一个名字。
     */
    @Schema(description = "证书类型")
    private String type;

    @Schema(description = "关联国标 ID（设备编号或平台编号）")
    private String gbId;

    @Schema(description = "主题 DN（CN）")
    private String subjectCn;

    /**
     * 密码模块 ID（GB 35114—2017 附录 B，22 位十进制编码）。
     *
     * <p>来源是设备证书 CN 里「设备ID_密码模块ID」的后半段（附录 A 表 A.1 第 6 项）。
     * 单列出来是为了满足 GB/T 43026—2023 表 4 序号 1「设备身份管理」——
     * 该检验项要求平台能展示「设备 ID、其密码模块 ID 与设备证书的对应关系」，
     * 只给一个 CN 字符串是过不了的。本平台无硬件密码模块时由用户填写，
     * 默认全 0（见 {@code Gb35114CertUtil.MODULE_ID_PLACEHOLDER}）。
     */
    @Schema(description = "密码模块 ID（附录 B，22 位）；无密码模块时默认全 0")
    private String moduleId;

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
     * {@code digitalSignature|nonRepudiation}；为空时按证书类型取默认值。
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

    /** 关联的国标设备主键（仅 ISSUED_DEVICE：本平台为该设备签发的客户端证书（下级设备））。 */
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

    /**
     * 导入时发现的问题提示（瞬态，仅导入响应填充，不落库）。
     *
     * <p>导入设备证书时，若签发它的 CA 还没导入本平台，这里带一条提示。<b>不阻断导入</b>：
     * 「证书先导入、CA 后导入」是合法顺序，信任判定由设备注册时的链校验实时承担，
     * 不依赖导入时这一眼。之所以仍要说，是因为不说的话这个问题要到设备注册失败才暴露 ——
     * 那时用户面对的是「设备连不上」，而不是「少导了一张 CA」。
     */
    @Schema(description = "导入提示（瞬态）")
    private String importWarning;

    /** 是否尚未签发（有 CSR 无证书）。 */
    public boolean isPending() {
        return (certPem == null || certPem.isEmpty()) && csrPem != null && !csrPem.isEmpty();
    }

    /** 该类型是否由本平台持有私钥。 */
    public static boolean holdsKey(String type) {
        return TYPE_SERVER_IDENTITY.equals(type) || TYPE_DEVICE_IDENTITY.equals(type);
    }
}
