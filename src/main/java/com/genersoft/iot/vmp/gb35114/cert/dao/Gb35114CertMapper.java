package com.genersoft.iot.vmp.gb35114.cert.dao;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface Gb35114CertMapper {

    /**
     * 列表/详情用的列清单：<b>不含 key_pem</b>（私钥密文永不下发），
     * 改用 has_key 布尔表示"本平台是否持有私钥"。
     */
    String LITE_COLUMNS =
            " id, type, gb_id, subject_cn, subject_dn, module_id, country, province, locality, " +
            " organization, organizational_unit, serial_number, ca_id, cert_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, key_fingerprint, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR key_pem = '' THEN 0 ELSE 1 END AS has_key ";

    /** 达梦 clob 列不可用 = '' 比较，改用 LENGTH。 */
    String LITE_COLUMNS_DM =
            " id, type, gb_id, subject_cn, subject_dn, module_id, country, province, locality, " +
            " organization, organizational_unit, serial_number, ca_id, cert_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, key_fingerprint, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR LENGTH(key_pem) = 0 THEN 0 ELSE 1 END AS has_key ";

    @Insert("INSERT INTO wvp_gb35114_cert (type, gb_id, subject_cn, subject_dn, module_id, country, province, " +
            " locality, organization, organizational_unit, serial_number, ca_id, cert_pem, key_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, key_fingerprint, " +
            " remark, create_time) " +
            " VALUES (#{type}, #{gbId}, #{subjectCn}, #{subjectDn}, #{moduleId}, #{country}, #{province}, " +
            " #{locality}, #{organization}, #{organizationalUnit}, #{serialNumber}, #{caId}, #{certPem}, " +
            " #{keyPem}, #{csrPem}, #{notBefore}, #{notAfter}, #{validityDays}, #{keyUsage}, #{revoked}, " +
            " #{keyFingerprint}, #{remark}, #{createTime})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int add(Gb35114Cert cert);

    /** 按 ID 查全列（含私钥密文），仅供服务端签名内部使用，禁止直接返回给 Controller。 */
    @Select("SELECT * FROM wvp_gb35114_cert WHERE id=#{id}")
    Gb35114Cert query(int id);

    /** 按 ID 查列表列（不含私钥密文）。 */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE id=#{id}")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert WHERE id=#{id}", databaseId = "dm")
    Gb35114Cert queryLite(int id);

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryAll();

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE type=#{type} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE type=#{type} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByType(String type);

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE gb_id=#{gbId} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE gb_id=#{gbId} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByGbId(String gbId);

    /**
     * 按 CSR 内容与类型查历史记录：同一份 CSR 可以多次签发（续期/重签），
     * 签发时先查是否已存过，避免重复落库同一份 CSR。
     *
     * <p><b>必须带类型</b>：服务端证书的待签发记录里也存着 CSR，不限定类型时
     * 一张服务端 CSR 会被「由下级 CSR 签发」这条路径找到，并按 {@code ISSUED_DEVICE}
     * 的语义签掉（落成一张没有本地私钥的设备证书），把服务端证书的私钥记录毁掉。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE csr_pem=#{csrPem} AND type=#{type} "
            + "ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert WHERE csr_pem=#{csrPem} "
            + "AND type=#{type} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByCsrPem(@Param("csrPem") String csrPem, @Param("type") String type);

    /** 仅回填 CSR（记录已存在时不覆盖已有证书）。 */
    @Update("UPDATE wvp_gb35114_cert SET csr_pem=#{csrPem} WHERE id=#{id} AND (csr_pem IS NULL OR csr_pem = '')")
    @Update(value = "UPDATE wvp_gb35114_cert SET csr_pem=#{csrPem} WHERE id=#{id} " +
            " AND (csr_pem IS NULL OR LENGTH(csr_pem) = 0)", databaseId = "dm")
    int updateCsrPem(@Param("id") int id, @Param("csrPem") String csrPem);

    /**
     * UAS 侧验 sign1 用：按国标 ID 取「客户端证书（下级设备）」（按 id 倒序，最新的在前）。
     *
     * <p>吊销与有效期过滤放在 Java 层做，避免 revoked 列在 MySQL(tinyint)/PG(bool)/达梦(bit)
     * 三方言下布尔比较不兼容。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE gb_id=#{gbId} AND type='" + Gb35114Cert.TYPE_ISSUED_DEVICE + "' " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE gb_id=#{gbId} AND type='" + Gb35114Cert.TYPE_ISSUED_DEVICE + "' " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryIssuedDeviceCert(@Param("gbId") String gbId);

    /** 回填待签发记录的证书（仅当尚未签发时生效，避免覆盖已有证书）。 */
    @Update("UPDATE wvp_gb35114_cert SET cert_pem=#{certPem}, serial_number=#{serialNumber}, " +
            " not_before=#{notBefore}, not_after=#{notAfter}, ca_id=#{caId}, validity_days=#{validityDays}, " +
            " key_usage=#{keyUsage}, key_fingerprint=#{keyFingerprint} " +
            " WHERE id=#{id} AND (cert_pem IS NULL OR cert_pem = '')")
    @Update(value = "UPDATE wvp_gb35114_cert SET cert_pem=#{certPem}, serial_number=#{serialNumber}, " +
            " not_before=#{notBefore}, not_after=#{notAfter}, ca_id=#{caId}, validity_days=#{validityDays}, " +
            " key_usage=#{keyUsage}, key_fingerprint=#{keyFingerprint} " +
            " WHERE id=#{id} AND (cert_pem IS NULL OR LENGTH(cert_pem) = 0)", databaseId = "dm")
    int completeCert(@Param("id") int id, @Param("certPem") String certPem,
                     @Param("serialNumber") String serialNumber,
                     @Param("notBefore") String notBefore, @Param("notAfter") String notAfter,
                     @Param("caId") Integer caId, @Param("validityDays") Integer validityDays,
                     @Param("keyUsage") String keyUsage, @Param("keyFingerprint") String keyFingerprint);

    @Update("UPDATE wvp_gb35114_cert SET revoked=#{revoked} WHERE id=#{id}")
    @Update(value = "UPDATE wvp_gb35114_cert SET revoked=#{revoked} WHERE id=#{id}", databaseId = "dm")
    int updateRevoked(@Param("id") int id, @Param("revoked") boolean revoked);

    /**
     * 原地换发：更新已有记录的证书内容，<b>不新增行</b>。
     *
     * <p>「同密钥再签」走这里。新增行会让证书 ID 变化，而配置文件、{@code wvp_device.server_cert_id}、
     * {@code wvp_platform.device_cert_id} 等处都是按 ID 引用的 —— ID 一变，这些引用立刻悬空，
     * 且只在注册时才暴露。原地更新让 ID 恒定，引用永不失效。
     *
     * <p>不动 {@code key_pem}（复用同一密钥对）与 {@code csr_pem}（CSR 未变）。
     */
    @Update("UPDATE wvp_gb35114_cert SET cert_pem=#{certPem}, serial_number=#{serialNumber}, " +
            " subject_cn=#{subjectCn}, subject_dn=#{subjectDn}, ca_id=#{caId}, " +
            " not_before=#{notBefore}, not_after=#{notAfter}, validity_days=#{validityDays}, " +
            " key_usage=#{keyUsage}, key_fingerprint=#{keyFingerprint}, revoked=0 " +
            " WHERE id=#{id}")
    @Update(value = "UPDATE wvp_gb35114_cert SET cert_pem=#{certPem}, serial_number=#{serialNumber}, " +
            " subject_cn=#{subjectCn}, subject_dn=#{subjectDn}, ca_id=#{caId}, " +
            " not_before=#{notBefore}, not_after=#{notAfter}, validity_days=#{validityDays}, " +
            " key_usage=#{keyUsage}, key_fingerprint=#{keyFingerprint}, revoked=0 " +
            " WHERE id=#{id}", databaseId = "dm")
    int updateServerIdentity(@Param("id") int id, @Param("certPem") String certPem,
                             @Param("serialNumber") String serialNumber,
                             @Param("subjectCn") String subjectCn, @Param("subjectDn") String subjectDn,
                             @Param("caId") Integer caId,
                             @Param("notBefore") String notBefore, @Param("notAfter") String notAfter,
                             @Param("validityDays") Integer validityDays,
                             @Param("keyUsage") String keyUsage,
                             @Param("keyFingerprint") String keyFingerprint);

    /**
     * 查全部服务端证书（按 id 倒序，最新的在前）。
     *
     * <p>吊销/有效期/私钥的过滤放在 Java 层，规避三方言布尔与 clob 差异。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_SERVER_IDENTITY + "' " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_SERVER_IDENTITY + "' " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryServerIdentities();

    /** 按公钥指纹查同组证书（同一个签名身份）。 */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_SERVER_IDENTITY + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_SERVER_IDENTITY + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryServerIdentitiesByFingerprint(@Param("fp") String fp);

    /**
     * 按公钥指纹查客户端证书（下级设备），校验设备自报证书是否已被本平台吊销。
     *
     * <p>设备在 Capability 的 cnonce 里自报证书时不经过数据库，需按指纹反查才能
     * 知道这张证书是否已被吊销。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_ISSUED_DEVICE + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE type='" + Gb35114Cert.TYPE_ISSUED_DEVICE + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryIssuedDeviceCertsByFingerprint(@Param("fp") String fp);

    /** 回填公钥指纹（存量证书在列新增前入库，指纹为空）。 */
    @Update("UPDATE wvp_gb35114_cert SET key_fingerprint=#{fp} WHERE id=#{id}")
    @Update(value = "UPDATE wvp_gb35114_cert SET key_fingerprint=#{fp} WHERE id=#{id}", databaseId = "dm")
    int updateFingerprint(@Param("id") int id, @Param("fp") String fp);

    /** 统计某 CA 签发的证书数（删除 CA 前的引用校验）。 */
    @Select("SELECT COUNT(0) FROM wvp_gb35114_cert WHERE ca_id=#{caId}")
    int countByCaId(@Param("caId") int caId);

    /**
     * 某 CA 签发的证书清单（CA 页面点开「关联证书」用）。
     *
     * <p>按签发时间倒序，最新签发的排在最前 —— 排查「这张 CA 还在不在用」时，
     * 先看到的应该是最近签的那张。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE ca_id=#{caId} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE ca_id=#{caId} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByCaId(@Param("caId") int caId);

    @Delete("DELETE FROM wvp_gb35114_cert WHERE id=#{id}")
    int delete(int id);
}
