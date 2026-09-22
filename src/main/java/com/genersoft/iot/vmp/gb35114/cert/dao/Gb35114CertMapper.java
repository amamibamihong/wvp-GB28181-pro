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
            " id, purpose, type, gb_id, subject_cn, subject_dn, country, province, locality, " +
            " organization, organizational_unit, serial_number, ca_id, cert_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, is_default, key_fingerprint, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR key_pem = '' THEN 0 ELSE 1 END AS has_key ";

    /** 达梦 clob 列不可用 = '' 比较，改用 LENGTH。 */
    String LITE_COLUMNS_DM =
            " id, purpose, type, gb_id, subject_cn, subject_dn, country, province, locality, " +
            " organization, organizational_unit, serial_number, ca_id, cert_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, is_default, key_fingerprint, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR LENGTH(key_pem) = 0 THEN 0 ELSE 1 END AS has_key ";

    @Insert("INSERT INTO wvp_gb35114_cert (purpose, type, gb_id, subject_cn, subject_dn, country, province, " +
            " locality, organization, organizational_unit, serial_number, ca_id, cert_pem, key_pem, csr_pem, " +
            " not_before, not_after, validity_days, key_usage, revoked, is_default, key_fingerprint, " +
            " remark, create_time) " +
            " VALUES (#{purpose}, #{type}, #{gbId}, #{subjectCn}, #{subjectDn}, #{country}, #{province}, " +
            " #{locality}, #{organization}, #{organizationalUnit}, #{serialNumber}, #{caId}, #{certPem}, " +
            " #{keyPem}, #{csrPem}, #{notBefore}, #{notAfter}, #{validityDays}, #{keyUsage}, #{revoked}, " +
            " #{isDefault}, #{keyFingerprint}, #{remark}, #{createTime})")
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

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE purpose=#{purpose} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE purpose=#{purpose} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByPurpose(String purpose);

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE gb_id=#{gbId} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE gb_id=#{gbId} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByGbId(String gbId);

    /**
     * 按 CSR 内容查历史记录：同一份 CSR 可以多次签发（续期/重签），
     * 签发时先查是否已存过，避免重复落库同一份 CSR。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert WHERE csr_pem=#{csrPem} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_cert WHERE csr_pem=#{csrPem} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryByCsrPem(@Param("csrPem") String csrPem);

    /** 仅回填 CSR（记录已存在时不覆盖已有证书）。 */
    @Update("UPDATE wvp_gb35114_cert SET csr_pem=#{csrPem} WHERE id=#{id} AND (csr_pem IS NULL OR csr_pem = '')")
    @Update(value = "UPDATE wvp_gb35114_cert SET csr_pem=#{csrPem} WHERE id=#{id} " +
            " AND (csr_pem IS NULL OR LENGTH(csr_pem) = 0)", databaseId = "dm")
    int updateCsrPem(@Param("id") int id, @Param("csrPem") String csrPem);

    /**
     * UAS 侧验 sign1 用：按国标 ID 取「下级客户端证书」（按 id 倒序，最新的在前）。
     *
     * <p>吊销与有效期过滤放在 Java 层做，避免 revoked 列在 MySQL(tinyint)/PG(bool)/达梦(bit)
     * 三方言下布尔比较不兼容。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE gb_id=#{gbId} AND purpose='" + Gb35114Cert.PURPOSE_ISSUED_DEVICE + "' " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE gb_id=#{gbId} AND purpose='" + Gb35114Cert.PURPOSE_ISSUED_DEVICE + "' " +
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

    /** 清除全部默认标记（仅服务器证书维度），与 {@link #markDefault} 配合实现「唯一默认」。 */
    @Update("UPDATE wvp_gb35114_cert SET is_default=0 WHERE purpose='" + Gb35114Cert.PURPOSE_SERVER_IDENTITY + "'")
    @Update(value = "UPDATE wvp_gb35114_cert SET is_default=0 WHERE purpose='" +
            Gb35114Cert.PURPOSE_SERVER_IDENTITY + "'", databaseId = "dm")
    int clearDefault();

    /** 置某张服务器证书为默认。 */
    @Update("UPDATE wvp_gb35114_cert SET is_default=1 WHERE id=#{id}")
    @Update(value = "UPDATE wvp_gb35114_cert SET is_default=1 WHERE id=#{id}", databaseId = "dm")
    int markDefault(@Param("id") int id);

    /**
     * 查默认服务器证书（按 is_default 过滤，按 id 倒序兜底）。
     *
     * <p>吊销/有效期/私钥的过滤放在 Java 层，规避三方言布尔与 clob 差异。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_SERVER_IDENTITY + "' " +
            " ORDER BY is_default DESC, id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_SERVER_IDENTITY + "' " +
            " ORDER BY is_default DESC, id DESC", databaseId = "dm")
    List<Gb35114Cert> queryServerIdentities();

    /** 按公钥指纹查同组证书（同一个签名身份）。 */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_SERVER_IDENTITY + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_SERVER_IDENTITY + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryServerIdentitiesByFingerprint(@Param("fp") String fp);

    /**
     * 按公钥指纹查下级客户端证书（校验设备自报证书是否已被本平台吊销）。
     *
     * <p>设备在 Capability 的 cnonce 里自报证书时不经过数据库，需按指纹反查才能
     * 知道这张证书是否已被吊销。
     */
    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_ISSUED_DEVICE + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_cert " +
            " WHERE purpose='" + Gb35114Cert.PURPOSE_ISSUED_DEVICE + "' AND key_fingerprint=#{fp} " +
            " ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Cert> queryIssuedDeviceCertsByFingerprint(@Param("fp") String fp);

    /** 回填公钥指纹（存量证书在列新增前入库，指纹为空）。 */
    @Update("UPDATE wvp_gb35114_cert SET key_fingerprint=#{fp} WHERE id=#{id}")
    @Update(value = "UPDATE wvp_gb35114_cert SET key_fingerprint=#{fp} WHERE id=#{id}", databaseId = "dm")
    int updateFingerprint(@Param("id") int id, @Param("fp") String fp);

    /** 统计某 CA 签发的证书数（删除 CA 前的引用校验）。 */
    @Select("SELECT COUNT(0) FROM wvp_gb35114_cert WHERE ca_id=#{caId}")
    int countByCaId(@Param("caId") int caId);

    @Delete("DELETE FROM wvp_gb35114_cert WHERE id=#{id}")
    int delete(int id);
}
