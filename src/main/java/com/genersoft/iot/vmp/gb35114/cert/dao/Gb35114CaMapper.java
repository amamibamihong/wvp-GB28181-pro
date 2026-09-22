package com.genersoft.iot.vmp.gb35114.cert.dao;

import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface Gb35114CaMapper {

    /** 列表列清单：不含 key_pem（私钥密文永不下发），用 has_key 表示是否持有私钥。 */
    String LITE_COLUMNS =
            " id, purpose, subject_cn, serial_number, cert_pem, not_before, not_after, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR key_pem = '' THEN 0 ELSE 1 END AS has_key ";

    /** 达梦 clob 列不可用 = '' 比较，改用 LENGTH。 */
    String LITE_COLUMNS_DM =
            " id, purpose, subject_cn, serial_number, cert_pem, not_before, not_after, " +
            " remark, create_time, " +
            " CASE WHEN key_pem IS NULL OR LENGTH(key_pem) = 0 THEN 0 ELSE 1 END AS has_key ";

    @Insert("INSERT INTO wvp_gb35114_ca (purpose, subject_cn, serial_number, cert_pem, key_pem, " +
            " not_before, not_after, remark, create_time) " +
            " VALUES (#{purpose}, #{subjectCn}, #{serialNumber}, #{certPem}, #{keyPem}, " +
            " #{notBefore}, #{notAfter}, #{remark}, #{createTime})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int add(Gb35114Ca ca);

    /** 按 ID 查全列（含私钥密文），仅供签发时取 CA 私钥内部使用。 */
    @Select("SELECT * FROM wvp_gb35114_ca WHERE id=#{id}")
    Gb35114Ca query(int id);

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_ca ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM + " FROM wvp_gb35114_ca ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Ca> queryAll();

    @Select("SELECT " + LITE_COLUMNS + " FROM wvp_gb35114_ca WHERE purpose=#{purpose} ORDER BY id DESC")
    @Select(value = "SELECT " + LITE_COLUMNS_DM +
            " FROM wvp_gb35114_ca WHERE purpose=#{purpose} ORDER BY id DESC", databaseId = "dm")
    List<Gb35114Ca> queryByPurpose(String purpose);

    @Delete("DELETE FROM wvp_gb35114_ca WHERE id=#{id}")
    int delete(int id);
}
