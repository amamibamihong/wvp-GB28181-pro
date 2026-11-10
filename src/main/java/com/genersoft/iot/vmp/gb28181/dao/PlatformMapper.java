package com.genersoft.iot.vmp.gb28181.dao;

import com.genersoft.iot.vmp.gb28181.bean.Platform;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 用于存储上级平台
 */
@Mapper
@Repository
public interface PlatformMapper {

    @Insert("INSERT INTO wvp_platform (enable, name, server_gb_id, server_gb_domain, server_ip, server_port,device_gb_id,device_ip,"+
            " device_port,username,password,expires,keep_timeout,transport,character_set,ptz,rtcp,status,catalog_group, update_time," +
            " create_time, as_message_channel, send_stream_ip, auto_push_channel, catalog_with_platform,catalog_with_group,catalog_with_region, "+
            " civil_code,manufacturer,model,address,register_way,secrecy,device_cert_id,platform_cert_id,server_id) " +
            " VALUES (#{enable}, #{name}, #{serverGBId}, #{serverGBDomain}, #{serverIp}, #{serverPort}, #{deviceGBId}, #{deviceIp}, " +
            " #{devicePort}, #{username}, #{password}, #{expires}, #{keepTimeout}, #{transport}, #{characterSet}, #{ptz}, #{rtcp}, #{status}, #{catalogGroup},#{updateTime}," +
            " #{createTime}, #{asMessageChannel}, #{sendStreamIp}, #{autoPushChannel}, #{catalogWithPlatform}, #{catalogWithGroup},#{catalogWithRegion}, " +
             " #{civilCode}, #{manufacturer}, #{model}, #{address}, #{registerWay}, #{secrecy}, #{deviceCertId}, #{platformCertId}, #{serverId})")
    int add(Platform parentPlatform);

    @Update("UPDATE wvp_platform " +
            "SET update_time = #{updateTime}," +
            " enable=#{enable}, " +
            " name=#{name}," +
            " server_gb_id=#{serverGBId}, " +
            " server_gb_domain=#{serverGBDomain}, " +
            " server_ip=#{serverIp}," +
            " server_port=#{serverPort}, " +
            " device_gb_id=#{deviceGBId}," +
            " device_ip=#{deviceIp}, " +
            " device_port=#{devicePort}, " +
            " username=#{username}, " +
            " password=#{password}, " +
            " expires=#{expires}, " +
            " keep_timeout=#{keepTimeout}, " +
            " transport=#{transport}, " +
            " character_set=#{characterSet}, " +
            " ptz=#{ptz}, " +
            " rtcp=#{rtcp}, " +
            " status=#{status}, " +
            " catalog_group=#{catalogGroup}, " +
            " as_message_channel=#{asMessageChannel}, " +
            " send_stream_ip=#{sendStreamIp}, " +
            " auto_push_channel=#{autoPushChannel}, " +
            " catalog_with_platform=#{catalogWithPlatform}, " +
            " catalog_with_group=#{catalogWithGroup}, " +
            " catalog_with_region=#{catalogWithRegion}, " +
            " civil_code=#{civilCode}, " +
            " manufacturer=#{manufacturer}, " +
            " model=#{model}, " +
            " address=#{address}, " +
            " register_way=#{registerWay}, " +
            " secrecy=#{secrecy}, " +
            " device_cert_id=#{deviceCertId}, " +
            " platform_cert_id=#{platformCertId}, " +
            " server_id=#{serverId} " +
            "WHERE id=#{id}")
    int update(Platform parentPlatform);

    @Delete("DELETE FROM wvp_platform WHERE id=#{id}")
    int delete(@Param("id") Integer id);

    /**
     * 清空某张证书在本表的绑定（两个引用列都清）。
     *
     * <p>供 GB35114 编辑页的「删除」使用：证书此刻仍被<b>本</b> platform 行按 ID 引用，
     * 不先清空就会被 {@code assertNoCertReference} 拦下，删不掉。
     * 只清匹配的那一列，不整行置空 —— 一行理论上可能同时绑设备证书与平台证书。
     */
    @Update("UPDATE wvp_platform SET device_cert_id = NULL WHERE device_cert_id = #{certId}")
    @Update(value = "UPDATE wvp_platform SET device_cert_id = NULL WHERE device_cert_id = #{certId}",
            databaseId = "dm")
    int clearDeviceCertBinding(@Param("certId") int certId);

    @Update("UPDATE wvp_platform SET platform_cert_id = NULL WHERE platform_cert_id = #{certId}")
    @Update(value = "UPDATE wvp_platform SET platform_cert_id = NULL WHERE platform_cert_id = #{certId}",
            databaseId = "dm")
    int clearPlatformCertBinding(@Param("certId") int certId);

    /**
     * 写入「本平台设备证书」的绑定（{@code NULL} 表示解绑）。
     *
     * <p>刻意只更新这一列，而不是走 {@link #update(Platform)} 整行覆盖：绑定是证书槽
     * 自己的动作，不该受整行保存的前置校验与唯一键（{@code uk_platform_unique_server_gb_id}）
     * 牵连 —— 整行保存失败时，绑定也跟着丢，页面上却看不出来。
     */
    @Update("UPDATE wvp_platform SET device_cert_id = #{certId} WHERE id = #{platformId}")
    @Update(value = "UPDATE wvp_platform SET device_cert_id = #{certId} WHERE id = #{platformId}",
            databaseId = "dm")
    int bindDeviceCert(@Param("platformId") int platformId, @Param("certId") Integer certId);

    /** 写入「上级平台证书」的绑定（{@code NULL} 表示解绑）。与 {@link #bindDeviceCert} 同理。 */
    @Update("UPDATE wvp_platform SET platform_cert_id = #{certId} WHERE id = #{platformId}")
    @Update(value = "UPDATE wvp_platform SET platform_cert_id = #{certId} WHERE id = #{platformId}",
            databaseId = "dm")
    int bindPlatformCert(@Param("platformId") int platformId, @Param("certId") Integer certId);

    @Select(" <script>" +
            " SELECT pp.*, " +
            " ( (SELECT count(0) FROM wvp_platform_channel pc WHERE pc.platform_id = pp.id ) + " +
            "  (SELECT count(0) FROM wvp_platform_group pg WHERE pg.platform_id = pp.id ) * pp.catalog_with_group  + " +
            "  (SELECT count(0) FROM wvp_platform_region pr WHERE pr.platform_id = pp.id ) * pp.catalog_with_region + " +
            "  pp.catalog_with_platform " +
            "    ) as channel_count" +
            " FROM wvp_platform pp where 1=1 " +
            " <if test='query != null'> " +
            " AND (pp.name LIKE concat('%',#{query},'%') escape '/' OR pp.server_gb_id  LIKE concat('%',#{query},'%') escape '/' )</if> " +
            " order by pp.id desc"+
            " </script>")
    List<Platform> queryList(@Param("query") String query);

    @Select("SELECT * FROM wvp_platform WHERE server_id=#{serverId} and enable=#{enable} ")
    List<Platform> queryEnableParentPlatformListByServerId(@Param("serverId") String serverId, @Param("enable") boolean enable);

    @Select("SELECT * FROM wvp_platform WHERE enable=true and as_message_channel=true")
    @Select(value = "SELECT * FROM wvp_platform WHERE enable=1 and as_message_channel=1", databaseId = "dm")
    List<Platform> queryEnablePlatformListWithAsMessageChannel();

    @Select("SELECT * FROM wvp_platform WHERE server_gb_id=#{platformGbId}")
    Platform getParentPlatByServerGBId(String platformGbId);

    @Select("SELECT * FROM wvp_platform WHERE id=#{id}")
    Platform query(int id);

    @Update("UPDATE wvp_platform SET status=#{online}, server_id = #{serverId} WHERE id=#{id}" )
    int updateStatus(@Param("id") int id, @Param("online") boolean online, @Param("serverId") String serverId);

    @Select("SELECT server_id FROM wvp_platform WHERE enable=true and server_id != #{serverId} group by server_id")
    @Select(value = "SELECT server_id FROM wvp_platform WHERE enable=1 and server_id !=" +
            "#{serverId} group by server_id", databaseId = "dm")
    List<String> queryServerIdsWithEnableAndNotInServer(@Param("serverId") String serverId);

    @Select("SELECT * FROM wvp_platform WHERE server_id = #{serverId}")
    List<Platform> queryByServerId(@Param("serverId") String serverId);

    @Select("SELECT * FROM wvp_platform ")
    List<Platform> queryAll();

    @Select("SELECT * FROM wvp_platform WHERE enable=true and server_id = #{serverId}")
    @Select(value = "SELECT * FROM wvp_platform WHERE enable=1 and server_id =" +
            "#{serverId}", databaseId = "dm")
    List<Platform> queryServerIdsWithEnableAndServer(@Param("serverId") String serverId);

    @Update("UPDATE wvp_platform SET status=false where server_id = #{serverId}" )
    @Update(value = "UPDATE wvp_platform SET status=0 where server_id = #{serverId}", databaseId = "dm")
    void offlineAll(@Param("serverId") String serverId);

}
