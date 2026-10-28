package com.genersoft.iot.vmp.bypass.dao;

import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Map;

@Mapper
public interface BypassMapper {

    @Delete("DELETE FROM tds_bypass WHERE dest_url=#{destUrl}")
    int del(@Param("destUrl") String destUrl);

    @Insert("insert into tds_bypass (dest_url,src_url) values (#{destUrl},#{srcUrl})")
    int add(@Param("destUrl") String destUrl,@Param("srcUrl") String srcUrl);
    /**
     * 查询所有旁路配置
     * @return
     */
    @Select("select dest_url,src_url from tds_bypass")
    List <Map<String,Object>> selectAll();
}
