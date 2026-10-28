package com.genersoft.iot.vmp.bypass.bean;

import com.genersoft.iot.vmp.media.bean.MediaServer;
import lombok.Data;

@Data
public class BypassInfo {
    /**
     * 转码前到地址
     */
    private String srcUrl;
    private String destUrl;

    private MediaServer mediaServer; //任务取消时需要删除拉流代理
    private volatile boolean delete = false;

    public BypassInfo(String srcUrl,String destUrl, MediaServer mediaServer) {
        this.srcUrl = srcUrl;
        this.destUrl = destUrl;
        this.mediaServer = mediaServer;
        delete = false;
    }
}
