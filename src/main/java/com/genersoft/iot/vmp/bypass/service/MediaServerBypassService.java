package com.genersoft.iot.vmp.bypass.service;

public interface MediaServerBypassService {
    public int  addBypass(String srcUrl, String destUrl);

    public int  delBypass(String targetUrl);
}
