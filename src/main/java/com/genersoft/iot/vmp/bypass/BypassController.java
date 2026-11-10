package com.genersoft.iot.vmp.bypass;

import com.genersoft.iot.vmp.bypass.service.MediaServerBypassService;
import com.genersoft.iot.vmp.vmanager.bean.WVPResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/index/bypass")
public class BypassController {
    @Autowired
    private MediaServerBypassService bypassService;


    @ResponseBody
    @RequestMapping(value = "/delete")
    public WVPResult<?> delBypass(String destUrl) {
        int rs = bypassService.delBypass(destUrl);
        if (rs == 0) {
            return WVPResult.success();
        } else {
            return WVPResult.fail(rs, null);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/add")
    public WVPResult<?> addBypass(String srcUrl, String destUrl) {
        int rs = bypassService.addBypass(srcUrl, destUrl);
        if (rs == 0) {
            return WVPResult.success();
        } else {
            return WVPResult.fail(rs, null);
        }
    }
}
