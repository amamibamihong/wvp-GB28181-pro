package com.genersoft.iot.vmp.bypass.service.impl;

import com.genersoft.iot.vmp.bypass.bean.BypassInfo;
import com.genersoft.iot.vmp.bypass.dao.BypassMapper;
import com.genersoft.iot.vmp.media.bean.MediaServer;
import com.genersoft.iot.vmp.media.event.media.MediaArrivalEvent;
import com.genersoft.iot.vmp.media.event.media.MediaDepartureEvent;
import com.genersoft.iot.vmp.media.event.media.MediaNotFoundEvent;
import com.genersoft.iot.vmp.media.service.IMediaServerService;
import com.genersoft.iot.vmp.bypass.service.MediaServerBypassService;
import com.genersoft.iot.vmp.media.zlm.ZLMRESTfulUtils;
import com.genersoft.iot.vmp.streamProxy.service.IStreamProxyPlayService;
import com.genersoft.iot.vmp.streamProxy.service.IStreamProxyService;
import com.genersoft.iot.vmp.vmanager.bean.WVPResult;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <delete>
 * 1. 任务停止  先删除bypass ,再停
 * 删的过程中,触发切换,不受也行
 * 删除到停止这一过程中,触发推流添加动作,那么这个值依然还在
 * </delete>
 * 2. 任务停止  先停, 再删除bypass
 * 停的时候触发bypass,那么就会切换到源地址,然后再删除bypass
 * <p>
 * 3. 任务切换:
 * 任务1 任务停止  先停, 再删除bypass
 * 任务2 任务启动  推流并添加bypass, 失败拉取原视频
 * <p>
 * 4.任务启动  如果开始旧没推上,那么就没有后续的切换
 * 所以要先添加bypass,
 * <p>
 * 这时候前一个删除可能在后一个添加后才开始操作,也就是添加的时候原先的也存在,那就删除旧的,添加新的,由于删除的校验动作,则不会删除新的
 */
@Slf4j
@Service
@Hidden
public class MediaServerBypassServiceImpl implements MediaServerBypassService {
    /**
     * 分为转码前转码后两个地址,
     * key:target
     * value:source
     * 当转码后地址流接入时,添加到bypassMap,并拉取当前地址到target
     * 当转码流失效时,删除当前拉流,并拉取源地址到当前target
     * 当任务取消时,删除bypassMap中的记录,并删除拉流代理
     * 仅在内存中维护,那么重启后将丢失
     */
    private ConcurrentHashMap<String, BypassInfo> bypassMap = new ConcurrentHashMap<>();

    @Autowired
    private ZLMRESTfulUtils zlmresTfulUtils;
    @Autowired
    private IMediaServerService mediaServerService;
    @Autowired
    private IStreamProxyPlayService streamProxyPlayService;
    @Autowired
    private IStreamProxyService streamProxyService;
    @Autowired
    private BypassMapper bypassMapper;

    @PostConstruct
    private void initBypassMap() {
        List<Map<String, Object>> bypassList = bypassMapper.selectAll();
        for (Map<String, Object> bypass : bypassList) {
            String destUrl = (String) bypass.get("dest_url");
            String srcUrl = (String) bypass.get("src_url");
            String host;
            int port = -1;
            String path;
            try {
                URL url = new URL("http" + destUrl.substring(4));
                host = url.getHost();
                port = url.getPort();
                path = url.getPath();
            } catch (MalformedURLException e) {
                log.warn("bypass dest_url格式错误:{}", destUrl);
                continue;
            }
            if (host == null) {
                log.warn("bypass dest_url格式错误:{}", destUrl);
                continue;
            }
            if (path == null) {
                log.warn("bypass dest_url格式错误:{}", destUrl);
                continue;
            }
            if (port == -1) {
                port = 554;
            }
            String[] paths = path.split("/");
            if (paths.length < 3) {
                log.warn("bypass dest_url格式错误:{}", destUrl);
                continue;
            }

            String app = paths[1];
            String stream = paths[2];

            List<MediaServer> mediaServerList = mediaServerService.getAll();
            MediaServer mediaServer = null;
            for (MediaServer ele : mediaServerList) {
                if (ele.getRtspPort() == port && host.equals(ele.getStreamIp())) {
                    mediaServer = ele;
                    break;
                }
            }
            if (mediaServer == null) {
                log.warn("cannot find media server ip:{} ,port:{}", host, port);
                continue;
            }

            String key = "/" + app + "/" + stream;
            BypassInfo bypassInfo = new BypassInfo(srcUrl, destUrl, mediaServer);
            bypassMap.put(key, bypassInfo);
        }
    }


    @Async("taskExecutor")
    @org.springframework.context.event.EventListener
    public void onApplicationEvent(MediaArrivalEvent event) {
        if (!event.getApp().startsWith("__")) {
            return;
        }
        String app = event.getApp().substring(2);
        String stream = event.getStream();
        String key = "/" + app + "/" + stream;
        BypassInfo bypassInfo = bypassMap.get(key);
        MediaServer mediaServer = event.getMediaServer();
        if (bypassInfo == null) {
            return;
        }
        synchronized (bypassInfo) {// 等操作完成,后面才能使用新值
            if (bypassInfo.isDelete()) {
                return;
            }

            Boolean delRs = mediaServerService.delStreamProxy(mediaServer, "__defaultVhost__" + key);
            log.info("删除拉流代理:__defaultVhost__/{}:rs:{}", key, delRs);

            String streamUrl = String.format("rtsp://127.0.0.1:%s/__%s/%s", mediaServer.getRtspPort(), app, stream);
            WVPResult<String> addRs = mediaServerService.addStreamProxy(event.getMediaServer(), app, stream, streamUrl, true, false, "0", 10);
            log.info("添加拉流代理:app:{},stream:{},url:{},rs:{}", app, stream, streamUrl, addRs);
        }

    }

    @Async("taskExecutor")
    @org.springframework.context.event.EventListener
    public void onApplicationEvent(MediaDepartureEvent event) {

        if (!event.getApp().startsWith("__")) {
            return;
        }
        String app = event.getApp().substring(2);
        String stream = event.getStream();
        String key = "/" + app + "/" + stream;
        BypassInfo bypassInfo = bypassMap.get(key);
        if (bypassInfo == null) {
            return;
        }
        synchronized (bypassInfo) { // 切换流
            if (bypassInfo.isDelete()) {
                return;
            }
            Boolean delRs = mediaServerService.delStreamProxy(bypassInfo.getMediaServer(), "__defaultVhost__" + key);
            log.info("删除拉流代理:__defaultVhost__/{}:rs:{}", key, delRs);

            WVPResult<String> addRs = mediaServerService.addStreamProxy(event.getMediaServer(), app, stream, bypassInfo.getSrcUrl(), true, false, "0", 10);
            log.info("添加拉流代理:app:{},stream:{},url:{},rs:{}", app, stream, bypassInfo.getSrcUrl(), addRs);
            // bypassMap.remove(targetUrl); // 这里如果删了,那么拉原始流的就会失去管理
        }
    }

    /**
     * 流未找到事件,如果未找到则拉取源地址到当前target,这种情况就是从未推流到当前target,或者推流失败
     *
     * @param event
     */
    @Async("taskExecutor")
    @org.springframework.context.event.EventListener
    public void onApplicationEvent(MediaNotFoundEvent event) {
        String app = event.getApp();
        String stream = event.getStream();
        String key = "/" + app + "/" + stream;
        BypassInfo bypassInfo = bypassMap.get(key);
        if (bypassInfo == null) {
            return;
        }
        synchronized (bypassInfo) { // 切换流
            if (bypassInfo.isDelete()) {
                return;
            }
            Boolean delRs = mediaServerService.delStreamProxy(bypassInfo.getMediaServer(), "__defaultVhost__" + key);
            log.info("删除拉流代理:__defaultVhost__/{}:rs:{}", key, delRs);
            WVPResult<String> addRs = mediaServerService.addStreamProxy(event.getMediaServer(), app, stream, bypassInfo.getSrcUrl(), true, false, "0", 10);
            log.info("添加拉流代理:app:{},stream:{},url:{},rs:{}", app, stream, bypassInfo.getSrcUrl(), addRs);
        }
    }


    /**
     * 在推流程序中清理
     * 在停止后再启动的情况下,因并发问题,造成前一个删除在后一个添加后执行
     *
     * @param destUrl
     */
    public int delBypass(String destUrl) {
        if (!destUrl.startsWith("rtsp://")) {
            return -1;
        }

        String host = null;
        int port = -1;
        String path = null;
        try {
            URL url = new URL("http" + destUrl.substring(4));
            host = url.getHost();
            port = url.getPort();
            path = url.getPath();

        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        if (path == null) {
            return -1;
        }
        String paths[] = path.split("/");
        if (paths.length < 3) {
            return -1;
        }
        String app = paths[1];
        String stream = paths[2];

        String key = "/" + app + "/" + stream;
        BypassInfo bypassInfo = bypassMap.get(key);
        while (true) {
            if (bypassInfo == null) {
                return -1;
            }
            synchronized (bypassInfo) { // 删除拉流

                BypassInfo tmp = bypassMap.get(key);
                if (tmp != bypassInfo) { // 变了重新加锁
                    bypassInfo = tmp;
                    continue;
                }
                if (bypassInfo.isDelete()) {
                    return -1;
                }

                bypassMap.remove(key);
                bypassInfo.setDelete(true);
                bypassMapper.del(bypassInfo.getDestUrl()); // 暂不使用update
                Boolean delRs = mediaServerService.delStreamProxy(bypassInfo.getMediaServer(), "__defaultVhost__" + key);
                log.info("删除拉流代理:__defaultVhost__/{}:rs:{}", destUrl, delRs);
                break;
            }
        }
        return 0;

    }

    public int addBypass(String srcUrl, String destUrl) {
        if (StringUtils.isEmpty(srcUrl) || StringUtils.isEmpty(destUrl)) {
            return -1;
        }
        // rtsp://127.0.0.1:554/app/12345678901234567890123456789012
        if (!destUrl.startsWith("rtsp://")) {
            return -1;
        }

        String host = null;
        int port = -1;
        String path = null;
        try {
            URL url = new URL("http" + destUrl.substring(4));
            host = url.getHost();
            port = url.getPort();
            path = url.getPath();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        if (host == null) {
            return -1;
        }
        if (path == null) {
            return -1;
        }
        if (port == -1) {
            port = 554;
        }
        List<MediaServer> mediaServerList = mediaServerService.getAll();
        MediaServer mediaServer = null;
        for (MediaServer ele : mediaServerList) {
            if (ele.getRtspPort() == port && host.equals(ele.getStreamIp())) {
                mediaServer = ele;
                break;
            }
        }
        if (mediaServer == null) {
            log.warn("cannot find media server ip:{} ,port:{}", host, port);
            return -1;
        }
        String paths[] = path.split("/");
        if (paths.length < 3) {
            return -1;
        }
        String app = paths[1];
        String stream = paths[2];

        String key = "/" + app + "/" + stream;

        BypassInfo bypassInfo = new BypassInfo(srcUrl, destUrl, mediaServer);
        // 如果在这里被删除,下面添加的可能会不再切换流

        synchronized (bypassInfo) {// 等操作完成,后面才能使用新值
            BypassInfo pre = bypassMap.put(key, bypassInfo);
            if (pre != null) {
                // 删除旧的,也许并不存在
                synchronized (pre) { // 旧值加锁,
                    pre.setDelete(true);
                    Boolean delRs = mediaServerService.delStreamProxy(pre.getMediaServer(), "__defaultVhost__" + key);
                    log.info("已存在,删除拉流代理:__defaultVhost__/{}:rs:{}", destUrl, delRs);
                    bypassMapper.del(pre.getDestUrl()); // 暂不使用update
                }
            }
            int rs = bypassMapper.add(destUrl, srcUrl);
            if (rs < 0) {
                log.warn("添加bypass配置失败:{}", destUrl);
                return -1;
            }
            // 这里先不创建拉流代理,由MediaNotFoundEvent事件触发
            // 第一步,在压缩推流没启动前先拉取原始流
            // ZLMResult<StreamProxyResult> addRs = zlmresTfulUtils.addStreamProxy(mediaServer, app, stream, srcUrl, true, false, "0", 10);
            // log.info("添加拉流代理:app:{},stream:{},url:{},rs:{}", app, stream, bypassInfo.getSourceUrl(), addRs);
        }
        return 0;
    }

}
