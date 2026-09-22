package com.genersoft.iot.vmp.gb35114.sip;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 国密注册会话缓存，按国标 ID（设备或上级平台编码）索引协商出的 VKEK。
 *
 * <p>UAS 侧：本平台收到设备注册后写入 deviceId → VKEK；
 * UAC 侧：本平台向上级注册成功后写入上级 serverGBId → VKEK。
 * 两种 ID 都进同一缓存，出站 Note 加签按对端 ID 查询即可天然覆盖。
 *
 * <p>当前为单机内存实现；集群部署可替换为 Redis（保留接口一致）。
 */
@Component
public class Gb35114VkekCache {

    private final Map<String, byte[]> vkekMap = new ConcurrentHashMap<>();

    /** 写入（或覆盖）某个对端的 VKEK。 */
    public void put(String id, byte[] vkek) {
        vkekMap.put(id, vkek);
    }

    /** 读取某个对端的 VKEK，未协商返回 {@code null}。 */
    public byte[] get(String id) {
        return vkekMap.get(id);
    }

    /** 移除某个对端的 VKEK。 */
    public void remove(String id) {
        vkekMap.remove(id);
    }

    /** 是否已存在协商好的 VKEK。 */
    public boolean contains(String id) {
        return vkekMap.containsKey(id);
    }
}
