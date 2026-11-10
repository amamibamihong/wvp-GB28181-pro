package com.genersoft.iot.vmp.gb28181.service.impl;

import com.genersoft.iot.vmp.common.*;
import com.genersoft.iot.vmp.conf.DynamicTask;
import com.genersoft.iot.vmp.conf.SipConfig;
import com.genersoft.iot.vmp.conf.UserSetting;
import com.genersoft.iot.vmp.conf.exception.ControllerException;
import com.genersoft.iot.vmp.conf.exception.SsrcTransactionNotFoundException;
import com.genersoft.iot.vmp.gb28181.bean.*;
import com.genersoft.iot.vmp.gb28181.dao.PlatformChannelMapper;
import com.genersoft.iot.vmp.gb28181.dao.PlatformMapper;
import com.genersoft.iot.vmp.gb28181.event.SipSubscribe;
import com.genersoft.iot.vmp.gb28181.service.IGbChannelService;
import com.genersoft.iot.vmp.gb28181.service.IInviteStreamService;
import com.genersoft.iot.vmp.gb28181.service.IPlatformService;
import com.genersoft.iot.vmp.gb28181.session.SSRCFactory;
import com.genersoft.iot.vmp.gb28181.session.SipInviteSessionManager;
import com.genersoft.iot.vmp.gb28181.task.platformStatus.PlatformKeepaliveTask;
import com.genersoft.iot.vmp.gb28181.task.platformStatus.PlatformRegisterTask;
import com.genersoft.iot.vmp.gb28181.task.platformStatus.PlatformRegisterTaskInfo;
import com.genersoft.iot.vmp.gb28181.task.platformStatus.PlatformStatusTaskRunner;
import com.genersoft.iot.vmp.gb28181.transmit.cmd.ISIPCommanderForPlatform;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import com.genersoft.iot.vmp.gb28181.utils.SipUtils;
import com.genersoft.iot.vmp.media.bean.MediaInfo;
import com.genersoft.iot.vmp.media.bean.MediaServer;
import com.genersoft.iot.vmp.media.event.hook.HookData;
import com.genersoft.iot.vmp.media.event.hook.HookSubscribe;
import com.genersoft.iot.vmp.media.event.media.MediaDepartureEvent;
import com.genersoft.iot.vmp.media.event.mediaServer.MediaSendRtpStoppedEvent;
import com.genersoft.iot.vmp.media.service.IMediaServerService;
import com.genersoft.iot.vmp.service.IReceiveRtpServerService;
import com.genersoft.iot.vmp.service.ISendRtpServerService;
import com.genersoft.iot.vmp.service.bean.*;
import com.genersoft.iot.vmp.service.redisMsg.IRedisRpcService;
import com.genersoft.iot.vmp.storager.IRedisCatchStorage;
import com.genersoft.iot.vmp.vmanager.bean.ErrorCode;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import gov.nist.javax.sip.message.SIPResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import javax.sdp.*;
import javax.sip.InvalidArgumentException;
import javax.sip.ResponseEvent;
import javax.sip.SipException;
import java.text.ParseException;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.TimeUnit;

/**
 * @author lin
 */
@Slf4j
@Service
public class PlatformServiceImpl implements IPlatformService {

    @Autowired
    private PlatformMapper platformMapper;

    @Autowired
    private IRedisCatchStorage redisCatchStorage;

    @Autowired
    private SSRCFactory ssrcFactory;

    @Autowired
    private IMediaServerService mediaServerService;

    @Autowired
    private ISIPCommanderForPlatform commanderForPlatform;

    @Autowired
    private DynamicTask dynamicTask;

    @Autowired
    private SubscribeHolder subscribeHolder;

    @Autowired
    private UserSetting userSetting;

    @Autowired
    private IRedisRpcService redisRpcService;

    @Autowired
    private SipConfig sipConfig;

    @Autowired
    private SipInviteSessionManager sessionManager;

    @Autowired
    private IInviteStreamService inviteStreamService;

    @Autowired
    private PlatformChannelMapper platformChannelMapper;

    @Autowired
    private IGbChannelService channelService;

    @Autowired
    private ISendRtpServerService sendRtpServerService;

    @Autowired
    private IReceiveRtpServerService receiveRtpServerService;

    @Autowired
    private PlatformStatusTaskRunner statusTaskRunner;

    /**
     * GB35114 证书服务，用于「新增上级时判断国密证书是否已配齐」。
     *
     * <p>{@code required = false}：GB35114 是可选模块，未引入时整体降级为「不跳过注册」，
     * 与本改动之前的行为一致。
     */
    @Autowired(required = false)
    private IGb35114CertService gb35114CertService;

    /**
     * 启动流程里「对仍在有效期的平台发送注销」这一步是否已经结束。
     *
     * <p>默认 {@code false}：{@code @Scheduled} 标注的任务在容器 refresh 阶段就会被注册并开始
     * 执行，<b>早于</b> {@link ApplicationReadyEvent}。也就是说容器刚起来时
     * {@link #statusLostCheck()} 可能先跑，与 {@link #onApplicationReady()} 里的注销流程并发
     * 操作同一个平台的同一条 SIP 通道。
     */
    private volatile boolean startupUnregisterFinished = false;

    /** 应用启动时刻，作为 {@link #startupUnregisterFinished} 的兜底 */
    private final long startupTimestamp = System.currentTimeMillis();

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(){

        // 查找国标推流
        List<SendRtpInfo> sendRtpItems = redisCatchStorage.queryAllSendRTPServer();
        if (!sendRtpItems.isEmpty()) {
            for (SendRtpInfo sendRtpItem : sendRtpItems) {
                MediaServer mediaServerItem = mediaServerService.getOne(sendRtpItem.getMediaServerId());
                CommonGBChannel channel = channelService.getOne(sendRtpItem.getChannelId());
                if (channel == null){
                    continue;
                }
                sendRtpServerService.delete(sendRtpItem);
                if (mediaServerItem != null) {
                    boolean stopResult = mediaServerService.initStopSendRtp(mediaServerItem, sendRtpItem.getApp(), sendRtpItem.getStream(), sendRtpItem.getSsrc());
                    if (stopResult) {
                        Platform platform = queryPlatformByServerGBId(sendRtpItem.getTargetId());

                        if (platform != null && userSetting.getServerId().equals(platform.getServerId())) {
                            try {
                                commanderForPlatform.streamByeCmd(platform, sendRtpItem, channel);
                            } catch (InvalidArgumentException | ParseException | SipException e) {
                                log.error("[命令发送失败] 国标级联 发送BYE: {}", e.getMessage());
                            }
                        }
                    }
                }
            }
        }

        // 启动时 如果存在未过期的注册平台，则发送注销
        List<PlatformRegisterTaskInfo> registerTaskInfoList = statusTaskRunner.getAllRegisterTaskInfo();
        if (registerTaskInfoList.isEmpty()) {
            startupUnregisterFinished = true;
            return;
        }
        try {
            for (PlatformRegisterTaskInfo taskInfo : registerTaskInfoList) {
                log.info("[国标级联] 启动服务是发现平台注册仍在有效期，注销： {}", taskInfo.getPlatformServerId());
                Platform platform = queryPlatformByServerGBId(taskInfo.getPlatformServerId());
                if (platform == null) {
                    statusTaskRunner.removeRegisterTask(taskInfo.getPlatformServerId());
                    continue;
                }
                if (userSetting.getServerId().equals(platform.getServerId())) {
                    sendUnRegister(platform, taskInfo.getSipTransactionInfo());
                }
            }
        } finally {
            startupUnregisterFinished = true;
        }
        // 启动时所有平台默认离线
        platformMapper.offlineAll(userSetting.getServerId());
    }
    @Scheduled(fixedDelay = 20, timeUnit = TimeUnit.SECONDS)   //每3秒执行一次
    public void statusLostCheck(){
        // 启动注销流程（onApplicationReady 里对「仍在有效期」的平台发注销）还没走完时不要发起注册：
        // 两条流程会并发操作同一个平台的同一条 SIP 通道，而 NioTcpMessageChannel 重新建连
        //（[2] Old socket different）时会关掉旧 socket，先发出去的那条 REGISTER 会连 socket 一起
        // 被另一个线程关掉，对端根本收不到，只在 2 秒后表现为「注册失败: 消息超时未回复」。
        // 兜底：万一上面那段清理逻辑抛异常导致标记没置位，启动 60 秒后强制放行。
        if (!startupUnregisterFinished
                && System.currentTimeMillis() - startupTimestamp < 60_000L) {
            return;
        }
        // 每隔20秒检测，是否存在启用但是未注册的平台，存在则发起注册
        // 获取所有在线并且启用的平台
        List<Platform> platformList = platformMapper.queryServerIdsWithEnableAndServer(userSetting.getServerId());
        if (platformList.isEmpty()) {
            return;
        }
        for (Platform platform : platformList) {
             if (statusTaskRunner.containsRegister(platform.getServerGBId()) && statusTaskRunner.containsKeepAlive(platform.getServerGBId())) {
                 continue;
             }
             if (statusTaskRunner.containsRegister(platform.getServerGBId())) {
                 SipTransactionInfo transactionInfo = statusTaskRunner.getRegisterTransactionInfo(platform.getServerGBId());
                 // 注销后出发平台离线， 如果是启用的平台，那么下次丢失检测会检测到并重新注册上线
                 sendUnRegister(platform, transactionInfo);
             }else {
                 statusTaskRunner.removeKeepAliveTask(platform.getServerGBId());
                 sendRegister(platform, null);
             }
        }
    }

    private void sendRegister(Platform platform, SipTransactionInfo sipTransactionInfo) {
        try {
            commanderForPlatform.register(platform, sipTransactionInfo, eventResult -> {
                log.info("[国标级联] {}（{}）,注册失败", platform.getName(), platform.getServerGBId());
                offline(platform);
            }, null);
        } catch (InvalidArgumentException | ParseException | SipException e) {
            log.error("[命令发送失败] 国标级联: {}", e.getMessage());
        }
    }

    private void sendUnRegister(Platform platform, SipTransactionInfo sipTransactionInfo) {
        statusTaskRunner.removeRegisterTask(platform.getServerGBId());
        statusTaskRunner.removeKeepAliveTask(platform.getServerGBId());
        try {
            commanderForPlatform.unregister(platform, sipTransactionInfo, null, eventResult -> {
                log.info("[国标级联] 注销成功， 平台：{}", platform.getServerGBId());
            });
        } catch (InvalidArgumentException | ParseException | SipException e) {
            log.error("[命令发送失败] 国标级联: {}", e.getMessage());
        }
    }

    // 定时监听国标级联所进行的WVP服务是否正常， 如果异常则选择新的wvp执行
    @Scheduled(fixedDelay = 2, timeUnit = TimeUnit.SECONDS)   //每3秒执行一次
    public void execute(){
        if (!userSetting.isAutoRegisterPlatform()) {
            return;
        }
        // 查找非平台的国标级联执行服务Id
        List<String> serverIds = platformMapper.queryServerIdsWithEnableAndNotInServer(userSetting.getServerId());
        if (serverIds == null || serverIds.isEmpty()) {
            return;
        }
        serverIds.forEach(serverId -> {
           // 检查每个是否存活
            ServerInfo serverInfo = redisCatchStorage.queryServerInfo(serverId);
            if (serverInfo != null) {
                return;
            }
            log.info("[集群] 检测到 {} 已离线", serverId);
            redisCatchStorage.removeOfflineWVPInfo(serverId);
            String chooseServerId = redisCatchStorage.chooseOneServer(serverId);
            if (!userSetting.getServerId().equals(chooseServerId)){
                return;
            }
            // 此平台需要选择新平台处理， 确定由当前平台即开始处理
            List<Platform> platformList = platformMapper.queryByServerId(serverId);
            platformList.forEach(platform -> {
                log.info("[集群] 由本平台开启上级平台{}({})的注册", platform.getName(), platform.getServerGBId());
                // 设置平台使用当前平台的IP
                platform.setAddress(getIpWithSameNetwork(platform.getAddress()));
                platform.setServerId(userSetting.getServerId());
                platformMapper.update(platform);
                // 检查就平台是否注册到期，没有则注销，由本平台重新注册
                List<PlatformRegisterTaskInfo> taskInfoList = statusTaskRunner.getRegisterTransactionInfoByServerId(serverId);
                boolean needUnregister = false;
                SipTransactionInfo sipTransactionInfo = null;
                if (!taskInfoList.isEmpty()) {
                    for (PlatformRegisterTaskInfo taskInfo : taskInfoList) {
                        if (taskInfo.getPlatformServerId().equals(platform.getServerGBId())
                                && taskInfo.getSipTransactionInfo() != null) {
                            needUnregister = true;
                            sipTransactionInfo = taskInfo.getSipTransactionInfo();
                            break;
                        }
                    }
                }
                if (needUnregister) {
                    sendUnRegister(platform, sipTransactionInfo);
                }else {
                    // 开始注册
                    // 注册成功时由程序直接调用了online方法
                    sendRegister(platform, null);
                }
            });
        });
    }

    /**
     * 获取同网段的IP
     */
    private String getIpWithSameNetwork(String ip){
        if (ip == null || sipConfig.getMonitorIps().size() == 1) {
            return sipConfig.getMonitorIps().get(0);
        }
        String[] ipSplit = ip.split("\\.");
        String ip1 = null, ip2 = null, ip3 = null;
        for (String monitorIp : sipConfig.getMonitorIps()) {
            String[] monitorIpSplit = monitorIp.split("\\.");
            if (monitorIpSplit[0].equals(ipSplit[0]) && monitorIpSplit[1].equals(ipSplit[1]) && monitorIpSplit[2].equals(ipSplit[2])) {
                ip3 = monitorIp;
            }else if (monitorIpSplit[0].equals(ipSplit[0]) && monitorIpSplit[1].equals(ipSplit[1])) {
                ip2 = monitorIp;
            }else if (monitorIpSplit[0].equals(ipSplit[0])) {
                ip1 = monitorIp;
            }
        }
        if (ip3 != null) {
            return ip3;
        }else if (ip2 != null) {
            return ip2;
        }else if (ip1 != null) {
            return ip1;
        }else {
            return sipConfig.getMonitorIps().get(0);
        }
    }

    /**
     * 流离开的处理
     */
    @Async
    @EventListener
    public void onApplicationEvent(MediaDepartureEvent event) {
        List<SendRtpInfo> sendRtpItems = sendRtpServerService.queryByStream(event.getStream());
        if (!sendRtpItems.isEmpty()) {
            for (SendRtpInfo sendRtpItem : sendRtpItems) {
                if (sendRtpItem != null && sendRtpItem.getApp().equals(event.getApp()) && sendRtpItem.isSendToPlatform()) {
                    String platformId = sendRtpItem.getTargetId();
                    Platform platform = platformMapper.getParentPlatByServerGBId(platformId);
                    CommonGBChannel channel = channelService.getOne(sendRtpItem.getChannelId());
                    try {
                        if (platform != null && channel != null) {
                            commanderForPlatform.streamByeCmd(platform, sendRtpItem, channel);
                            sendRtpServerService.delete(sendRtpItem);
                        }
                    } catch (SipException | InvalidArgumentException | ParseException e) {
                        log.error("[命令发送失败] 发送BYE: {}", e.getMessage());
                    }
                }
            }
        }
    }


    /**
     * 发流停止
     */
    @Async
    @EventListener
    public void onApplicationEvent(MediaSendRtpStoppedEvent event) {
        List<SendRtpInfo> sendRtpItems = sendRtpServerService.queryByStream(event.getStream());
        if (sendRtpItems != null && !sendRtpItems.isEmpty()) {
            for (SendRtpInfo sendRtpItem : sendRtpItems) {
                if (sendRtpItem != null && sendRtpItem.getApp().equals(event.getApp()) && sendRtpItem.isSendToPlatform()) {
                    Platform platform = platformMapper.getParentPlatByServerGBId(sendRtpItem.getTargetId());
                    CommonGBChannel channel = channelService.getOne(sendRtpItem.getChannelId());
                    try {
                        commanderForPlatform.streamByeCmd(platform, sendRtpItem, channel);
                    } catch (SipException | InvalidArgumentException | ParseException e) {
                        log.error("[命令发送失败] 国标级联 发送BYE: {}", e.getMessage());
                    }
                    sendRtpServerService.delete(sendRtpItem);
                }
            }
        }
    }

    @Override
    public Platform queryPlatformByServerGBId(String platformGbId) {
        return platformMapper.getParentPlatByServerGBId(platformGbId);
    }

    @Override
    public PageInfo<Platform> queryPlatformList(int page, int count, String query) {
        PageHelper.startPage(page, count);
        if (query != null) {
            query = query.replaceAll("/", "//")
                    .replaceAll("%", "/%")
                    .replaceAll("_", "/_");
        }
        List<Platform> all = platformMapper.queryList(query);
        return new PageInfo<>(all);
    }

    @Override
    public boolean add(Platform platform) {
        log.info("[国标级联]添加平台 {}", platform.getDeviceGBId());
        if (platform.getCatalogGroup() == 0) {
            // 每次发送目录的数量默认为1
            platform.setCatalogGroup(1);
        }
        platform.setServerId(userSetting.getServerId());
        int result = platformMapper.add(platform);

        if (platform.isEnable()) {
            // 保存时启用就发送注册
            // 注册成功时由程序直接调用了online方法
            if (canRegisterNow(platform)) {
                sendRegister(platform, null);
            } else {
                log.info("[新增平台] {} GB35114 证书未配置，暂不注册，请在编辑页配置后保存",
                        platform.getDeviceGBId());
            }
        }
        return result > 0;
    }

    /**
     * 新增上级时是否具备立刻发起注册的条件。
     *
     * <p>唯一的例外是 GB35114（{@code registerWay} 为 3/4）而<b>设备证书还没配</b>：
     * 新增页不渲染证书槽（证书动作都要把「本上级的 id」写进引用列，而此刻 platform
     * 还没有 id），所以此时发注册必然失败 ——
     * {@code SIPCommanderForPlatform} 进入国密分支后
     * {@code uacStateMachine} 返回 null，随后抛
     * {@code SipException("GB35114 device certificate not configured")}。
     * 与其白抛一次异常刷错误日志，不如跳过，提示用户去编辑页配好证书再保存。
     *
     * <p>判据与 {@code uacStateMachine} 的取值口径一致：它返回 null 的唯一原因就是
     * {@code loadDeviceIdentity} 拿不到设备证书，即 {@code device_cert_id} 为空且按
     * 上级国标编码也解析不到「客户端证书（本平台）」。上级平台证书缺失不在此列 ——
     * 它只影响 sign2 的验签，不影响首包宣告 Capability。
     *
     * <p>编辑页保存（{@link #update}）不走这里：那时证书已配好，正常注册。
     */
    private boolean canRegisterNow(Platform platform) {
        if (platform.getRegisterWay() != 3 && platform.getRegisterWay() != 4) {
            return true;
        }
        if (gb35114CertService == null) {
            // GB35114 模块缺席，无从判断，维持原有行为
            return true;
        }
        if (platform.getDeviceCertId() != null) {
            return true;
        }
        // 这里要传的是「本平台向上注册的国标编码」，即 deviceGBId —— 与
        // SIPCommanderForPlatform 调用 uacStateMachine(deviceGBId, serverGBId, ...) 的
        // 第一个参数一致；DEVICE_IDENTITY 证书的 gb_id 存的就是这个值。
        return gb35114CertService.queryDeviceIdentity(platform.getDeviceGBId()) != null;
    }



    @Override
    public boolean update(Platform platform) {
        Assert.isTrue(platform.getId() > 0, "ID必须存在");
        log.info("[国标级联] 更新平台 {}({})", platform.getName(), platform.getDeviceGBId());
        platform.setCharacterSet(platform.getCharacterSet().toUpperCase());
        Platform platformInDb = platformMapper.query(platform.getId());
        Assert.notNull(platformInDb, "平台不存在");
        if (!userSetting.getServerId().equals(platformInDb.getServerId())) {
            return redisRpcService.updatePlatform(platformInDb.getServerId(), platform);
        }
        // 更新数据库
        if (platform.getCatalogGroup() == 0) {
            platform.setCatalogGroup(1);
        }
        platformMapper.update(platform);
        if (statusTaskRunner.containsRegister(platformInDb.getServerGBId())) {
            SipTransactionInfo transactionInfo = statusTaskRunner.getRegisterTransactionInfo(platformInDb.getServerGBId());
            // 注销后出发平台离线， 如果是启用的平台，那么下次丢失检测会检测到并重新注册上线
            sendUnRegister(platformInDb, transactionInfo);
        }else if (platform.isEnable()) {
            sendRegister(platform, null);
        }

        return false;
    }

    @Override
    public void online(Platform platform, SipTransactionInfo sipTransactionInfo) {
        log.info("[国标级联]：{}, 平台上线", platform.getServerGBId());
        PlatformRegisterTask registerTask = new PlatformRegisterTask(platform.getServerGBId(), platform.getExpires() * 1000L - 500L,
                sipTransactionInfo, (platformServerGbId) -> {
            this.registerExpire(platformServerGbId, sipTransactionInfo);
        });
        statusTaskRunner.addRegisterTask(registerTask);

        PlatformKeepaliveTask keepaliveTask = new PlatformKeepaliveTask(platform.getServerGBId(), platform.getKeepTimeout() * 1000L,
                this::keepaliveExpire);
        statusTaskRunner.addKeepAliveTask(keepaliveTask);
        platformMapper.updateStatus(platform.getId(), true, userSetting.getServerId());

        if (platform.getAutoPushChannel() != null && platform.getAutoPushChannel()) {
            if (subscribeHolder.getCatalogSubscribe(platform.getServerGBId()) == null) {
                log.info("[国标级联]：{}, 添加自动通道推送模拟订阅信息", platform.getServerGBId());
                addSimulatedSubscribeInfo(platform);
            }
        }else {
            SubscribeInfo catalogSubscribe = subscribeHolder.getCatalogSubscribe(platform.getServerGBId());
            if (catalogSubscribe != null && catalogSubscribe.getExpires() == -1) {
                subscribeHolder.removeCatalogSubscribe(platform.getServerGBId());
            }
        }
    }

    /**
     * 注册到期处理
     */
    private void registerExpire(String platformServerId, SipTransactionInfo transactionInfo) {
        log.info("[国标级联] 注册到期， 上级平台编号： {}", platformServerId);
        Platform platform = queryPlatformByServerGBId(platformServerId);
        if (platform == null || !platform.isEnable()) {
            log.info("[国标级联] 注册到期， 上级平台编号： {}, 平台不存在或者未启用， 忽略", platformServerId);
            return;
        }
        sendRegister(platform, transactionInfo);
    }

    private void keepaliveExpire(String platformServerId, int failCount) {
        Platform platform = queryPlatformByServerGBId(platformServerId);
        if (platform == null || !platform.isEnable()) {
            log.info("[国标级联] 心跳到期， 上级平台编号： {}, 平台不存在或者未启用， 忽略", platformServerId);
            return;
        }
        try {
            commanderForPlatform.keepalive(platform, eventResult -> {
                // 心跳失败
                if (eventResult.type != SipSubscribe.EventResultType.timeout) {
                    log.warn("[国标级联] 发送心跳收到错误，code： {}, msg: {}", eventResult.statusCode, eventResult.msg);
                }

                // 心跳超时失败
                if (failCount < 2) {
                    log.info("[国标级联] 心跳发送超时， 平台服务编号： {}", platformServerId);
                    PlatformKeepaliveTask keepaliveTask = new PlatformKeepaliveTask(platform.getServerGBId(), platform.getKeepTimeout() * 1000L,
                            this::keepaliveExpire);
                    keepaliveTask.setFailCount(failCount + 1);
                    statusTaskRunner.addKeepAliveTask(keepaliveTask);
                }else {
                    // 心跳超时三次, 不再发送心跳， 平台离线
                    log.info("[国标级联] 心跳发送超时三次，平台离线， 平台服务编号： {}", platformServerId);
                    offline(platform);
                }
            }, eventResult -> {
                PlatformKeepaliveTask keepaliveTask = new PlatformKeepaliveTask(platform.getServerGBId(), platform.getKeepTimeout() * 1000L,
                        this::keepaliveExpire);
                statusTaskRunner.addKeepAliveTask(keepaliveTask);
            });
        } catch (SipException | InvalidArgumentException | ParseException e) {
            log.error("[命令发送失败] 国标级联 发送心跳: {}", e.getMessage());
            if (failCount < 2) {
                PlatformKeepaliveTask keepaliveTask = new PlatformKeepaliveTask(platform.getServerGBId(), platform.getKeepTimeout() * 1000L,
                        this::keepaliveExpire);
                keepaliveTask.setFailCount(failCount + 1);
                statusTaskRunner.addKeepAliveTask(keepaliveTask);
            }else {
                // 心跳超时三次, 不再发送心跳， 平台离线
                log.info("[国标级联] 心跳发送失败三次，平台离线， 平台服务编号： {}", platformServerId);
                offline(platform);
            }
        }
    }

    @Override
    public void addSimulatedSubscribeInfo(Platform platform) {
        // 自动添加一条模拟的订阅信息
        subscribeHolder.putCatalogSubscribe(platform.getServerGBId(),
                SubscribeInfo.buildSimulated(platform.getServerGBId(), platform.getServerIp()));
    }

    @Override
    public void offline(Platform platform) {
        log.info("[平台离线]：{}({})", platform.getName(), platform.getServerGBId());
        statusTaskRunner.removeRegisterTask(platform.getServerGBId());
        statusTaskRunner.removeKeepAliveTask(platform.getServerGBId());

        subscribeHolder.removeCatalogSubscribe(platform.getServerGBId());
        subscribeHolder.removeMobilePositionSubscribe(platform.getServerGBId());

        platformMapper.updateStatus(platform.getId(), false, userSetting.getServerId());

        // 停止所有推流
        log.info("[平台离线] {}({}), 停止所有推流", platform.getName(),  platform.getServerGBId());
        stopAllPush(platform.getServerGBId());
    }

    private void stopAllPush(String platformId) {
        List<SendRtpInfo> sendRtpItems = sendRtpServerService.queryForPlatform(platformId);
        if (sendRtpItems != null && !sendRtpItems.isEmpty()) {
            for (SendRtpInfo sendRtpItem : sendRtpItems) {
                sendRtpServerService.delete(sendRtpItem);
                MediaServer mediaInfo = mediaServerService.getOne(sendRtpItem.getMediaServerId());
                mediaServerService.stopSendRtp(mediaInfo, sendRtpItem.getApp(), sendRtpItem.getStream(), null);
            }
        }
    }

    @Override
    public void sendNotifyMobilePosition(String platformId) {
        Platform platform = platformMapper.getParentPlatByServerGBId(platformId);
        if (platform == null) {
            return;
        }
        SubscribeInfo subscribe = subscribeHolder.getMobilePositionSubscribe(platform.getServerGBId());
        if (subscribe != null) {

            List<CommonGBChannel> channelList = platformChannelMapper.queryShare(platform.getId(), null);
            if (channelList.isEmpty()) {
                return;
            }
            for (CommonGBChannel channel : channelList) {
                GPSMsgInfo gpsMsgInfo = redisCatchStorage.getGpsMsgInfo(channel.getGbDeviceId());
                // 无最新位置则发送当前位置
                if (gpsMsgInfo != null && (gpsMsgInfo.getLng() == 0 && gpsMsgInfo.getLat() == 0)) {
                    gpsMsgInfo = null;
                }

                if (gpsMsgInfo == null && !userSetting.isSendPositionOnDemand()){
                    gpsMsgInfo = new GPSMsgInfo();
                    gpsMsgInfo.setId(channel.getGbDeviceId());
                    gpsMsgInfo.setLng(channel.getGbLongitude());
                    gpsMsgInfo.setLat(channel.getGbLatitude());
                    gpsMsgInfo.setAltitude(channel.getGpsAltitude());
                    gpsMsgInfo.setSpeed(channel.getGpsSpeed());
                    gpsMsgInfo.setDirection(channel.getGpsDirection());
                    gpsMsgInfo.setTime(channel.getGpsTime());
                }

                // 无最新位置不发送
                if (gpsMsgInfo != null) {
                    // 发送GPS消息
                    try {
                        commanderForPlatform.sendNotifyMobilePosition(platform, gpsMsgInfo, channel, subscribe);
                    } catch (InvalidArgumentException | ParseException | NoSuchFieldException | SipException |
                             IllegalAccessException e) {
                        log.error("[命令发送失败] 国标级联 移动位置通知: {}", e.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public void broadcastInvite(Platform platform, CommonGBChannel channel, String sourceId, MediaServer mediaServerItem, HookSubscribe.Event hookEvent,
                                SipSubscribe.Event errorEvent, InviteTimeOutCallback timeoutCallback) throws InvalidArgumentException, ParseException, SipException {

        if (mediaServerItem == null) {
            log.info("[国标级联] 语音喊话未找到可用的zlm. platform: {}", platform.getServerGBId());
            return;
        }
        InviteInfo inviteInfoForOld = inviteStreamService.getInviteInfoByDeviceAndChannel(InviteSessionType.BROADCAST, channel.getGbId());

        if (inviteInfoForOld != null && inviteInfoForOld.getStreamInfo() != null) {
            // 如果zlm不存在这个流，则删除数据即可
            MediaServer mediaServerItemForStreamInfo = mediaServerService.getOne(inviteInfoForOld.getStreamInfo().getMediaServer().getId());
            if (mediaServerItemForStreamInfo != null) {
                Boolean ready = mediaServerService.isStreamReady(mediaServerItemForStreamInfo, inviteInfoForOld.getStreamInfo().getApp(), inviteInfoForOld.getStreamInfo().getStream());
                if (!ready) {
                    // 错误存在于redis中的数据
                    inviteStreamService.removeInviteInfo(inviteInfoForOld);
                }else {
                    // 流确实尚在推流，直接回调结果
                    HookData hookData = new HookData();
                    hookData.setApp(inviteInfoForOld.getStreamInfo().getApp());
                    hookData.setStream(inviteInfoForOld.getStreamInfo().getStream());
                    hookData.setMediaServer(mediaServerItemForStreamInfo);
                    hookEvent.response(hookData);
                    return;
                }
            }
        }

        SSRCInfo ssrcInfo = receiveRtpServerService.openGbRTPServerForBroadcast(mediaServerItem, platform, channel, ((code, msg, data) -> {
                    if (code == InviteErrorCode.SUCCESS.getCode() && data != null && data.getHookData() != null) {
                        log.info("[国标级联] 发起语音喊话 收到上级推流 deviceId: {}, channelId: {}", platform.getServerGBId(), channel.getGbDeviceId());
                        HookData hookData = data.getHookData();
                        // hook响应
                        onPublishHandlerForBroadcast(hookData.getMediaServer(), hookData.getMediaInfo(), platform, channel);
                        // 收到流
                        if (hookEvent != null) {
                            hookEvent.response(hookData);
                        }
                    }else {
                        InviteInfo inviteInfoForBroadcast = inviteStreamService.getInviteInfo(InviteSessionType.BROADCAST, channel.getGbId(), null);
                        if (inviteInfoForBroadcast == null) {
                            log.info("[国标级联] 发起语音喊话 收流超时 deviceId: {}, channelId: {}", platform.getServerGBId(), channel.getGbDeviceId());
                            // 点播超时回复BYE 同时释放ssrc以及此次点播的资源
                            try {
                                commanderForPlatform.streamByeCmd(platform, channel, data.getSsrcInfo().getApp(), data.getSsrcInfo().getStream(), null, null);
                            } catch (InvalidArgumentException | ParseException | SipException | SsrcTransactionNotFoundException e) {
                                log.error("[点播超时]， 发送BYE失败 {}", e.getMessage());
                            } finally {
                                timeoutCallback.run(1, "收流超时");
                                receiveRtpServerService.closeRTPServer(mediaServerItem, data.getSsrcInfo().getApp(), data.getSsrcInfo().getStream());
                                sessionManager.removeByStream(data.getSsrcInfo().getApp(), data.getSsrcInfo().getStream());
                            }
                        }
                    }
                }));
        if (ssrcInfo == null || ssrcInfo.getPort() < 0) {
            log.info("[国标级联] 发起语音喊话 开启端口监听失败， platform: {}, channel： {}", platform.getServerGBId(), channel.getGbDeviceId());
            SipSubscribe.EventResult<Object> eventResult = new SipSubscribe.EventResult<>();
            eventResult.statusCode = -1;
            eventResult.msg = "端口监听失败";
            eventResult.type = SipSubscribe.EventResultType.failedToGetPort;
            errorEvent.response(eventResult);
            return;
        }
        log.info("[国标级联] 语音喊话，发起Invite消息 deviceId: {}, channelId: {},收流端口： {}, 收流模式：{}, SSRC: {}, SSRC校验：{}",
                platform.getServerGBId(), channel.getGbDeviceId(), ssrcInfo.getPort(), userSetting.getBroadcastForPlatform(), ssrcInfo.getSsrc(), false);

        // 初始化redis中的invite消息状态
        InviteInfo inviteInfo = InviteInfo.getInviteInfo(platform.getServerGBId(), channel.getGbId(), ssrcInfo.getStream(), ssrcInfo, mediaServerItem.getId(),
                mediaServerItem.getSdpIp(), ssrcInfo.getPort(), userSetting.getBroadcastForPlatform(), InviteSessionType.BROADCAST,
                InviteSessionStatus.ready);
        inviteStreamService.updateInviteInfo(inviteInfo);
        commanderForPlatform.broadcastInviteCmd(platform, channel,sourceId, mediaServerItem, ssrcInfo, event -> {
            inviteOKHandler(event, ssrcInfo, false, mediaServerItem, platform, channel,
                    null, inviteInfo, InviteSessionType.BROADCAST);
        }, eventResult -> {
            // 收到错误回复
            if (errorEvent != null) {
                errorEvent.response(eventResult);
            }
            inviteStreamService.removeInviteInfo(inviteInfo);
        });
    }

    public void onPublishHandlerForBroadcast(MediaServer mediaServerItem, MediaInfo mediaInfo, Platform platform, CommonGBChannel channel) {
        StreamInfo streamInfo = mediaServerService.getStreamInfoByAppAndStream(mediaServerItem, mediaInfo.getApp(), mediaInfo.getStream(), mediaInfo, null);
        streamInfo.setChannelId(channel.getGbId());

        InviteInfo inviteInfo = inviteStreamService.getInviteInfoByDeviceAndChannel(InviteSessionType.BROADCAST, channel.getGbId());
        if (inviteInfo != null) {
            inviteInfo.setStatus(InviteSessionStatus.ok);
            inviteInfo.setStreamInfo(streamInfo);
            inviteStreamService.updateInviteInfo(inviteInfo);
        }
    }

    private void inviteOKHandler(SipSubscribe.EventResult eventResult, SSRCInfo ssrcInfo, boolean ssrcCheck, MediaServer mediaServerItem,
                                 Platform platform, CommonGBChannel channel, ErrorCallback<Object> callback,
                                 InviteInfo inviteInfo, InviteSessionType inviteSessionType){
        inviteInfo.setStatus(InviteSessionStatus.ok);
        ResponseEvent responseEvent = (ResponseEvent) eventResult.event;
        String contentString = new String(responseEvent.getResponse().getRawContent());
        String ssrcInResponse = SipUtils.getSsrcFromSdp(contentString);
        // 兼容回复的消息中缺少ssrc(y字段)的情况
        if (ssrcInResponse == null) {
            ssrcInResponse = ssrcInfo.getSsrc();
        }
        if (ssrcInfo.getSsrc().equals(ssrcInResponse)) {
            if (userSetting.getBroadcastForPlatform().equalsIgnoreCase("TCP-ACTIVE")) {
                if (mediaServerItem.isRtpEnable()) {
                    tcpActiveHandler(platform, channel, contentString, mediaServerItem, ssrcCheck,
                            ssrcInfo, callback);
                }else {
                    log.warn("[Invite 200OK] 单端口收流模式不支持tcp主动模式收流");
                }
            }
        }else {
            log.info("[Invite 200OK] 收到invite 200, 发现下级自定义了ssrc: {}", ssrcInResponse);
            // ssrc 不一致
            if (mediaServerItem.isRtpEnable()) {
                // 多端口
                if (ssrcCheck) {
                    // ssrc检验
                    // 更新ssrc
                    log.info("[Invite 200OK] SSRC修正 {}->{}", ssrcInfo.getSsrc(), ssrcInResponse);
                    Boolean result = mediaServerService.updateRtpServerSSRC(mediaServerItem, ssrcInfo.getApp(), ssrcInfo.getStream(), ssrcInResponse);
                    if (!result) {
                        try {
                            log.warn("[Invite 200OK] 更新ssrc失败，停止喊话 {}/{}", platform.getServerGBId(), channel.getGbDeviceId());
                            commanderForPlatform.streamByeCmd(platform, channel, ssrcInfo.getApp(), ssrcInfo.getStream(), null, null);
                        } catch (InvalidArgumentException | SipException | ParseException | SsrcTransactionNotFoundException e) {
                            log.error("[命令发送失败] 停止播放， 发送BYE: {}", e.getMessage());
                        } finally {
                            receiveRtpServerService.closeRTPServer(mediaServerItem, ssrcInfo.getApp(), ssrcInfo.getStream());
                            sessionManager.removeByStream(ssrcInfo.getApp(), ssrcInfo.getStream());

                            callback.run(InviteErrorCode.ERROR_FOR_RESET_SSRC.getCode(),
                                    "下级自定义了ssrc,重新设置收流信息失败", null);
                            inviteStreamService.call(inviteSessionType, channel.getGbId(), null,
                                    InviteErrorCode.ERROR_FOR_RESET_SSRC.getCode(),
                                    "下级自定义了ssrc,重新设置收流信息失败", null);
                            inviteStreamService.removeInviteInfo(inviteInfo);
                        }
                    }else {
                        ssrcInfo.setSsrc(ssrcInResponse);
                        inviteInfo.setSsrcInfo(ssrcInfo);
                        inviteInfo.setStream(ssrcInfo.getStream());
                        if (userSetting.getBroadcastForPlatform().equalsIgnoreCase("TCP-ACTIVE")) {
                            if (mediaServerItem.isRtpEnable()) {
                                tcpActiveHandler(platform, channel, contentString, mediaServerItem, ssrcCheck,
                                        ssrcInfo, callback);
                            }else {
                                log.warn("[Invite 200OK] 单端口收流模式不支持tcp主动模式收流");
                            }
                        }
                        inviteStreamService.updateInviteInfo(inviteInfo);
                    }
                }else {
                    ssrcInfo.setSsrc(ssrcInResponse);
                    inviteInfo.setSsrcInfo(ssrcInfo);
                    inviteInfo.setStream(ssrcInfo.getStream());
                    if (userSetting.getBroadcastForPlatform().equalsIgnoreCase("TCP-ACTIVE")) {
                        if (mediaServerItem.isRtpEnable()) {
                            tcpActiveHandler(platform, channel, contentString, mediaServerItem, ssrcCheck,
                                    ssrcInfo, callback);
                        }else {
                            log.warn("[Invite 200OK] 单端口收流模式不支持tcp主动模式收流");
                        }
                    }
                    inviteStreamService.updateInviteInfo(inviteInfo);
                }
            }else {
                if (ssrcInResponse != null) {
                    // 单端口
                    // 重新订阅流上线
                    SsrcTransaction ssrcTransaction = sessionManager.getSsrcTransactionByStream(ssrcInfo.getApp(), inviteInfo.getStream());
                    if (ssrcTransaction == null) {
                        return;
                    }
                    sessionManager.removeByStream(ssrcInfo.getApp(), inviteInfo.getStream());
                    inviteStreamService.updateInviteInfoForSSRC(inviteInfo, ssrcInResponse);

                    ssrcTransaction.setPlatformId(platform.getServerGBId());
                    ssrcTransaction.setChannelId(channel.getGbId());
                    ssrcTransaction.setApp(ssrcInfo.getApp());
                    ssrcTransaction.setStream(inviteInfo.getStream());
                    ssrcTransaction.setSsrc(ssrcInResponse);
                    ssrcTransaction.setMediaServerId(mediaServerItem.getId());
                    ssrcTransaction.setSipTransactionInfo(new SipTransactionInfo((SIPResponse) responseEvent.getResponse()));
                    ssrcTransaction.setType(inviteSessionType);

                    sessionManager.put(ssrcTransaction);
                }
            }
        }
    }

    private void tcpActiveHandler(Platform platform, CommonGBChannel channel, String contentString,
                                  MediaServer mediaServerItem, boolean ssrcCheck,
                                  SSRCInfo ssrcInfo, ErrorCallback<Object> callback){
        String substring;
        if (contentString.indexOf("y=") > 0) {
            substring = contentString.substring(0, contentString.indexOf("y="));
        }else {
            substring = contentString;
        }
        try {
            SessionDescription sdp = SdpFactory.getInstance().createSessionDescription(substring);
            int port = -1;
            Vector mediaDescriptions = sdp.getMediaDescriptions(true);
            for (Object description : mediaDescriptions) {
                MediaDescription mediaDescription = (MediaDescription) description;
                Media media = mediaDescription.getMedia();

                Vector mediaFormats = media.getMediaFormats(false);
                if (mediaFormats.contains("8") || mediaFormats.contains("0")) {
                    port = media.getMediaPort();
                    break;
                }
            }
            log.info("[TCP主动连接对方] serverGbId: {}, channelId: {}, 连接对方的地址：{}:{}, SSRC: {}, SSRC校验：{}",
                    platform.getServerGBId(), channel.getGbDeviceId(), sdp.getConnection().getAddress(), port, ssrcInfo.getSsrc(), ssrcCheck);
            Boolean result = mediaServerService.connectRtpServer(mediaServerItem, sdp.getConnection().getAddress(), port, ssrcInfo.getApp(), ssrcInfo.getStream());
            log.info("[TCP主动连接对方] 结果： {}", result);
        } catch (SdpException e) {
            log.error("[TCP主动连接对方] serverGbId: {}, channelId: {}, 解析200OK的SDP信息失败", platform.getServerGBId(), channel.getGbDeviceId(), e);
            receiveRtpServerService.closeRTPServer(mediaServerItem, ssrcInfo.getApp(), ssrcInfo.getStream());
            sessionManager.removeByStream(ssrcInfo.getApp(), ssrcInfo.getStream());

            callback.run(InviteErrorCode.ERROR_FOR_SDP_PARSING_EXCEPTIONS.getCode(),
                    InviteErrorCode.ERROR_FOR_SDP_PARSING_EXCEPTIONS.getMsg(), null);
            inviteStreamService.call(InviteSessionType.PLAY, channel.getGbId(), null,
                    InviteErrorCode.ERROR_FOR_SDP_PARSING_EXCEPTIONS.getCode(),
                    InviteErrorCode.ERROR_FOR_SDP_PARSING_EXCEPTIONS.getMsg(), null);
        }
    }

    @Override
    public void stopBroadcast(Platform platform, CommonGBChannel channel, String app, String stream, boolean sendBye, MediaServer mediaServerItem) {

        try {
            if (sendBye) {
                commanderForPlatform.streamByeCmd(platform, channel, app, stream, null, null);
            }
        } catch (InvalidArgumentException | SipException | ParseException | SsrcTransactionNotFoundException e) {
            log.warn("[消息发送失败] 停止语音对讲， 平台：{}，通道：{}", platform.getId(), channel.getGbDeviceId() );
        } finally {
            receiveRtpServerService.closeRTPServer(mediaServerItem, app, stream);
            InviteInfo inviteInfo = inviteStreamService.getInviteInfo(null, channel.getGbId(), stream);
            if (inviteInfo != null) {
                inviteStreamService.removeInviteInfo(inviteInfo);
            }
            sessionManager.removeByStream(app, stream);
        }
    }

    @Override
    public Platform queryOne(Integer platformId) {
        return platformMapper.query(platformId);
    }

    @Override
    public List<Platform> queryEnablePlatformList(String serverId) {
        return platformMapper.queryEnableParentPlatformListByServerId(serverId,true);
    }

    @Override
    @Transactional
    public boolean delete(Integer platformId) {
        Platform platform = platformMapper.query(platformId);
        Assert.notNull(platform, "平台不存在");
        log.info("[删除平台] {}/{} {}:{}", platform.getName(), platform.getServerGBId(), platform.getServerIp(), platform.getServerPort());
        if (!userSetting.getServerId().equals(platform.getServerId())) {
            boolean result = redisRpcService.deletePlatform(platform.getServerId(), platformId);
            if (result) {
                log.info("[删除平台] 跨平台删除成功 {}/{}", platform.getName(), platform.getServerGBId());
            }else {
                log.info("[删除平台] 跨平台删除失败 {}/{}", platform.getName(), platform.getServerGBId());
            }
            return result;
        }
        try {
            if (statusTaskRunner.containsRegister(platform.getServerGBId())) {
                try {
                    SipTransactionInfo transactionInfo = statusTaskRunner.getRegisterTransactionInfo(platform.getServerGBId());
                    sendUnRegister(platform, transactionInfo);
                }catch (Exception ignored) {}
            }
            platformMapper.delete(platform.getId());

            statusTaskRunner.removeRegisterTask(platform.getServerGBId());
            statusTaskRunner.removeKeepAliveTask(platform.getServerGBId());

            subscribeHolder.removeCatalogSubscribe(platform.getServerGBId());
            subscribeHolder.removeMobilePositionSubscribe(platform.getServerGBId());

            // 级联平台删了，它绑的那两张 GB35114 证书也就没有归属了，一并删除。
            // 必须在 platformMapper.delete 之后：反过来的话 assertNoCertReference 会把
            // 本行算成「仍被引用」而拒绝，每张都删不掉，而删平台看起来还「成功」了。
            deleteBoundGb35114Certs(platform);
        }catch (Exception e) {
            throw new ControllerException(ErrorCode.ERROR100.getCode(), e.getMessage());
        }

        return true;
    }

    /**
     * 删除级联平台时，连带删除它绑定的 GB35114 证书（设备证书 / 上级平台证书）。
     *
     * <p>逐张删除，任何一张删不掉都<b>只记日志、不让删平台失败</b>：存量数据里可能两个
     * 上级指向同一张证书，先删的那个平台会因「仍被别的平台引用」被守卫拒绝 ——
     * 这是正确的判定，但不该把「删平台」这个已经成功的动作也一起回滚。
     *
     * <p>CA 不在此列：CA 是全局的，不随任何级联平台删除。
     */
    private void deleteBoundGb35114Certs(Platform platform) {
        if (gb35114CertService == null) {
            // GB35114 模块缺席，无证书可删
            return;
        }
        Integer deviceCertId = platform.getDeviceCertId();
        Integer platformCertId = platform.getPlatformCertId();
        for (Integer certId : new Integer[]{deviceCertId, platformCertId}) {
            if (certId == null) {
                continue;
            }
            try {
                gb35114CertService.deleteCert(certId);
                log.info("[删除平台] 已连带删除 GB35114 证书 #{}（{}/{}）",
                        certId, platform.getName(), platform.getServerGBId());
            } catch (Exception e) {
                log.warn("[删除平台] 连带删除 GB35114 证书 #{} 失败，已跳过（{}/{}）：{}",
                        certId, platform.getName(), platform.getServerGBId(), e.getMessage());
            }
        }
    }

    @Override
    public List<Platform> queryAll(String serverId) {
        return platformMapper.queryByServerId(serverId);
    }
}
