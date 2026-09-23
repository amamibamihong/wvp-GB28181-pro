package com.genersoft.iot.vmp.gb28181.transmit.event.request.impl;

import com.genersoft.iot.vmp.common.RemoteAddressInfo;
import com.genersoft.iot.vmp.conf.SipConfig;
import com.genersoft.iot.vmp.conf.UserSetting;
import com.genersoft.iot.vmp.gb28181.auth.DigestServerAuthenticationHelper;
import com.genersoft.iot.vmp.gb28181.bean.Device;
import com.genersoft.iot.vmp.gb28181.bean.GbCode;
import com.genersoft.iot.vmp.gb28181.bean.GbSipDate;
import com.genersoft.iot.vmp.gb28181.bean.SipTransactionInfo;
import com.genersoft.iot.vmp.gb28181.service.IDeviceService;
import com.genersoft.iot.vmp.gb28181.transmit.SIPProcessorObserver;
import com.genersoft.iot.vmp.gb28181.transmit.SIPSender;
import com.genersoft.iot.vmp.gb28181.transmit.event.request.ISIPRequestProcessor;
import com.genersoft.iot.vmp.gb28181.transmit.event.request.SIPRequestProcessorParent;
import com.genersoft.iot.vmp.gb28181.utils.SipUtils;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114PlatformStateMachine;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SecurityService;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SipHeaders;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114VkekCache;
import com.genersoft.iot.vmp.storager.IRedisCatchStorage;
import com.genersoft.iot.vmp.utils.IpPortUtil;
import gov.nist.javax.sip.address.AddressImpl;
import gov.nist.javax.sip.address.SipUri;
import gov.nist.javax.sip.header.SIPDateHeader;
import gov.nist.javax.sip.message.SIPRequest;
import gov.nist.javax.sip.message.SIPResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import javax.sip.RequestEvent;
import javax.sip.SipException;
import javax.sip.header.AuthorizationHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.ExpiresHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.Request;
import javax.sip.message.Response;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

/**
 * SIP命令类型： REGISTER请求
 */
@Slf4j
@Component
public class RegisterRequestProcessor extends SIPRequestProcessorParent implements InitializingBean, ISIPRequestProcessor {

    public final String method = "REGISTER";

    @Autowired
    private SipConfig sipConfig;

    @Autowired
    private SIPProcessorObserver sipProcessorObserver;

    @Autowired
    private IDeviceService deviceService;

    @Autowired
    private SIPSender sipSender;

    @Autowired
    private UserSetting userSetting;

    @Autowired
    private IRedisCatchStorage redisCatchStorage;

    @Autowired
    private Gb35114SecurityService gb35114SecurityService;

    @Autowired
    private Gb35114VkekCache gb35114VkekCache;


    @Override
    public void afterPropertiesSet() throws Exception {
        // 添加消息处理的订阅
        sipProcessorObserver.addRequestProcessor(method, this);
    }

    @Override
    public void process(RequestEvent evt) {
        try {
            SIPRequest request = (SIPRequest) evt.getRequest();

            FromHeader fromHeader = (FromHeader) request.getHeader(FromHeader.NAME);
            AddressImpl address = (AddressImpl) fromHeader.getAddress();
            SipUri uri = (SipUri) address.getURI();
            String deviceId = uri.getUser();

            if (userSetting.isDeviceIdStrict()) {
                GbCode decode = GbCode.decode(deviceId);
                if (decode == null) {
                    Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
                    sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
                    return;
                }
            }

            ExpiresHeader expiresHeader = request.getExpires();
            if (expiresHeader == null) {
                Response response = getMessageFactory().createResponse(Response.BAD_REQUEST, request);
                sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
                return;
            }

            boolean registerFlag = expiresHeader.getExpires() != 0;

            Device device = deviceService.getDeviceByDeviceId(deviceId);

            RemoteAddressInfo remoteAddressInfo = SipUtils.getRemoteAddressFromRequest(request,
                    userSetting.getSipUseSourceIpAsRemoteAddress());
            String requestAddress = remoteAddressInfo.getIp() + ":" + remoteAddressInfo.getPort();

            if (registerFlag) {
                registerHandler(device, request, remoteAddressInfo, deviceId, requestAddress);
            } else {
                cancellationHandler(device, request, remoteAddressInfo, deviceId, requestAddress);
            }
        } catch (SipException | NoSuchAlgorithmException | ParseException e) {
            log.error("未处理的异常 ", e);
        }
    }

    private Response getRegisterOkResponse(Request request) throws ParseException {
        // 携带授权头并且密码正确
        Response response = getMessageFactory().createResponse(Response.OK, request);
        // 如果主动禁用了Date头，则不添加
        if (!userSetting.isDisableDateHeader()) {
            // 添加date头
            SIPDateHeader dateHeader = new SIPDateHeader();
            // 使用自己修改的
            GbSipDate gbSipDate = new GbSipDate(Calendar.getInstance(Locale.ENGLISH).getTimeInMillis());
            dateHeader.setDate(gbSipDate);
            response.addHeader(dateHeader);
        }

        // 添加Contact头
        response.addHeader(request.getHeader(ContactHeader.NAME));
        // 添加Expires头
        response.addHeader(request.getExpires());

        return response;

    }

    private void registerHandler(Device device, SIPRequest request, RemoteAddressInfo remoteAddressInfo,
                                  String deviceId, String requestAddress) throws SipException, NoSuchAlgorithmException, ParseException {
        // GB35114 A 级：优先按请求头识别国密注册。
        // 设备是主动注册过来的，首包时库里可能还没有这条设备记录（被动注册），
        // 因此不能只依赖预置的 registerWay；Authorization 的 scheme 才是权威依据。
        Integer registerWay = device == null ? null : device.getRegisterWay();
        String authScheme = Gb35114SipHeaders.schemeOf(
                Gb35114SipHeaders.rawHeaderValue(request, "Authorization"));
        boolean gb35114Scheme = "Capability".equalsIgnoreCase(authScheme)
                || "Unidirection".equalsIgnoreCase(authScheme)
                || "Bidirection".equalsIgnoreCase(authScheme);
        boolean gb35114Configured = registerWay != null && (registerWay == 3 || registerWay == 4);
        if (gb35114SecurityService.isEnabled() && (gb35114Scheme || gb35114Configured)) {
            gb35114RegisterHandler(device, request, remoteAddressInfo, deviceId, requestAddress,
                    resolveRegisterWay(authScheme, registerWay));
            return;
        }

        if (device != null && device.getSipTransactionInfo() != null &&
                request.getCallIdHeader().getCallId().equals(device.getSipTransactionInfo().getCallId())) {
            log.info("[注册续订] 设备：{}", device.getDeviceId());
            device.setExpires(request.getExpires().getExpires());
            device.setIp(remoteAddressInfo.getIp());
            device.setPort(remoteAddressInfo.getPort());
            device.setHostAddress(IpPortUtil.concatenateIpAndPort(remoteAddressInfo.getIp(), String.valueOf(remoteAddressInfo.getPort())));
            device.setLocalIp(request.getLocalAddress().getHostAddress());

            ViaHeader reqViaHeader = (ViaHeader) request.getHeader(ViaHeader.NAME);
            String transport = reqViaHeader.getTransport();
            device.setTransport("TCP".equalsIgnoreCase(transport) ? "TCP" : "UDP");

            Response okResponse = getRegisterOkResponse(request);
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), okResponse);
            device.setRegisterTimeStamp(System.currentTimeMillis());
            deviceService.online(device);
            redisCatchStorage.updateDeviceRegisterTimeStamp(List.of(device));
            return;
        }

        if (device == null && ObjectUtils.isEmpty(sipConfig.getPassword())) {
            log.info("[注册请求] 设备：{}, 地址: {}, 公共密码已经禁用，请添加用户信息后注册", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }
        String password = device != null && !ObjectUtils.isEmpty(device.getPassword()) ? device.getPassword() : sipConfig.getPassword();

        AuthorizationHeader authHead = (AuthorizationHeader) request.getHeader(AuthorizationHeader.NAME);
        if (!ObjectUtils.isEmpty(password) && authHead == null) {
            log.info("[注册请求] 设备：{}, 回复401: {}", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.UNAUTHORIZED, request);
            new DigestServerAuthenticationHelper().generateChallenge(getHeaderFactory(), response, sipConfig.getDomain());
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }

        if (!ObjectUtils.isEmpty(password) && !new DigestServerAuthenticationHelper().doAuthenticatePlainTextPassword(request, password)) {
            log.info("[注册请求] 设备：{}, 密码/SIP服务器ID错误, 回复403: {}", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
            response.setReasonPhrase("wrong password");
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }

        Response response = getMessageFactory().createResponse(Response.OK, request);
        if (!userSetting.isDisableDateHeader()) {
            SIPDateHeader dateHeader = new SIPDateHeader();
            GbSipDate gbSipDate = new GbSipDate(Calendar.getInstance(Locale.ENGLISH).getTimeInMillis());
            dateHeader.setDate(gbSipDate);
            response.addHeader(dateHeader);
        }
        response.addHeader(request.getHeader(ContactHeader.NAME));
        response.addHeader(request.getExpires());

        if (device == null) {
            device = new Device();
            device.setStreamMode("TCP-PASSIVE");
            device.setCharset("GB2312");
            device.setGeoCoordSys("WGS84");
            device.setMediaServerId("auto");
            device.setDeviceId(deviceId);
            device.setOnLine(false);
        } else {
            if (ObjectUtils.isEmpty(device.getStreamMode())) {
                device.setStreamMode("TCP-PASSIVE");
            }
            if (ObjectUtils.isEmpty(device.getCharset())) {
                device.setCharset("GB2312");
            }
            if (ObjectUtils.isEmpty(device.getGeoCoordSys())) {
                device.setGeoCoordSys("WGS84");
            }
        }
        device.setServerId(userSetting.getServerId());
        device.setIp(remoteAddressInfo.getIp());
        device.setPort(remoteAddressInfo.getPort());
        device.setHostAddress(IpPortUtil.concatenateIpAndPort(remoteAddressInfo.getIp(), String.valueOf(remoteAddressInfo.getPort())));
        device.setLocalIp(request.getLocalAddress().getHostAddress());
        device.setExpires(request.getExpires().getExpires());

        ViaHeader reqViaHeader = (ViaHeader) request.getHeader(ViaHeader.NAME);
        String transport = reqViaHeader.getTransport();
        device.setTransport("TCP".equalsIgnoreCase(transport) ? "TCP" : "UDP");

        sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);

        device.setRegisterTimeStamp(System.currentTimeMillis());
        SipTransactionInfo sipTransactionInfo = new SipTransactionInfo((SIPResponse) response);
        device.setSipTransactionInfo(sipTransactionInfo);
        deviceService.online(device);
        redisCatchStorage.updateDeviceRegisterTimeStamp(List.of(device));

        log.info("[注册成功] deviceId: {}->{}", deviceId, requestAddress);
    }

    /**
     * GB35114 A 级证书注册：Capability 宣告 → 401 challenge；已认证 Authorization → 200 + SecurityInfo。
     */
    /**
     * 判定本次注册使用的国密方案：Bidirection(3) / Unidirection(4)。
     *
     * <p>设备主动注册时库里可能没有预置 registerWay，此时以 Authorization scheme 为准，
     * 并在后续落库时把它固化下来，避免每次注册都要人工配置。
     */
    private int resolveRegisterWay(String authScheme, Integer configured) {
        if ("Bidirection".equalsIgnoreCase(authScheme)) {
            return 3;
        }
        if ("Unidirection".equalsIgnoreCase(authScheme)) {
            return 4;
        }
        return configured != null && configured == 4 ? 4 : 3;
    }

    private void gb35114RegisterHandler(Device device, SIPRequest request, RemoteAddressInfo remoteAddressInfo,
                                        String deviceId, String requestAddress, int registerWay)
            throws SipException, ParseException {
        // 国密握手里的 serverid 是「平台的国标编码」，即 sip.id（如 35020000002000000001），
        // 不是 userSetting.serverId（那是集群内节点标识，默认 000000）。
        // 设备签名 sign1 时用的就是 sip.id，这里必须一致，否则报 server id mismatch。
        //
        // 签名身份必须与「该设备配置时导入的平台证书」配对，否则设备验 sign2 失败并
        // 拒绝对后续信令服务。优先取设备级绑定；未绑定时用证书表中唯一的那张服务端证书
        // （该用途由后端强制唯一，见 Gb35114SecurityService#platformStateMachine）。
        // 绑定的证书若已吊销或同密钥组内已无可用证书，这里会抛异常并回 403，
        // 不做「换一张证书再签」的静默降级（那会让设备侧验签失败，故障点漂到设备侧）。
        Integer deviceServerCertId = device == null ? null : device.getServerCertId();
        Gb35114PlatformStateMachine machine;
        try {
            machine = gb35114SecurityService.platformStateMachine(
                    userSetting.getServerId(), sipConfig.getId(), deviceServerCertId);
        } catch (Gb35114Exception e) {
            log.warn("[GB35114注册] 设备：{} 拒绝注册：{}", deviceId, e.getMessage());
            Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
            response.setReasonPhrase("GB35114 server certificate unavailable");
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }

        String authorization = Gb35114SipHeaders.rawHeaderValue(request, "Authorization");
        String scheme = Gb35114SipHeaders.schemeOf(authorization);

        if ("Capability".equalsIgnoreCase(scheme)) {
            // 首包：生成 random1 挑战，回 401。
            String www = machine.challenge(deviceId, authorization);
            Response response = getMessageFactory().createResponse(Response.UNAUTHORIZED, request);
            Gb35114SipHeaders.addRawHeader(response, "WWW-Authenticate", www);
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            log.info("[GB35114注册] 设备：{} 收到 Capability，回 401 challenge（mode={}）", deviceId, registerWay);
            return;
        }

        if ("Unidirection".equalsIgnoreCase(scheme) || "Bidirection".equalsIgnoreCase(scheme)) {
            // 已认证包：验 sign1、协商 VKEK、Bidirection 时签 sign2，回 200 + SecurityInfo。
            String securityInfo;
            try {
                securityInfo = machine.verifyRegister(deviceId, authorization);
            } catch (Gb35114Exception e) {
                log.warn("[GB35114注册] 设备：{} 认证失败: {}", deviceId, e.getMessage());
                Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
                response.setReasonPhrase("GB35114 authentication failed");
                sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
                return;
            }

            byte[] vkek = machine.vkek(deviceId);
            if (vkek != null) {
                gb35114VkekCache.put(deviceId, vkek);
            }

            Response response = getMessageFactory().createResponse(Response.OK, request);
            Gb35114SipHeaders.addRawHeader(response, "SecurityInfo", securityInfo);
            response.addHeader(request.getHeader(ContactHeader.NAME));
            response.addHeader(request.getExpires());

            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);

            // 落库 / 上线逻辑对齐 Digest 注册成功分支。
            Device target = device;
            if (target == null) {
                target = new Device();
                target.setStreamMode("TCP-PASSIVE");
                target.setCharset("GB2312");
                target.setGeoCoordSys("WGS84");
                target.setMediaServerId("auto");
                target.setDeviceId(deviceId);
                target.setOnLine(false);
            } else {
                if (ObjectUtils.isEmpty(target.getStreamMode())) {
                    target.setStreamMode("TCP-PASSIVE");
                }
                if (ObjectUtils.isEmpty(target.getCharset())) {
                    target.setCharset("GB2312");
                }
                if (ObjectUtils.isEmpty(target.getGeoCoordSys())) {
                    target.setGeoCoordSys("WGS84");
                }
            }
            target.setRegisterWay(registerWay);
            target.setServerId(userSetting.getServerId());
            target.setIp(remoteAddressInfo.getIp());
            target.setPort(remoteAddressInfo.getPort());
            target.setHostAddress(IpPortUtil.concatenateIpAndPort(remoteAddressInfo.getIp(), String.valueOf(remoteAddressInfo.getPort())));
            target.setLocalIp(request.getLocalAddress().getHostAddress());
            target.setExpires(request.getExpires().getExpires());

            ViaHeader reqViaHeader = (ViaHeader) request.getHeader(ViaHeader.NAME);
            String transport = reqViaHeader.getTransport();
            target.setTransport("TCP".equalsIgnoreCase(transport) ? "TCP" : "UDP");

            target.setRegisterTimeStamp(System.currentTimeMillis());
            SipTransactionInfo sipTransactionInfo = new SipTransactionInfo((SIPResponse) response);
            target.setSipTransactionInfo(sipTransactionInfo);
            deviceService.online(target);
            redisCatchStorage.updateDeviceRegisterTimeStamp(List.of(target));

            log.info("[GB35114注册成功] deviceId: {}->{}（mode={}）", deviceId, requestAddress, registerWay);
            return;
        }

        // 既非 Capability 也非 Unidirection/Bidirection：视为未认证，回 401 走 challenge 起步。
        Response response = getMessageFactory().createResponse(Response.UNAUTHORIZED, request);
        sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
        log.info("[GB35114注册] 设备：{} 缺少国密 Authorization，回 401", deviceId);
    }

    private void cancellationHandler(Device device, SIPRequest request, RemoteAddressInfo remoteAddressInfo,
                                      String deviceId, String requestAddress) throws SipException, NoSuchAlgorithmException, ParseException {
        if (device != null && device.getSipTransactionInfo() != null &&
                request.getCallIdHeader().getCallId().equals(device.getSipTransactionInfo().getCallId())) {
            Response response = getRegisterOkResponse(request);
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            deviceService.offline(device);
            device.setRegisterTimeStamp(System.currentTimeMillis());
            redisCatchStorage.updateDeviceRegisterTimeStamp(List.of(device));
            log.info("[注销成功] deviceId: {}->{}", deviceId, requestAddress);
            return;
        }

        if (device == null && ObjectUtils.isEmpty(sipConfig.getPassword())) {
            log.info("[注销请求] 设备：{}, 地址: {}, 公共密码已经禁用，请添加用户信息后注销", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }
        String password = device != null && !ObjectUtils.isEmpty(device.getPassword()) ? device.getPassword() : sipConfig.getPassword();

        AuthorizationHeader authHead = (AuthorizationHeader) request.getHeader(AuthorizationHeader.NAME);
        if (!ObjectUtils.isEmpty(password) && authHead == null) {
            log.info("[注销请求] 设备：{}, 回复401: {}", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.UNAUTHORIZED, request);
            new DigestServerAuthenticationHelper().generateChallenge(getHeaderFactory(), response, sipConfig.getDomain());
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }

        if (!ObjectUtils.isEmpty(password) && !new DigestServerAuthenticationHelper().doAuthenticatePlainTextPassword(request, password)) {
            log.info("[注销请求] 设备：{}, 密码/SIP服务器ID错误, 回复403: {}", deviceId, requestAddress);
            Response response = getMessageFactory().createResponse(Response.FORBIDDEN, request);
            response.setReasonPhrase("wrong password");
            sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);
            return;
        }

        Response response = getRegisterOkResponse(request);
        sipSender.transmitRequest(request.getLocalAddress().getHostAddress(), response);

        if (device != null) {
            deviceService.offline(device);
            device.setRegisterTimeStamp(System.currentTimeMillis());
            redisCatchStorage.updateDeviceRegisterTimeStamp(List.of(device));
        }

        log.info("[注销成功] deviceId: {}->{}", deviceId, requestAddress);
    }

}
