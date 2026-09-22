package com.genersoft.iot.vmp.gb28181.transmit.event.response.impl;

import com.genersoft.iot.vmp.gb28181.bean.Platform;
import com.genersoft.iot.vmp.gb28181.bean.SipTransactionInfo;
import com.genersoft.iot.vmp.gb28181.event.SipSubscribe;
import com.genersoft.iot.vmp.gb28181.event.sip.SipEvent;
import com.genersoft.iot.vmp.gb28181.service.IPlatformService;
import com.genersoft.iot.vmp.gb28181.transmit.SIPProcessorObserver;
import com.genersoft.iot.vmp.gb28181.transmit.cmd.ISIPCommanderForPlatform;
import com.genersoft.iot.vmp.gb28181.transmit.event.response.SIPResponseProcessorAbstract;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114DeviceStateMachine;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SecurityService;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SipHeaders;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114VkekCache;
import com.genersoft.iot.vmp.storager.IRedisCatchStorage;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import gov.nist.javax.sip.message.SIPResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.sip.InvalidArgumentException;
import javax.sip.ResponseEvent;
import javax.sip.SipException;
import javax.sip.header.WWWAuthenticateHeader;
import javax.sip.message.Response;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

/**
 * @description:Register响应处理器
 * @author: swwheihei
 * @date:   2020年5月3日 下午5:32:23
 */
@Slf4j
@Component
public class RegisterResponseProcessor extends SIPResponseProcessorAbstract {

	private final String method = "REGISTER";

	@Autowired
	private ISIPCommanderForPlatform sipCommanderForPlatform;

	@Autowired
	private IRedisCatchStorage redisCatchStorage;

	@Autowired
	private SIPProcessorObserver sipProcessorObserver;

	@Autowired
	private IPlatformService platformService;

	@Autowired
	private SipSubscribe sipSubscribe;

	@Autowired
	private Gb35114SecurityService gb35114SecurityService;

	@Autowired
	private Gb35114VkekCache gb35114VkekCache;

	/**
	 * 同一次注册会话（同一个 Call-ID）里已经应答过几次 401 挑战。
	 *
	 * <p>挑战应答是一条<b>没有出口的环路</b>：收到 401 就用新的挑战重发 REGISTER，
	 * 若对端再次回 401（口令错、认证方案不被接受、平台侧把这次注册判为非法……），
	 * 又会立刻再发一次 —— 中间没有任何延迟或次数上限。实测这种环路会以每秒两千余次
	 * 的速度空转，几分钟就能写出上百 MB 日志，同时把线程池和对方平台一起拖垮。
	 *
	 * <p>这里按 Call-ID 记次数，超过上限就停手并留下明确的可行动日志。用 Call-ID 作 key
	 * 是因为重发复用同一个 Call-ID（见 {@code SIPCommanderForPlatform#register}），
	 * 而正常的「注册过期后重新注册」会换新的 Call-ID，不会被误伤。
	 */
	private final Cache<String, Integer> challengeAttempts = Caffeine.newBuilder()
			.expireAfterWrite(1, TimeUnit.MINUTES)
			.maximumSize(2000)
			.build();

	/** 一次注册会话最多应答几次挑战，超过即认定对端不会接受，停手。 */
	private static final int MAX_CHALLENGE_ATTEMPTS = 3;

	@Override
	public void afterPropertiesSet() throws Exception {
		// 添加消息处理的订阅
		sipProcessorObserver.addResponseProcessor(method, this);
	}

	/**
	 * 处理Register响应
	 *
 	 * @param evt 事件
	 */
	@Override
	public void process(ResponseEvent evt) {
		SIPResponse response = (SIPResponse)evt.getResponse();
		String callId = response.getCallIdHeader().getCallId();
		long seqNumber = response.getCSeqHeader().getSeqNumber();
		SipEvent subscribe = sipSubscribe.getSubscribe(callId + seqNumber);
		if (subscribe == null || subscribe.getSipTransactionInfo() == null || subscribe.getSipTransactionInfo().getUser() == null) {
			return;
		}

		String action = subscribe.getSipTransactionInfo().getExpires()  > 0 ? "注册" : "注销";
		String platFormServerGbId = subscribe.getSipTransactionInfo().getUser();

		log.info("[国标级联]{} {}响应 {} ", action, response.getStatusCode(), platFormServerGbId);
		Platform platform = platformService.queryPlatformByServerGBId(platFormServerGbId);
		if (platform == null) {
			log.warn("[国标级联]收到 来自{}的 {} 回复 {}, 但是平台信息未查询到!!!", platFormServerGbId, action, response.getStatusCode());
			return;
		}

		if (response.getStatusCode() == Response.UNAUTHORIZED) {
			int attempt = challengeAttempts.get(callId, k -> 0) + 1;
			challengeAttempts.put(callId, attempt);
			if (attempt > MAX_CHALLENGE_ATTEMPTS) {
				// 停手不是「放弃修复」，而是把故障从日志洪水里拎出来：环路本身看不出原因，
				// 停下来才留得住那几条能定位问题的日志，也才不会把线程池和对端平台拖垮。
				log.error("[国标级联] 平台 {} 连续 {} 次回 401，已停止重试；"
								+ "请检查上级平台的口令/认证方案配置（callId={}）",
						platFormServerGbId, MAX_CHALLENGE_ATTEMPTS, callId);
				return;
			}
			WWWAuthenticateHeader www = (WWWAuthenticateHeader)response.getHeader(WWWAuthenticateHeader.NAME);
			SipTransactionInfo sipTransactionInfo = new SipTransactionInfo(response);
			try {
				sipCommanderForPlatform.register(platform, sipTransactionInfo, www, null, null, subscribe.getSipTransactionInfo().getExpires()  > 0);
			} catch (SipException | InvalidArgumentException | ParseException e) {
				log.error("[命令发送失败] 国标级联 再次注册: {}", e.getMessage());
			}
		}else if (response.getStatusCode() == Response.OK){
			// 握手已结束，本次会话不再有挑战可答；清掉计数，避免复用 Call-ID 的续订被误判。
			challengeAttempts.invalidate(callId);
			if (subscribe.getSipTransactionInfo().getExpires()  > 0) {
				// GB35114 A 级：200 带 SecurityInfo 时校验并落 VKEK（本平台作为下级的 UAC 侧）。
				String securityInfo = Gb35114SipHeaders.rawHeaderValue(response, "SecurityInfo");
				if (gb35114SecurityService.isEnabled() && securityInfo != null && !securityInfo.isEmpty()) {
					Gb35114DeviceStateMachine machine = gb35114SecurityService.uacStateMachine(
							platform.getDeviceGBId(), platform.getServerGBId(),
							platform.getDeviceCertId(), platform.getPlatformCertId());
					if (machine != null) {
						try {
							machine.verifyOk(securityInfo);
							if (machine.vkek() != null) {
								gb35114VkekCache.put(platform.getServerGBId(), machine.vkek());
							}
						} catch (Gb35114Exception e) {
							log.warn("[GB35114级联] 校验 SecurityInfo 失败，平台 {}: {}", platform.getServerGBId(), e.getMessage());
						}
					}
				}

				SipTransactionInfo sipTransactionInfo = new SipTransactionInfo(response);
				platformService.online(platform, sipTransactionInfo);
			}else {
				platformService.offline(platform);
			}
		}
	}
}
