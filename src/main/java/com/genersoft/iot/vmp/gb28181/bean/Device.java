package com.genersoft.iot.vmp.gb28181.bean;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * 国标设备/平台
 * @author lin
 */
@Data
@Schema(description = "国标设备/平台")
public class Device {

	@Schema(description = "数据库自增ID")
	private int id;

	/**
	 * 设备国标编号
	 */
	@Schema(description = "设备国标编号")
	private String deviceId;

	/**
	 * 设备名
	 */
	@Schema(description = "名称")
	private String name;

	/**
	 * 生产厂商
	 */
	@Schema(description = "生产厂商")
	private String manufacturer;

	/**
	 * 型号
	 */
	@Schema(description = "型号")
	private String model;

	/**
	 * 固件版本
	 */
	@Schema(description = "固件版本")
	private String firmware;

	/**
	 * 传输协议
	 * UDP/TCP
	 */
	@Schema(description = "传输协议（UDP/TCP）")
	private String transport;

	/**
	 * 数据流传输模式
	 * UDP:udp传输
	 * TCP-ACTIVE：tcp主动模式
	 * TCP-PASSIVE：tcp被动模式
	 */
	@Schema(description = "数据流传输模式")
	private String streamMode;

	/**
	 * wan地址_ip
	 */
	@Schema(description = "IP")
	private String  ip;

	/**
	 * wan地址_port
	 */
	@Schema(description = "端口")
	private int port;

	/**
	 * wan地址
	 */
	@Schema(description = "wan地址")
	private String  hostAddress;

	/**
	 * 在线
	 */
	@Schema(description = "是否在线，true为在线，false为离线")
	private boolean onLine;


	/**
	 * 注册时间
	 */
	@Schema(description = "注册时间戳")
	private Long registerTimeStamp;


	/**
	 * 心跳时间
	 */
	@Schema(description = "心跳时间")
	private Long keepaliveTimeStamp;


	/**
	 * 心跳间隔
	 */
	@Schema(description = "心跳间隔")
	private Integer heartBeatInterval;


	/**
	 * 心跳超时次数
	 */
	@Schema(description = "心跳超时次数")
	private Integer heartBeatCount;


	/**
	 * 定位功能支持情况
	 */
	@Schema(description = "定位功能支持情况。取值:0-不支持;1-支持 GPS定位;2-支持北斗定位(可选,默认取值为0")
	private Integer positionCapability;

	/**
	 * 通道个数
	 */
	@Schema(description = "通道个数")
	private int channelCount;

	/**
	 * 注册有效期
	 */
	@Schema(description = "注册有效期")
	private int expires;

	/**
	 * 创建时间
	 */
	@Schema(description = "创建时间")
	private String createTime;

	/**
	 * 更新时间
	 */
	@Schema(description = "更新时间")
	private String updateTime;

	/**
	 * 设备使用的媒体id, 默认为null
	 */
	@Schema(description = "设备使用的媒体id, 默认为null")
	private String mediaServerId;

	/**
	 * 字符集, 支持 UTF-8 与 GB2312
	 */
	@Schema(description = "符集, 支持 UTF-8 与 GB2312")
	private String charset ;

	/**
	 * 目录订阅周期，0为不订阅
	 */
	@Schema(description = "目录订阅周期，o为不订阅")
	private int subscribeCycleForCatalog;

	/**
	 * 移动设备位置订阅周期，0为不订阅
	 */
	@Schema(description = "移动设备位置订阅周期，0为不订阅")
	private int subscribeCycleForMobilePosition;

	/**
	 * 移动设备位置信息上报时间间隔,单位:秒,默认值5
	 */
	@Schema(description = "移动设备位置信息上报时间间隔,单位:秒,默认值5")
	private int mobilePositionSubmissionInterval = 5;

	/**
	 * 报警订阅周期，0为不订阅
	 */
	@Schema(description = "报警心跳时间订阅周期，0为不订阅")
	private int subscribeCycleForAlarm;

	/**
	 * 是否开启ssrc校验，默认关闭，开启可以防止串流
	 */
	@Schema(description = "是否开启ssrc校验，默认关闭，开启可以防止串流")
	private boolean ssrcCheck = false;

	/**
	 * 地理坐标系， 目前支持 WGS84,GCJ02, 此字段保留，暂无用
	 */
	@Schema(description = "地理坐标系， 目前支持 WGS84,GCJ02")
	private String geoCoordSys;

	@Schema(description = "密码")
	private String password;

	@Schema(description = "收流IP")
	private String sdpIp;

	@Schema(description = "SIP交互IP（设备访问平台的IP）")
	private String localIp;

	@Schema(description = "是否作为消息通道")
	private boolean asMessageChannel;

	@Schema(description = "设备注册的事务信息")
	private SipTransactionInfo sipTransactionInfo;

	@Schema(description = "控制语音对讲流程，释放收到ACK后发流")
	private boolean broadcastPushAfterAck;

	@Schema(description = "所属服务Id")
	private String serverId;

	@Schema(description = "注册方式：1-摘要认证，3-基于数字证书双向认证，4-基于数字证书单向认证")
	private Integer registerWay;

	@Schema(description = "关联的国密证书ID（wvp_gb35114_cert.id）")
	private Integer certId;

	/**
	 * 该设备信任的服务器证书 ID（{@code wvp_gb35114_cert.id}）。
	 *
	 * <p>平台可并存多张服务端证书，而设备只信任它配置时导入的那张平台证书的公钥。
	 * 此处为空时用全局默认证书；显式绑定后，即使平台新增/切换了默认证书，本设备的
	 * sign2 仍用这张签，不会被静默打挂。
	 */
	@Schema(description = "该设备信任的服务器证书ID（空则用默认证书）")
	private Integer serverCertId;

    public boolean checkWgs84() {
        return geoCoordSys.equalsIgnoreCase("WGS84");
    }

	public Integer getHeartBeatCount() {
		if (heartBeatCount == null) {
			return 3;
		}
		return heartBeatCount;
	}

	public Integer getHeartBeatInterval() {
		if (heartBeatCount == null) {
			return 60;
		}
		return heartBeatInterval;
	}
}
