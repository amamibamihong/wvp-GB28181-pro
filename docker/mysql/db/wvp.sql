/*建库*/
DROP DATABASE IF EXISTS `wvp`;

CREATE DATABASE `wvp` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

USE `wvp`;

/*建表*/
drop table IF EXISTS wvp_device;
create table IF NOT EXISTS wvp_device
(
    id                                  serial primary key,
    device_id                           character varying(50) not null,
    name                                character varying(255),
    manufacturer                        character varying(255),
    model                               character varying(255),
    firmware                            character varying(255),
    transport                           character varying(50),
    stream_mode                         character varying(50),
    on_line                             bool    default false,
    register_time                       character varying(50),
    keepalive_time                      character varying(50),
    ip                                  character varying(50),
    create_time                         character varying(50),
    update_time                         character varying(50),
    port                                integer,
    expires                             integer,
    subscribe_cycle_for_catalog         integer DEFAULT 0,
    subscribe_cycle_for_mobile_position integer DEFAULT 0,
    mobile_position_submission_interval integer DEFAULT 5,
    subscribe_cycle_for_alarm           integer DEFAULT 0,
    host_address                        character varying(50),
    charset                             character varying(50),
    ssrc_check                          bool    default false,
    geo_coord_sys                       character varying(50),
    media_server_id                     character varying(50) default 'auto',
    custom_name                         character varying(255),
    sdp_ip                              character varying(50),
    local_ip                            character varying(50),
    password                            character varying(255),
    as_message_channel                  bool    default false,
    heart_beat_interval                 integer,
    heart_beat_count                    integer,
    position_capability                 integer,
    broadcast_push_after_ack            bool    default false,
    server_id                           character varying(50),
    register_way                        integer default 1 COMMENT '注册方式：1-摘要，3-证书双向，4-证书单向',
    cert_id                             integer COMMENT '关联的国密证书ID（wvp_gb35114_cert.id）',
    server_cert_id                      integer COMMENT '该设备信任的服务器证书ID（wvp_gb35114_cert.id，空则用平台唯一的那张服务端证书）',
    constraint uk_device_device unique (device_id)
);

drop table IF EXISTS wvp_device_alarm;
create table IF NOT EXISTS wvp_device_alarm
(
    id                serial primary key,
    device_id         character varying(50) not null,
    channel_id        character varying(50) not null,
    alarm_priority    character varying(50),
    alarm_method      character varying(50),
    alarm_time        character varying(50),
    alarm_description character varying(255),
    longitude         double precision,
    latitude          double precision,
    alarm_type        character varying(50),
    create_time       character varying(50) not null
);

drop table IF EXISTS wvp_device_mobile_position;
create table IF NOT EXISTS wvp_device_mobile_position
(
    id              serial primary key,
    device_id       character varying(50) not null,
    channel_id      character varying(50) not null,
    device_name     character varying(255),
    time            character varying(50),
    longitude       double precision,
    latitude        double precision,
    altitude        double precision,
    speed           double precision,
    direction       double precision,
    report_source   character varying(50),
    create_time     character varying(50)
);

drop table IF EXISTS wvp_device_channel;
create table IF NOT EXISTS wvp_device_channel
(
    id                           serial primary key,
    device_id                    character varying(50),
    name                         character varying(255),
    manufacturer                 character varying(50),
    model                        character varying(50),
    owner                        character varying(50),
    civil_code                   character varying(50),
    block                        character varying(50),
    address                      character varying(50),
    parental                     integer,
    parent_id                    character varying(50),
    safety_way                   integer,
    register_way                 integer,
    cert_num                     character varying(50),
    certifiable                  integer,
    err_code                     integer,
    end_time                     character varying(50),
    secrecy                      integer,
    ip_address                   character varying(50),
    port                         integer,
    password                     character varying(255),
    status                       character varying(50),
    longitude                    double precision,
    latitude                     double precision,
    ptz_type                     integer,
    position_type                integer,
    room_type                    integer,
    use_type                     integer,
    supply_light_type            integer,
    direction_type               integer,
    resolution                   character varying(255),
    business_group_id            character varying(255),
    download_speed               character varying(255),
    svc_space_support_mod        integer,
    svc_time_support_mode        integer,
    create_time                  character varying(50) not null,
    update_time                  character varying(50) not null,
    sub_count                    integer,
    stream_id                    character varying(255),
    has_audio                    bool default false,
    gps_time                     character varying(50),
    stream_identification        character varying(50),
    channel_type                 int  default 0        not null,
    gb_device_id                 character varying(50),
    gb_name                      character varying(255),
    gb_manufacturer              character varying(255),
    gb_model                     character varying(255),
    gb_owner                     character varying(255),
    gb_civil_code                character varying(255),
    gb_block                     character varying(255),
    gb_address                   character varying(255),
    gb_parental                  integer,
    gb_parent_id                 character varying(255),
    gb_safety_way                integer,
    gb_register_way              integer,
    gb_cert_num                  character varying(50),
    gb_certifiable               integer,
    gb_err_code                  integer,
    gb_end_time                  character varying(50),
    gb_secrecy                   integer,
    gb_ip_address                character varying(50),
    gb_port                      integer,
    gb_password                  character varying(50),
    gb_status                    character varying(50),
    gb_longitude                 double,
    gb_latitude                  double,
    gb_business_group_id         character varying(50),
    gb_ptz_type                  integer,
    gb_position_type             integer,
    gb_room_type                 integer,
    gb_use_type                  integer,
    gb_supply_light_type         integer,
    gb_direction_type            integer,
    gb_resolution                character varying(255),
    gb_download_speed            character varying(255),
    gb_svc_space_support_mod     integer,
    gb_svc_time_support_mode     integer,
    record_plan_id               integer,
    data_type                    integer not null,
    data_device_id               integer not null,
    gps_speed                    double precision,
    gps_altitude                 double precision,
    gps_direction                double precision,
    index (data_type),
    index (data_device_id),
    constraint uk_wvp_unique_channel unique (gb_device_id)
);

drop table IF EXISTS wvp_media_server;
create table IF NOT EXISTS wvp_media_server
(
    id                  character varying(255) primary key,
    ip                  character varying(50),
    hook_ip             character varying(50),
    sdp_ip              character varying(50),
    stream_ip           character varying(50),
    http_port           integer,
    http_ssl_port       integer,
    rtmp_port           integer,
    rtmp_ssl_port       integer,
    rtp_proxy_port      integer,
    rtsp_port           integer,
    rtsp_ssl_port       integer,
    flv_port            integer,
    flv_ssl_port        integer,
    ws_flv_port         integer,
    ws_flv_ssl_port     integer,
    auto_config         bool                  default false,
    secret              character varying(50),
    type                character varying(50) default 'zlm',
    rtp_enable          bool                  default false,
    rtp_port_range      character varying(50),
    send_rtp_port_range character varying(50),
    record_assist_port  integer,
    default_server      bool                  default false,
    create_time         character varying(50),
    update_time         character varying(50),
    hook_alive_interval integer,
    record_path         character varying(255),
    record_day          integer               default 7,
    transcode_suffix    character varying(255),
    server_id           character varying(50),
    constraint uk_media_server_unique_ip_http_port unique (ip, http_port, server_id)
);

drop table IF EXISTS wvp_platform;
create table IF NOT EXISTS wvp_platform
(
    id                    serial primary key,
    enable                bool default false,
    name                  character varying(255),
    server_gb_id          character varying(50),
    server_gb_domain      character varying(50),
    server_ip             character varying(50),
    server_port           integer,
    device_gb_id          character varying(50),
    device_ip             character varying(50),
    device_port           character varying(50),
    username              character varying(255),
    password              character varying(50),
    expires               character varying(50),
    keep_timeout          character varying(50),
    transport             character varying(50),
    civil_code            character varying(50),
    manufacturer          character varying(255),
    model                 character varying(255),
    address               character varying(255),
    character_set         character varying(50),
    ptz                   bool default false,
    rtcp                  bool default false,
    status                bool default false,
    catalog_group         integer,
    register_way          integer,
    secrecy               integer,
    create_time           character varying(50),
    update_time           character varying(50),
    as_message_channel    bool default false,
    catalog_with_platform integer default 1,
    catalog_with_group    integer default 1,
    catalog_with_region   integer default 1,
    auto_push_channel     bool default true,
    send_stream_ip        character varying(50),
    server_id             character varying(50),
    device_cert_id        integer COMMENT '本平台作下级注册的设备证书ID（wvp_gb35114_cert.id）',
    platform_cert_id      integer COMMENT '受信上级平台证书ID（wvp_gb35114_cert.id）',
    constraint uk_platform_unique_server_gb_id unique (server_gb_id)
);

drop table IF EXISTS wvp_platform_channel;
create table IF NOT EXISTS wvp_platform_channel
(
    id                           serial primary key,
    platform_id                  integer,
    device_channel_id            integer,
    custom_device_id             character varying(50),
    custom_name                  character varying(255),
    custom_manufacturer          character varying(50),
    custom_model                 character varying(50),
    custom_owner                 character varying(50),
    custom_civil_code            character varying(50),
    custom_block                 character varying(50),
    custom_address               character varying(50),
    custom_parental              integer,
    custom_parent_id             character varying(50),
    custom_safety_way            integer,
    custom_register_way          integer,
    custom_cert_num              character varying(50),
    custom_certifiable           integer,
    custom_err_code              integer,
    custom_end_time              character varying(50),
    custom_secrecy               integer,
    custom_ip_address            character varying(50),
    custom_port                  integer,
    custom_password              character varying(255),
    custom_status                character varying(50),
    custom_longitude             double precision,
    custom_latitude              double precision,
    custom_ptz_type              integer,
    custom_position_type         integer,
    custom_room_type             integer,
    custom_use_type              integer,
    custom_supply_light_type     integer,
    custom_direction_type        integer,
    custom_resolution            character varying(255),
    custom_business_group_id     character varying(255),
    custom_download_speed        character varying(255),
    custom_svc_space_support_mod integer,
    custom_svc_time_support_mode integer,
    constraint uk_platform_gb_channel_platform_id_catalog_id_device_channel_id unique (platform_id, device_channel_id),
    constraint uk_platform_gb_channel_device_id unique (custom_device_id)
);

drop table IF EXISTS wvp_platform_group;
create table IF NOT EXISTS wvp_platform_group
(
    id          serial primary key,
    platform_id integer,
    group_id    integer,
    constraint uk_wvp_platform_group_platform_id_group_id unique (platform_id, group_id)
);

drop table IF EXISTS wvp_platform_region;
create table IF NOT EXISTS wvp_platform_region
(
    id          serial primary key,
    platform_id integer,
    region_id   integer,
    constraint uk_wvp_platform_region_platform_id_group_id unique (platform_id, region_id)
);

drop table IF EXISTS wvp_stream_proxy;
create table IF NOT EXISTS wvp_stream_proxy
(
    id                         serial primary key,
    type                       character varying(50),
    app                        character varying(255),
    stream                     character varying(255),
    src_url                    character varying(255),
    timeout                    integer,
    ffmpeg_cmd_key             character varying(255),
    rtsp_type                  character varying(50),
    media_server_id            character varying(50),
    enable_audio               bool default false,
    enable_mp4                 bool default false,
    pulling                    bool default false,
    enable                     bool default false,
    enable_remove_none_reader  bool default false,
    create_time                character varying(50),
    name                       character varying(255),
    update_time                character varying(50),
    stream_key                 character varying(255),
    server_id                  character varying(50),
    enable_disable_none_reader bool default false,
    relates_media_server_id    character varying(50),
    constraint uk_stream_proxy_app_stream unique (app, stream)
);

drop table IF EXISTS wvp_stream_push;
create table IF NOT EXISTS wvp_stream_push
(
    id                 serial primary key,
    app                character varying(255),
    stream             character varying(255),
    create_time        character varying(50),
    media_server_id    character varying(50),
    server_id          character varying(50),
    push_time          character varying(50),
    status             bool default false,
    update_time        character varying(50),
    pushing            bool default false,
    self               bool default false,
    start_offline_push bool default true,
    constraint uk_stream_push_app_stream unique (app, stream)
);

drop table IF EXISTS wvp_cloud_record;
create table IF NOT EXISTS wvp_cloud_record
(
    id              serial primary key,
    app             character varying(255),
    stream          character varying(255),
    call_id         character varying(255),
    start_time      bigint,
    end_time        bigint,
    media_server_id character varying(50),
    server_id       character varying(50),
    file_name       character varying(255),
    folder          character varying(500),
    file_path       character varying(500),
    collect         bool default false,
    file_size       bigint,
    time_len        bigint
);

drop table IF EXISTS wvp_user;
create table IF NOT EXISTS wvp_user
(
    id               serial primary key,
    username         character varying(255),
    password         character varying(255),
    role_id          integer,
    create_time      character varying(50),
    update_time      character varying(50),
    push_key         character varying(50),
    default_password bool default false,
    constraint uk_user_username unique (username)
);

drop table IF EXISTS wvp_user_role;
create table IF NOT EXISTS wvp_user_role
(
    id          serial primary key,
    name        character varying(50),
    authority   character varying(50),
    create_time character varying(50),
    update_time character varying(50)
);


drop table IF EXISTS wvp_user_api_key;
create table IF NOT EXISTS wvp_user_api_key
(
    id          serial primary key,
    user_id     bigint,
    app         character varying(255),
    api_key     text,
    expired_at  bigint,
    remark      character varying(255),
    enable      bool default true,
    create_time character varying(50),
    update_time character varying(50)
);


/*初始数据*/
INSERT INTO wvp_user (id, username, password, role_id, create_time, update_time, push_key, default_password)
VALUES (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 1, '2021-04-13 14:14:57', '2021-04-13 14:14:57',
        '3e80d1762a324d5b0ff636e0bd16f1e3', TRUE);
INSERT INTO wvp_user_role
VALUES (1, 'admin', '0', '2021-04-13 14:14:57', '2021-04-13 14:14:57');

drop table IF EXISTS wvp_common_group;
create table IF NOT EXISTS wvp_common_group
(
    id               serial primary key,
    device_id        varchar(50)  NOT NULL,
    name             varchar(255) NOT NULL,
    parent_id        int,
    parent_device_id varchar(50) DEFAULT NULL,
    business_group   varchar(50)  NOT NULL,
    create_time      varchar(50)  NOT NULL,
    update_time      varchar(50)  NOT NULL,
    civil_code       varchar(50) default null,
    constraint uk_common_group_device_platform unique (device_id)
);

drop table IF EXISTS wvp_common_region;
create table IF NOT EXISTS wvp_common_region
(
    id               serial primary key,
    device_id        varchar(50)  NOT NULL,
    name             varchar(255) NOT NULL,
    parent_id        int,
    parent_device_id varchar(50) DEFAULT NULL,
    create_time      varchar(50)  NOT NULL,
    update_time      varchar(50)  NOT NULL,
    constraint uk_common_region_device_id unique (device_id)
);

drop table IF EXISTS wvp_record_plan;
create table IF NOT EXISTS wvp_record_plan
(
    id              serial primary key,
    snap            bool default false,
    name            varchar(255) NOT NULL,
    create_time     character varying(50),
    update_time     character varying(50)
);

drop table IF EXISTS wvp_record_plan_item;
create table IF NOT EXISTS wvp_record_plan_item
(
    id              serial primary key,
    start           int,
    stop            int,
    week_day        int,
    plan_id         int,
    create_time     character varying(50),
    update_time     character varying(50)
);

/*
* 以下为 2.7.4 新增的表，放在升级段之前，便于新库与升级库共用同一套建表语句
*/
-- 交通部 JT/T 1076 终端信息
create table IF NOT EXISTS wvp_jt_terminal (
                                 id serial primary key COMMENT '主键ID',
                                 phone_number character varying(50) COMMENT '终端SIM卡号',
                                 terminal_id character varying(50) COMMENT '终端设备ID',
                                 province_id character varying(50) COMMENT '所在省份ID',
                                 province_text character varying(100) COMMENT '所在省份名称',
                                 city_id character varying(50) COMMENT '所在城市ID',
                                 city_text character varying(100) COMMENT '所在城市名称',
                                 maker_id character varying(50) COMMENT '厂商ID',
                                 model character varying(50) COMMENT '终端型号',
                                 plate_color character varying(50) COMMENT '车牌颜色',
                                 plate_no character varying(50) COMMENT '车牌号码',
                                 longitude double precision COMMENT '经度',
                                 latitude double precision COMMENT '纬度',
                                 status bool default false COMMENT '在线状态',
                                 register_time character varying(50) default null COMMENT '注册时间',
                                 update_time character varying(50) not null COMMENT '更新时间',
                                 create_time character varying(50) not null COMMENT '创建时间',
                                 geo_coord_sys character varying(50) COMMENT '坐标系',
                                 media_server_id character varying(50) default 'auto' COMMENT '媒体服务器ID',
                                 sdp_ip character varying(50) COMMENT 'SDP IP',
                                 constraint uk_jt_device_id_device_id unique (id, phone_number)
);

-- 交通部 JT/T 1076 通道信息
create table IF NOT EXISTS wvp_jt_channel (
                               id serial primary key COMMENT '主键ID',
                               terminal_db_id integer COMMENT '所属终端记录ID',
                               channel_id integer COMMENT '通道号',
                               has_audio bool default false COMMENT '是否有音频',
                               name character varying(255) COMMENT '通道名称',
                               update_time character varying(50) not null COMMENT '更新时间',
                               create_time character varying(50) not null COMMENT '创建时间',
                               constraint uk_jt_channel_id_device_id unique (terminal_db_id, channel_id)
);

-- 报警信息表，表结构参考alarm类
create table IF NOT EXISTS wvp_alarm (
                          id serial primary key COMMENT '主键ID',
                          channel_id integer COMMENT '关联通道的数据库id',
                          description character varying(255) COMMENT '报警描述',
                          snap_path character varying(255) COMMENT '报警快照路径',
                          record_path character varying(255) COMMENT '报警录像路径',
                          longitude double precision COMMENT '报警附带的经度',
                          latitude double precision COMMENT '报警附带的纬度',
                          alarm_type integer COMMENT '报警类别',
                          alarm_time bigint COMMENT '报警时间'
);

-- GB35114 A 级国密证书管理表

-- 根 CA 表
create table IF NOT EXISTS wvp_gb35114_ca
(
    id                  serial primary key COMMENT '主键ID',
    type                character varying(20) DEFAULT 'LOCAL_CA'
                        COMMENT '类型：LOCAL_CA-本地CA(可签发，全局唯一) / TRUSTED_CA-受信任的CA(仅公钥，可重复导入)',
    subject_cn          character varying(255) COMMENT '主题 CN',
    subject_dn          character varying(500) COMMENT '完整主题DN（RFC2253）',
    country             character varying(10) COMMENT '国家 C',
    province            character varying(64) COMMENT '省份 ST',
    locality            character varying(64) COMMENT '城市 L',
    organization        character varying(255) COMMENT '组织 O',
    organizational_unit character varying(255) COMMENT '组织单位 OU',
    serial_number       character varying(100) COMMENT '序列号',
    cert_pem            text COMMENT '证书 PEM',
    key_pem             text COMMENT '私钥 PEM（对称加密存储）',
    not_before          character varying(50) COMMENT '生效时间',
    not_after           character varying(50) COMMENT '失效时间',
    remark              character varying(500) COMMENT '备注',
    create_time         character varying(50) COMMENT '创建时间'
);

-- 证书表
create table IF NOT EXISTS wvp_gb35114_cert
(
    id                  serial primary key COMMENT '主键ID',
    type                character varying(30) DEFAULT 'ISSUED_DEVICE'
                        COMMENT '证书类型：SERVER_IDENTITY-服务端证书(本平台) / DEVICE_IDENTITY-客户端证书(本平台) / ISSUED_DEVICE-客户端证书(下级设备) / TRUSTED_PLATFORM-服务端证书(上级平台)',
    gb_id               character varying(50) COMMENT '关联国标 ID',
    subject_cn          character varying(255) COMMENT '主题 CN',
    subject_dn          character varying(500) COMMENT '完整主题DN（RFC2253）',
    module_id           character varying(64) COMMENT '密码模块 ID（附录B，22位十进制）；空表示无密码模块',
    country             character varying(10) COMMENT '国家 C',
    province            character varying(64) COMMENT '省份 ST',
    locality            character varying(64) COMMENT '城市 L',
    organization        character varying(255) COMMENT '组织 O',
    organizational_unit character varying(255) COMMENT '组织单位 OU',
    serial_number       character varying(100) COMMENT '序列号',
    ca_id               integer COMMENT '签发 CA 的 ID，null 表示自签',
    cert_pem            text COMMENT '证书 PEM',
    key_pem             text COMMENT '私钥 PEM（对称加密存储）',
    csr_pem             text COMMENT '待签发记录的CSR PEM（私钥与之同记录）',
    not_before          character varying(50) COMMENT '生效时间',
    not_after           character varying(50) COMMENT '失效时间',
    validity_days       integer COMMENT '签发时的有效期天数快照',
    key_usage           character varying(200) COMMENT '密钥用途扩展，如 digitalSignature、keyCertSign|cRLSign',
    revoked             bool default false COMMENT '是否已吊销',
    key_fingerprint     character varying(64) COMMENT '公钥指纹（SM3 十六进制）；相同表示同一个签名身份，证书可互换',
    remark              character varying(500) COMMENT '备注',
    create_time         character varying(50) COMMENT '创建时间',
    key idx_gb35114_cert_type (type, gb_id),
    key idx_gb35114_cert_fingerprint (type, key_fingerprint)
);

/*
* 20240528
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20240528`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_media_server' and column_name = 'transcode_suffix')
    THEN
        ALTER TABLE wvp_media_server ADD transcode_suffix  character varying(255);
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'type')
    THEN
        alter table wvp_media_server
            add  type character varying(50) default 'zlm';
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'flv_port')
    THEN
        alter table wvp_media_server  add flv_port integer;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'flv_ssl_port')
    THEN
        alter table wvp_media_server add flv_ssl_port integer;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'ws_flv_port')
    THEN
        alter table wvp_media_server add ws_flv_port integer;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'ws_flv_ssl_port')
    THEN
        alter table wvp_media_server add ws_flv_ssl_port integer;
    END IF;
END; //
call wvp_20240528();
DROP PROCEDURE wvp_20240528;
DELIMITER ;

create table IF NOT EXISTS wvp_user_api_key (
                                  id serial primary key ,
                                  user_id bigint,
                                  app character varying(255) ,
                                  api_key text,
                                  expired_at bigint,
                                  remark character varying(255),
                                  enable bool default true,
                                  create_time character varying(50),
                                  update_time character varying(50)
);

/*
* 20241222
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20241222`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and INDEX_NAME = 'uk_wvp_device_channel_unique_device_channel')
    THEN
        alter table wvp_device_channel drop index uk_wvp_device_channel_unique_device_channel;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and INDEX_NAME = 'uk_wvp_unique_stream_push_id')
    THEN
        alter table wvp_device_channel drop index uk_wvp_unique_stream_push_id;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and INDEX_NAME = 'uk_wvp_unique_stream_proxy_id')
    THEN
        alter table wvp_device_channel drop index uk_wvp_unique_stream_proxy_id;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device_channel' and column_name = 'data_type')
    THEN
        alter table wvp_device_channel add data_type integer not null;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device_channel' and column_name = 'data_device_id')
    THEN
        alter table wvp_device_channel add data_device_id integer not null;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device_channel' and column_name = 'device_db_id')
    THEN
        update wvp_device_channel wdc INNER JOIN
            (SELECT id, device_db_id from wvp_device_channel where device_db_id is not null ) ct on ct.id = wdc.id
        set wdc.data_type = 1, wdc.data_device_id = ct.device_db_id where wdc.device_db_id is not null;
        alter table wvp_device_channel drop device_db_id;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device_channel' and column_name = 'stream_push_id')
    THEN
        update wvp_device_channel wdc INNER JOIN
            (SELECT id, stream_push_id from wvp_device_channel where stream_push_id is not null ) ct on ct.id = wdc.id
        set wdc.data_type = 2, wdc.data_device_id = ct.stream_push_id where wdc.stream_push_id is not null;
        alter table wvp_device_channel drop stream_push_id;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device_channel' and column_name = 'stream_proxy_id')
    THEN
        update wvp_device_channel wdc INNER JOIN
            (SELECT id, stream_proxy_id from wvp_device_channel where stream_proxy_id is not null ) ct on ct.id = wdc.id
        set wdc.data_type = 3, wdc.data_device_id = ct.stream_proxy_id where wdc.stream_proxy_id is not null;
        alter table wvp_device_channel drop stream_proxy_id;
    END IF;
END; //
call wvp_20241222();
DROP PROCEDURE wvp_20241222;
DELIMITER ;
/*
* 20241231
*/
DELIMITER //
CREATE PROCEDURE `wvp_20241231`()
BEGIN
    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_stream_proxy' and column_name = 'relates_media_server_id')
    THEN
        alter table wvp_stream_proxy add relates_media_server_id character varying(50);
    END IF;
END; //
call wvp_20241231();
DROP PROCEDURE wvp_20241231;
DELIMITER ;
/*
* 20250111
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250111`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.STATISTICS
               WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_cloud_record' and INDEX_NAME = 'uk_stream_push_app_stream_path')
    THEN
        alter table wvp_cloud_record drop index uk_stream_push_app_stream_path ;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_cloud_record' and column_name = 'folder')
    THEN
        alter table wvp_cloud_record modify folder varchar(500) null;
    END IF;

    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_cloud_record' and column_name = 'file_path')
    THEN
        alter table wvp_cloud_record modify file_path varchar(500) null;
    END IF;
END; //
call wvp_20250111();
DROP PROCEDURE wvp_20250111;
DELIMITER ;

/*
* 20250211
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250211`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.STATISTICS
               WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device' and column_name = 'keepalive_interval_time')
    THEN
        alter table wvp_device change keepalive_interval_time heart_beat_interval integer after as_message_channel;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'heart_beat_count')
    THEN
        alter table wvp_device add heart_beat_count integer;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'position_capability')
    THEN
        alter table wvp_device add position_capability integer;
    END IF;
END; //
call wvp_20250211();
DROP PROCEDURE wvp_20250211;
DELIMITER ;

/**
  * 20250312
 */
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250312`()
BEGIN
    DECLARE serverId VARCHAR(32) DEFAULT '你的服务ID';
    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'server_id')
    THEN
        alter table wvp_device add server_id character varying(50);
        update wvp_device set server_id = serverId;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_media_server' and column_name = 'server_id')
    THEN
        alter table wvp_media_server add server_id character varying(50);
        update wvp_media_server set server_id = serverId;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_stream_proxy' and column_name = 'server_id')
    THEN
        alter table wvp_stream_proxy add server_id character varying(50);
        update wvp_stream_proxy set server_id = serverId;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_cloud_record' and column_name = 'server_id')
    THEN
        alter table wvp_cloud_record add server_id character varying(50);
        update wvp_cloud_record set server_id = serverId;
    END IF;

    IF not EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_platform' and column_name = 'server_id')
    THEN
        alter table wvp_platform add server_id character varying(50);
    END IF;
END; //
call wvp_20250312();
DROP PROCEDURE wvp_20250312;
DELIMITER ;

/*
* 20250319
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250319`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and column_name = 'gps_speed')
    THEN
        alter table wvp_device_channel add gps_speed double precision;
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and column_name = 'gps_altitude')
    THEN
        alter table wvp_device_channel add gps_altitude double precision;
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and column_name = 'gps_direction')
    THEN
        alter table wvp_device_channel add gps_direction double precision;
    END IF;
END; //
call wvp_20250319();
DROP PROCEDURE wvp_20250319;
DELIMITER ;

/*
* 20250402
*/
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250402`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and INDEX_NAME = 'data_type')
    THEN
        create index data_type on wvp_device_channel (data_type);
    END IF;
    IF NOT EXISTS (SELECT column_name FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and INDEX_NAME = 'data_device_id')
    THEN
        create index data_device_id on wvp_device_channel (data_device_id);
    END IF;

END; //
call wvp_20250402();
DROP PROCEDURE wvp_20250402;
DELIMITER ;




-- 旁路转推映射表：dest_url（转码后地址） -> src_url（转码前源地址）
create table IF NOT EXISTS tds_bypass
(
    dest_url character varying(255) primary key COMMENT '转码后地址',
    src_url  character varying(255) not null COMMENT '转码前源地址'
);


/*
* ===== 2.7.4 升级段：以下与 数据库/2.7.4/更新-mysql-2.7.4.sql 一致，在已有库上幂等补齐 =====
*/
/*
* 20250708
*/
DROP PROCEDURE IF EXISTS `wvp_20250708`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250708`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_media_server' and column_name = 'jtt_proxy_port')
    THEN
        ALTER TABLE wvp_media_server ADD jtt_proxy_port  integer;
    END IF;
END; //
DELIMITER ;
call wvp_20250708();
DROP PROCEDURE wvp_20250708;

/*
* 20250917
*/
DROP PROCEDURE IF EXISTS `wvp_20250917`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250917`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_media_server' and column_name = 'mp4_port')
    THEN
        ALTER TABLE wvp_media_server ADD mp4_port integer;
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_media_server' and column_name = 'mp4_ssl_port')
    THEN
        ALTER TABLE wvp_media_server ADD mp4_ssl_port integer;
    END IF;
END; //
DELIMITER ;
call wvp_20250917();
DROP PROCEDURE wvp_20250917;

/*
* 20250924
*/
DROP PROCEDURE IF EXISTS `wvp_20250924`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20250924`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and column_name = 'enable_broadcast')
    THEN
        ALTER TABLE wvp_device_channel ADD enable_broadcast integer default 0;
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                       WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_channel' and column_name = 'map_level')
    THEN
        ALTER TABLE wvp_device_channel ADD map_level integer default 0;
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                       WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_common_group' and column_name = 'alias')
    THEN
        ALTER TABLE wvp_common_group ADD alias varchar(255) default null;
    END IF;
END; //
DELIMITER ;
call wvp_20250924();
DROP PROCEDURE wvp_20250924;


/*
* 20251027
*/
DROP PROCEDURE IF EXISTS `wvp_20251027`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20251027`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_stream_proxy' and column_name = 'enable_remove_none_reader')
    THEN
        ALTER TABLE wvp_stream_proxy DROP enable_remove_none_reader;
    END IF;
END; //
DELIMITER ;
call wvp_20251027();
DROP PROCEDURE wvp_20251027;

/*
* 20251101
*/
DROP PROCEDURE IF EXISTS `wvp_20251101`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20251101`()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND TABLE_NAME = 'wvp_media_server'
                 AND INDEX_NAME = 'uk_media_server_unique_ip_http_port')
    THEN
        drop index uk_media_server_unique_ip_http_port on wvp_media_server;
    END IF;
END; //
DELIMITER ;
call wvp_20251101();
DROP PROCEDURE wvp_20251101;

/*
* 202601025
*/
DROP PROCEDURE IF EXISTS `wvp_202601025`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_202601025`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device' and column_name = 'register_time')
    THEN
        ALTER TABLE wvp_device DROP register_time;
    END IF;
    IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device' and column_name = 'keepalive_time')
    THEN
        ALTER TABLE wvp_device DROP keepalive_time;
    END IF;
END; //
DELIMITER ;
call wvp_202601025();
DROP PROCEDURE wvp_202601025;


/*
* 20260417 将wvp_device_mobile_position从专属国标的位置记录表，改为通用通道共用的位置记录表
*/
DROP PROCEDURE IF EXISTS `wvp_20260417`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20260417`()
BEGIN
 IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position' and column_name = 'timestamp')
    THEN
    ALTER TABLE wvp_device_mobile_position ADD timestamp BIGINT COMMENT '上报时间';
END IF;
IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position' and column_name = 'time')
    THEN
    UPDATE wvp_device_mobile_position SET timestamp = UNIX_TIMESTAMP(time) * 1000;
    ALTER TABLE wvp_device_mobile_position DROP time;
END IF;
IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position' and column_name = 'device_id')
    THEN
    ALTER TABLE wvp_device_mobile_position DROP device_id;
END IF;
IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position' and column_name = 'device_name')
    THEN
    ALTER TABLE wvp_device_mobile_position DROP device_name;
END IF;
IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position' and column_name = 'report_source')
    THEN
ALTER TABLE wvp_device_mobile_position DROP report_source;
END IF;
-- 修改表名
IF EXISTS (SELECT table_name FROM information_schema.tables
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_device_mobile_position')
    THEN
ALTER TABLE wvp_device_mobile_position RENAME TO wvp_mobile_position;
END IF;

END; //
DELIMITER ;
call wvp_20260417();
DROP PROCEDURE wvp_20260417;

/*
* 20260521 添加wvp_device_channel唯一约束，防止通道重复写入
*/
DROP PROCEDURE IF EXISTS `wvp_20260521`;
DELIMITER //
CREATE PROCEDURE `wvp_20260521`()
BEGIN
    IF NOT EXISTS (SELECT 1
                   FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND TABLE_NAME = 'wvp_device_channel'
                     AND INDEX_NAME = 'uk_device_channel_source')
    THEN
        -- 用 GROUP BY + LEFT JOIN 替代自连接 DELETE
        DELETE t1
        FROM wvp_device_channel t1
                 LEFT JOIN (SELECT MAX(id) as id
                            FROM wvp_device_channel
                            GROUP BY data_device_id, device_id) t2 ON t1.id = t2.id
        WHERE t2.id IS NULL;

ALTER TABLE wvp_device_channel
    ADD UNIQUE INDEX uk_device_channel_source (data_device_id, device_id);
END IF;
END; //
DELIMITER ;
call wvp_20260521();
DROP PROCEDURE wvp_20260521;







/*
* 20260606 添加用户默认密码标记字段（默认密码强制修改）
*/
DROP PROCEDURE IF EXISTS `wvp_20260606`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_20260606`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and  table_name = 'wvp_user' and column_name = 'default_password')
    THEN
        ALTER TABLE wvp_user ADD default_password bool default false COMMENT '是否使用默认密码';
    END IF;

    -- 仅当 admin 的密码仍是默认密码时才标记 default_password=TRUE，已改过密码的不强制
    UPDATE wvp_user
       SET default_password = TRUE
     WHERE username = 'admin'
       AND password = '21232f297a57a5a743894a0e4a801fc3';
END; //
DELIMITER ;
call wvp_20260606();
DROP PROCEDURE wvp_20260606;

/*
* GB35114：为已有库补齐设备/平台的证书关联列（表本身由上面的 create table IF NOT EXISTS 建好）
*/
DROP PROCEDURE IF EXISTS `wvp_gb35114_cols`;
DELIMITER //  -- 重定义分隔符避免分号冲突
CREATE PROCEDURE `wvp_gb35114_cols`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'register_way')
    THEN
        ALTER TABLE wvp_device ADD register_way integer default 1 COMMENT '注册方式：1-摘要，3-证书双向，4-证书单向';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'cert_id')
    THEN
        ALTER TABLE wvp_device ADD cert_id integer COMMENT '关联的国密证书ID（wvp_gb35114_cert.id）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_device' and column_name = 'server_cert_id')
    THEN
        ALTER TABLE wvp_device ADD server_cert_id integer COMMENT '该设备信任的服务器证书ID（wvp_gb35114_cert.id）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_platform' and column_name = 'device_cert_id')
    THEN
        ALTER TABLE wvp_platform ADD device_cert_id integer COMMENT '本平台作下级注册的设备证书ID（wvp_gb35114_cert.id）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE()) and table_name = 'wvp_platform' and column_name = 'platform_cert_id')
    THEN
        ALTER TABLE wvp_platform ADD platform_cert_id integer COMMENT '受信上级平台证书ID（wvp_gb35114_cert.id）';
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_cols();
DROP PROCEDURE wvp_gb35114_cols;
