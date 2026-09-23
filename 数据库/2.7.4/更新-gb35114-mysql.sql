-- GB35114 A 级国密证书管理表结构变更（MySQL）
-- 在 wvp-GB28181-pro 2.7.4 基础上新增

-- 根 CA 表
create table IF NOT EXISTS wvp_gb35114_ca
(
    id            serial primary key COMMENT '主键ID',
    subject_cn    character varying(255) COMMENT '主题 CN',
    serial_number character varying(100) COMMENT '序列号',
    cert_pem      text COMMENT '证书 PEM',
    key_pem       text COMMENT '私钥 PEM（对称加密存储）',
    not_before    character varying(50) COMMENT '生效时间',
    not_after     character varying(50) COMMENT '失效时间',
    create_time   character varying(50) COMMENT '创建时间'
);

-- 证书表
create table IF NOT EXISTS wvp_gb35114_cert
(
    id            serial primary key COMMENT '主键ID',
    type          integer COMMENT '证书类型：1-服务器证书，2-设备证书',
    gb_id         character varying(50) COMMENT '关联国标 ID',
    subject_cn    character varying(255) COMMENT '主题 CN',
    serial_number character varying(100) COMMENT '序列号',
    ca_id         integer COMMENT '签发 CA 的 ID，null 表示自签',
    cert_pem      text COMMENT '证书 PEM',
    key_pem       text COMMENT '私钥 PEM（对称加密存储）',
    not_before    character varying(50) COMMENT '生效时间',
    not_after     character varying(50) COMMENT '失效时间',
    revoked       bool default false COMMENT '是否已吊销',
    create_time   character varying(50) COMMENT '创建时间'
);

-- 设备表新增国密注册方式与关联证书（幂等：判列后添加）
DROP PROCEDURE IF EXISTS `wvp_gb35114`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_device'
                     AND column_name = 'register_way')
    THEN
        ALTER TABLE wvp_device ADD register_way integer default 1 COMMENT '注册方式：1-摘要，3-证书双向，4-证书单向';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_device'
                     AND column_name = 'cert_id')
    THEN
        ALTER TABLE wvp_device ADD cert_id integer COMMENT '关联的国密证书ID（wvp_gb35114_cert.id）';
    END IF;

    -- 国标级联（wvp_platform）新增：本平台作为下级接入上级平台时的国密证书
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_platform'
                     AND column_name = 'device_cert_id')
    THEN
        ALTER TABLE wvp_platform ADD device_cert_id integer COMMENT '本平台作下级注册的设备证书ID（wvp_gb35114_cert.id）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_platform'
                     AND column_name = 'platform_cert_id')
    THEN
        ALTER TABLE wvp_platform ADD platform_cert_id integer COMMENT '受信上级平台证书ID（wvp_gb35114_cert.id）';
    END IF;
END; //
DELIMITER ;
call wvp_gb35114();
DROP PROCEDURE wvp_gb35114;

-- ============================================================================
-- 证书用途（purpose）改造：区分「本地持有私钥」与「仅对端公钥」的证书，
-- 避免级联页面把"本平台自己的身份证书"与"签发给下级的证书"混在一起。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_purpose`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_purpose`()
BEGIN
    -- ---- 证书表新增列 ----
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'purpose')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD purpose varchar(30) DEFAULT 'ISSUED_DEVICE'
            COMMENT '用途：SERVER_IDENTITY/DEVICE_IDENTITY/ISSUED_DEVICE/TRUSTED_PLATFORM';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'subject_dn')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD subject_dn varchar(500) COMMENT '完整主题DN（RFC2253）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'country')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD country varchar(10) COMMENT '国家 C';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'province')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD province varchar(64) COMMENT '省份 ST';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'locality')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD locality varchar(64) COMMENT '城市 L';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'organization')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD organization varchar(255) COMMENT '组织 O';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'organizational_unit')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD organizational_unit varchar(255) COMMENT '组织单位 OU';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'csr_pem')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD csr_pem text COMMENT '待签发记录的CSR PEM（私钥与之同记录）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'remark')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD remark varchar(500) COMMENT '备注';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'validity_days')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD validity_days integer COMMENT '签发时的有效期天数快照';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'key_usage')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD key_usage varchar(200)
            COMMENT '密钥用途扩展，如 digitalSignature、keyCertSign|cRLSign';
    END IF;

    -- ---- CA 表新增列 ----
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'purpose')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD purpose varchar(20) DEFAULT 'LOCAL_CA'
            COMMENT '用途：LOCAL_CA-本地CA（可签发），TRUSTED_CA-上级CA（仅公钥，标识签发者）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'remark')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD remark varchar(500) COMMENT '备注';
    END IF;

    -- ---- 索引 ----
    IF NOT EXISTS (SELECT index_name FROM information_schema.statistics
                   WHERE table_schema = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert'
                     AND index_name = 'idx_gb35114_cert_purpose')
    THEN
        CREATE INDEX idx_gb35114_cert_purpose ON wvp_gb35114_cert (purpose, gb_id);
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_purpose();
DROP PROCEDURE wvp_gb35114_purpose;

-- ============================================================================
-- 存量数据归类（启发式，执行后请人工核对各 tab 归类是否正确）
-- 优先级：被级联/设备引用的证书 > 按 type 与是否持有私钥推断
-- ============================================================================

-- 被级联平台引用的证书（用途明确）
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE id IN (SELECT platform_cert_id FROM wvp_platform WHERE platform_cert_id IS NOT NULL);

UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE id IN (SELECT device_cert_id FROM wvp_platform WHERE device_cert_id IS NOT NULL)
    OR id IN (SELECT cert_id FROM wvp_device WHERE cert_id IS NOT NULL);

-- type=2 且无私钥：由下级 CSR 签发，私钥在下级
UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE'
 WHERE type = 2 AND (key_pem IS NULL OR key_pem = '');

-- type=2 且有私钥：本平台自己的客户端身份
UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE type = 2 AND key_pem IS NOT NULL AND key_pem != '';

-- type=1 且无私钥：受信的上级服务端证书
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE type = 1 AND (key_pem IS NULL OR key_pem = '');

-- type=1 且有私钥：本平台自己的服务端身份
UPDATE wvp_gb35114_cert SET purpose = 'SERVER_IDENTITY'
 WHERE type = 1 AND key_pem IS NOT NULL AND key_pem != '';

-- 兜底
UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE' WHERE purpose IS NULL;

-- CA 归类：有私钥为本地 CA，否则为上级 CA
UPDATE wvp_gb35114_ca SET purpose = 'LOCAL_CA'
 WHERE key_pem IS NOT NULL AND key_pem != '';
UPDATE wvp_gb35114_ca SET purpose = 'TRUSTED_CA'
 WHERE purpose IS NULL OR key_pem IS NULL OR key_pem = '';

-- 回填完整 DN（仅展示用）
UPDATE wvp_gb35114_cert SET subject_dn = CONCAT('CN=', subject_cn) WHERE subject_dn IS NULL;

-- 回填密钥用途：存量证书签出时未写入该扩展，此处仅作为展示值，不影响已签发证书
UPDATE wvp_gb35114_cert SET key_usage = 'digitalSignature' WHERE key_usage IS NULL;

-- 核对清单：启用中的级联平台及其证书引用
SELECT p.id, p.name, p.server_gb_id, p.register_way, p.device_cert_id, p.platform_cert_id,
       (SELECT purpose FROM wvp_gb35114_cert c WHERE c.id = p.device_cert_id)   AS device_cert_purpose,
       (SELECT purpose FROM wvp_gb35114_cert c WHERE c.id = p.platform_cert_id) AS platform_cert_purpose
  FROM wvp_platform p WHERE p.enable = 1;

-- ============================================================================
-- 按设备绑定它实际信任的那张服务器证书。
--
-- 背景：UAS 签 sign2 时只能用一个私钥，而设备侧只信任它配置时导入的那张平台
-- 证书的公钥。此前「按 id 倒序取最新」的隐式选择意味着新增一张服务器证书就会
-- 静默顶掉旧证书，让所有按旧证书配置过的设备注册后立刻被 403 拒绝。
-- 现在 SERVER_IDENTITY 由后端强制唯一（换发走「同密钥再签」原地更新），
-- 未绑定设备的设备直接使用平台唯一的那张；此列只用于「设备信任的并非平台
-- 当前签名身份」的例外情况。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_multi_server_cert`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_multi_server_cert`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_device' AND column_name = 'server_cert_id')
    THEN
        ALTER TABLE wvp_device ADD server_cert_id integer
            COMMENT '该设备信任的服务器证书ID（wvp_gb35114_cert.id，空则用平台唯一的那张服务端证书）';
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_multi_server_cert();
DROP PROCEDURE wvp_gb35114_multi_server_cert;

-- ============================================================================
-- 移除 is_default 列（如存在）。
--
-- 该列曾用于在「同一密钥对签出的多张服务端证书」之间挑锚点。现已改为：后端强制
-- SERVER_IDENTITY 至多一条未吊销记录，换发走「同密钥再签」原地更新（不新增行，
-- 证书 ID 恒定，配置文件与设备绑定按 ID 的引用永不悬空），于是「选哪张」这个问题
-- 本身消失了，标记默认既无必要也无意义。
--
-- 存量的多行 SERVER_IDENTITY 不会被本脚本删除：本平台只保留一组密钥，但同组可以
-- 有多张证书（换有效期/DN/签发者），它们公钥指纹相同、彼此可互换，都在用。
-- 新代码取「id 最大的一张未吊销记录」作为签名身份。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_drop_is_default`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_drop_is_default`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_cert' AND column_name = 'is_default')
    THEN
        ALTER TABLE wvp_gb35114_cert DROP COLUMN is_default;
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_drop_is_default();
DROP PROCEDURE wvp_gb35114_drop_is_default;

-- 核对：当前服务端证书（按 id 倒序，第一条未吊销的即为签名身份）
SELECT id, gb_id, subject_cn, serial_number, not_after, key_fingerprint,
       CASE WHEN key_pem IS NULL OR key_pem = '' THEN 0 ELSE 1 END AS has_key
  FROM wvp_gb35114_cert WHERE purpose = 'SERVER_IDENTITY' ORDER BY id DESC;

-- ============================================================================
-- 公钥指纹：标识「同一个 SM2 签名身份」。
--
-- 设备侧只保存一个平台公钥（无 CA 链校验，直接公钥比对），因此平台签 sign2 用的
-- 私钥必须与设备导入的那张证书配对。若多张服务端证书共用同一密钥对（证书轮换：
-- 只换有效期/DN/签发者），它们的公钥指纹相同、彼此可互换 —— 设备导入其中任意一张，
-- 平台用同组任意一张的私钥签名都能被验过，换证书无需重新配置设备。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_key_fingerprint`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_key_fingerprint`()
BEGIN
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'key_fingerprint')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD key_fingerprint varchar(64)
            COMMENT '公钥指纹（SM3 十六进制）；相同表示同一个签名身份，证书可互换';
    END IF;

    IF NOT EXISTS (SELECT index_name FROM information_schema.statistics
                   WHERE table_schema = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert'
                     AND index_name = 'idx_gb35114_cert_fingerprint')
    THEN
        CREATE INDEX idx_gb35114_cert_fingerprint
            ON wvp_gb35114_cert (purpose, key_fingerprint);
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_key_fingerprint();
DROP PROCEDURE wvp_gb35114_key_fingerprint;

-- 存量证书的指纹无法在 SQL 里算（需解析 DER 取 SubjectPublicKeyInfo），
-- 留空即可：新签发/新导入的证书会自动写入。核对现有服务端证书的密钥对分布：
SELECT id, subject_cn, serial_number, ca_id, key_fingerprint
  FROM wvp_gb35114_cert WHERE purpose = 'SERVER_IDENTITY' ORDER BY id;

-- ============================================================================
-- 删除 CA 别名列（name）。
--
-- CA 的身份就是它证书的主题 CN，另起一个别名只会让同一张 CA 在页面上有两个
-- 都像名字的字段。该列自证书改造起就不再读写，此处从库里彻底移除。
-- 幂等：判列存在后再删，重复执行安全。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_drop_ca_name`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_drop_ca_name`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_ca' AND column_name = 'name')
    THEN
        ALTER TABLE wvp_gb35114_ca DROP COLUMN name;
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_drop_ca_name();
DROP PROCEDURE wvp_gb35114_drop_ca_name;

-- 核对：CA 表列清单里不应再有 name
SELECT id, purpose, subject_cn, serial_number, not_after
  FROM wvp_gb35114_ca ORDER BY purpose, id;
