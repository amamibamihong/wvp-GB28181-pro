/*============================================================================
 * GB35114 A 级国密证书管理表结构变更（达梦 DM8）
 *---------------------------------------------------------------------------
 * 在 wvp-GB28181-pro 2.7.4 基础上新增。
 * 达梦原生规范（对齐《初始化-达梦-2.7.4.sql》）：
 *   1) 自增主键使用达梦原生标识列 IDENTITY(1,1)
 *   2) 达梦原生不支持 CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS，
 *      表/列存在性判断通过匿名块查询系统表 SYSOBJECTS / USER_TAB_COLUMNS 实现
 *   3) 类型使用达梦原生类型：varchar / int / clob / bit（布尔用 bit，0=假 1=真）
 *   4) 注释使用 COMMENT ON COLUMN 语法
 *============================================================================*/

-- 根 CA 表
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM SYSOBJECTS WHERE NAME = 'WVP_GB35114_CA' AND TYPE$ = 'SCHOBJ';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'CREATE TABLE wvp_gb35114_ca
(
    id            int identity(1,1) primary key,
    subject_cn    varchar(255),
    serial_number varchar(100),
    cert_pem      clob,
    key_pem       clob,
    not_before    varchar(50),
    not_after     varchar(50),
    create_time   varchar(50)
)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_ca.id IS '主键ID';
COMMENT ON COLUMN wvp_gb35114_ca.subject_cn IS '主题 CN';
COMMENT ON COLUMN wvp_gb35114_ca.serial_number IS '序列号';
COMMENT ON COLUMN wvp_gb35114_ca.cert_pem IS '证书 PEM';
COMMENT ON COLUMN wvp_gb35114_ca.key_pem IS '私钥 PEM（对称加密存储）';
COMMENT ON COLUMN wvp_gb35114_ca.not_before IS '生效时间';
COMMENT ON COLUMN wvp_gb35114_ca.not_after IS '失效时间';
COMMENT ON COLUMN wvp_gb35114_ca.create_time IS '创建时间';

-- 证书表
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM SYSOBJECTS WHERE NAME = 'WVP_GB35114_CERT' AND TYPE$ = 'SCHOBJ';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'CREATE TABLE wvp_gb35114_cert
(
    id            int identity(1,1) primary key,
    type          int,
    gb_id         varchar(50),
    subject_cn    varchar(255),
    serial_number varchar(100),
    ca_id         int,
    cert_pem      clob,
    key_pem       clob,
    not_before    varchar(50),
    not_after     varchar(50),
    revoked       bit default 0,
    create_time   varchar(50)
)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.id IS '主键ID';
COMMENT ON COLUMN wvp_gb35114_cert.type IS '证书类型：1-服务器证书，2-设备证书';
COMMENT ON COLUMN wvp_gb35114_cert.gb_id IS '关联国标 ID';
COMMENT ON COLUMN wvp_gb35114_cert.subject_cn IS '主题 CN';
COMMENT ON COLUMN wvp_gb35114_cert.serial_number IS '序列号';
COMMENT ON COLUMN wvp_gb35114_cert.ca_id IS '签发 CA 的 ID，null 表示自签';
COMMENT ON COLUMN wvp_gb35114_cert.cert_pem IS '证书 PEM';
COMMENT ON COLUMN wvp_gb35114_cert.key_pem IS '私钥 PEM（对称加密存储）';
COMMENT ON COLUMN wvp_gb35114_cert.not_before IS '生效时间';
COMMENT ON COLUMN wvp_gb35114_cert.not_after IS '失效时间';
COMMENT ON COLUMN wvp_gb35114_cert.revoked IS '是否已吊销';
COMMENT ON COLUMN wvp_gb35114_cert.create_time IS '创建时间';

-- 设备表新增国密注册方式与关联证书（幂等：判列后添加）
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_DEVICE' AND COLUMN_NAME = 'REGISTER_WAY';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_device ADD register_way int default 1';
END IF;
END;
/
COMMENT ON COLUMN wvp_device.register_way IS '注册方式：1-摘要，3-证书双向，4-证书单向';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_DEVICE' AND COLUMN_NAME = 'CERT_ID';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_device ADD cert_id int';
END IF;
END;
/
COMMENT ON COLUMN wvp_device.cert_id IS '关联的国密证书ID（wvp_gb35114_cert.id）';

-- 国标级联（wvp_platform）新增：本平台作为下级接入上级平台时的国密证书
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_PLATFORM' AND COLUMN_NAME = 'DEVICE_CERT_ID';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_platform ADD device_cert_id int';
END IF;
END;
/
COMMENT ON COLUMN wvp_platform.device_cert_id IS '本平台作下级注册的设备证书ID（wvp_gb35114_cert.id）';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_PLATFORM' AND COLUMN_NAME = 'PLATFORM_CERT_ID';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_platform ADD platform_cert_id int';
END IF;
END;
/
COMMENT ON COLUMN wvp_platform.platform_cert_id IS '受信上级平台证书ID（wvp_gb35114_cert.id）';

/*============================================================================
 * 证书用途（purpose）改造
 *---------------------------------------------------------------------------
 * 区分「本地持有私钥」与「仅对端公钥」的证书，避免级联页面把
 * "本平台自己的身份证书"与"签发给下级的证书"混在一起。
 * 达梦 clob 列判空不可用 key_pem = ''，统一用 LENGTH(key_pem) = 0。
 *============================================================================*/

-- ---- 证书表新增列 ----
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'PURPOSE';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD purpose varchar(30) default ''ISSUED_DEVICE''';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.purpose IS '用途：SERVER_IDENTITY/DEVICE_IDENTITY/ISSUED_DEVICE/TRUSTED_PLATFORM';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'SUBJECT_DN';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD subject_dn varchar(500)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.subject_dn IS '完整主题DN（RFC2253）';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'COUNTRY';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD country varchar(10)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.country IS '国家 C';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'PROVINCE';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD province varchar(64)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.province IS '省份 ST';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'LOCALITY';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD locality varchar(64)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.locality IS '城市 L';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'ORGANIZATION';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD organization varchar(255)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.organization IS '组织 O';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'ORGANIZATIONAL_UNIT';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD organizational_unit varchar(255)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.organizational_unit IS '组织单位 OU';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'CSR_PEM';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD csr_pem clob';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.csr_pem IS '待签发记录的CSR PEM（私钥与之同记录）';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'REMARK';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD remark varchar(500)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.remark IS '备注';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'VALIDITY_DAYS';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD validity_days int';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.validity_days IS '签发时的有效期天数快照';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'KEY_USAGE';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD key_usage varchar(200)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.key_usage IS '密钥用途扩展，如 digitalSignature、keyCertSign|cRLSign';

-- ---- CA 表新增列 ----
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CA' AND COLUMN_NAME = 'PURPOSE';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_ca ADD purpose varchar(20) default ''LOCAL_CA''';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_ca.purpose IS '用途：LOCAL_CA-本地CA（可签发），TRUSTED_CA-上级CA（仅公钥，标识签发者）';

DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS WHERE TABLE_NAME = 'WVP_GB35114_CA' AND COLUMN_NAME = 'REMARK';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_ca ADD remark varchar(500)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_ca.remark IS '备注';

-- ---- 索引 ----
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM SYSOBJECTS WHERE NAME = 'IDX_GB35114_CERT_PURPOSE' AND TYPE$ = 'SCHOBJ';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'CREATE INDEX idx_gb35114_cert_purpose ON wvp_gb35114_cert (purpose, gb_id)';
END IF;
END;
/

/*============================================================================
 * 存量数据归类（启发式，执行后请人工核对各 tab 归类是否正确）
 * 达梦 clob 判空用 LENGTH(...) = 0
 *============================================================================*/
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE id IN (SELECT platform_cert_id FROM wvp_platform WHERE platform_cert_id IS NOT NULL);

UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE id IN (SELECT device_cert_id FROM wvp_platform WHERE device_cert_id IS NOT NULL)
    OR id IN (SELECT cert_id FROM wvp_device WHERE cert_id IS NOT NULL);

UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE'
 WHERE type = 2 AND (key_pem IS NULL OR LENGTH(key_pem) = 0);
UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE type = 2 AND key_pem IS NOT NULL AND LENGTH(key_pem) > 0;
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE type = 1 AND (key_pem IS NULL OR LENGTH(key_pem) = 0);
UPDATE wvp_gb35114_cert SET purpose = 'SERVER_IDENTITY'
 WHERE type = 1 AND key_pem IS NOT NULL AND LENGTH(key_pem) > 0;
UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE' WHERE purpose IS NULL;

UPDATE wvp_gb35114_ca SET purpose = 'LOCAL_CA'
 WHERE key_pem IS NOT NULL AND LENGTH(key_pem) > 0;
UPDATE wvp_gb35114_ca SET purpose = 'TRUSTED_CA'
 WHERE purpose IS NULL OR key_pem IS NULL OR LENGTH(key_pem) = 0;

UPDATE wvp_gb35114_cert SET subject_dn = 'CN=' || subject_cn WHERE subject_dn IS NULL;

-- 回填密钥用途：存量证书签出时未写入该扩展，此处仅作为展示值，不影响已签发证书
UPDATE wvp_gb35114_cert SET key_usage = 'digitalSignature' WHERE key_usage IS NULL;


/*============================================================================
 * 按设备绑定它实际信任的那张服务器证书。
 *
 * 背景：UAS 签 sign2 时只能用一个私钥，而设备侧只信任它配置时导入的那张平台
 * 证书的公钥。此前「按 id 倒序取最新」的隐式选择意味着新增一张服务器证书就会
 * 静默顶掉旧证书，让所有按旧证书配置过的设备注册后立刻被 403 拒绝。
 * 现在 SERVER_IDENTITY 由后端强制唯一（换发走「同密钥再签」原地更新），
 * 未绑定设备的设备直接使用平台唯一的那张；此列只用于「设备信任的并非平台
 * 当前签名身份」的例外情况。
 * 达梦原生不支持 ADD COLUMN IF NOT EXISTS，用匿名块判列后添加。
 *============================================================================*/
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS
 WHERE TABLE_NAME = 'WVP_DEVICE' AND COLUMN_NAME = 'SERVER_CERT_ID';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_device ADD server_cert_id int';
END IF;
END;
/
COMMENT ON COLUMN wvp_device.server_cert_id IS
    '该设备信任的服务器证书ID（wvp_gb35114_cert.id，空则用平台唯一的那张服务端证书）';

/*============================================================================
 * 移除 is_default 列（如存在）。
 *
 * 该列曾用于在「同一密钥对签出的多张服务端证书」之间挑锚点。现已改为：后端强制
 * SERVER_IDENTITY 至多一条未吊销记录，换发走「同密钥再签」原地更新（不新增行，
 * 证书 ID 恒定，配置文件与设备绑定按 ID 的引用永不悬空），于是「选哪张」这个问题
 * 本身消失了，标记默认既无必要也无意义。
 *
 * 存量的多行 SERVER_IDENTITY 不会被本脚本删除：本平台只保留一组密钥，但同组可以
 * 有多张证书（换有效期/DN/签发者），它们公钥指纹相同、彼此可互换，都在用。
 * 新代码取「id 最大的一张未吊销记录」作为签名身份。
 *============================================================================*/
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS
 WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'IS_DEFAULT';
IF V_CNT > 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert DROP COLUMN is_default';
END IF;
END;
/

-- 核对：当前服务端证书（按 id 倒序，第一条未吊销的即为签名身份）
SELECT id, gb_id, subject_cn, serial_number, not_after, key_fingerprint,
       CASE WHEN key_pem IS NULL OR LENGTH(key_pem) = 0 THEN 0 ELSE 1 END AS has_key
  FROM wvp_gb35114_cert WHERE purpose = 'SERVER_IDENTITY' ORDER BY id DESC;

/*============================================================================
 * 公钥指纹：标识「同一个 SM2 签名身份」。
 *
 * 设备侧只保存一个平台公钥（无 CA 链校验，直接公钥比对），因此平台签 sign2 用的
 * 私钥必须与设备导入的那张证书配对。若多张服务端证书共用同一密钥对（证书轮换：
 * 只换有效期/DN/签发者），它们的公钥指纹相同、彼此可互换 —— 设备导入其中任意一张，
 * 平台用同组任意一张的私钥签名都能被验过，换证书无需重新配置设备。
 * 达梦原生不支持 ADD COLUMN IF NOT EXISTS，用匿名块判列后添加。
 *============================================================================*/
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS
 WHERE TABLE_NAME = 'WVP_GB35114_CERT' AND COLUMN_NAME = 'KEY_FINGERPRINT';
IF V_CNT = 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_cert ADD key_fingerprint varchar(64)';
END IF;
END;
/
COMMENT ON COLUMN wvp_gb35114_cert.key_fingerprint IS
    '公钥指纹（SM3 十六进制）；相同表示同一个签名身份，证书可互换';

CREATE INDEX idx_gb35114_cert_fingerprint ON wvp_gb35114_cert (purpose, key_fingerprint);

-- 存量证书的指纹无法在 SQL 里算（需解析 DER 取 SubjectPublicKeyInfo），
-- 留空即可：新签发/新导入的证书会自动写入。核对现有服务端证书的密钥对分布：
SELECT id, subject_cn, serial_number, ca_id, key_fingerprint
  FROM wvp_gb35114_cert WHERE purpose = 'SERVER_IDENTITY' ORDER BY id;

/*============================================================================
 * 删除 CA 别名列（name）。
 *
 * CA 的身份就是它证书的主题 CN，另起一个别名只会让同一张 CA 在页面上有两个
 * 都像名字的字段。该列自证书改造起就不再读写，此处从库里彻底移除。
 * 幂等：判列存在后再删，重复执行安全。
 *============================================================================*/
DECLARE
V_CNT INT;
BEGIN
SELECT COUNT(*) INTO V_CNT FROM USER_TAB_COLUMNS
 WHERE TABLE_NAME = 'WVP_GB35114_CA' AND COLUMN_NAME = 'NAME';
IF V_CNT > 0 THEN
        EXECUTE IMMEDIATE 'ALTER TABLE wvp_gb35114_ca DROP COLUMN name';
END IF;
END;
/

-- 核对：CA 表列清单里不应再有 name
SELECT id, purpose, subject_cn, serial_number, not_after
  FROM wvp_gb35114_ca ORDER BY purpose, id;
