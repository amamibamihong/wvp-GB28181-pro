-- GB35114 A 级国密证书管理表结构变更（PostgreSQL / KingbaseES）
-- 在 wvp-GB28181-pro 2.7.4 基础上新增

-- 根 CA 表
create table IF NOT EXISTS wvp_gb35114_ca
(
    id            serial primary key,
    subject_cn    character varying(255),
    serial_number character varying(100),
    cert_pem      text,
    key_pem       text,
    not_before    character varying(50),
    not_after     character varying(50),
    create_time   character varying(50)
);
COMMENT ON COLUMN wvp_gb35114_ca.id IS '主键ID';
COMMENT ON COLUMN wvp_gb35114_ca.subject_cn IS '主题 CN';
COMMENT ON COLUMN wvp_gb35114_ca.serial_number IS '序列号';
COMMENT ON COLUMN wvp_gb35114_ca.cert_pem IS '证书 PEM';
COMMENT ON COLUMN wvp_gb35114_ca.key_pem IS '私钥 PEM（对称加密存储）';
COMMENT ON COLUMN wvp_gb35114_ca.not_before IS '生效时间';
COMMENT ON COLUMN wvp_gb35114_ca.not_after IS '失效时间';
COMMENT ON COLUMN wvp_gb35114_ca.create_time IS '创建时间';

-- 证书表
create table IF NOT EXISTS wvp_gb35114_cert
(
    id            serial primary key,
    type          integer,
    gb_id         character varying(50),
    subject_cn    character varying(255),
    serial_number character varying(100),
    ca_id         integer,
    cert_pem      text,
    key_pem       text,
    not_before    character varying(50),
    not_after     character varying(50),
    revoked       bool default false,
    create_time   character varying(50)
);
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

-- 设备表新增国密注册方式与关联证书
ALTER TABLE wvp_device ADD COLUMN IF NOT EXISTS register_way integer default 1;
ALTER TABLE wvp_device ADD COLUMN IF NOT EXISTS cert_id integer;
COMMENT ON COLUMN wvp_device.register_way IS '注册方式：1-摘要，3-证书双向，4-证书单向';
COMMENT ON COLUMN wvp_device.cert_id IS '关联的国密证书ID（wvp_gb35114_cert.id）';

-- 国标级联（wvp_platform）新增：本平台作为下级接入上级平台时的国密证书
ALTER TABLE wvp_platform ADD COLUMN IF NOT EXISTS device_cert_id integer;
ALTER TABLE wvp_platform ADD COLUMN IF NOT EXISTS platform_cert_id integer;
COMMENT ON COLUMN wvp_platform.device_cert_id IS '本平台作下级注册的设备证书ID（wvp_gb35114_cert.id）';
COMMENT ON COLUMN wvp_platform.platform_cert_id IS '受信上级平台证书ID（wvp_gb35114_cert.id）';

-- ============================================================================
-- 证书用途（purpose）改造：区分「本地持有私钥」与「仅对端公钥」的证书
-- ============================================================================

-- ---- 证书表新增列 ----
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS purpose varchar(30) DEFAULT 'ISSUED_DEVICE';
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS subject_dn varchar(500);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS country varchar(10);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS province varchar(64);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS locality varchar(64);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS organization varchar(255);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS organizational_unit varchar(255);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS csr_pem text;
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS remark varchar(500);
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS validity_days integer;
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS key_usage varchar(200);

COMMENT ON COLUMN wvp_gb35114_cert.purpose IS '用途：SERVER_IDENTITY/DEVICE_IDENTITY/ISSUED_DEVICE/TRUSTED_PLATFORM';
COMMENT ON COLUMN wvp_gb35114_cert.subject_dn IS '完整主题DN（RFC2253）';
COMMENT ON COLUMN wvp_gb35114_cert.country IS '国家 C';
COMMENT ON COLUMN wvp_gb35114_cert.province IS '省份 ST';
COMMENT ON COLUMN wvp_gb35114_cert.locality IS '城市 L';
COMMENT ON COLUMN wvp_gb35114_cert.organization IS '组织 O';
COMMENT ON COLUMN wvp_gb35114_cert.organizational_unit IS '组织单位 OU';
COMMENT ON COLUMN wvp_gb35114_cert.csr_pem IS '待签发记录的CSR PEM（私钥与之同记录）';
COMMENT ON COLUMN wvp_gb35114_cert.remark IS '备注';
COMMENT ON COLUMN wvp_gb35114_cert.validity_days IS '签发时的有效期天数快照';
COMMENT ON COLUMN wvp_gb35114_cert.key_usage IS '密钥用途扩展，如 digitalSignature、keyCertSign|cRLSign';

-- ---- CA 表新增列 ----
ALTER TABLE wvp_gb35114_ca ADD COLUMN IF NOT EXISTS purpose varchar(20) DEFAULT 'LOCAL_CA';
ALTER TABLE wvp_gb35114_ca ADD COLUMN IF NOT EXISTS remark varchar(500);
COMMENT ON COLUMN wvp_gb35114_ca.purpose IS '用途：LOCAL_CA-本地CA（可签发），TRUSTED_CA-上级CA（仅公钥，标识签发者）';
COMMENT ON COLUMN wvp_gb35114_ca.remark IS '备注';

-- ---- 索引 ----
CREATE INDEX IF NOT EXISTS idx_gb35114_cert_purpose ON wvp_gb35114_cert (purpose, gb_id);

-- ============================================================================
-- 存量数据归类（启发式，执行后请人工核对各 tab 归类是否正确）
-- ============================================================================
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE id IN (SELECT platform_cert_id FROM wvp_platform WHERE platform_cert_id IS NOT NULL);

UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE id IN (SELECT device_cert_id FROM wvp_platform WHERE device_cert_id IS NOT NULL)
    OR id IN (SELECT cert_id FROM wvp_device WHERE cert_id IS NOT NULL);

UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE'
 WHERE type = 2 AND (key_pem IS NULL OR key_pem = '');
UPDATE wvp_gb35114_cert SET purpose = 'DEVICE_IDENTITY'
 WHERE type = 2 AND key_pem IS NOT NULL AND key_pem != '';
UPDATE wvp_gb35114_cert SET purpose = 'TRUSTED_PLATFORM'
 WHERE type = 1 AND (key_pem IS NULL OR key_pem = '');
UPDATE wvp_gb35114_cert SET purpose = 'SERVER_IDENTITY'
 WHERE type = 1 AND key_pem IS NOT NULL AND key_pem != '';
UPDATE wvp_gb35114_cert SET purpose = 'ISSUED_DEVICE' WHERE purpose IS NULL;

UPDATE wvp_gb35114_ca SET purpose = 'LOCAL_CA' WHERE key_pem IS NOT NULL AND key_pem != '';
UPDATE wvp_gb35114_ca SET purpose = 'TRUSTED_CA' WHERE purpose IS NULL OR key_pem IS NULL OR key_pem = '';

UPDATE wvp_gb35114_cert SET subject_dn = 'CN=' || subject_cn WHERE subject_dn IS NULL;

-- 回填密钥用途：存量证书签出时未写入该扩展，此处仅作为展示值，不影响已签发证书
UPDATE wvp_gb35114_cert SET key_usage = 'digitalSignature' WHERE key_usage IS NULL;

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
ALTER TABLE wvp_device ADD COLUMN IF NOT EXISTS server_cert_id integer;
COMMENT ON COLUMN wvp_device.server_cert_id IS
    '该设备信任的服务器证书ID（wvp_gb35114_cert.id，空则用平台唯一的那张服务端证书）';

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
ALTER TABLE wvp_gb35114_cert DROP COLUMN IF EXISTS is_default;

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
ALTER TABLE wvp_gb35114_cert ADD COLUMN IF NOT EXISTS key_fingerprint varchar(64);
COMMENT ON COLUMN wvp_gb35114_cert.key_fingerprint IS
    '公钥指纹（SM3 十六进制）；相同表示同一个签名身份，证书可互换';

CREATE INDEX IF NOT EXISTS idx_gb35114_cert_fingerprint
    ON wvp_gb35114_cert (purpose, key_fingerprint);

-- 存量证书的指纹无法在 SQL 里算（需解析 DER 取 SubjectPublicKeyInfo），
-- 留空即可：新签发/新导入的证书会自动写入。核对现有服务端证书的密钥对分布：
SELECT id, subject_cn, serial_number, ca_id, key_fingerprint
  FROM wvp_gb35114_cert WHERE purpose = 'SERVER_IDENTITY' ORDER BY id;

-- ============================================================================
-- 删除 CA 别名列（name）。
--
-- CA 的身份就是它证书的主题 CN，另起一个别名只会让同一张 CA 在页面上有两个
-- 都像名字的字段。该列自证书改造起就不再读写，此处从库里彻底移除。
-- 幂等：DROP COLUMN IF EXISTS，重复执行安全。
-- ============================================================================
ALTER TABLE wvp_gb35114_ca DROP COLUMN IF EXISTS name;

-- 核对：CA 表列清单里不应再有 name
SELECT id, purpose, subject_cn, serial_number, not_after
  FROM wvp_gb35114_ca ORDER BY purpose, id;
