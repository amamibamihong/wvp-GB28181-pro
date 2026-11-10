-- GB35114 A 级国密证书管理表结构变更（MySQL）
-- 在 wvp-GB28181-pro 2.7.4 基础上新增

-- 根 CA 表
create table IF NOT EXISTS wvp_gb35114_ca
(
    id            serial primary key COMMENT '主键ID',
    type          character varying(20) DEFAULT 'LOCAL_CA'
                  COMMENT '类型：LOCAL_CA-本地CA(可签发，全局唯一) / TRUSTED_CA-受信任的CA(仅公钥，可重复导入)',
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
    type          character varying(30) DEFAULT 'ISSUED_DEVICE'
                  COMMENT '证书类型：SERVER_IDENTITY-服务端证书(本平台) / DEVICE_IDENTITY-客户端证书(本平台) / ISSUED_DEVICE-客户端证书(下级设备) / TRUSTED_PLATFORM-服务端证书(上级平台)',
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
-- 证书/CA 表补列：用途改造（区分「本地持有私钥」与「仅对端公钥」的证书，
-- 避免级联页面把"本平台自己的身份证书"与"签发给下级的证书"混在一起）
-- 以及后续陆续新增的 DN 各段、CSR、有效期、密钥用途、密码模块 ID 等。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_columns`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_columns`()
BEGIN
    -- ---- 证书表新增列 ----
    -- purpose 只在「老库」补：老库的 type 是整数（1-服务器/2-设备），需要先补出 purpose
    -- 承载四个字符串取值，再由脚本末尾的迁移段把 purpose 改名为 type、删掉整数 type。
    -- 新装库的 type 建表时已是 varchar(30)，不需要也不该再加一列 purpose。
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_cert' AND column_name = 'type'
                 AND data_type IN ('int', 'integer', 'bigint', 'smallint', 'tinyint'))
       AND NOT EXISTS (SELECT column_name FROM information_schema.columns
                       WHERE TABLE_SCHEMA = (SELECT DATABASE())
                         AND table_name = 'wvp_gb35114_cert' AND column_name = 'purpose')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD purpose varchar(30) DEFAULT 'ISSUED_DEVICE'
            COMMENT '类型：SERVER_IDENTITY/DEVICE_IDENTITY/ISSUED_DEVICE/TRUSTED_PLATFORM';
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

    -- ---- 证书表新增列 ----
    -- 密码模块 ID：GB 35114—2017 附录 A 表 A.1 第 6 项规定设备证书 CN 为
    -- 「设备ID_密码模块ID」。单列出来是为满足 GB/T 43026—2023 表 4 序号 1
    -- 「设备身份管理」——该检验项要求平台展示「设备 ID、其密码模块 ID 与设备证书
    -- 的对应关系」，只给一个 CN 字符串过不了。存量记录留空，新签发/新导入自动解析。
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'module_id')
    THEN
        ALTER TABLE wvp_gb35114_cert ADD module_id varchar(64)
            COMMENT '密码模块 ID（附录B，22位十进制）；空表示无密码模块';
    END IF;

    -- ---- CA 表新增列 ----
    -- 老库这里补的仍是 purpose，由脚本末尾的迁移段统一改名为 type —— 与证书表同步，
    -- 也让紧随其后的「存量数据归类」能照旧按 purpose 写入。
    -- 新装库建表时就是 type，两个条件都不成立，本段跳过。
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'purpose')
       AND NOT EXISTS (SELECT column_name FROM information_schema.columns
                       WHERE TABLE_SCHEMA = (SELECT DATABASE())
                         AND table_name = 'wvp_gb35114_ca' AND column_name = 'type')
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

    -- CA 表补齐主题 DN 各段，与证书表口径一致：界面上「生成本地根 CA」收的
    -- C/ST/L/O/OU 会真的写进证书并落库，不再出现「DN 里有 C=CN、country 列却是 NULL」。
    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'subject_dn')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD subject_dn varchar(500) COMMENT '完整主题DN（RFC2253）';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'country')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD country varchar(10) COMMENT '国家 C';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'province')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD province varchar(64) COMMENT '省份 ST';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'locality')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD locality varchar(64) COMMENT '城市 L';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'organization')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD organization varchar(255) COMMENT '组织 O';
    END IF;

    IF NOT EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_ca' AND column_name = 'organizational_unit')
    THEN
        ALTER TABLE wvp_gb35114_ca ADD organizational_unit varchar(255) COMMENT '组织单位 OU';
    END IF;

    -- ---- 索引 ----
    -- 建在「当前存在的那一列」上：老库是 purpose（末尾迁移段改名时索引名一并统一），
    -- 新装库是 type。列名动态拼，避免新装库因 purpose 不存在而报错。
    IF NOT EXISTS (SELECT index_name FROM information_schema.statistics
                   WHERE table_schema = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert'
                     AND index_name = 'idx_gb35114_cert_purpose')
       AND NOT EXISTS (SELECT index_name FROM information_schema.statistics
                       WHERE table_schema = (SELECT DATABASE())
                         AND table_name = 'wvp_gb35114_cert'
                         AND index_name = 'idx_gb35114_cert_type')
    THEN
        IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'purpose')
        THEN
            CREATE INDEX idx_gb35114_cert_purpose ON wvp_gb35114_cert (purpose, gb_id);
        ELSE
            CREATE INDEX idx_gb35114_cert_type ON wvp_gb35114_cert (type, gb_id);
        END IF;
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_columns();
DROP PROCEDURE wvp_gb35114_columns;

-- ============================================================================
-- 存量数据归类（启发式，执行后请人工核对各 tab 归类是否正确）
-- 优先级：被级联/设备引用的证书 > 按 type 与是否持有私钥推断
--
-- 整段包在过程里并以「purpose 列还在不在」为闸：本段依赖 purpose（写入目标）与
-- type（整数，推断依据）两列并存，而脚本末尾会把 purpose 改名为 type 并删掉整数
-- type。重跑本脚本时 purpose 已不存在，裸跑这些 UPDATE 会因未知列直接报错 ——
-- 有了这道闸，重复执行安全。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_backfill`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_backfill`()
BEGIN
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_cert' AND column_name = 'purpose')
    THEN
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

        -- 核对清单：启用中的级联平台及其证书引用。
        -- 必须留在本守卫块内：本段运行时 purpose 还在（迁移段在其后），一旦迁移完成，
        -- 重跑时 purpose 已不存在，这句裸放会因未知列报错。
        SELECT p.id, p.name, p.server_gb_id, p.register_way, p.device_cert_id, p.platform_cert_id,
               (SELECT purpose FROM wvp_gb35114_cert c WHERE c.id = p.device_cert_id)   AS device_cert_type,
               (SELECT purpose FROM wvp_gb35114_cert c WHERE c.id = p.platform_cert_id) AS platform_cert_type
          FROM wvp_platform p WHERE p.enable = 1;
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_backfill();
DROP PROCEDURE wvp_gb35114_backfill;

-- ============================================================================
-- 合并 purpose 与整数 type 为单一 type 列。
--
-- 背景：证书表曾同时存在 purpose varchar（四个字符串取值）与 type integer
-- （1-服务器证书/2-设备证书）。后者只是前者的派生投影 —— 全代码库写入点 2 处、
-- 读取点 0 处 —— 而且有损：SERVER_IDENTITY（本平台作 UAS）与 TRUSTED_PLATFORM
-- （上级平台作 UAS）方向相反，却同落成 1。现在一个概念一个名字。
--
-- 位置：必须排在「存量数据归类」之后 —— 那段靠整数 type（1/2）推断用途，改完名
-- 就无从推断了；也必须排在本文件其余所有 type 引用之前。
--
-- 顺序不能反：先 DROP 整数 type 腾出列名，再把 purpose 改名为 type。
-- CA 表同属「这一行是什么」，一并对齐为 type，免得两张证书表用两个名字表达同一概念。
--
-- 幂等：仅在 purpose 还在时执行；重复跑本脚本安全。
-- 新装库没有 purpose（建表时就是 type varchar），本段整体跳过。
-- ============================================================================
DROP PROCEDURE IF EXISTS `wvp_gb35114_merge_type`;
DELIMITER //
CREATE PROCEDURE `wvp_gb35114_merge_type`()
BEGIN
    -- ---- 证书表 ----
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_cert' AND column_name = 'purpose')
    THEN
        -- 先删掉冗余的整数 type，腾出列名
        IF EXISTS (SELECT column_name FROM information_schema.columns
                   WHERE TABLE_SCHEMA = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert' AND column_name = 'type')
        THEN
            ALTER TABLE wvp_gb35114_cert DROP COLUMN type;
        END IF;

        ALTER TABLE wvp_gb35114_cert
            CHANGE COLUMN purpose type varchar(30) DEFAULT 'ISSUED_DEVICE'
            COMMENT '证书类型：SERVER_IDENTITY-服务端证书(本平台) / DEVICE_IDENTITY-客户端证书(本平台) / ISSUED_DEVICE-客户端证书(下级设备) / TRUSTED_PLATFORM-服务端证书(上级平台)';

        -- 索引名里带 purpose，改列名不会改索引名，重建为与新列名一致的名字。
        -- （idx_gb35114_cert_fingerprint 的列引用由 MySQL 自动跟随，名字本身不含
        --  purpose，无需重建。）
        IF EXISTS (SELECT index_name FROM information_schema.statistics
                   WHERE table_schema = (SELECT DATABASE())
                     AND table_name = 'wvp_gb35114_cert'
                     AND index_name = 'idx_gb35114_cert_purpose')
        THEN
            ALTER TABLE wvp_gb35114_cert DROP INDEX idx_gb35114_cert_purpose;
        END IF;
        IF NOT EXISTS (SELECT index_name FROM information_schema.statistics
                       WHERE table_schema = (SELECT DATABASE())
                         AND table_name = 'wvp_gb35114_cert'
                         AND index_name = 'idx_gb35114_cert_type')
        THEN
            CREATE INDEX idx_gb35114_cert_type ON wvp_gb35114_cert (type, gb_id);
        END IF;
    END IF;

    -- ---- CA 表 ----
    IF EXISTS (SELECT column_name FROM information_schema.columns
               WHERE TABLE_SCHEMA = (SELECT DATABASE())
                 AND table_name = 'wvp_gb35114_ca' AND column_name = 'purpose')
       AND NOT EXISTS (SELECT column_name FROM information_schema.columns
                       WHERE TABLE_SCHEMA = (SELECT DATABASE())
                         AND table_name = 'wvp_gb35114_ca' AND column_name = 'type')
    THEN
        ALTER TABLE wvp_gb35114_ca
            CHANGE COLUMN purpose type varchar(20) DEFAULT 'LOCAL_CA'
            COMMENT '类型：LOCAL_CA-本地CA(可签发，全局唯一) / TRUSTED_CA-受信任的CA(仅公钥，可重复导入)';
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_merge_type();
DROP PROCEDURE wvp_gb35114_merge_type;

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
        -- 本段排在迁移段之后，purpose 必已改名为 type，直接用 type 即可。
        CREATE INDEX idx_gb35114_cert_fingerprint
            ON wvp_gb35114_cert (type, key_fingerprint);
    END IF;
END; //
DELIMITER ;
call wvp_gb35114_key_fingerprint();
DROP PROCEDURE wvp_gb35114_key_fingerprint;

-- 存量证书的指纹无法在 SQL 里算（需解析 DER 取 SubjectPublicKeyInfo），
-- 留空即可：新签发/新导入的证书会自动写入。
--
-- 核对：当前服务端证书 —— 按 id 倒序，第一条未吊销的即为签名身份；key_fingerprint
-- 相同的一组表示共用同一密钥对，彼此可互换。本 SELECT 必须排在上面加列的过程之后。
SELECT id, gb_id, subject_cn, serial_number, not_after, key_fingerprint,
       CASE WHEN key_pem IS NULL OR key_pem = '' THEN 0 ELSE 1 END AS has_key
  FROM wvp_gb35114_cert WHERE type = 'SERVER_IDENTITY' ORDER BY id DESC;

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
SELECT id, type, subject_cn, serial_number, not_after
  FROM wvp_gb35114_ca ORDER BY type, id;
