<!-- GB35114 安装说明 -->

# GB35114 安装说明

本文覆盖：数据库迁移、配置、编译打包、部署、升级与回退。

> 逐步的证书签发与接入操作见 [使用说明](usage.md)，设计取舍见 [设计说明](design.md)。

---

## 一、环境要求

| 项 | 要求 |
|---|---|
| JDK | 21 及以上（与 wvp-GB28181-pro 2.7.4 基线一致） |
| 数据库 | MySQL 5.7+ / PostgreSQL / KingbaseES / 达梦 DM8 |
| Redis | 6+ |
| 前端构建 | Node.js 16+ 与 npm |

新增的第三方依赖只有一个：`org.bouncycastle:bcprov-jdk18on:1.78.1`（已在 `pom.xml` 中声明）。
`bcpkix-jdk18on` 基线已有，两者配合完成 SM2/SM3 与证书构造。

---

## 二、数据库迁移

### 2.1 三个脚本，按数据库选一个

| 数据库 | 脚本 |
|---|---|
| MySQL | `数据库/2.7.4/更新-gb35114-mysql.sql` |
| PostgreSQL / KingbaseES | `数据库/2.7.4/更新-gb35114-postgresql-kingbase.sql` |
| 达梦 DM8 | `数据库/2.7.4/更新-gb35114-达梦.sql` |

### 2.2 ⚠️ 这是**分阶段幂等迁移脚本**，不是一次性建表脚本

脚本开头的 `CREATE TABLE IF NOT EXISTS` 只覆盖最初的表形态，
**线上实际使用的列（`purpose` / `subject_dn` / `is_default` / `key_fingerprint` 等）
是后续若干段存储过程通过 `ALTER TABLE ... ADD` 补上的**。

因此：

- **必须整份执行**，不能只跑开头那段建表语句 —— 只跑建表会得到一张缺列的表，
  应用启动后会在写证书时报"未知列"；
- **可以重复执行**。每段 DDL 前都用 `information_schema`（达梦用 `SYSOBJECTS` /
  `USER_TAB_COLUMNS`）判过列是否存在，已有则跳过；
- 脚本末尾有几段核对 `SELECT`，用于人工确认列齐了。

脚本内的阶段划分：

| 阶段 | 内容 |
|---|---|
| ① | 建 `wvp_gb35114_ca` / `wvp_gb35114_cert` 基础表；`wvp_device` 加 `register_way` / `cert_id`；`wvp_platform` 加 `device_cert_id` / `platform_cert_id` |
| ② | 证书表加 `purpose` / `subject_dn` / DN 各段 / `csr_pem` / `remark` / `validity_days` / `key_usage`；CA 表加 `purpose` / `remark`；建索引 `idx_gb35114_cert_purpose`；**存量数据启发式归类**（按已有列推断 `purpose`） |
| ③ | 证书表加 `is_default`；`wvp_device` 加 `server_cert_id`；初始化默认服务端证书 |
| ④ | 证书表加 `key_fingerprint` + 索引 |
| ⑤ | **删除 CA 表的 `name` 列**（CA 别名已废弃，身份改用证书主题 CN） |

> **从零部署**：先执行 `初始化-mysql-2.7.4.sql`（或对应数据库的初始化脚本）建好 wvp 全量表，
> 再执行本脚本。
>
> **已有 GB35114 旧版本升级**：直接执行本脚本即可，阶段 ②③④ 的 `ALTER` 会补齐新列，
> 存量证书的 `purpose` 会被自动推断。

### 2.3 执行

```bash
mysql -h127.0.0.1 -P3306 -uroot -p -D wvp < 数据库/2.7.4/更新-gb35114-mysql.sql
```

达梦用 `disql`，KingbaseES 用 `ksql`，PostgreSQL 用 `psql`。

---

## 三、配置

### 3.1 `gb35114:` 配置段

```yaml
gb35114:
  # [可选] 国密总开关，默认 false（关闭不影响原有 GB28181 Digest 注册）
  enabled: false
  # [可选] 本平台作为下级向上级平台注册时使用的设备证书ID（关联 wvp_gb35114_cert.id）
  # 为空时无法进行 UAC 侧国密注册（向上级注册仍走 Digest）
  # device-cert-id:
  # [可选] 本平台作为平台（UAS）使用的服务器证书ID，配置后注册方式为双向（Bidirection）
  # server-cert-id:
  # [可选] 本平台受信的上级平台证书ID（UAC 侧验 sign2，双向时使用）
  # platform-cert-id:
  # [可选] 私钥落地加密的对称密钥（至少 16 字节），生产环境务必修改
  key-encrypt-password: wvp-gb35114-default
  # [可选] 证书默认有效期（天）
  cert-validity-days: 3650
  # [可选] 是否拒绝已过期的证书，默认 false（过期只在页面标出，不拦截注册；吊销始终拒绝）
  reject-expired-cert: false
  # [可选] 目录同步前等待的毫秒数，规避国密握手与查询之间的时序竞争，0 表示不等待
  # sync-delay-ms: 0
  # [可选] 控制信令 Note 认证参数
  # note:
  #   # 是否启用 Note 加签/验签；关闭后既不给对端加 Note，也不校验对端的 Note
  #   enabled: true
  #   # VKEK 参与摘要时的拼接形式：raw（16 字节原文）/ base64 / hex
  #   vkek-form: raw
```

逐项说明：

| 配置项 | 默认 | 说明 |
|---|---|---|
| `enabled` | `false` | 国密总开关。**关闭时整套 GB35114 逻辑短路**，不影响原有 Digest 注册 |
| `device-cert-id` | 空 | UAC 侧签 `sign1` 用的本地客户端证书。为空时向上级注册走 Digest |
| `server-cert-id` | 空 | UAS 侧签 `sign2` 用的本地服务端证书。不配则取证书表中 `is_default=1` 的那张 |
| `platform-cert-id` | 空 | UAC 侧验 `sign2` 用的上级服务端证书 |
| `key-encrypt-password` | `wvp-gb35114-default` | **私钥落地加密密钥，生产环境必须改**。改它不会自动重加密已有私钥 |
| `cert-validity-days` | `3650` | 签发证书时的默认有效期 |
| `reject-expired-cert` | `false` | **过期是否拒绝注册**。默认 false：过期只在页面标出，不拦截；置 true 则按日期硬拒绝 |
| `sync-delay-ms` | `0` | 设备回 200 OK 后还要解密 cryptkey、装载 VKEK，紧接着到达的查询会被按"密钥未就绪"拒绝（403）。留余量可让设备先完成握手收尾 |
| `note.enabled` | `true` | 关掉后既不加签也不验签，用于判定"对端 4xx 是否由 Note 引起" |
| `note.vkek-form` | `raw` | 标准未规定 VKEK 在摘要里的文本形式，各厂商实现不一。现场可逐项切换二分定位 |

> **`reject-expired-cert` 为什么默认 false**：A 级握手不校验证书链与有效期，
> 一张刚过期几小时的证书在协议上仍然可用。按日期硬拒绝会让设备在运维还没反应过来时
> 就被挡在门外，且现场只能翻日志才看得出原因。需要严格合规的部署再置为 `true`。
>
> **吊销不受此开关影响** —— 任何取值下都拒绝。

> **`device-cert-id` / `server-cert-id` / `platform-cert-id` 是"全局兜底"**：
> 级联可各自在编辑页绑定（`wvp_platform.device_cert_id` / `platform_cert_id`），
> 设备可绑定信任的服务端证书（`wvp_device.server_cert_id`）。
> 优先级：**设备级绑定 > 全局配置 > 证书表默认证书**。
> 多上级场景建议在级联编辑页逐条绑定，不要只依赖全局配置。

### 3.2 三处配置文件都要同步

`gb35114:` 段出现在三个文件里，**部署时用的是哪一个就改哪一个**：

| 文件 | 用途 |
|---|---|
| `src/main/resources/application-dev.yml` | 源码直跑 / 本地开发 |
| `src/main/resources/application-docker.yml` | Docker 部署（值是环境变量占位符） |
| `src/main/resources/配置详情.yml` | 配置项说明文档（不生效，但需保持同步） |

> 注意：`.gitignore` 里有 `src/main/resources/application-*.yml` 这条规则，但这三个文件
> **在规则加入之前就已被 git 跟踪**，因此规则对它们不生效，改动会正常进 patch。
> 合并到别的仓库时若报"文件被忽略"，用 `git add -f` 强制加入。

> 另：`src/main/resources/static/`（前端构建产物）**确实**被忽略，不在版本库里，
> 每次打包都要重新构建前端（见 §4.1）。

Docker 版的环境变量名：

```
WVP_GB35114_ENABLED
WVP_GB35114_DEVICE_CERT_ID
WVP_GB35114_SERVER_CERT_ID
WVP_GB35114_PLATFORM_CERT_ID
WVP_GB35114_KEY_PWD
WVP_GB35114_CERT_VALIDITY_DAYS
WVP_GB35114_REJECT_EXPIRED_CERT
```

> Docker 版里 `device-cert-id` 等三项默认注释掉：空字符串绑定 `Integer` 会失败。
> 需要时取消注释并填入 `wvp_gb35114_cert.id`。

---

## 四、编译打包

### 4.1 前端

前端产物要打进 jar 的 `src/main/resources/static/`，**先构建前端**：

```bash
cd web
npm install          # 首次
npx vue-cli-service build      # 或 npm run build:prod
```

产物落到 `src/main/resources/static/`。

> 该目录在 `.gitignore` 中，不进版本库 —— 每次打包都要重新构建前端。

### 4.2 后端

```bash
export JAVA_HOME=<JDK21+ 路径>
mvn -o -q -DskipTests package
```

产物：`target/wvp-pro-2.7.4-<时间戳>.jar`（已内嵌前端静态资源）。

> 首次打包若本地仓库缺 `bcprov-jdk18on:1.78.1`，去掉 `-o` 联网拉一次。

### 4.3 单元测试

```bash
mvn -o test -Dtest='Gb35114*'
```

> ⚠️ `pom.xml` 里 `maven-surefire-plugin` 配了 `<skipTests>true</skipTests>`，
> 上面这条命令**不会真的跑测试** —— 它只打印 `BUILD SUCCESS`，不产生
> `target/surefire-reports/`。命令行加 `-DskipTests=false` **也覆盖不了**
> （实测无效，pom 里的配置优先）。
> 要真跑，临时把那一行改成 `<skipTests>false</skipTests>`，跑完改回来；
> 或者直接跑 `mvn -o surefire:test -Dtest='Gb35114*'` 前先确认报告目录里确实出现了
> `Tests run:` 行 —— 没出现就是没跑。

6 个测试类共 34 个用例，覆盖：证书密钥复用（`Gb35114CertUtilKeyReuseTest`）、
SIP 头构造与解析（`Gb35114HeaderUtilTest`）、401 挑战头 golden 值
（`Gb35114ChallengeGoldenTest`）、SM2/SM3/VKEK 封装（`Gb35114SmCryptoTest`）、
UAS/UAC 握手状态机（`Gb35114StateMachineTest`）、签发者反查
（`Gb35114IssuerResolveTest`）。

---

## 五、部署

### 5.1 ⚠️ 关键陷阱：CentOS 7（内核 3.10）上容器内 JVM 无法启动

`eclipse-temurin:21-jre` / `openjdk:21-jre-slim` 等镜像在 **CentOS 7（内核 3.10.0）** 上
运行 `java -version` 即报错：

```
Failed to start thread "GC Thread#0" - pthread_create failed (EPERM)
```

根因：新版 JDK 容器镜像的 glibc / JVM 与 CentOS 7 旧内核不兼容。

**解决：wvp 进程用宿主机 JDK 直接运行 jar**，MySQL / Redis 仍走容器。
`docker/gb35114-deploy/` 目录下的脚手架就是按这个混合模式搭的。

如果你的服务器内核较新（4.x+），可以忽略这一节，用 `docker-compose.yml` 里的
`wvp-gb35114` 服务直接起容器。

### 5.2 目录结构（混合模式示例）

```
/opt/wvp-gb35114/
├── wvp.jar                      # mvn package 产物（含前端 static）
├── docker-compose.yml           # 编排 mysql + redis（+ wvp 容器备选）
├── config/
│   ├── application-host.yml     # 宿主机直跑配置（实际生效）
│   └── application.yml          # 容器内网络配置（备用）
├── mysql/
│   ├── 01-init.sql              # wvp 2.7.4 全量建表
│   ├── 02-gb35114.sql           # GB35114 迁移脚本
│   └── data/                    # MySQL 数据卷
├── redis/data/                  # Redis 数据卷
└── logs/                        # 运行日志
```

### 5.3 步骤

```bash
# 1. 传输 jar 与 SQL
scp target/wvp-pro-2.7.4-*.jar root@<服务器>:/opt/wvp-gb35114/wvp.jar
scp 数据库/2.7.4/初始化-mysql-2.7.4.sql   root@<服务器>:/opt/wvp-gb35114/mysql/01-init.sql
scp 数据库/2.7.4/更新-gb35114-mysql.sql   root@<服务器>:/opt/wvp-gb35114/mysql/02-gb35114.sql

# 2. 启动 mysql / redis 容器（首次会自动执行 01/02 初始化 SQL）
cd /opt/wvp-gb35114
docker compose up -d wvp-gb35114-mysql wvp-gb35114-redis

# 3. 宿主机 JDK 直跑 wvp
export JAVA_HOME=/usr/lib/jvm/jdk-21-oracle-x64
nohup $JAVA_HOME/bin/java -Xms512m -Xmx1024m \
  -jar /opt/wvp-gb35114/wvp.jar \
  --spring.config.location=/opt/wvp-gb35114/config/application-host.yml \
  > /opt/wvp-gb35114/logs/wvp-host.log 2>&1 &
```

> `docker/gb35114-deploy/deploy.sh` 把上述步骤串成了脚本，可按需修改服务器地址后使用。
>
> `docker-entrypoint-initdb.d` 只在**数据卷为空时**执行一次。已经初始化过的库
> 要手工再跑一次 `02-gb35114.sql`（脚本幂等，重复执行安全）。

### 5.4 端口分配（示例）

| 服务 | 端口 | 说明 |
|---|---|---|
| wvp HTTP | 18978 | web 界面 + REST API |
| wvp SIP | 5060/tcp+udp | GB28181 信令 |
| MySQL（容器） | 13306 → 3306 | 避开宿主机已有的 3306 |
| Redis（容器） | 16379 → 6379 | 避开宿主机已有的 6379 |

### 5.5 外置配置的必填项

`application-host.yml` 里以下几项缺失会导致启动失败：

- `media.id` / `media.ip` / `media.secret`
- `media.rtp.enable` / `media.rtp.port-range` / `media.rtp.send-port-range`
  （`MediaConfig` 用 `@Value` 硬编码占位符，缺一个都 `PlaceholderResolutionException`）
- `sip.id`（**平台国标编码**，国密握手里的 `serverid` 取的就是它，不是 `user-settings.server-id`）

### 5.6 首次登录必须改密码

admin 默认密码 `21232f297a57a5a743894a0e4a801fc3`（`md5("admin")`）。
`wvp_user.default_password=true` 时，过滤器只放行 `/api/user/changePassword`
与 `/api/user/logout`，其余接口一律 403。**必须先改密码再测试业务接口。**

新密码需满足复杂度：10 位以上 + 大小写 + 数字 + 特殊符号。

### 5.7 验证启动

```bash
grep -E 'Started VManageBootstrap|APPLICATION FAILED' logs/wvp-host.log | tail -3
curl http://127.0.0.1:18978/                # HTTP 200
```

启动后日志里应能看到 UAS 状态机初始化：

```
[GB35114] UAS 状态机已初始化，serverid=35020000002000000001，模式=Bidirection，服务器证书=#20
[GB35114] Note 认证参数：enabled=true，VKEK 拼接形式=raw
```

---

## 六、升级与回退

### 6.1 从 Digest 版升级到国密版

1. 执行数据库迁移脚本（幂等，已有列自动跳过）；
2. 部署新 jar；
3. `gb35114.enabled: true`，重启；
4. 按 [使用说明](usage.md) 签发/导入证书，回填配置；
5. 逐台设备切换注册方式（**可以逐台灰度**：国密注册分支是靠请求头的
   `Authorization` scheme 识别的，未切换的设备仍走 Digest）。

> `enabled: false` 时整套逻辑短路，因此**先部署、后开开关**是安全的升级顺序。

### 6.2 回退

1. `gb35114.enabled: false` 重启 —— 设备/级联立即回到 Digest 流程，
   数据库里多出的列和表不影响原有功能（全部是可空新增列）；
2. 如需彻底回退，删除 `wvp_gb35114_ca` / `wvp_gb35114_cert` 两张表，
   并删除 `wvp_device` 的 `register_way` / `cert_id` / `server_cert_id`
   与 `wvp_platform` 的 `device_cert_id` / `platform_cert_id` 五列。

> 回退**不会**自动把设备的 `register_way` 改回 1。如果设备侧已经切换到证书注册，
> 单靠平台回退会注册不上 —— 需要设备侧同步切回摘要认证。

### 6.3 与后续 wvp 版本合并

见 [补丁与合并说明](patch.md)。

---

## 七、常见启动/配置问题

| 现象 | 原因与处理 |
|---|---|
| `PlaceholderResolutionException` | `media.rtp.*` 等必填项缺失，见 §5.5 |
| 容器内 JVM `pthread_create failed (EPERM)` | CentOS 7 旧内核，见 §5.1，改宿主机 JDK 直跑 |
| 接口一律 403，只有 `changePassword` / `logout` 能通 | 首次登录未改密码，见 §5.6 |
| 证书表写入报"未知列" | 数据库迁移脚本没跑完整（只跑了建表段），见 §2.2 |
| 改了 `key-encrypt-password` 后读不出旧私钥 | 该密钥用于加解密落地私钥，**改它不会自动重加密已有记录**。改回原值，或用界面重新签发 |
