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
**线上实际使用的列（`type` / `subject_dn` / `key_fingerprint` 等）
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
| ③ | **`purpose` → `type` 合并**：先 `DROP` 冗余的整数 `type`（1-服务器 / 2-设备），再把 `purpose` 改名为 `type`，重建两个索引；CA 表的 `purpose` 同步改名。**顺序不可颠倒**，详见下 |
| ④ | `wvp_device` 加 `server_cert_id`；**删除证书表的 `is_default` 列**（服务端证书已由后端强制唯一，不再需要"默认"标记） |
| ⑤ | 证书表加 `key_fingerprint` + 索引 |
| ⑥ | **删除 CA 表的 `name` 列**（CA 别名已废弃，身份改用证书主题 CN） |

> **阶段 ③ 为什么必须排在阶段 ② 之后、其余引用之前**：
> 存量数据的启发式归类（阶段 ②）靠的是整数 `type` 的 `1`/`2` 推断用途，
> 改完名就无从推断；而本文件其余所有段落写列名时用的都已是 `type`。
> 阶段 ③ 自身是幂等的（仅在 `purpose` 还在时执行），新装库建表时就是 `type varchar`，
> 整段跳过。

> **从零部署**：先执行 `初始化-mysql-2.7.4.sql`（或对应数据库的初始化脚本）建好 wvp 全量表，
> 再执行本脚本。
>
> **已有 GB35114 旧版本升级**：直接执行本脚本即可，阶段 ②～⑥ 的 `ALTER` 会补齐新列、
> 完成 `purpose` → `type` 改名；存量证书的类型会被自动推断。

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
  # 用哪张证书不由本文件指定：证书全部存在 wvp_gb35114_cert 表里，运行时按类型从库中解析
  # （服务端证书取唯一的一张；下级接入多个上级时按上级国标编码区分）。
  # 在配置文件里写证书 ID，证书一旦重建（主键自增不回退）就会变成悬空引用，且只在注册时才暴露。
  # [可选] 私钥落地加密的对称密钥（至少 16 字节），生产环境务必修改
  key-encrypt-password: wvp-gb35114-default
  # [可选] 证书默认有效期（天）
  cert-validity-days: 3650
  # [可选] 是否拒绝已过期的证书，默认 false（过期只在页面标出，不拦截注册；已吊销记录始终拒绝）
  reject-expired-cert: false
  # [可选] 本平台作下级（UAC）时是否校验上级证书链，默认 true（校验）
  # 上级证书的签发 CA 必须已导入「CA 证书管理 · 受信任的 CA 证书」，
  # 自签的上级证书要把该证书本身也导入那一栏，否则级联注册被拒。
  # 不校验就置 false —— 只关上级方向；本平台作上级（UAS）时对设备证书的链校验恒开，不受本项控制。
  verify-upstream-cert-chain: true
  # [可选] 是否跳过证书链签名验证，默认 false（验证）。
  # 拿不到 CA 时的逃生口：上级只发一张证书不给 CA、设备证书的 CA 不外流等。
  # 置 true 后不再要求「由已导入的 CA 签发」，但指纹反查、有效期、握手验签都不受影响。
  # 仅在确实拿不到 CA 时使用 —— 会降低对「证书被替换」的防护。
  skip-cert-chain-verify: false
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
| `key-encrypt-password` | `wvp-gb35114-default` | **私钥落地加密密钥，生产环境必须改**。改它不会自动重加密已有私钥 |
| `cert-validity-days` | `3650` | 签发证书时的默认有效期 |
| `reject-expired-cert` | `false` | **过期是否拒绝注册**。默认 false：过期只在页面标出，不拦截；置 true 则按日期硬拒绝 |
| `verify-upstream-cert-chain` | `true` | **本平台作下级（UAC）时是否校验上级证书链**。默认校验：上级证书的签发 CA 必须已导入「CA 证书管理 · 受信任的 CA 证书」（自签的上级证书把它本身导入一份），否则级联注册被拒。置 `false` 即放宽，**只关上级方向**。本平台作上级（UAS）时对设备证书的链校验**恒开**，不受本项影响 |
| `skip-cert-chain-verify` | `false` | **全局跳过证书链签名验证**。拿不到 CA 时的逃生口（见下），两个方向的链校验都受影响。**不影响**指纹反查、有效期、握手 SM2 验签 |
| `sync-delay-ms` | `0` | 设备回 200 OK 后还要解密 cryptkey、装载 VKEK，紧接着到达的查询会被按"密钥未就绪"拒绝（403）。留余量可让设备先完成握手收尾 |
| `note.enabled` | `true` | 关掉后既不加签也不验签，用于判定"对端 4xx 是否由 Note 引起" |
| `note.vkek-form` | `raw` | 标准未规定 VKEK 在摘要里的文本形式，各厂商实现不一。现场可逐项切换二分定位 |

> **`reject-expired-cert` 为什么默认 false**：一张刚过期几小时的证书在协议上仍然可用，
> 按日期硬拒绝会让设备在运维还没反应过来时就被挡在门外，且现场只能翻日志才看得出原因。
> 需要严格合规的部署再置为 `true`。
>
> **已吊销的记录不受此开关影响** —— 命中 `revoked` 即拒绝，任何取值下都是；
> 界面上的「删除」同样绕不过（查不到记录也拒绝）。

> **`verify-upstream-cert-chain` 为什么默认 true**：GB/T 43026—2023 附录 B 表 B.1 里
> 「需验证证书链是否正确」只出现在序号 3/6/7（7.2、7.4 设备身份认证），序号 8/9
> （7.5 上联/下联）的备注列是空的 —— 标准对**平台间**认证没有链校验**要求**。
> 但"没有要求"不等于"应当关掉"：关掉它意味着任意一张证书都能冒充上级，
> 默认从严、需要时显式放宽更符合检测现场的口径。
>
> 放宽的两条路，**优先用前一条**：
>
> | 情形 | 用什么 | 影响面 |
> |---|---|---|
> | 只有上级方向拿不到 CA | 本项置 `false` | 只关上级方向，设备方向照旧恒开 |
> | 上级与设备两个方向都拿不到 CA | `skip-cert-chain-verify: true` | 全局，两个方向一起放行 |
>
> 现场「受信任的 CA」与「上级证书」常常是**同一张自签证书**（上级只发一张，要求下级既当
> 服务端证书导入、又当 CA 导入）。自签证书走的是「受信任的 CA 列表里存在与它同公钥的一条」
> 这条判据，所以**把该证书本身在「受信任的 CA 证书」里也导入一份即可**，不必真去要一张独立 CA。
>
> **本平台作为上级（UAS）时不受本项控制**：对设备证书的链校验恒开 —— 7.4 的
> 「需验证证书链是否正确」是必测项。第三方机构签发给下级设备的证书，把签发它的 CA
> 导入「受信任的 CA 证书」即可通过，**与本项取值无关**。

> **`skip-cert-chain-verify` 为什么需要存在**：现场有一种**无解**的情况 —— CA 根本拿不到。
> 上级只发一张证书、不给签发它的 CA；设备证书由厂商工具签发，CA 不外流；或 CA 已停用/丢失。
> 此时链校验会让设备或级联平台**全部无法接入**，而本平台没有任何办法自行补出那张 CA。
> 本项提供一个显式的全局逃生口。
>
> **它关的是「证书链」，不是「签名」。** 置 `true` 后仍会照常校验：
>
> | 仍然校验 | 说明 |
> |---|---|
> | 设备证书**指纹反查** | 仍要求命中本平台 `ISSUED_DEVICE` 签发记录 |
> | **吊销** | 命中 `revoked` 记录时任何取值下都拒绝 |
> | **有效期** | 是否拒绝另由 `reject-expired-cert` 控制 |
> | 握手 **SM2 验签**（`sign1`/`sign2`） | 协议层身份认证，与「证书由谁签发」是两件事 |
>
> 因此打开后**仍然无法冒充对端** —— 冒充需要对方的私钥。但信任依据退化为
> 「本平台签发记录存在」（设备方向）与「对端自报的证书可直接使用」（上级方向），
> 会降低对「证书被替换」的防护。**仅在确实拿不到 CA 时使用，并记录在案。**

> **配置里没有 `device-cert-id` / `server-cert-id` / `platform-cert-id`**。
> 曾经有过，但那是把数据库主键写死在 yml 里 —— 证书一旦重建（主键自增不回退）
> 配置就指向不存在的行，且只在设备注册时才暴露。现在证书的存在与选择全由数据库承担：
>
> | 角色 | 解析规则 |
> |---|---|
> | 服务端证书（本平台）·UAS 签 `sign2` | 后端强制**唯一**（见 usage.md §2.2），未绑定设备的设备直接用这一张 |
> | 客户端证书（本平台）·UAC 签 `sign1` | 不唯一（可接入多个上级）。按 `wvp_platform.device_cert_id` 绑定；未绑定时按上级国标编码匹配证书的 `gb_id`，只有一张则用它，多张则**拒绝猜测** |
> | 服务端证书（上级平台）·UAC 验 `sign2` | 同上，对应 `wvp_platform.platform_cert_id` |
> | 设备信任的服务端证书 | 按 `wvp_device.server_cert_id` 绑定；未绑定则用平台唯一的那张 |
>
> 多上级场景**务必在级联编辑页逐条绑定**，不要依赖兜底。

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
WVP_GB35114_KEY_PWD
WVP_GB35114_CERT_VALIDITY_DAYS
WVP_GB35114_REJECT_EXPIRED_CERT
```

> Docker 版里 `gb35114:` 段同样不含证书 ID —— 证书全部从数据库解析，
> 环境变量 `WVP_GB35114_*_CERT_ID` 也已随之取消。

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
> （实测无效，pom 里的配置优先）。改 pom 也不推荐（会污染提交）；
> 实际做法是绕过 surefire，用 JUnit Platform 启动器直接选类跑：
>
> ```bash
> # 一次性编译出启动器与依赖清单（/tmp/wvptest/cp.txt 是 mvn dependency:build-classpath 的产物）
> CLASSES=$(cd target/test-classes && find . -path "*gb35114*" -name "*Test.class" \
>   ! -name "*\$*" | sed 's|^\./||; s|\.class$||; s|/|.|g' | sort | tr '\n' ' ')
> java -cp "/tmp/wvptest:$(cat /tmp/wvptest/cp.txt)" RunTests ${=CLASSES}
> ```
>
> ⚠️ 当前 shell 是 **zsh**，不会对未加引号的变量做分词，必须写 `${=CLASSES}`；
> 写成 `$CLASSES` 会把 19 个类名当成一个类名，报 `ClassNotFoundException`。
> 另外 `RunTests` 不传参时发现 0 个用例（只按参数选类，不做包扫描），
> 且 `mvn clean package` 会清掉 `target/test-classes`，打包后要重新 `mvn -o test-compile`。

19 个测试类共 162 个用例，覆盖：证书密钥复用（`Gb35114CertUtilKeyReuseTest`）、
SIP 头构造与解析（`Gb35114HeaderUtilTest`）、401 挑战头 golden 值
（`Gb35114ChallengeGoldenTest`）、SM2/SM3/VKEK 封装（`Gb35114SmCryptoTest`）、
UAS/UAC 握手状态机（`Gb35114StateMachineTest`）、签发者反查
（`Gb35114IssuerResolveTest` / `Gb35114IssuerResolveServiceTest`）、
证书链校验（`Gb35114CertChainTest` / `Gb35114CertChainServiceTest`）、
设备证书 CN 格式（`Gb35114DeviceCnServiceTest`）、CA 主题 DN 落库
（`Gb35114CaSubjectServiceTest`）、删除证书的引用守卫
（`Gb35114CertReferenceGuardTest`）、链校验跳过与签发者 DN 快速映射
（`Gb35114CertChainSkipAndDnNarrowTest`）、UAC/UAS 外壳与回环
（`Gb35114UacChainHookTest` / `Gb35114UacLoopbackTest` / `Gb35114UasLoopbackTest`）、
CA 管理（`Gb35114CaManagementTest`）、服务端证书的 CSR 路径
（`Gb35114ServerCsrServiceTest`）、受信任 CA 签发的设备证书
（`Gb35114TrustedCaDeviceCertTest`）。

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
