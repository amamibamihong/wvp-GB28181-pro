# GB35114 A 级 部署说明（docker / 宿主机混合）

## 部署目标

将 GB35114 A 级国密改造（证书管理 + 证书注册认证 + 信令 Note 认证）部署到测试服务器上验证。

## 0. 先准备口令（.env）

`config/*.yml` 与 `docker-compose.yml` 里**不含任何口令**，全是 `${VAR}` 占位符：

```bash
cp .env.example .env
vi .env          # 填 WVP_SERVER / MYSQL_ROOT_PASSWORD / WVP_PWD / WVP_GB35114_KEY_PWD / ...
```

`.env` 已被 `.gitignore` 忽略，不会进版本库。口令只在这一处维护 ——
compose（建库）与应用连库用的是同一个 `MYSQL_ROOT_PASSWORD`，不会出现
「容器口令改了、应用还在用旧口令」这种只在启动时才暴露的错配。

> `WVP_GB35114_KEY_PWD` 是**私钥落地加密密钥**。改它不会自动重加密已存私钥，
> 改后旧的证书私钥读不出来，需重新签发。生产部署务必换成自己的值。

## 服务器环境

- 架构：x86_64（CentOS 7，内核 3.10.0）
- 已安装：Docker 26.1.4 + Docker Compose v2.27.1
- 宿主机 **Oracle JDK 21**：`/usr/lib/jvm/jdk-21-oracle-x64`
- 已有镜像：`mysql:8.0.32`、`redis:7-alpine`

## ⚠️ 关键陷阱：容器内 JVM 无法启动（内核 3.10）

`eclipse-temurin:21-jre` / `openjdk:21-jre-slim` 等镜像在此宿主机（内核 3.10.0）上运行
`java -version` 即报错：

```
Failed to start thread "GC Thread#0" - pthread_create failed (EPERM)
```

根因：新版 JDK 容器镜像的 glibc / JVM 与 CentOS 7 旧内核不兼容。

**解决**：wvp 进程改用**宿主机 Oracle JDK 21 直接运行 jar**，数据库 / Redis 仍走容器。

## 部署目录结构（服务器 `/opt/wvp-gb35114/`）

```
/opt/wvp-gb35114/
├── wvp.jar                          # 本地 mvn package 产物（含前端 static）
├── Dockerfile                       # 备用：eclipse-temurin:21-jre 方案（旧内核不可用）
├── docker-compose.yml               # 编排 mysql + redis（+ wvp 备选）
├── config/
│   ├── application-host.yml         # 宿主机直跑配置（实际生效）
│   └── application.yml              # 容器内网络配置（备用）
├── mysql/
│   ├── 01-init.sql                  # wvp 2.7.4 全量建表，含 GB35114 两表与 tds_bypass
│   └── data/                        # MySQL 数据卷
├── redis/data/                      # Redis 数据卷
└── logs/                            # 运行日志
```

## 部署步骤

### 1. 本地打包

```bash
cd wvp-GB28181-pro
# 前端已构建进 resources/static
export JAVA_HOME=<JDK25>
mvn -o clean package   # 产出 target/wvp-pro-2.7.4-*.jar
```

### 2. 传输到服务器

```bash
cp .env.example .env && vi .env     # 填 <部署服务器> 的地址与各口令
./deploy.sh                          # 串起传输 + 起容器 + 宿主机直跑 wvp + 验证
```

或手工逐步：

```bash
scp target/wvp-pro-2.7.4-*.jar root@<部署服务器>:/opt/wvp-gb35114/wvp.jar
scp 数据库/2.7.4/初始化-mysql-2.7.4.sql root@<部署服务器>:/opt/wvp-gb35114/mysql/01-init.sql
scp docker/gb35114-deploy/.env root@<部署服务器>:/opt/wvp-gb35114/.env
```

> 注：`01-init.sql` 已含 GB35114 两张表、`wvp_device`/`wvp_platform` 的证书关联列以及
> `tds_bypass`，新部署只执行它即可。`数据库/2.7.4/更新-*.sql` 只在**老库升级**时手工执行，
> 不放进 `initdb.d`。

### 3. 启动 mysql / redis 容器

```bash
cd /opt/wvp-gb35114
docker compose up -d wvp-gb35114-mysql wvp-gb35114-redis
# 等待 mysql healthy（会自动执行 01-init.sql）
```

### 4. 宿主机 JDK 直跑 wvp

外置配置里全是 `${VAR}` 占位符，**必须先 source .env 再启动**，否则 Spring 会以
`PlaceholderResolutionException` 启动失败：

```bash
cd /opt/wvp-gb35114
set -a && . ./.env && set +a
export JAVA_HOME=/usr/lib/jvm/jdk-21-oracle-x64
nohup $JAVA_HOME/bin/java -Xms512m -Xmx1024m \
  -jar /opt/wvp-gb35114/wvp.jar \
  --spring.config.location=/opt/wvp-gb35114/config/application-host.yml \
  > /opt/wvp-gb35114/logs/wvp-host.log 2>&1 &
```

### 5. 验证

```bash
# 首页
curl http://127.0.0.1:18978/          # HTTP 200

# 登录（password 为 32 位 md5）
curl "http://127.0.0.1:18978/api/user/login?username=admin&password=<md5>"

# 首次登录需先改默认密码（复杂度要求 10 位 + 大小写 + 数字 + 特殊符号）
curl -X POST ".../api/user/changePassword" -H "access-token: $TOKEN" \
  --data-urlencode "oldPassword=<旧md5>" --data-urlencode "password=<新密码>"

# 生成根 CA（CA 没有独立的名称字段，其身份即证书主题 CN）
curl -X POST ".../api/gb35114/cert/ca/generate?subjectCn=GB35114-Root-CA" -H "access-token: $TOKEN"
```

## 端口分配

| 服务 | 端口 | 说明 |
|---|---|---|
| wvp HTTP | 18978 | web 界面 + REST API |
| wvp SIP | 5060/tcp+udp | GB28181 信令 |
| MySQL（容器） | 13306 → 3306 | 避开宿主机 mariadb 3306 |
| Redis（容器） | 16379 → 6379 | 避开宿主 6379 |

## 已知默认密码强制修改逻辑

admin 默认密码 `21232f297a57a5a743894a0e4a801fc3`（md5("admin")）。
`wvp_user.default_password=true` 时，过滤器只放行 `/api/user/changePassword`
与 `/api/user/logout`，其余接口一律 403。必须先改密码再测试业务接口。

## 配置要点

外置配置 `application-host.yml` 必填项（否则启动失败）：

- `media.id` / `media.ip` / `media.secret`
- `media.rtp.enable` / `media.rtp.port-range` / `media.rtp.send-port-range`
  （`MediaConfig` 用 `@Value` 硬编码占位符，缺一个都 `PlaceholderResolutionException`）
- `gb35114.enabled=true` 开启国密；证书 ID 在 web 界面签发后回填
