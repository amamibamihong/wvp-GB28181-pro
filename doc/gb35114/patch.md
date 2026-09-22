<!-- GB35114 补丁与合并说明 -->

# 补丁与合并说明

本目录下的 **`gb35114.patch`** 是 GB35114 A 级改造的完整补丁，用于：

- 在后续 wvp-GB28181-pro 版本升级后**重新合并**这份改造；
- 把改造**移植到其它 wvp 版本或衍生分支**。

> 安装部署见 [安装说明](install.md)，设计取舍见 [设计说明](design.md)，
> 使用操作见 [使用说明](usage.md)。

---

## 一、补丁基线

| 项 | 值 |
|---|---|
| 基线 commit | `fb45787da01cb4f33a0b1dfaa613becf67391c17` |
| 基线日期 | 2026-08-29 |
| 基线说明 | `Merge pull request #2220 from xiaoQQya/fix/heartbeat` |
| 版本 | wvp-GB28181-pro 2.7.4 |
| 补丁规模 | 65 个文件，其中 **42 个新增文件**（约 1.15 万行新增，37 行删除） |

> 行数随文档修订小幅浮动；**文件数（60 个业务文件 + 5 个文档文件）是稳定的**。

**这份补丁是在上述 commit 的工作区上 `git diff --cached --binary HEAD` 得到的**，
即补丁的相对路径与仓库根目录一致，用 `git apply -p1`（默认）即可。

> 补丁以仓库根目录为基准，**路径带中文**（`数据库/2.7.4/...`、`src/main/resources/配置详情.yml`）。
> Windows 上应用时建议先 `git config core.quotepath false`，避免路径转义带来的困扰。
>
> `gb35114.patch` **自身不在补丁内容里**（生成时用 `:(exclude)doc/gb35114/gb35114.patch` 排除），
> 可以放心重复生成、重复应用。
>
> **已实测**：在基线 `fb45787` 的干净检出上 `git apply --check` 通过，无冲突。

---

## 二、应用补丁

### 2.1 在**同一个基线**上应用

```bash
cd wvp-GB28181-pro
git checkout fb45787da01cb4f33a0b1dfaa613becf67391c17

# 先干跑，确认无冲突
git apply --check gb35114.patch

git apply gb35114.patch
```

或者保留提交历史：

```bash
git checkout -b gb35114 fb45787da01cb4f33a0b1dfaa613becf67391c17
git apply gb35114.patch
git add -A
git commit -m "feat(gb35114): GB35114 A 级国密接入与级联"
```

### 2.2 在**更新的 wvp 版本**上应用

新版本上大概率有冲突，用三方合并更省事：

```bash
git checkout -b gb35114-merge <新版本分支>
git apply --3way gb35114.patch
# 逐个解决冲突
git status
git add -A && git commit
```

`--3way` 需要补丁里记录了 blob 哈希（本补丁由 `git diff` 生成，已包含），
它会在冲突时把原始版本、当前版本、补丁版本三方合并，比直接 `git apply` 精确得多。

### 2.3 只想看补丁动了什么

```bash
git apply --stat gb35114.patch      # 文件级统计
git apply --numstat gb35114.patch   # 增删行数
```

---

## 三、冲突高发文件与处理

按经验，升级后冲突集中在**改动密集的既有文件**上。这些文件的改动**逻辑上互相独立**，
逐块取舍即可：

| 文件 | 本补丁的改动 | 冲突处理 |
|---|---|---|
| `gb28181/transmit/SIPSender.java` | `transmitRequest` 开头加一行 `gb35114NoteIntegrator.decorateOutgoing(message);` + 一个 `@Autowired` 字段 | **必须保留**。这是出站加签的唯一接入点，丢了会导致点播被设备回 403 |
| `gb28181/transmit/SIPProcessorObserver.java` | `processRequest` 开头加 Note 验签 + 回 403 分支 | **必须保留**。入站验签唯一接入点 |
| `gb28181/transmit/event/request/impl/RegisterRequestProcessor.java` | `registerHandler` 开头加国密分支判定，文件末尾加 `gb35114RegisterHandler` 等方法 | **必须保留**。若上游重构了注册流程，把 `gb35114RegisterHandler` 整体挪到新的注册入口即可，它是自包含的 |
| `gb28181/transmit/event/response/impl/RegisterResponseProcessor.java` | UAC 侧处理 401 挑战、校验 200 的 SecurityInfo + Caffeine 限流 | 同上，整体搬移 |
| `gb28181/service/impl/PlatformServiceImpl.java` | `startupUnregisterFinished` 标志 + `try/finally` 串行化 | **建议保留**（修的是启动期并发缺陷，对普通 GB28181 也是净收益） |
| `gb28181/bean/GBStringMsgParser.java` | 无 listener 分支加 `message.addUnparsed(header)` | **必须保留**。丢了会导致 Note 验签拿不到 `Date` |
| `gov/nist/javax/sip/stack/CustomNioTcpMessageProcessor.java` | 覆写 `send(SocketChannel, byte[])` + `ensureChannelCached`；**撤掉**原有的两个 `createMessageChannel` 覆写 | **必须保留**。若上游也改了这里，以"不覆写 `createMessageChannel`、只覆写 `send`"为原则合并 |
| `gb28181/bean/Device.java` / `Platform.java` | 各加 2~3 个字段 | 纯新增，几乎不冲突 |
| `gb28181/dao/DeviceMapper.java` / `PlatformMapper.java` | 增列的进出 SQL | 若上游改了这些 SQL，按"保留新列"合并 |
| `pom.xml` | 新增 `bcprov-jdk18on` 依赖 | 纯新增 |

**新增文件不会冲突**（除非新版本里恰好有同名文件）：

- `src/main/java/com/genersoft/iot/vmp/gb35114/**`（21 个文件）
- `src/test/java/com/genersoft/iot/vmp/gb35114/**`（6 个文件）
- `web/src/api/gb35114.js`、`web/src/views/gb35114/index.vue`
- `数据库/2.7.4/更新-gb35114-*.sql`（3 个）
- `docker/gb35114-deploy/**`

---

## 四、合并后必须检查的几件事

### 4.1 三个接入点还在不在

补丁能干净应用，**不代表功能完整** —— 如果新版本重构了发送/接收链路，
`git apply` 可能把改动应用到了一个已经不被调用的旧方法上。合并后**逐一确认**：

1. **出站加签**：`SIPSender` 里所有真正发信令的路径最终都经过 `transmitRequest`。
   若新版本新增了绕过它的发送方法，需要在那些地方也调用 `decorateOutgoing`。
2. **入站验签**：`SIPProcessorObserver.processRequest` 仍是所有入站请求的唯一入口。
3. **原始头保留**：`GBStringMsgParser` 的 `addUnparsed` 仍在**实际使用的**解析路径上
   （NIO 走 `NioPipelineParser`，listener 为 null 的那条分支）。

### 4.2 配置段要手工补

`gb35114:` 段出现在三个文件里，**补丁会带上它们，但要确认新版本没把配置结构改掉**：

| 文件 | 说明 |
|---|---|
| `src/main/resources/application-dev.yml` | 源码直跑 |
| `src/main/resources/application-docker.yml` | Docker（环境变量占位符形式） |
| `src/main/resources/配置详情.yml` | 配置项说明文档 |

> 这三个文件虽然匹配 `.gitignore` 里的 `src/main/resources/application-*.yml`，
> 但它们在规则加入之前就已被 git 跟踪，规则对它们不生效 —— 补丁会正常带上改动。
> 若在别的仓库里 `git apply` 报"文件被忽略"，用 `git add -f` 强制加入。

完整配置项清单见 [安装说明 §3.1](install.md#31-gb35114-配置段)。

### 4.3 数据库迁移脚本

`数据库/2.7.4/更新-gb35114-*.sql` 三个脚本是**分阶段幂等迁移**，
不是一次性建表脚本（详见 [安装说明 §2.2](install.md#22-️-这是分阶段幂等迁移脚本不是一次性建表脚本)）。

如果合并到的 wvp 版本数据库结构变了，**需要同步调整脚本里阶段 ① 的基础建表段**，
但阶段 ②③④ 的 `ALTER` 逻辑（判列后加）可以照用。

### 4.4 前端

`web/src/views/gb35114/index.vue` 是独立页面，只依赖：

- `web/src/api/gb35114.js`（自包含）
- `web/src/router/index.js` 里的一条路由（补丁会加）

如果新版本换了 UI 框架或路由写法，需要改的是**路由那一条**，页面本身可以整体搬运。

### 4.5 编译验证

```bash
cd web && npx vue-cli-service build     # 前端产物进 src/main/resources/static/
export JAVA_HOME=<JDK21+>
mvn -o -q -DskipTests package
mvn -o test -Dtest='Gb35114*'
```

`Gb35114*` 六个测试类共 34 个用例，覆盖证书密钥复用（`Gb35114CertUtilKeyReuseTest`）、
SIP 头构造与解析（`Gb35114HeaderUtilTest`）、401 挑战头 golden 值
（`Gb35114ChallengeGoldenTest`）、SM2/SM3/VKEK 封装（`Gb35114SmCryptoTest`）、
UAS/UAC 握手状态机（`Gb35114StateMachineTest`）、签发者反查
（`Gb35114IssuerResolveTest`）—— **合并后这几个测试全过**，说明核心逻辑移植成功。

> ⚠️ `pom.xml` 里 `maven-surefire-plugin` 配了 `<skipTests>true</skipTests>`，
> 直接 `mvn test -Dtest='Gb35114*'` **不会真的跑**（只打印 BUILD SUCCESS，
> 不产生 `target/surefire-reports/`）。命令行加 `-DskipTests=false` **也覆盖不了**
> （实测无效，pom 里的配置优先）—— 需要临时把那一行改成 `false`。
>
> **已实测**：本补丁在基线 `fb45787` 的干净检出差上 `git apply` 后 `mvn compile` 通过，
> 34 个 GB35114 用例全绿。

---

## 五、只要一部分功能

不需要整套改造时，可以按下面的边界裁剪：

| 想要的能力 | 必需的部分 |
|---|---|
| **只要证书管理页面**（不接入） | `gb35114/conf` + `gb35114/crypto` + `gb35114/cert/**` + `web/src/**` 相关 + 三套 SQL + `pom.xml` 依赖。**不需要**任何 `gb28181/**` 与 `gov/nist/**` 的改动 |
| **只要设备证书注册（UAS）** | 上面的 + `gb35114/sip/{PlatformStateMachine,SecurityService,VkekCache,SipHeaders}` + `RegisterRequestProcessor` + `GBStringMsgParser` |
| **只要向上级注册（UAC）** | 上面的 + `DeviceStateMachine` + `RegisterResponseProcessor` + `SIPCommanderForPlatform` |
| **只要信令 Note 认证** | `gb35114/sip/{NoteIntegrator,NoteService,VkekCache,SipHeaders}` + `SIPSender` + `SIPProcessorObserver` + `GBStringMsgParser` + `crypto/Gb35114HeaderUtil`（Note 部分） |
| **只要两个 NIO/启动修复** | 仅 `CustomNioTcpMessageProcessor` 与 `PlatformServiceImpl` 两个文件 —— 与国密无关，可独立合入 |

> 后两项是**独立的净收益修复**，即使完全不用 GB35114 也建议合入：
> NIO 换 socket 竞态会丢包（表现为"注册时好时坏"），启动期注销/注册并发会让容器刚起时偶发注册失败。

---

## 六、已知的版本约束

| 项 | 约束 |
|---|---|
| JDK | 21+（与 2.7.4 基线一致） |
| Spring Boot | 3.x（用到 `jakarta.annotation.PostConstruct`、`ObjectProvider`） |
| jain-sip | 1.3.0-91 —— `CustomNioTcpMessageProcessor` 的修补是针对这个版本的内部实现（`NIOHandler.sendBytes` / `openOutgoingConnection` / `blockingConnect` 的调用顺序）。**换 jain-sip 版本需重新核对该时序** |
| 数据库 | MySQL / PostgreSQL / KingbaseES / 达梦 DM8 四套脚本。达梦版用 `SYSOBJECTS` 判表、`USER_TAB_COLUMNS` 判列，clob 列判空用 `LENGTH(...) = 0`（达梦 clob 不可用 `= ''` 比较） |
| 前端 | Vue 2 + Element UI（与 2.7.4 一致） |

---

## 七、回退

```bash
git apply -R gb35114.patch       # 反向应用
```

或 `git revert <合并提交>`。

回退后数据库里多出的表与列**不影响原有功能**（全部是可空新增列），
可保留；若要彻底清理，见 [安装说明 §6.2](install.md#62-回退)。

> ⚠️ 回退前确认**设备侧**是否已切到证书注册 —— 平台回退不会自动把设备的
> `register_way` 改回 1，设备侧需要同步切回摘要认证。
