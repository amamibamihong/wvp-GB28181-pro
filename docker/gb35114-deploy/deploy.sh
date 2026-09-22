#!/bin/bash
# GB35114 部署脚本（在本机执行，目标为部署服务器）
# 前置：
#   1) 本地已 mvn package 产出 target/wvp-pro-*.jar
#   2) 已 cp .env.example .env 并填好其中的口令与服务器地址
set -e

DEPLOY_DIR=/opt/wvp-gb35114

# 口令等敏感值全部来自 .env（该文件不进版本库），脚本本身不含任何口令
if [ ! -f .env ]; then
  echo "缺少 .env：请先 cp .env.example .env 并填写其中的值" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
. ./.env
set +a

if [ -z "${WVP_SERVER}" ]; then
  echo "请在 .env 中设置 WVP_SERVER=<部署服务器地址>" >&2
  exit 1
fi
SERVER="${WVP_SERVER}"

echo "==> 1. 传输 jar"
scp ../../target/wvp-pro-2.7.4-*.jar root@${SERVER}:${DEPLOY_DIR}/wvp.jar

echo "==> 2. 传输 SQL"
scp ../../数据库/2.7.4/初始化-mysql-2.7.4.sql root@${SERVER}:${DEPLOY_DIR}/mysql/01-init.sql
scp ../../数据库/2.7.4/更新-gb35114-mysql.sql root@${SERVER}:${DEPLOY_DIR}/mysql/02-gb35114.sql

echo "==> 3. 传输配置与 .env"
scp config/application-host.yml root@${SERVER}:${DEPLOY_DIR}/config/application-host.yml
scp docker-compose.yml root@${SERVER}:${DEPLOY_DIR}/docker-compose.yml
# .env 供远端 docker compose 与下面的 java 启动命令读取，两边口令同源
scp .env root@${SERVER}:${DEPLOY_DIR}/.env

echo "==> 4. 启动 mysql/redis 容器"
ssh root@${SERVER} "cd ${DEPLOY_DIR} && docker compose up -d wvp-gb35114-mysql wvp-gb35114-redis"

echo "==> 5. 等待 mysql 健康"
ssh root@${SERVER} "for i in \$(seq 1 30); do st=\$(docker inspect -f '{{.State.Health.Status}}' wvp-gb35114-wvp-gb35114-mysql-1 2>/dev/null); [ \"\$st\" = healthy ] && echo healthy && exit 0; sleep 5; done; echo unhealthy; exit 1"

echo "==> 6. 宿主机 JDK 直跑 wvp（旧内核 3.10 无法用容器 JDK）"
# 先 source .env 把占位符要用的值导出，再启动 —— 外置配置里全是 ${VAR} 占位符，
# 少了任意一个 Spring 会以 PlaceholderResolutionException 启动失败。
ssh root@${SERVER} "cd ${DEPLOY_DIR} && set -a && . ./.env && set +a && \
  export JAVA_HOME=/usr/lib/jvm/jdk-21-oracle-x64 && \
  pkill -f 'wvp.jar' || true; sleep 2; \
  nohup \$JAVA_HOME/bin/java -Xms512m -Xmx1024m -jar wvp.jar \
  --spring.config.location=${DEPLOY_DIR}/config/application-host.yml \
  > ${DEPLOY_DIR}/logs/wvp-host.log 2>&1 & echo \"wvp PID=\$!\""

echo "==> 7. 等待启动"
sleep 30
ssh root@${SERVER} "grep -E 'Started VManageBootstrap|APPLICATION FAILED' ${DEPLOY_DIR}/logs/wvp-host.log | tail -3"

echo "==> 完成。访问 http://${SERVER}:18978/（默认 admin/admin，首次需改密码）"
