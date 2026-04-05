#!/bin/bash
# 用途：
# 1. 供 systemd 服务异常退出时调用
# 2. 读取 /etc/default/zhuce5-monitor 中的 DINGTALK_WEBHOOK
# 3. 向钉钉发送一条简单文本告警

set -u

# 参数 1：systemd unit 名称；默认 monitor.service
UNIT_NAME="${1:-monitor.service}"
# 参数 2：事件名称；默认 unexpected_exit
EVENT_NAME="${2:-unexpected_exit}"
# 可选环境文件：用于放 DINGTALK_WEBHOOK，避免把 webhook 硬编码进脚本
ENV_FILE="/etc/default/monitor"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

# 未配置 webhook 则静默退出
WEBHOOK="${DINGTALK_WEBHOOK:-}"
[ -n "$WEBHOOK" ] || exit 0

# 收集主机、时间、退出状态等信息
HOSTNAME_VAL="$(hostname)"
TIME_VAL="$(date '+%F %T %Z')"
RESULT_VAL="${SERVICE_RESULT:-unknown}"
EXIT_CODE_VAL="${EXIT_CODE:-unknown}"
EXIT_STATUS_VAL="${EXIT_STATUS:-unknown}"

# 发送到钉钉的文本内容（注意关键词）
CONTENT="CLI变动\nCLI服务告警\n主机：${HOSTNAME_VAL}\n服务：${UNIT_NAME}\n事件：${EVENT_NAME}\n时间：${TIME_VAL}\n结果：${RESULT_VAL}\nEXIT_CODE：${EXIT_CODE_VAL}\nEXIT_STATUS：${EXIT_STATUS_VAL}"

# 用 python 安全生成 JSON，避免 shell 转义问题
PAYLOAD="$(python3 - "$CONTENT" <<'PY'
import json, sys
print(json.dumps({"msgtype": "text", "text": {"content": sys.argv[1]}}, ensure_ascii=False))
PY
)"

[ -n "$PAYLOAD" ] || exit 0
# 告警失败也不影响主流程，因此最后吞掉错误
curl -fsS -H 'Content-Type: application/json' -d "$PAYLOAD" "$WEBHOOK" >/dev/null 2>&1 || true
