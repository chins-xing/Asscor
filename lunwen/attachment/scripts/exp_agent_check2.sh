#!/bin/bash
# C2 API key：**不写明文**（Task 14 脱敏 D2 —— 原值是真凭据的明文，已移除）。
# 取值：环境变量 → 未跟踪的本地配置 → 响亮失败（不猜、不降级）。本脚本是一次性排查小工具
# （不 source 库），故这段内联；六个跑批主脚本用唯一取值点 scripts/edge_c2_key.sh。
KEY="${EDGEEXP_CALDERA_KEY:-}"
if [ -z "$KEY" ]; then
  _local_env="${EDGEEXP_LOCAL_ENV:-${HOME:-/root}/.config/asscor/edgeexp.local.env}"
  [ -r "$_local_env" ] && . "$_local_env"
  KEY="${EDGEEXP_CALDERA_KEY:-}"
fi
if [ -z "$KEY" ]; then
  echo "exp_agent_check2: 缺少 EDGEEXP_CALDERA_KEY —— 仓库不再提供明文默认值。" >&2
  echo "  修法：export EDGEEXP_CALDERA_KEY='<C2 API 口令>'，或写进未跟踪的本地配置 ${_local_env:-}" >&2
  exit 2
fi
echo "=== raw agents response ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/agents | head -c 500
echo
echo "=== raw operations ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/operations | head -c 300
echo
echo "=== sandcat still alive? ==="
docker exec asc-asscor-host1 pgrep -f sandcat >/dev/null 2>&1 && echo "SANDCAT-RUNNING" || echo "SANDCAT-DEAD"
docker exec asc-asscor-host1 tail -5 /tmp/sandcat.log 2>&1
echo DONE
