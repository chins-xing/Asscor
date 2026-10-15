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
  echo "exp_caldera_api3: 缺少 EDGEEXP_CALDERA_KEY —— 仓库不再提供明文默认值。" >&2
  echo "  修法：export EDGEEXP_CALDERA_KEY='<C2 API 口令>'，或写进未跟踪的本地配置 ${_local_env:-}" >&2
  exit 2
fi
echo "=== whoami ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/whoami | head -c 300
echo
echo "=== abilities ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/abilities | python3 -c 'import json,sys; d=json.load(sys.stdin); print("abilities:", len(d))' 2>&1
echo "=== adversaries ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/adversaries | python3 -c 'import json,sys; d=json.load(sys.stdin); print("adversaries:", len(d))' 2>&1
echo "=== agents ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/agents | python3 -c 'import json,sys; d=json.load(sys.stdin); print("agents:", len(d))' 2>&1
echo "=== operations ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/operations | python3 -c 'import json,sys; d=json.load(sys.stdin); print("operations:", len(d))' 2>&1
echo DONE
