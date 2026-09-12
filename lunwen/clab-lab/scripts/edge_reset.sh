#!/bin/bash
# ============================================================================
# edge_reset.sh —— 每个场景的"干净环境"复位（spec §5 / §5.3）
# ============================================================================
#
# 用法：
#   ./scripts/edge_reset.sh [scenario]
#
# 做什么（顺序即依赖）：
#   1. 确保 Caldera C2 可用（已在跑就用现有的；没跑就按冻结的参数启动）；
#   2. `clab destroy --cleanup` + `clab deploy` **重建拓扑**；
#      —— 必须 destroy+deploy，**不用** `--reconfigure`：后者不重建 veth，
#      上一场景的接口状态会带进下一场景（Task 3 之前的实验实测过）。
#   3. 等全部节点 running；
#   4. 把 sandcat agent 部署到目标节点并**验证它真的回连心跳**；
#   5. 写 `data/edgefactors/run.d/reset-<scenario>.json`（耗时/拓扑哈希/节点数/agent paw）。
#
# 退出码：0 成功；1 任何一步失败（**不降级、不跳过**——一条"环境没起来但照常采集"的记录
# 比一次失败危险得多：它会以完全正常的语气进入报告）。
#
# 环境变量（全部可选）：
#   EDGEEXP_TOPOLOGY     拓扑文件，默认 <lab>/asscor.clab.yml
#   EDGEEXP_TARGET_HOST  攻击目标节点名（不带 clab 前缀），默认 host1
#   EDGEEXP_CALDERA_URL  Caldera API，默认 http://127.0.0.1:8888
#   EDGEEXP_CALDERA_KEY  API key，默认 ADMIN123（本机 Caldera 的 --insecure 部署值）
#   EDGEEXP_CALDERA_HOME Caldera 安装目录，默认 /opt/caldera
#   EDGEEXP_CALDERA_BOOT_S / EDGEEXP_NODE_WAIT_S / EDGEEXP_AGENT_WAIT_S  各阶段超时（秒）
# ============================================================================
set -euo pipefail

SCENARIO="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
RUN_D="$DATA_DIR/run.d"
TOPOLOGY="${EDGEEXP_TOPOLOGY:-$LAB_DIR/asscor.clab.yml}"
TARGET="${EDGEEXP_TARGET_HOST:-host1}"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://127.0.0.1:8888}"
CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-ADMIN123}"
CALDERA_HOME="${EDGEEXP_CALDERA_HOME:-/opt/caldera}"
CALDERA_BOOT_S="${EDGEEXP_CALDERA_BOOT_S:-240}"
NODE_WAIT_S="${EDGEEXP_NODE_WAIT_S:-300}"
AGENT_WAIT_S="${EDGEEXP_AGENT_WAIT_S:-180}"

mkdir -p "$RUN_D"
FILLER="reset-${SCENARIO:-noarg}.json"
TMP_OUT="$RUN_D/.$FILLER.tmp"

for bin in clab docker curl python3 sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "edge_reset: 缺少必需命令 $bin" >&2; exit 1; }
done
[ -f "$TOPOLOGY" ] || { echo "edge_reset: 拓扑文件不存在: $TOPOLOGY" >&2; exit 1; }

now_rfc3339() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_s() { date -u +%s; }

START_S=$(now_s)
STARTED_AT=$(now_rfc3339)
TOPO_HASH="sha256:$(sha256sum "$TOPOLOGY" | awk '{print $1}')"

# --- 1. Caldera --------------------------------------------------------------
caldera_s=0
ensure_caldera() {
  local t0=$1
  if curl -fsS -m 5 -H "KEY: $CALDERA_KEY" "$CALDERA_URL/api/v2/abilities" >/dev/null 2>&1; then
    echo "edge_reset: Caldera 已在运行（$CALDERA_URL）"
    return 0
  fi
  [ -x "$CALDERA_HOME/venv/bin/python" ] || {
    echo "edge_reset: Caldera 不可用：API 无响应且 $CALDERA_HOME/venv/bin/python 不存在 —— 攻击侧是客观结果的唯一来源，不得跳过" >&2
    return 1
  }
  echo "edge_reset: 启动 Caldera（$CALDERA_HOME，插件 sandcat,stockpile,atomic）"
  # -P 必须显式给：缺插件列表时 sandcat payload 不会被生成（Task 1 之前的实验实测）
  ( cd "$CALDERA_HOME" && setsid ./venv/bin/python server.py --fresh -P sandcat,stockpile,atomic \
      > /tmp/caldera-edgeexp.log 2>&1 < /dev/null & )
  local waited=0
  until curl -fsS -m 5 -H "KEY: $CALDERA_KEY" "$CALDERA_URL/api/v2/abilities" >/dev/null 2>&1; do
    if [ "$waited" -ge "$CALDERA_BOOT_S" ]; then
      echo "edge_reset: Caldera 在 ${CALDERA_BOOT_S}s 内没有起来，见 /tmp/caldera-edgeexp.log 尾部：" >&2
      tail -20 /tmp/caldera-edgeexp.log >&2 || true
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  caldera_s=$(( $(now_s) - t0 ))
  echo "edge_reset: Caldera 就绪（等待 ${caldera_s}s）"
}
T0=$(now_s); ensure_caldera "$T0" || exit 1

# 节点计数（`clab inspect --format json` 是权威视图，不是解析 yml 的缩进）。回显 "total up down"。
clab_node_counts() {
  clab inspect -t "$TOPOLOGY" --format json > /tmp/edgeexp-clab-inspect.json 2>>/tmp/edgeexp-clab-inspect.log
  python3 - <<'PY'
import json
try:
    data = json.load(open('/tmp/edgeexp-clab-inspect.json'))
except Exception:
    print(0, 0, 0); raise SystemExit
# clab 的 --format json 是 {<lab 名>: [节点…]}（0.78 实测）；同时兼容 {containers:[…]} 形态
nodes = []
if isinstance(data, dict):
    if isinstance(data.get('containers'), list):
        nodes = data['containers']
    else:
        for value in data.values():
            if isinstance(value, list):
                nodes.extend(value)
elif isinstance(data, list):
    nodes = data
up = sum(1 for c in nodes if (c.get('state') or '').lower() in ('running', 'up'))
print(len(nodes), up, len(nodes) - up)
PY
}

# --- 2. destroy + deploy -----------------------------------------------------
# destroy 的失败**不是**关键路径失败：没部署过任何容器时它本来就会报错，而那一趟的语义
# 正是"从干净状态开始"。关键路径是 deploy —— 它没有任何容错。
T0=$(now_s)
DESTROY_TOLERATED=0
if clab destroy -t "$TOPOLOGY" --cleanup >/tmp/edgeexp-clab-destroy.log 2>&1; then
  echo "edge_reset: clab destroy 完成"
else
  DESTROY_TOLERATED=1
  echo "edge_reset: clab destroy 报错（多半是本来就没有部署，属幂等路径）—— 见 /tmp/edgeexp-clab-destroy.log"
fi
destroy_s=$(( $(now_s) - T0 ))

# destroy 被容忍时**必须**补一条断言（I9）：只有"拓扑真的空了"才谈得上"从干净状态开始"。
# 否则 destroy 因真实原因失败、deploy 只是对残留容器做 reconcile 时，整个复位的前提已经不成立，
# 而后面每一步都会照常通过 —— 那是最难发现的一类环境污染。
if [ "$DESTROY_TOLERATED" -eq 1 ]; then
  read -r LEFT_TOTAL LEFT_UP LEFT_DOWN <<EOF
$(clab_node_counts)
EOF
  if [ "$LEFT_TOTAL" -ne 0 ]; then
    echo "edge_reset: clab destroy 失败且拓扑里仍有 $LEFT_TOTAL 个节点（$LEFT_UP running）—— '干净环境'的前提不成立：" >&2
    echo "  deploy 可能只是对残留容器做 reconcile，上一场景的接口/路由状态会被带进本场景。整轮失败。" >&2
    echo "  见 /tmp/edgeexp-clab-destroy.log；手工排障后重跑。" >&2
    exit 1
  fi
  echo "edge_reset: destroy 虽报错但拓扑已空（0 节点）—— 干净环境前提成立，继续"
fi

T0=$(now_s)
clab deploy -t "$TOPOLOGY"   # 关键路径：失败即整轮失败（不做 --reconfigure）
deploy_s=$(( $(now_s) - T0 ))
echo "edge_reset: clab deploy 完成（${deploy_s}s）"

# --- 3. 等节点 running -------------------------------------------------------
# 权威判据是 `clab inspect --format json`（拓扑自己的视图），不是解析 yml 的缩进，
# 也不是"docker ps 里有多少个容器"。必须等到**全部**节点 running：clab deploy 返回时
# 容器可能才刚创建，此时容器间的链路还没就绪，直接开打会得到与本实验无关的失败。
T0=$(now_s)
waited=0
while :; do
  read -r TOTAL_NODES UP_NODES DOWN_NODES <<EOF
$(clab_node_counts)
EOF
  if [ "$TOTAL_NODES" -gt 0 ] && [ "$DOWN_NODES" -eq 0 ]; then
    break
  fi
  if [ "$waited" -ge "$NODE_WAIT_S" ]; then
    break
  fi
  sleep 5
  waited=$((waited + 5))
done
wait_s=$(( $(now_s) - T0 ))
echo "edge_reset: 节点 $UP_NODES/$TOTAL_NODES running（等待 ${wait_s}s）"
[ "$TOTAL_NODES" -gt 0 ] || { echo "edge_reset: 拓扑里一个节点都没起来 —— 环境不可用" >&2; exit 1; }
[ "$DOWN_NODES" -eq 0 ] || { echo "edge_reset: 有 $DOWN_NODES 个节点不是 running —— 环境不可用" >&2; exit 1; }

# --- 4. sandcat agent --------------------------------------------------------
# 容器名 = <拓扑 prefix>-<lab 名>-<节点名>（本拓扑 prefix=asc ⇒ asc-asscor-host1）。
# prefix 由拓扑自己声明，脚本**不硬编码**：从 `clab inspect` 的视图里按后缀取节点名，
# 拓扑改 prefix 时这里不会变成一次"目标节点不存在"的假故障。
NODE="$(python3 - "$TARGET" <<'PY'
import json, sys
target = sys.argv[1]
try:
    data = json.load(open('/tmp/edgeexp-clab-inspect.json'))
except Exception:
    print(''); raise SystemExit
nodes = []
if isinstance(data, dict):
    for value in data.values():
        if isinstance(value, list):
            nodes.extend(value)
for c in nodes:
    name = c.get('name') or ''
    if name.endswith('-' + target):
        print(name); break
PY
)"
[ -n "$NODE" ] || { echo "edge_reset: 在拓扑里找不到节点 $TARGET 的容器（见 /tmp/edgeexp-clab-inspect.json）" >&2; exit 1; }
docker inspect "$NODE" >/dev/null 2>&1 || { echo "edge_reset: 目标节点容器不存在: $NODE" >&2; exit 1; }
PAYLOAD="$CALDERA_HOME/plugins/sandcat/payloads/sandcat.go-linux"
[ -f "$PAYLOAD" ] || { echo "edge_reset: sandcat payload 不存在: $PAYLOAD（Caldera 启动时是否漏了 -P sandcat?）" >&2; exit 1; }

T0=$(now_s)
# C2 地址必须从**节点侧可达**的候选里探测出来，不能想当然地取"默认网关"：
# 本拓扑的 exec 会把节点默认路由指向内网（`ip route replace default via 10.10.1.1 dev eth1`），
# 那个地址不是 WSL 主机 —— 实测过：按默认网关拼 URL 的 sandcat 会**静默**起不来
# （容器里进程在跑、Caldera 里 agent 一直 untrusted，而 reset 只会在超时后报"没有回连"）。
# 判据只能是"真的能连上 8888"：候选 = 管理网（eth0）网关 + 默认网关，逐个探测 TCP。
MGMT_CIDR="$(docker exec "$NODE" ip -4 -o addr show eth0 2>/dev/null | awk '{print $4; exit}')"
MGMT_GW="$(python3 - "$MGMT_CIDR" <<'PY'
import ipaddress, sys
cidr = (sys.argv[1] if len(sys.argv) > 1 else '').strip()
try:
    net = ipaddress.ip_network(cidr, strict=False)
    print(str(net.network_address + 1))
except Exception:
    print('')
PY
)"
DEFAULT_GW="$(docker exec "$NODE" ip route | awk '/^default/{print $3; exit}')"

SANDCAT_URL=""
CANDIDATES="$MGMT_GW $DEFAULT_GW"
PROBED=""
for cand in $CANDIDATES; do
  [ -n "$cand" ] || continue
  PROBED="$PROBED $cand"
  if docker exec "$NODE" bash -c "timeout 3 bash -c 'echo > /dev/tcp/$cand/8888' 2>/dev/null"; then
    SANDCAT_URL="http://$cand:8888"
    break
  fi
done
[ -n "$SANDCAT_URL" ] || {
  echo "edge_reset: 节点 $NODE 连不上 Caldera：探测过$PROBED 的 :8888 全部不通 —— 攻击侧不可用" >&2
  exit 1
}
echo "edge_reset: C2 地址 $SANDCAT_URL（管理网网关 $MGMT_GW / 默认网关 $DEFAULT_GW）"
docker exec "$NODE" bash -c "rm -f /tmp/sandcat /tmp/sandcat.log"
docker cp "$PAYLOAD" "$NODE:/tmp/sandcat" >/dev/null
docker exec "$NODE" chmod 755 /tmp/sandcat
# 本节要证明的是"**本次**部署的 agent 真的在跳"，不是"Caldera 记得有个 agent"：
# Caldera 会保留已被销毁容器的 agent 条目（last_seen 停在容器消失那一刻），
# 只按 host 名匹配会在**新 agent 根本没起来**时误判成功（实测：上一次部署的 agent
# 让检查在 1s 内"通过"，而那 1s 里新容器里连 sandcat 都还没启动）。
# 故以"启动时刻"为界：只有 last_seen **不早于**启动时刻的条目才算数。
AGENT_SINCE="$(now_rfc3339)"
docker exec -d "$NODE" bash -c "/tmp/sandcat --server $SANDCAT_URL > /tmp/sandcat.log 2>&1"

paw=""
waited=0
while :; do
  paw="$(curl -fsS -m 5 -H "KEY: $CALDERA_KEY" "$CALDERA_URL/api/v2/agents" \
    | python3 -c '
import datetime, json, sys
target, since = sys.argv[1], sys.argv[2]
def parse(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
cutoff = parse(since) - datetime.timedelta(seconds=5)
for a in json.load(sys.stdin):
    if a.get("host") != target or not a.get("trusted"):
        continue
    seen = parse(a.get("last_seen"))
    if seen is not None and cutoff is not None and seen < cutoff:
        continue
    print(a.get("paw")); break' "$TARGET" "$AGENT_SINCE" 2>/dev/null || true)"
  if [ -n "$paw" ]; then break; fi
  if [ "$waited" -ge "$AGENT_WAIT_S" ]; then break; fi
  sleep 5
  waited=$((waited + 5))
done
agent_wait_s=$(( $(now_s) - T0 ))
if [ -z "$paw" ]; then
  echo "edge_reset: sandcat agent 在 ${AGENT_WAIT_S}s 内没有回连 $SANDCAT_URL（判据：host=$TARGET 且 trusted 且 last_seen ≥ $AGENT_SINCE）—— 攻击侧不可用，整轮失败" >&2
  docker exec "$NODE" tail -20 /tmp/sandcat.log >&2 || true
  exit 1
fi
echo "edge_reset: agent 就绪（host=$TARGET paw=$paw，等待 ${agent_wait_s}s）"

# --- 5. 留痕 -----------------------------------------------------------------
FINISHED_AT=$(now_rfc3339)
TOTAL_S=$(( $(now_s) - START_S ))
cat > "$TMP_OUT" <<EOF
{
  "scenario": "${SCENARIO}",
  "phase": "reset",
  "env": "${EDGEEXP_ENV:-wsl-clab-14}",
  "started_at": "$STARTED_AT",
  "finished_at": "$FINISHED_AT",
  "elapsed_s": $TOTAL_S,
  "topology": "$TOPOLOGY",
  "topology_hash": "$TOPO_HASH",
  "nodes": {"total": $TOTAL_NODES, "running": $UP_NODES, "down": $DOWN_NODES},
  "timings_s": {"caldera": $caldera_s, "destroy": $destroy_s, "deploy": $deploy_s, "node_wait": $wait_s, "agent": $agent_wait_s},
  "target": {"node": "$NODE", "host": "$TARGET", "paw": "$paw", "sandcat_url": "$SANDCAT_URL"},
  "note": "destroy 失败已被容忍（没部署过时本该失败）；deploy 无容错。未使用 --reconfigure（不重建 veth）。"
}
EOF
mv "$TMP_OUT" "$RUN_D/$FILLER"
echo "edge_reset: 复位完成（总 ${TOTAL_S}s）→ $RUN_D/$FILLER"
