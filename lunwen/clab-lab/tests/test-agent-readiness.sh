#!/bin/bash
# ============================================================================
# test-agent-readiness.sh —— agent 就绪判据的离线钉子（Task 4D Fix round 2 / Minor-6②）
# ============================================================================
#
# 钉的是 Step 4-B2 的**缺陷 4**（本轮最贵的一条）：`live_agent_paws` 把"容器内活 pid 列表"从
# **stdin** 读进来，而程序本体又是 `python3 - <<'PY' … PY` 从 **stdin** 读的 —— 同一路 stdin 被用了
# 两次：程序把 heredoc 读完时已到 EOF，`sys.stdin.read()` **永远是空串** ⇒ `pids` 恒空 ⇒
# **这个函数从来匹配不到任何 agent**（实测：`printf '886\n1096' | live_agent_paws` 回空行，
# 而 Caldera 里那两条 `trusted=true`、pid 也对得上的条目被静默滤掉）。
#
# 后果不是"多拉一次 sandcat"这么轻：它让"目标上有没有活着的 agent"这条判据**恒为否** ——
# 而那正是**避免把 operation 打到死 agent 上**（`status=-3` 看起来像"被拦住"）的唯一闸门。
#
# 本夹具**不碰真 Caldera**：起一个本机假 API（返回四条条目，覆盖判据的三种排除），
# 把 `edge_target_prepare.sh` 里的 `live_agent_paws` **原样抽出来**执行（与 `test-chain-derivation.sh`
# 同款手法：判据只有一份，夹具抽它而不是抄它）。
#
# 判据三格：
#   A) 新布局（pid 列表走**第 5 个 argv**）⇒ 必须回出那条 paw（且只回它：陈旧 pid / 过期心跳 / 别的主机
#      三条都必须被排除）；
#   B) 空 pid 列表 ⇒ 必须回空（"目标上没有活着的进程"不等于"有 agent"）；
#   C) **旧布局**（pid 列表走 stdin）⇒ 必须回空 —— 这一格是"回归钉"：若有人把实现改回读 stdin，
#      A 会红、C 会绿，夹具因此能抓住回退（只测 A 是不够的：那种写法下 A 与 C 无法区分）。
#
# 只读、离线：不碰 clab/LXD/容器，不调真 Caldera（假 API 只在本机回一段固定 JSON）。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
PREP="$REPO/lunwen/clab-lab/scripts/edge_target_prepare.sh"
D="${T4D_AGENT_TEST_DIR:-${HOME:-/tmp}}/t4d-agent-readiness"
rm -rf "$D"; mkdir -p "$D"
PASS=0; FAIL=0
ok()   { echo "  ok   $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

[ -f "$PREP" ] || { echo "缺少 $PREP" >&2; exit 1; }

# --- 1. 从被测脚本里**抽出** live_agent_paws（markers：函数头 … 独占一行的 `}`）-------
awk '/^live_agent_paws\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$PREP" > "$D/live_agent_paws.sh"
if ! grep -q 'live_agent_paws()' "$D/live_agent_paws.sh"; then
  echo "FAIL 没能从 $PREP 抽出 live_agent_paws（marker 变了？）" >&2; exit 1
fi
echo "抽出 live_agent_paws：$(wc -l < "$D/live_agent_paws.sh") 行"

# --- 2. 本机假 Caldera API（只回一段固定 JSON；端口由内核分配）-------------------
cat > "$D/fake_api.py" <<'PY'
import http.server, json, socketserver
from datetime import datetime, timedelta, timezone

PAW = "cbjeio"
PIDS = [886, 1096]

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/api/v2/agents'):
            self.send_error(404); return
        now = datetime.now(timezone.utc)
        fresh = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        stale = (now - timedelta(seconds=9999)).strftime('%Y-%m-%dT%H:%M:%SZ')
        agents = [
            # 目标上的**活** agent：host + pid 对得上 + trusted + 心跳新鲜 ⇒ 唯一应被选中的那条
            {"paw": PAW, "host": "asc-tgt-1", "pid": PIDS[1], "trusted": True,
             "group": "t4d-ttp", "last_seen": fresh},
            # 判据②排除：pid 不在（容器内当前）活进程表里
            {"paw": "stale-pid", "host": "asc-tgt-1", "pid": 4242, "trusted": True,
             "group": "t4d-ttp", "last_seen": fresh},
            # 判据③排除：pid 对得上但心跳过期
            {"paw": "stale-seen", "host": "asc-tgt-1", "pid": PIDS[0], "trusted": True,
             "group": "t4d-ttp", "last_seen": stale},
            # 判据①排除：别的机器上的活 agent
            {"paw": "other-host", "host": "probe-ot005", "pid": PIDS[1], "trusted": True,
             "group": "red", "last_seen": fresh},
        ]
        body = json.dumps(agents).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
PY
python3 "$D/fake_api.py" > "$D/port.txt" 2>"$D/api.err" &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null' EXIT
i=0
while [ ! -s "$D/port.txt" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
PORT="$(cat "$D/port.txt" 2>/dev/null || true)"
[ -n "$PORT" ] || { echo "FAIL 假 API 没起来：$(cat "$D/api.err")" >&2; exit 1; }
echo "假 Caldera API: http://127.0.0.1:$PORT"

# --- 3. 三格判据 ---------------------------------------------------------------
probe() { # probe <argv|stdin> <pid 列表>
  local layout="$1" pids="$2"
  TARGET=asc-tgt-1 CALDERA_URL="http://127.0.0.1:$PORT" CALDERA_KEY=ADMIN123 \
  EDGEEXP_AGENT_FRESH_S=180 LAYOUT="$layout" PIDS="$pids" \
  bash -c '. "$0"; if [ "$LAYOUT" = stdin ]; then printf "%s" "$PIDS" | live_agent_paws; else live_agent_paws "$PIDS"; fi' \
    "$D/live_agent_paws.sh" 2>"$D/probe.err"
}

out="$(probe argv "886 1096")"
if [ "$out" = "cbjeio" ]; then
  ok "A) 新布局（argv[5]）：pid 列表 ⇒ 回出 paw=cbjeio（且陈旧 pid/过期心跳/别的主机三条都被排除）"
else
  fail "A) 新布局没有回出 paw：out='$out' err=$(head -2 "$D/probe.err" | tr '\n' ';')"
fi

out="$(probe argv "")"
if [ -z "$out" ]; then
  ok "B) 空 pid 列表 ⇒ 回空（『没有活着的进程』不得被读成『有 agent』）"
else
  fail "B) 空 pid 列表竟然回出了 paw：out='$out'"
fi

out="$(probe stdin "886 1096")"
if [ -z "$out" ]; then
  ok "C) 旧布局（stdin）⇒ 回空 —— **回归钉**：这条绿说明『把 pid 列表喂 stdin』那种写法确实坏（若有人改回去，A 会红）"
else
  fail "C) 旧布局竟然回出了 paw（'$out'）—— 两个布局不再可分辨，A 格的证据价值下降"
fi

echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: agent 就绪判据的离线钉子全绿"
