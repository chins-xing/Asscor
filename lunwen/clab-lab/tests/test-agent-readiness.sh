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
# **Task 10 Step 4.1 追加两格**（同一缺陷的姊妹形态，两次以"超范围"停手的那条）：Caldera 保留
# 已死 agent 的条目，而容器 **pid 会被复用** ⇒ 同一台机器上可能同时有**两条**都满足
# "host 对 + trusted + pid 命中活进程 + 心跳新鲜"的记录。原实现 `for a in agents: … print(paw);
# raise SystemExit` 取**列表里第一只**（数据库序 = 通常最老那只）⇒ 复位的日志把 paw 报成**上一只**
# （实例：产物记 `bvecgb`、实际活的是 `thgfyz`）。修法：命中多条时取 **`last_seen` 最新**的那只，
# 并把其余候选打进 stderr 的**响亮警告**。两格判据：
#   D) 两条同 pid、都新鲜，**旧的那条排在前面** ⇒ 必须回**心跳最新**的那只，且警告里点名其余候选
#      （缺陷版会回列表第一只 ⇒ 这一格在缺陷版上必红）；
#   E) **反向**：把两条的心跳对调 ⇒ 回的 paw 必须**跟着换**（证明按心跳选，而不是按列表序/创建时间）。
#
# 判据三格（原有）：
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
import http.server, json, os, socketserver
from datetime import datetime, timedelta, timezone

PAW = "cbjeio"
PIDS = [886, 1096]

AGENTS_JSON = os.environ.get('AGENTS_JSON') or ''

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/api/v2/agents'):
            self.send_error(404); return
        if AGENTS_JSON and os.path.exists(AGENTS_JSON):
            # **实例列表来自文件**（Task 10 的两格要换列表跑；A/B/C 三格不写它 ⇒ 走下面的内置列表，
            # 行为与加这两格之前逐字相同）。
            body = json.dumps(json.load(open(AGENTS_JSON, encoding='utf-8'))).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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
AGENTS_JSON="$D/agents.json" python3 "$D/fake_api.py" > "$D/port.txt" 2>"$D/api.err" &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null' EXIT
i=0
while [ ! -s "$D/port.txt" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
PORT="$(cat "$D/port.txt" 2>/dev/null || true)"
[ -n "$PORT" ] || { echo "FAIL 假 API 没起来：$(cat "$D/api.err")" >&2; exit 1; }
echo "假 Caldera API: http://127.0.0.1:$PORT"

# --- 3. 三格判据 ---------------------------------------------------------------
# ⚠️ `CALDERA_KEY` 是**夹具自带的假值**（Task 14 脱敏 D2）：本夹具的假 API **不校验** KEY 头，
# 而被抽出来执行的 `live_agent_paws` 只是把 KEY 塞进请求头 ⇒ 这里给什么值都一样。
# 纪律：**夹具不许依赖真凭据**（原值是真口令的明文，已随 D2 一起移除）。给空串则会让
# "KEY 变量丢了"这种低级错也被静默吞掉，故显式给一个一眼看出是假的常量。
FIXTURE_KEY='fixture-key-not-a-real-credential'
probe() { # probe <argv|stdin> <pid 列表>
  local layout="$1" pids="$2"
  TARGET=asc-tgt-1 CALDERA_URL="http://127.0.0.1:$PORT" CALDERA_KEY="$FIXTURE_KEY" \
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

# --- 4. Task 10 的两格：pid 复用（同 pid 的两条）时的 paw 归属 -------------------
# 造两条**都满足**判据的记录（同 host、同 pid、trusted、心跳都新鲜）——这正是 CT 重启后
# pid 被复用的现场形态。区别只在 `last_seen` 与 `created`。
now_iso() { python3 -c "import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))"; }
ago_iso() { python3 -c "import datetime,sys;print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=int(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))" "$1"; }

write_agents() { # write_agents <旧paw的心跳秒数> <新paw的心跳秒数>
  python3 - "$D/agents.json" "$(ago_iso "$1")" "$(ago_iso "$2")" <<'PY'
import json, sys
path, old_seen, new_seen = sys.argv[1], sys.argv[2], sys.argv[3]
json.dump([
    # **旧记录在前**（数据库序里通常也是它在前）—— 缺陷版会把它当成"现在在跳的那只"
    {"paw": "oldpaw", "host": "asc-tgt-1", "pid": 1096, "trusted": True, "group": "t4d-ttp",
     "last_seen": old_seen, "created": "2026-10-10T06:30:15Z"},
    {"paw": "newpaw", "host": "asc-tgt-1", "pid": 1096, "trusted": True, "group": "t4d-ttp",
     "last_seen": new_seen, "created": "2026-10-14T17:05:20Z"},
], open(path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
}

write_agents 100 5           # 旧的心跳 100s 前、新的 5s 前 ⇒ 活的是 newpaw
out="$(probe argv "886 1096")"
err="$(cat "$D/probe.err")"
if [ "$out" = "newpaw" ]; then
  ok "D) pid 复用（两条都新鲜、同 pid）：取**心跳最新**的 newpaw，而不是列表里第一只 oldpaw"
else
  fail "D) pid 复用时的归属错：out='$out'（期望 newpaw —— 取列表第一只是**缺陷版**的行为）"
fi
if echo "$err" | grep -q '命中' && echo "$err" | grep -q 'oldpaw'; then
  ok "D2) 命中多条时**响亮警告**并列出了其余候选（stderr 里点名 oldpaw）"
else
  fail "D2) 没有列出其余候选的警告：err=$(echo "$err" | head -2 | tr '\n' ';')"
fi

write_agents 5 100           # 反向：把心跳对调 ⇒ 活的是 oldpaw
out="$(probe argv "886 1096")"
if [ "$out" = "oldpaw" ]; then
  ok "E) **反向**：把两条的心跳对调 ⇒ 回的 paw 跟着换成 oldpaw（按心跳选，不是按列表序/创建时间）"
else
  fail "E) 反向情形错了：out='$out'（期望 oldpaw）"
fi

echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: agent 就绪判据（含 Task 10 的 pid 复用/paw 归属两格）的离线钉子全绿"
