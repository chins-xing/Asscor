#!/bin/bash
# ============================================================================
# edge_agent_preflight.sh —— 跑批前的 **agent 复核 / 清理**（Task 10 Step 4.2）
# ============================================================================
#
# **为什么要有它**：Caldera **保留已死 agent 的条目**，而容器里的 **pid 会被复用**
# （同一个 CT 重启后 sandcat 常常还是 `pid=312`）。于是同一台机器上可能同时存在
# "已死记录"与"当前在跳的记录"，两者**记着同一个 pid** —— 现场实测出现过
# `thgfyz`（死）/ `vfljce`（活）、以及更早的 `bvecgb`（死）/ `thgfyz`（活）。
# 这种残留会让三件事**静默错**：
#   ① 复位的日志把 paw 报成上一只（"产物说 A、现场是 B"）——已由
#      `edge_target_prepare.sh` 的 `live_agent_paws` 取"心跳最新"修掉；
#   ② 攻击脚本按 `(host, 活 pid)` 挑 agent 时命中已死的那只 ⇒ link `status=-3`，
#      而 `-3` **看起来像"被拦住"**（会直接扭曲标签）；
#   ③ 现场越跑越脏，全量 75 次跑批之后无法回答"这一轮到底打的是哪个 agent"。
#
# ## 判据（四条**同时**成立才算"活着的 agent"，与 `live_agent_paws` 逐条同源）
#   1. `host` == `EDGEEXP_TARGET`（默认 `asc-tgt-c2`）
#   2. `trusted` == `true`
#   3. `pid` ∈ **容器内当前活着的 sandcat pid**（`lab_node_pids`，由基质层取）
#   4. `last_seen` ≥ now − `EDGEEXP_AGENT_FRESH_S`（默认 180s；心跳停了就不是活的）
#
#   · 命中 **1 条** ⇒ 干净
#   · 命中 **0 条** ⇒ 目标上没有活 agent（退出码 1：跑批前需要先复位/拉起）
#   · 命中 **>1 条** ⇒ **pid 复用 + 残留**：心跳最新的那条是"活着的"，其余全部是残留
#     （退出码 10；`--clean` 会把残留删掉）
#   · `host` 相同但 **pid 不在活 pid 里**、或 `trusted=false`、或心跳过期 ⇒ 也一律算残留
#     （它们同样会污染"哪只 agent 是这一轮的"这个问题）
#
# ## 用法
#   edge_agent_preflight.sh              # 只复核（**不改现场**；给表格）
#   edge_agent_preflight.sh --clean      # 复核 + 删除残留（删除前把整份 agent 列表留档到 JSON）
#
# 退出码：0 = 恰好 1 只活 agent 且无残留；10 = 有残留（`--clean` 时已删）；1 = 没有活 agent。
#
# ## 环境变量
#   EDGEEXP_TARGET           目标节点名（基质层的名字，默认 asc-tgt-c2）
#   EDGEEXP_SUBSTRATE        clab（默认）| lxd | pve（决定 pid 怎么取）
#   EDGEEXP_CALDERA_URL/KEY  C2（URL 默认 http://192.168.30.2:8888；**KEY 无默认值** ——
#                            取法见 scripts/edge_c2_key.sh：环境变量 → 未跟踪的本地配置 → 响亮失败）
#   EDGEEXP_AGENT_FRESH_S    心跳新鲜度上限（秒，默认 180）
#   EDGEEXP_AGENTS_FIXTURE   **离线测试缝**：用 JSON 文件里的 agent 列表替掉真实 API
#                            （判据同源；离线夹具用它做正反两向证据）
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 这里原先有一行死变量 `REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"`（Task 14 Step 4 清掉）：
# ① 全文件只出现这一次赋值、**没有任何读取点**；② 而且它少算一层（`$SCRIPT_DIR/../..` = `<repo>/lunwen`
# 而不是仓库根 —— 仓库根是往上**三层**，见 tests/ 与 edge_prebatch_check.sh 的同一口径）。
# 因为无人使用，这个错一直没现形；留着它只会让下一个人以为"这里有个能用的仓库根"。
# shellcheck source=scripts/edge_lab.sh
. "$SCRIPT_DIR/edge_lab.sh"

TARGET="${EDGEEXP_TARGET:-asc-tgt-c2}"
# C2 API key：**不再有明文默认值**（Task 14 脱敏 D2）。取值顺序与三条红线见 edge_c2_key.sh；
# 缺 key 时它**当场 exit 2** —— 本脚本的全部判据都建立在"从 C2 取到 agent 列表"之上。
# shellcheck source=scripts/edge_c2_key.sh
. "$SCRIPT_DIR/edge_c2_key.sh"
edge_require_c2_key edge_agent_preflight.sh
# C2 地址也在**取值之后**解析（理由同 edge_reset.sh：本地配置里通常同时给 KEY 与 URL）。
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://192.168.30.2:8888}"
CALDERA_KEY="$EDGEEXP_CALDERA_KEY"
FRESH="${EDGEEXP_AGENT_FRESH_S:-180}"
CLEAN=0
[ "${1:-}" = "--clean" ] && CLEAN=1

# 容器内当前活着的 sandcat pid（基质层取；取不到 ⇒ **响亮失败**，不猜）。
PIDS="$(lab_node_pids "$TARGET" sandcat 2>/dev/null | tr '\n' ' ')"
PIDS_RC=$?
if [ "$PIDS_RC" -ne 0 ]; then
  echo "edge_agent_preflight: 取不到容器内活 sandcat pid（$lab_target_bin，节点 $TARGET）—— 实例不存在/没在跑？" >&2
  exit 1
fi

OUT="$(mktemp)"
python3 - "$CALDERA_URL" "$CALDERA_KEY" "$TARGET" "$FRESH" "$PIDS" "${EDGEEXP_AGENTS_FIXTURE:-}" "$CLEAN" "$OUT" <<'PY'
import json, sys, time, urllib.request
from datetime import datetime, timezone

api, key, host = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3]
fresh, pid_s, fixture, clean, out = int(sys.argv[4]), sys.argv[5], sys.argv[6].strip(), sys.argv[7] == '1', sys.argv[8]
pids = sorted(int(x) for x in pid_s.split() if x.strip().isdigit())


def api_call(path, method='GET'):
    req = urllib.request.Request(api + path, headers={'KEY': key}, method=method)
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode('utf-8') or '{}'
    try:
        return json.loads(body)
    except Exception:
        return {}


if fixture:
    agents = json.load(open(fixture, encoding='utf-8'))
    src = 'fixture:%s' % fixture
else:
    try:
        agents = api_call('/api/v2/agents')
    except Exception as exc:
        print('edge_agent_preflight: 取 Caldera agent 列表失败：%s' % exc, file=sys.stderr)
        raise SystemExit(2)
    src = api

now = time.time()
rows, live, stale = [], [], []
for a in agents:
    if a.get('host') != host:
        continue
    paw = a.get('paw') or '?'
    try:
        seen = datetime.fromisoformat((a.get('last_seen') or '').replace('Z', '+00:00')).timestamp()
    except Exception:
        seen = None
    is_live = (a.get('trusted') is True
               and a.get('pid') is not None and int(a['pid']) in pids
               and seen is not None and seen >= now - fresh)
    rows.append((paw, a.get('pid'), bool(a.get('trusted')), seen, a.get('created'), is_live))
    (live if is_live else stale).append((paw, seen, a.get('created')))

live.sort(key=lambda r: (r[1] or 0, r[2] or ''), reverse=True)
keep = live[0] if live else None
# **注意**：命中多条时"活着的"是**心跳最新**的那条（pid 复用 ⇒ 其余是同 pid 的残留），
# 与 `edge_target_prepare.sh` 的 `live_agent_paws` 同一条规则。
rest = [r for r in live[1:]] + stale

print('edge_agent_preflight: C2=%s 节点=%s 容器内活 sandcat pid=%s 新鲜度≤%ds（agent 表来源 %s）'
      % (api, host, pids or '（无）', fresh, src))
print('  %-8s %-7s %-8s %-22s %-22s %s' % ('paw', 'pid', 'trusted', 'last_seen', 'created', '判定'))
for paw, pid, trusted, seen, created, is_live in sorted(rows, key=lambda r: r[3] or 0, reverse=True):
    verdict = '活着的（keep）' if (keep and paw == keep[0]) else ('残留（delete）' if rows else '')
    print('  %-8s %-7s %-8s %-22s %-22s %s' % (
        paw, pid, trusted,
        datetime.fromtimestamp(seen, timezone.utc).strftime('%FT%TZ') if seen else '（不可解析）',
        created or '?', verdict))

if not pids:
    print('edge_agent_preflight: 容器内**没有**活着的 sandcat ⇒ 没有"活着的 agent"（跑批前先复位拉起）', file=sys.stderr)
    raise SystemExit(1)
if not rows:
    print('edge_agent_preflight: 这台机器在 C2 上**没有任何** agent 记录 ⇒ 需要先复位拉起', file=sys.stderr)
    raise SystemExit(1)
if keep is None:
    print('edge_agent_preflight: 有 agent 记录，但**没有一条**满足四条判据（trusted/pid/心跳）'
          '⇒ 跑批前必须先复位拉起一只新的', file=sys.stderr)
    raise SystemExit(1)

if rest:
    print('edge_agent_preflight: **有残留**：%d 条（%s）—— 它们与活着的 %s 记着同一个 pid 或心跳已过期'
          % (len(rest), ', '.join(r[0] for r in rest), keep[0]), file=sys.stderr)
    if clean:
        snap = out + '.agents.json'
        with open(snap, 'w', encoding='utf-8') as fh:
            json.dump(agents, fh, ensure_ascii=False, indent=2)
        print('edge_agent_preflight: 删除前留档 → %s' % snap)
        if not fixture:
            for paw, _s, _c in rest:
                try:
                    api_call('/api/v2/agents/' + paw, method='DELETE')
                    print('edge_agent_preflight: 已删除残留 agent %s' % paw)
                except Exception as exc:
                    print('edge_agent_preflight: 删除 %s 失败：%s' % (paw, exc), file=sys.stderr)
        else:
            print('edge_agent_preflight: （fixture 模式：不真的删）')
    raise SystemExit(10)

print('edge_agent_preflight: 干净 —— 恰好 1 只活着的 agent（%s，pid=%s），无残留' % (keep[0], pids))
raise SystemExit(0)
PY
RC=$?
rm -f "$OUT"
exit "$RC"
