#!/bin/bash
# test-chain-derivation.sh —— A1 的**离线固定夹具**：用 Step 3B 的两条**真实 chain**
# 钉住"目标 TTP 与对照分开计"（Task 4D Step 4）。
#
# 为什么必须有它（brief A4）：
#   · 旧实现 `compromised = (任意 link status==0)` —— 策略在时"**对照**成功 + 目标失败"
#     会被算成 `compromised=true`，而它与真正的"目标达成"**在数据上同形**；
#   · 这两条链是**真机**产物（operation `7795106f-…` 策略在 / `2b839421-…` 策略不在），
#     不是手写的假链 ⇒ 夹具判的是"用真实数据能不能得出正确标签"。
#
# 做法：从 **harness 脚本本身**抽出那个 python 块（不另抄一份判据），在受控命名空间里跑它。
# 抽块用的是两个显式标记（见 edge_attack.sh）：`--- 派生客观结果` … `report = {`。
#
# 判据：
#   1. 策略在  ⇒ compromised=false / block_effective=true；对照仍成功（通道健康）
#   2. 策略不在⇒ compromised=true  / block_effective=false
#   3. **旧实现**（`任意 link 成功`）在策略在的那条链上会给出 true ⇒ 夹具"能在旧实现下红"
#   4. 目标 -3 且零成功 ⇒ 响亮失败（`-3` 绝不算"被拦住"）
#   5. basis=recon_playbook 且声明了目标 ⇒ 响亮失败（口径不一致）
#   6. 没有目标 link ⇒ 响亮失败（不猜标签）
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
ATTACK="$REPO/lunwen/clab-lab/scripts/edge_attack.sh"
CHAINS="${T4D_CHAINS_DIR:-$REPO/build/chains}"
WORK="${HOME:-/root}/t4d-chain-fixture"
rm -rf "$WORK"; mkdir -p "$WORK"
PASS=0; FAIL=0
ok()   { echo "  ok   $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

[ -f "$ATTACK" ] || { echo "找不到 harness 脚本 $ATTACK" >&2; exit 2; }
for f in op-policy-on.json op-policy-off.json; do
  [ -f "$CHAINS/$f" ] || { echo "缺夹具链 $CHAINS/$f（从 A-1 拷回 /root/t4d-chains）" >&2; exit 2; }
done

# --- 从 harness 脚本里抽出判据块（不另抄一份）--------------------------------
python3 - "$ATTACK" "$WORK/derive.py" <<'PY'
import sys
src = open(sys.argv[1], encoding='utf-8').read()
start_marker = '# --- 派生客观结果（状态码语义取自 c_link.py 的 states 表）--------------------'
end_marker = 'report = {'
i = src.index(start_marker)
j = src.index(end_marker, i)
open(sys.argv[2], 'w', encoding='utf-8').write(src[i:j])
print('抽出判据块 %d 字节（从 %r 到 %r 之前）' % (j - i, start_marker[:20], end_marker))
PY

# --- 跑一条链，返回派生出的关键字段 ------------------------------------------
run_case() { # $1=链文件 $2=basis $3=target_id $4=target_name $5=control_id $6=agent_import(0/1)
  python3 - "$WORK/derive.py" "$CHAINS/$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json, os, sys, time
from datetime import datetime, timezone

derive_src = open(sys.argv[1], encoding='utf-8').read()
op = json.load(open(sys.argv[2], encoding='utf-8'))
basis, target, target_name, control, agent_import = sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]

env = {
    'BASIS': basis,
    'TARGET_ABILITY': target,
    'TARGET_ABILITY_NAME': target_name,
    'CONTROL_ABILITY': control,
    'AGENT_FRESH_S': '180',
    'ATTACK_HOST': 'asc-tgt-1',
    'LAB_PIDS_HELPER': '/nonexistent',
}

class Failed(Exception):
    pass

def fake_fail(msg):
    raise Failed(msg)

def fake_api(path, method='GET', body=None, timeout=15):
    # 这个块只需要 `/agents`（判断"攻击结束时 agent 还活着吗"）；夹具里返回**链上那条 paw**
    # 对应的活 agent —— 否则"agent 失联"的守卫会先开火，测不到标签判据。
    if path == '/agents':
        chains = op.get('chain') or []
        pids = [(l.get('paw') or '') for l in chains if l.get('paw')]
        paw = pids[-1] if pids else 'paw-fixture'
        return [{'paw': paw, 'host': 'asc-tgt-1', 'pid': 790, 'trusted': True,
                 'last_seen': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}]
    raise Failed('夹具不支持 API 路径 %s' % path)

ns = {
    'os': os, 'sys': sys, 'time': time, 'json': json,
    'api': fake_api, 'fail': fake_fail,
    # 触发段设的那几个常量（抽出来的块只从这一行之后开始 ⇒ 这里显式补上，
    # 值必须与 edge_attack.sh 里 `BASIS = os.environ['BASIS']` 那几行**同源**）
    'BASIS': basis, 'TARGET_ABILITY': target, 'TARGET_ABILITY_NAME': target_name,
    'CONTROL_ABILITY': control, 'AGENT_FRESH_S': int(env['AGENT_FRESH_S']), 'ATTACK_HOST': env['ATTACK_HOST'],
    'now': lambda: datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'parse_ts': lambda ts: (datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp() if ts else None),
    'link_ability_id': lambda l: ((l.get('ability') or {}).get('ability_id') or '').strip(),
    'link_ability_name': lambda l: ((l.get('ability') or {}).get('name') or '').strip(),
    'link_time': lambda l: next((l.get(k) for k in ('collect', 'finish', 'decide') if l.get(k)), None),
    'chain': op.get('chain') or [],
    'op_id': op.get('id'),
    'state': op.get('state'),
    'counts': {},
    'start_epoch': 0.0,
}
# 环境变量：判据块用 os.environ.get 读的几个（这里显式注入，避免依赖外层 shell）
env_orig = dict(os.environ)
os.environ.update(env)
if agent_import == '1':
    ns['live_sandcat_pids'] = lambda: {790}          # 假装容器内活着的是 pid 790
else:
    ns['live_sandcat_pids'] = lambda: set()          # 容器里没有任何活 sandcat ⇒ 失联
ns['agent_alive'] = lambda a, live: (a.get('pid') in live and
                                     (a.get('last_seen') or '') != '')
ns['alive_at_end'] = [a for a in fake_api('/agents') if ns['agent_alive'](a, ns['live_sandcat_pids']())]
ns['agents_live'] = sorted({a['paw'] for a in ns['alive_at_end']})
ns['paws'] = {l.get('paw') for l in ns['chain'] if l.get('paw')}
ns['attempted'] = [l for l in ns['chain'] if l.get('status') not in (-2, -5)]

try:
    exec(compile(derive_src, 'derive', 'exec'), ns)
except Failed as exc:
    print(json.dumps({'loud_failure': str(exc)}, ensure_ascii=False))
    raise SystemExit(0)
finally:
    os.environ.clear(); os.environ.update(env_orig)

print(json.dumps({
    'compromised': ns.get('compromised'),
    'block_effective': ns.get('block_effective'),
    'target_links': len(ns.get('target_links') or []),
    'target_successes': len(ns.get('target_successes') or []),
    'control_links': len(ns.get('control_links') or []),
    'control_successes': len(ns.get('control_successes') or []),
    'other_links': len(ns.get('other_links') or []),
    'ttps_achieved': len(ns.get('successes') or []),
    # 旧实现的口径（用于证明"夹具能在旧实现下红"）
    'legacy_compromised': len(ns.get('successes') or []) > 0,
    'legacy_block_effective': len(ns.get('successes') or []) == 0,
}, ensure_ascii=False))
PY
}

TID="a5c0ffee-0000-4000-8000-0000000003b1"
TNAME="T4D Step 3B: read /etc/shadow (AppArmor target TTP)"
CID="a5c0ffee-0000-4000-8000-0000000003c1"

echo "############ 1) 策略**在**（真实链 7795106f-…）：目标 status=1、对照 status=0"
OUT_ON="$(run_case op-policy-on.json targeted_ttp "$TID" "$TNAME" "$CID" 1)"
echo "  派生：$OUT_ON"
python3 - "$OUT_ON" <<'PY'
import json, sys
g = json.loads(sys.argv[1])
ok = (g['compromised'] is False and g['block_effective'] is True
      and g['target_successes'] == 0 and g['control_successes'] == 1)
print(('  ok   ' if ok else '  FAIL ') + 'compromised=false / block_effective=true（对照仍成功 ⇒ 通道健康）')
print('  ' + ('ok   ' if g['legacy_compromised'] is True else 'FAIL ') +
      '旧口径在这条链上会给出 compromised=true ⇒ 夹具**能在旧实现下红**（实测旧值=%s）' % g['legacy_compromised'])
sys.exit(0 if ok else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+2)) || { FAIL=$((FAIL+2)); }

echo
echo "############ 2) 策略**不在**（真实链 2b839421-…）：目标 status=0（链上还有一条陈旧 -3）"
OUT_OFF="$(run_case op-policy-off.json targeted_ttp "$TID" "$TNAME" "$CID" 1)"
echo "  派生：$OUT_OFF"
python3 - "$OUT_OFF" <<'PY'
import json, sys
g = json.loads(sys.argv[1])
ok = (g['compromised'] is True and g['block_effective'] is False and g['target_successes'] == 1)
print(('  ok   ' if ok else '  FAIL ') + 'compromised=true / block_effective=false')
# 那条 status=-3 属于**对照** ability（陈旧 agent），它不得把标签顶起来、也不得把标签压下去
print('  ' + ('ok   ' if g['other_links'] == 0 else 'FAIL ') + '陈旧对照 link 归类正确（other_links=%d）' % g['other_links'])
sys.exit(0 if ok else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+2)) || { FAIL=$((FAIL+2)); }

echo
echo "############ 3) 目标 -3 且零成功 ⇒ 响亮失败（-3 不算被拦住）"
python3 - "$CHAINS/op-policy-on.json" "$CHAINS/op-target-execute.json" <<'PY'
import json, sys
# 直接改一条链：把目标 link 的 status 改成 -3（模拟"打到死 agent"）
op = json.load(open(sys.argv[1], encoding='utf-8'))
op['id'] = op['id'] + '-stale-variant'
for l in op['chain']:
    if (l.get('ability') or {}).get('ability_id', '').endswith('3b1'):
        l['status'] = -3
json.dump(op, open(sys.argv[2], 'w'), ensure_ascii=False, indent=2)
print('  造出变异链:', sys.argv[2])
PY
OUT_STALE="$(run_case op-target-execute.json targeted_ttp "$TID" "$TNAME" "$CID" 1 2>/dev/null || true)"
echo "  派生：$OUT_STALE"
python3 - "$OUT_STALE" <<'PY'
import json, sys
try:
    g = json.loads(sys.argv[1])
except Exception:
    print('  FAIL 夹具输出不是 JSON: %r' % sys.argv[1][:200]); sys.exit(1)
msg = g.get('loud_failure') or ''
ok = 'EXECUTE' in msg
print(('  ok   ' if ok else '  FAIL ') + '目标 link 全为 -3 且零成功 ⇒ 响亮失败（EXECUTE 不算被拦住）')
print('     ' + msg[:200])
sys.exit(0 if ok else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "############ 4) basis=recon_playbook 且声明了目标 ⇒ 由 shell 侧拒绝（口径不一致）"
bash -c "EDGEEXP_BASIS=recon_playbook EDGEEXP_TARGET_ABILITY=$TID bash '$ATTACK' S0-baseline /tmp/x.json" 2>&1 | head -2
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then ok "退出码非零（$rc）—— 口径不一致被拒绝"; PASS=$((PASS+1)); else bad "没有拒绝"; FAIL=$((FAIL+1)); fi

echo
echo "############ 5) 没有目标 link ⇒ 响亮失败（不猜标签）"
OUT_NOTARGET="$(run_case op-policy-off.json targeted_ttp 'deadbeef-0000-4000-8000-000000000000' '' "$CID" 1 2>/dev/null || true)"
echo "  派生：$OUT_NOTARGET"
python3 - "$OUT_NOTARGET" <<'PY'
import json, sys
g = json.loads(sys.argv[1]) if sys.argv[1].strip() else {}
msg = g.get('loud_failure') or ''
ok = '没有' in msg and '目标 ability' in msg
print(('  ok   ' if ok else '  FAIL ') + '链上没有目标 ability 的 link ⇒ 响亮失败（不写任何标签）')
print('     ' + msg[:160])
sys.exit(0 if ok else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: chain 派生夹具全绿"
