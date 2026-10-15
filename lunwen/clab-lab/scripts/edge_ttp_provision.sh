#!/bin/bash
# ============================================================================
# edge_ttp_provision.sh —— **幂等**地建出 T4D pair 剧本的三件 Caldera 实体
# （Task 8 Step ①；ID 与 A-1 上的**逐字相同**）
# ============================================================================
#
# 为什么需要它（Task 8 的阻塞项）：
#   `edge_matrix.sh` 把"注入因子含 EF-SELINUX/EF-APPARMOR"的 11 个场景判成 `targeted_ttp`，
#   并要求给 `EDGEEXP_TTP_TARGET_ABILITY` / `EDGEEXP_TTP_CONTROL_ABILITY` /
#   `EDGEEXP_TTP_PLAYBOOK_ID`。这套口径在 A-1 上有对应实体，但**是手工建的、仓里没有创建脚本**
#   ⇒ 换一台 C2（dl360gen9 上的这个 Caldera）就**没有它们**，25 个场景一齐跑会被门禁整批拒绝。
#   本脚本把"怎么建"变成**可跟踪、可重跑**的东西 —— 这既是 provisioning，也是**记档**。
#
# 三件实体（语义取自 A-1 试点 `lunwen/clab-lab/experiments-final/pilot-step5-2026-09-13/`
# 的原始 chain 与 README，**逐字保留**；ID 也逐字保留，故 L2 判据夹具
# `lunwen/clab-lab/tests/fixtures/chains/*.json` 与真机对得上）：
#
#   · 目标 ability  a5c0ffee-0000-4000-8000-0000000003b1
#       名字 T4D Step 3B: read /etc/shadow (AppArmor target TTP)
#       命令 head -1 /etc/shadow        tactic credential-access / T1003.008
#       —— 它**撞 AppArmor 策略**：策略在 ⇒ 被拒（`compromised=false`）；策略不在 ⇒ 成功。
#
#   · 对照 ability  a5c0ffee-0000-4000-8000-0000000003c1
#       名字 T4D Step 3B control: write marker (no policy collision)
#       命令 echo t4d-control-ok > /tmp/t4d-control-marker && cat /tmp/t4d-control-marker
#       tactic execution / T1059.004
#       —— 它**不撞策略**，用来回答"通道与执行器健不健康"：
#          对照失败 ⇒ 目标失败不能归因于策略；对照成功而目标失败 ⇒ 那才是策略拦住的。
#
#   · pair 剧本     a5c0ffee-0000-4000-8000-0000000003c2
#       名字 T4D Step 3B pair (control + target TTP)
#       atomic_ordering [ …3c1, …3b1 ]（**先对照、后目标**）
#       objective 495a9828-cab1-44dd-a0ca-66e58177d8cc（Caldera 自带的 `default`）
#       tags [t4d-step3b, pair]
#
# **不得拿别的 ability 冒充**（比如用 Caldera 自带的 `Access /etc/shadow (Local)`）：
# 自带那条的执行器是 `sudo cat /etc/shadow > /tmp/T1003.008.txt; cat …`，与 A-1 上被判据
# 引用的那一条**命令不同**；换掉它，链上看到的 command 就与已落盘的历史数据不可比。
# 这里只借用现成 Linux ability 的 **executor 字段形状**（`sh` / `platform: linux` / timeout），
# 命令与 ID 一律用 A-1 的原文。
#
# 幂等：已存在则不重建，而是**核对关键字段**（命令 / ordering）—— 不一致就**响亮失败**，
# 因为那意味着"夹具/文档里的 ID 与 C2 上的实体不是同一个东西"，比"缺实体"更难发现。
#
# 用法：
#   EDGEEXP_CALDERA_URL=http://192.168.30.2:8888 EDGEEXP_CALDERA_KEY='<C2 API 口令>' \
#     bash scripts/edge_ttp_provision.sh
#   （KEY **不再有明文默认值** —— 也可以写进未跟踪的本地配置，见 scripts/edge_c2_key.sh）
#
# 退出码：0 = 三件实体都在且字段核对通过；非零 = 任一步失败（不降级）。
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://127.0.0.1:8888}"
# C2 API key：**不再有明文默认值**（Task 14 脱敏 D2）。取值顺序与三条红线见 edge_c2_key.sh；
# 缺 key 时它**当场 exit 2** —— "三件实体都在且字段核对通过"这个判据必须真的问过 C2。
# shellcheck source=scripts/edge_c2_key.sh
. "$SCRIPT_DIR/edge_c2_key.sh"
edge_require_c2_key edge_ttp_provision.sh
CALDERA_KEY="$EDGEEXP_CALDERA_KEY"
command -v python3 >/dev/null 2>&1 || { echo "edge_ttp_provision: 缺少 python3" >&2; exit 2; }

TARGET_ID="a5c0ffee-0000-4000-8000-0000000003b1"
CONTROL_ID="a5c0ffee-0000-4000-8000-0000000003c1"
PLAYBOOK_ID="a5c0ffee-0000-4000-8000-0000000003c2"
TARGET_CMD='head -1 /etc/shadow'
CONTROL_CMD='echo t4d-control-ok > /tmp/t4d-control-marker && cat /tmp/t4d-control-marker'

echo "edge_ttp_provision: Caldera = $CALDERA_URL"

python3 - "$CALDERA_URL" "$CALDERA_KEY" "$TARGET_ID" "$CONTROL_ID" "$PLAYBOOK_ID" "$TARGET_CMD" "$CONTROL_CMD" <<'PY'
import json, sys, urllib.request, urllib.error

api = sys.argv[1].rstrip('/') + '/api/v2'
key = sys.argv[2]
TID, CID, PID, TCMD, CCMD = sys.argv[3:8]
fail = []


def call(path, method='GET', body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method,
                                 headers={'KEY': key, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:
        return 0, str(e)


# executor 字段形状**借自**本 C2 上现成的一条 Linux ability（`sh` / `platform: linux`），
# 命令与 ID 用 A-1 的原文。
def executor(command, cleanup):
    return {'name': 'sh', 'platform': 'linux', 'command': command,
            'payloads': [], 'uploads': [], 'timeout': 60, 'parsers': [],
            'cleanup': cleanup, 'variations': [], 'additional_info': {}}


def ability(aid, name, desc, tactic, tech_id, tech_name, command, cleanup):
    return {'ability_id': aid, 'name': name, 'description': desc, 'tactic': tactic,
            'technique_id': tech_id, 'technique_name': tech_name,
            'executors': [executor(command, cleanup)], 'requirements': [],
            'privilege': '', 'repeatable': False, 'buckets': [tactic],
            'additional_info': {}, 'access': {}, 'singleton': False, 'plugin': ''}


SPECS = [
    (TID, ability(TID, 'T4D Step 3B: read /etc/shadow (AppArmor target TTP)',
                  '目标 TTP：撞 AppArmor 对 /etc/shadow 的拒绝策略。策略在 ⇒ 被拒；策略不在 ⇒ 成功。\n',
                  'credential-access', 'T1003.008',
                  'OS Credential Dumping: /etc/passwd, /etc/master.passwd and /etc/shadow',
                  TCMD, []), 'command', TCMD),
    (CID, ability(CID, 'T4D Step 3B control: write marker (no policy collision)',
                  '对照：写一个 marker，不撞任何策略。用来证明通道与执行器是健康的。\n',
                  'execution', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell',
                  CCMD, ['rm -f /tmp/t4d-control-marker']), 'command', CCMD),
]

for aid, body, cmpf, want in SPECS:
    status, got = call('/abilities/' + aid)
    if status == 200:
        have = ((got.get('executors') or [{}])[0] or {}).get(cmpf)
        if have != want:
            fail.append('%s 已存在但 %s 不一致：C2=[%r] 期望=[%r]'
                        '（说明 C2 上的实体与夹具/文档引用的不是同一个东西）' % (aid, cmpf, have, want))
        else:
            print('  [已存在·核对通过] ability %s  %s' % (aid, got.get('name')))
        continue
    if status != 404:
        fail.append('查询 ability %s 失败：HTTP %s %s' % (aid, status, got)); continue
    st, res = call('/abilities', 'POST', body)
    if st in (200, 201):
        print('  [新建] ability %s  %s' % (aid, body['name']))
    else:
        fail.append('创建 ability %s 失败：HTTP %s %s' % (aid, st, res))

adv = {'adversary_id': PID, 'name': 'T4D Step 3B pair (control + target TTP)',
       'description': '两条 ability 的同一条 operation：先写标记（对照），再读 /etc/shadow（目标 TTP）。',
       'atomic_ordering': [CID, TID],
       'objective': '495a9828-cab1-44dd-a0ca-66e58177d8cc',
       'tags': ['t4d-step3b', 'pair'], 'has_repeatable_abilities': False, 'plugin': ''}

status, got = call('/adversaries/' + PID)
if status == 200:
    if list(got.get('atomic_ordering') or []) != [CID, TID]:
        fail.append('adversary %s 已存在但 atomic_ordering 不一致：C2=%r 期望=%r'
                    % (PID, got.get('atomic_ordering'), [CID, TID]))
    else:
        print('  [已存在·核对通过] adversary %s  %s' % (PID, got.get('name')))
elif status == 404:
    st, res = call('/adversaries', 'POST', adv)
    if st in (200, 201):
        print('  [新建] adversary %s  %s' % (PID, adv['name']))
    else:
        fail.append('创建 adversary %s 失败：HTTP %s %s' % (PID, st, res))
else:
    fail.append('查询 adversary %s 失败：HTTP %s %s' % (PID, status, got))

if fail:
    for f in fail:
        print('edge_ttp_provision: **失败** ' + f, file=sys.stderr)
    raise SystemExit(1)
print('edge_ttp_provision: 三件实体就绪（目标 %s / 对照 %s / 剧本 %s）' % (TID, CID, PID))
PY
rc=$?
[ "$rc" -eq 0 ] || exit "$rc"

echo "edge_ttp_provision: 供跑批用的变量（**五个，不是三个**；其中**必需 3 个、可选 2 个**）："
echo "  —— 必需 3 个（选中 targeted 场景时缺任一，矩阵层干跑就 rc=2）——"
echo "  EDGEEXP_TTP_TARGET_ABILITY=$TARGET_ID"
echo "      # 目标 TTP：$TARGET_CMD"
echo "  EDGEEXP_TTP_PLAYBOOK_ID=$PLAYBOOK_ID"
echo "      # pair 剧本（先对照、后目标）"
echo "  EDGEEXP_TTP_PLAYBOOK_NAME='T4D Step 3B pair (control + target TTP)'"
echo "      # **必须给**：edge_attack.sh 的剧本名默认是 'Discovery'，而它有一条"
echo "      #   **剧本漂移守卫**（'剧本 ID … 现在的名字是 …，与固定的 Discovery 不符'）。"
echo "      #   只给 ID 不给名字 ⇒ targeted_ttp 的每一轮都会在攻击步被拒（Task 8 实测踩到）；"
echo "      #   2026-10-13 起矩阵层也拦它（缺了在**干跑**就 rc=2）。"
echo "  —— 可选 2 个（给了更好，缺了不会被拒；源码判据见 edge_attack.sh:49/:816/:852）——"
echo "  EDGEEXP_TTP_CONTROL_ABILITY=$CONTROL_ID"
echo "      # 对照：$CONTROL_CMD"
echo "      # 可选：只用于归类与报告（没有它目标 link 照样能算出来）"
echo "  EDGEEXP_TTP_TARGET_ABILITY_NAME='T4D Step 3B: read /etc/shadow (AppArmor target TTP)'"
echo "      # 可选：仅用于**核对 ID 没被换掉**（漂移守卫的可选那一半），建议一起给"
exit 0
