#!/bin/bash
# test-matrix-classification.sh —— 矩阵层**条件分类**的离线回归钉子
# （Task 8 复审的 Important：`edge_matrix.sh` 那个尾随空格）
#
# 为什么必须有它（复审实测，不是推断）：
#   `27d8050` 在**非缺失路径**（采集器在位）里把
#       SCEN_FACTORS_RAW="$( … )"
#   写成了
#       SCEN_FACTORS_RAW="$( … ) "      ← 双引号内多一个空格
#   于是 `SCEN_FACTORS_RAW` 的值结尾多一个空格 ⇒ `while IFS=$'\t' read` 解析出的
#   **最后一行**的因子串变成 `EF-NO-SIEM `（带尾随空白）。而分类判据是
#       local csv=",${SCEN_FACTORS[$1]:-},"   +   case "$csv" in *",$f,"*)
#   —— 逗号边界被那个空格破坏 ⇒ 恰好这**一个**场景被判成 `recon_playbook + POLICY_ON=1`
#   （复审实测：`EDGEEXP_TTP_FACTORS=EF-NO-SIEM` 时 BASE 8 targeted / 有缺陷版 7 targeted，
#   `R-no-siem` 被翻转）。默认因子集下"恰好"不影响分类（最后一行不含 TTP 因子），
#   所以它是一颗**埋着的雷**：分类会取决于"场景表里哪一行排在最后"或"TTP 因子集怎么配"，
#   而计划表的"合计 == 25"断言**照样通过** —— 正是"看起来正常、其实全错"那一类。
#
# 这个夹具怎么钉住它（**不靠手工复核**）：造一个**桩采集器**，把 TTP 触发因子挂在
# **最后一行**（尾随空白缺陷恰好只打最后一行），再跑真 `edge_matrix.sh` 的干跑，
# 然后断言四件事 —— 最后一行必须是 `targeted_ttp`、条件分布必须是 1/24、
# 计划表里**不得**出现"因子串带尾随空白"的痕迹、以及非最后一行也要照样分类正确。
#
# 判据（6 条，逐条可判真假）：
#   1. 桩表被脚本接受（名单逐项相等）⇒ 干跑 rc=0
#   2. **最后一行**（挂着 TTP 因子的那行）判 `basis=targeted_ttp`
#   3. 条件分布 = `targeted_ttp=1 ｜ recon_playbook=24 ｜ 合计 25`
#   4. 计划表里"因子=…"到"｜"之间**恰好一个空格**（多一个就是尾随空白渗进了因子串）
#   5. 反例对照：同一个因子集换成**不含任何行因子**的值 ⇒ 该行判 `recon_playbook`
#      （证明这条分类**真的读了因子集**，不是恒真）
#   6. 非最后一行同样分类正确（防止"只给最后一行打补丁"式的修法）
#
# 纪律：**只读、离线** —— 不碰 clab / LXD / 容器 / Caldera，不写仓库（临时目录在 $HOME）。
# 基质用默认 `clab`：干跑路径只在 `pve` 下才会去问 `pct list`（`lab_target_spec`），
# 用 clab 可以让这个夹具在任何 Linux 上都跑起来，而**分类逻辑与基质无关**。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
MATRIX="$REPO/lunwen/clab-lab/scripts/edge_matrix.sh"
WORK="${HOME:-/root}/t8-matrix-fixture"
rm -rf "$WORK"; mkdir -p "$WORK"
PASS=0; FAIL=0
ok()  { echo "  ok   $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

[ -f "$MATRIX" ] || { echo "找不到矩阵脚本 $MATRIX" >&2; exit 2; }

# --- 场景名单从**脚本本身**抽（不另抄一份；名单漂移时这里要能看出来）-------------
mapfile -t NAMES < <(sed -n '/^SCENARIOS=(/,/^)/p' "$MATRIX" | sed '1d;$d' | tr -s '[:space:]' '\n' | grep -v '^$')
if [ "${#NAMES[@]}" -ne 25 ]; then
  echo "从 $MATRIX 抽出的场景名是 ${#NAMES[@]} 个（期望 25）—— 抽法或名单变了，夹具必须先跟着改" >&2
  exit 2
fi
LAST="${NAMES[${#NAMES[@]}-1]}"
FIRST="${NAMES[0]}"
echo "  场景名单 25 个（第 1 行 $FIRST ／ 最后一行 $LAST）"

# --- 桩采集器：TTP 触发因子挂在**最后一行** -----------------------------------
LAST_FACTOR="EF-NO-SIEM"      # "挂在最后一行"的那个因子（缺陷恰好只打最后一行）
OTHER_FACTOR="EF-002FA"
STUB="$WORK/stub-edgescen"
{
  printf '#!/bin/bash\n'
  printf '# 桩采集器（只给这个夹具用）：只支持 -list，形状与 edgescen -list 一致。\n'
  printf 'case "${1:-}" in\n'
  printf '  -list)\n'
  printf 'cat <<%s\n' "'TBL'"
  i=0
  for n in "${NAMES[@]}"; do
    i=$((i + 1))
    if [ "$i" -eq "${#NAMES[@]}" ]; then
      printf '  %s  注入=check_fail   因子=%s\n' "$n" "$LAST_FACTOR"
    else
      printf '  %s  注入=check_fail   因子=%s\n' "$n" "$OTHER_FACTOR"
    fi
  done
  printf 'TBL\n'
  printf '    ;;\n'
  printf '  *)\n'
  printf '    echo "stub-edgescen: 只支持 -list（收到 ${1:-}）" >&2; exit 2 ;;\n'
  printf 'esac\n'
} > "$STUB"
chmod +x "$STUB"
echo "  桩采集器 : $STUB（最后一行 $LAST 的因子 = $LAST_FACTOR，其余 = $OTHER_FACTOR）"

TID="a5c0ffee-0000-4000-8000-0000000003b1"
PID="a5c0ffee-0000-4000-8000-0000000003c2"
PNAME="T4D Step 3B pair (control + target TTP)"

# --- 跑真脚本的干跑（不发任何攻击、不建任何环境）---------------------------------
run_dry() { # $1=TTP 因子集；其余 = 选中的场景（无则全量 25）
  local factors="$1"; shift
  env -u EDGEEXP_RECORDS -u EDGEEXP_RESUME -u EDGEEXP_RUN_INDEX \
      -u EDGEEXP_BASELINE_FACTORS -u EDGEEXP_BASELINE_FACTORS_SOURCE \
      -u EDGEEXP_TTP_CONTROL_ABILITY -u EDGEEXP_TTP_TARGET_ABILITY_NAME \
      EDGEEXP_SUBSTRATE=clab EDGEEXP_DRY_RUN=1 EDGEEXP_EDGESCEN="$STUB" \
      EDGEEXP_DATA_DIR="$WORK/data" EDGEEXP_TTP_FACTORS="$factors" \
      EDGEEXP_TTP_TARGET_ABILITY="$TID" EDGEEXP_TTP_PLAYBOOK_ID="$PID" \
      EDGEEXP_TTP_PLAYBOOK_NAME="$PNAME" \
      bash "$MATRIX" "$@"
}

echo
echo "############ 1) 桩表被接受 ⇒ 25 场景干跑 rc=0（不给 TTP 变量无关，本情形三个必需项已给）"
run_dry "$LAST_FACTOR" > "$WORK/out-full.txt" 2>&1; RC_FULL=$?
echo "  rc=$RC_FULL；条件分布那一行："
grep -E '条件分布' "$WORK/out-full.txt" | sed 's/^/    /'
python3 - "$WORK/out-full.txt" "$RC_FULL" <<'PY'
import sys, re
out = open(sys.argv[1], encoding='utf-8').read()
rc = int(sys.argv[2])
want = '合计 25 个（必须 == 25）'
# 干跑门禁的**原文**（只有分类塌成常量时才会出现；注意计划表抬头那句"两列都必须不是常量"
# 里也有"常量"两个字，故判据必须取更长的、门禁自己那句 —— 否则这条会假红）。
gate = '是**常量**'
dist = next((l for l in out.splitlines() if '条件分布' in l), '')
ok = (rc == 0 and want in dist)
print(('  ok   ' if ok else '  FAIL ') + '干跑 rc=0 且「合计 25」出现（rc=%d）' % rc)
print('  ' + ('ok   ' if gate not in out else 'FAIL ') +
      '没有触发「basis/policy 是**常量**」那条门禁（触发即说明 TTP 因子一个都没被认出来）')
sys.exit(0 if (ok and gate not in out) else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+2)) || FAIL=$((FAIL+2))

echo
echo "############ 2)+3) 最后一行必须判 targeted_ttp；条件分布必须是 1 / 24"
python3 - "$WORK/out-full.txt" "$LAST" <<'PY'
import sys, re
out = open(sys.argv[1], encoding='utf-8').read().splitlines()
last, name = sys.argv[2], sys.argv[2]
line = next((l for l in out if re.search(r'\[\s*\d+/\s*\d+\]\s+%s\b' % re.escape(name), l)), '')
hit = 'basis=targeted_ttp' in line and 'policy=0' in line
print(('  ok   ' if hit else '  FAIL ') + '最后一行 %s 判 basis=targeted_ttp policy=0' % name)
print('      %s' % line.strip()[:160])
dist = next((l for l in out if '条件分布' in l), '')
m = re.search(r'targeted_ttp=(\d+)\s+个\s+｜\s+recon_playbook=(\d+)\s+个', dist)
tgt, rec = (int(m.group(1)), int(m.group(2))) if m else (-1, -1)
d_ok = (tgt == 1 and rec == 24)
print(('  ok   ' if d_ok else '  FAIL ') + '条件分布 targeted_ttp=1 ｜ recon_playbook=24（实测 %d ｜ %d）' % (tgt, rec))
sys.exit(0 if (hit and d_ok) else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+2)) || FAIL=$((FAIL+2))

echo
echo "############ 4) 计划表里「因子=…」到「｜」之间必须**恰好一个空格**（尾随空白的直接痕迹）"
python3 - "$WORK/out-full.txt" <<'PY'
import re, sys
bad = []
n = 0
for line in open(sys.argv[1], encoding='utf-8').read().splitlines():
    m = re.search(r'因子=(.*?)｜', line)
    if not m:
        continue
    n += 1
    seg = m.group(1)                      # 正常形态 = "<因子串>" + 恰好一个分隔空格
    if not seg.endswith(' ') or seg.endswith('  ') or seg != seg.lstrip():
        bad.append((seg, line.strip()[:120]))
print('  检查了 %d 行计划表' % n)
if n < 25:
    print('  FAIL 计划表行数 %d < 25（干跑没打全）' % n); sys.exit(1)
if bad:
    for seg, line in bad[:3]:
        print('  FAIL 因子串带尾随/前导空白：%r' % seg)
        print('      %s' % line)
    sys.exit(1)
print('  ok   每一行的因子串两侧都没有多余空白（缺陷形态是 "EF-NO-SIEM  ｜"，两个空格）')
sys.exit(0)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "############ 5) 反例对照：因子集不含任何行因子 ⇒ 该行必须判 recon_playbook（分类不是恒真）"
run_dry "EF-SYNCOOKIE" "$LAST" > "$WORK/out-none.txt" 2>&1; RC_NONE=$?
python3 - "$WORK/out-none.txt" "$RC_NONE" "$LAST" <<'PY'
import re, sys
out = open(sys.argv[1], encoding='utf-8').read().splitlines()
rc, name = int(sys.argv[2]), sys.argv[3]
line = next((l for l in out if re.search(r'\[\s*\d+/\s*\d+\]\s+%s\b' % re.escape(name), l)), '')
hit = (rc == 0 and 'basis=recon_playbook' in line and 'policy=1' in line)
print(('  ok   ' if hit else '  FAIL ') + 'TTP 因子集不含该行因子 ⇒ %s 判 recon_playbook policy=1（rc=%d）' % (name, rc))
print('      %s' % line.strip()[:160])
sys.exit(0 if hit else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "############ 6) 非最后一行同样分类正确（防止只给最后一行打补丁）"
run_dry "$OTHER_FACTOR" "$FIRST" > "$WORK/out-first.txt" 2>&1; RC_FIRST=$?
python3 - "$WORK/out-first.txt" "$RC_FIRST" "$FIRST" <<'PY'
import re, sys
out = open(sys.argv[1], encoding='utf-8').read().splitlines()
rc, name = int(sys.argv[2]), sys.argv[3]
line = next((l for l in out if re.search(r'\[\s*\d+/\s*\d+\]\s+%s\b' % re.escape(name), l)), '')
hit = (rc == 0 and 'basis=targeted_ttp' in line)
print(('  ok   ' if hit else '  FAIL ') + '第一行 %s（因子 %s）判 targeted_ttp（rc=%d）' % (name, 'EF-002FA', rc))
print('      %s' % line.strip()[:160])
sys.exit(0 if hit else 1)
PY
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: 矩阵层条件分类（逗号边界 + 因子串两侧无空白）全绿"
