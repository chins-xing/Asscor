#!/bin/bash
# ============================================================================
# run-all.sh —— 离线判据的统一入口（Task 5 Step 0.5 / 复审"开工必带"第 2 条）
# ============================================================================
#
# 用法（仓库根或任意位置都行；脚本按**自身位置**解析仓库根）：
#   bash lunwen/clab-lab/tests/run-all.sh            # 跑全部 5 组夹具
#   bash lunwen/clab-lab/tests/run-all.sh edge-lab   # 只跑其中一组
#
# 为什么要有这个入口（复审 N-1：判据此前全在 `build/`，而 `build/` 被 `.gitignore` 整个忽略 ⇒
# **克隆者拿不到这些判据**，回归能力只存在于开发机上）：
#   · 5 组夹具现在都在 `lunwen/clab-lab/tests/`（仓内可跟踪）——
#     设计夹具（`lab-diff.sh` 的真基线差分）、基质层（`test-edge-lab.sh`）、
#     条件探针（`test-edge-probe.sh`）、chain 派生（`test-chain-derivation.sh`）、
#     agent 就绪判据（`test-agent-readiness.sh`）；
#   · 每组都**只读、离线**：不碰 clab / LXD / 容器 / Caldera，不写仓库（临时目录在 $HOME 或 /tmp）。
#
# 期望的通过数（复审 7.6 第 3 条的判据，**任何一条不到就是回归**）：
#   test-agent-readiness   3
#   test-edge-lab         26
#   lab-diff              31
#   test-chain-derivation  8
#   test-edge-probe       20（它按 `ok` 行计数，没有 PASS= 汇总行）
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
export REPO

declare -A EXPECT=(
  [test-agent-readiness]=3
  [test-edge-lab]=26
  [test-edge-probe]=20
  [lab-diff]=31
  [test-chain-derivation]=8
)
ORDER=(test-agent-readiness test-edge-lab test-edge-probe lab-diff test-chain-derivation)

WANT=("$@")
TOTAL_FAIL=0
echo "############ 离线夹具统一入口（仓库 $REPO）"
echo
for name in "${ORDER[@]}"; do
  if [ "${#WANT[@]}" -gt 0 ]; then
    keep=0
    for w in "${WANT[@]}"; do [ "$w" = "$name" ] && keep=1; done
    [ "$keep" -eq 1 ] || continue
  fi
  f="$TESTS_DIR/$name.sh"
  [ -f "$f" ] || { echo "== $name: **缺失**（$f）⇒ 回归能力不完整"; TOTAL_FAIL=$((TOTAL_FAIL + 1)); continue; }
  out="$(mktemp)"
  if bash "$f" > "$out" 2>&1; then rc=0; else rc=$?; fi
  # 计数口径：有 `PASS=` 汇总行的用它，否则数 `ok` 行（test-edge-probe 属于后者，且有专门的 `rc=2` 断言）。
  if grep -q 'PASS=' "$out"; then
    got="$(grep -oE 'PASS=[0-9]+' "$out" | tail -1 | cut -d= -f2)"
  else
    got="$(grep -cE '^  ok' "$out")"
  fi
  exp="${EXPECT[$name]}"
  if [ "$rc" -eq 0 ] && [ "$got" = "$exp" ]; then
    printf '== %-24s ok   通过数 %-3s（期望 %s）rc=%s\n' "$name" "$got" "$exp" "$rc"
  else
    printf '== %-24s FAIL 通过数 %-3s（期望 %s）rc=%s —— 尾部输出：\n' "$name" "$got" "$exp" "$rc"
    tail -12 "$out" | sed 's/^/     /'
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
  rm -f "$out"
done

echo
if [ "$TOTAL_FAIL" -eq 0 ]; then
  echo "run-all: 全部通过（5 组：3/26/20/31/8）"
  exit 0
fi
echo "run-all: $TOTAL_FAIL 组未达标 —— 见上面的尾部输出" >&2
exit 1
