#!/bin/bash
# ============================================================================
# run-all.sh —— 离线判据的统一入口（Task 5 Step 0.5 / 复审"开工必带"第 2 条）
# ============================================================================
#
# 用法（仓库根或任意位置都行；脚本按**自身位置**解析仓库根）：
#   bash lunwen/clab-lab/tests/run-all.sh            # 跑全部 6 组夹具
#   bash lunwen/clab-lab/tests/run-all.sh edge-lab   # 只跑其中一组
#
# 为什么要有这个入口（复审 N-1：判据此前全在 `build/`，而 `build/` 被 `.gitignore` 整个忽略 ⇒
# **克隆者拿不到这些判据**，回归能力只存在于开发机上）：
#   · 6 组夹具现在都在 `lunwen/clab-lab/tests/`（仓内可跟踪）——
#     设计夹具（`lab-diff.sh` 的真基线差分）、基质层（`test-edge-lab.sh`）、
#     条件探针（`test-edge-probe.sh`）、chain 派生（`test-chain-derivation.sh`）、
#     agent 就绪判据（`test-agent-readiness.sh`）、矩阵层条件分类
#     （`test-matrix-classification.sh`：Task 8 复审那颗"尾随空格翻转 basis"的雷的钉子）；
#   · 每组都**只读、离线**：不碰 clab / LXD / 容器 / Caldera，不写仓库（临时目录在 $HOME 或 /tmp）。
#
# 期望的通过数（复审 7.6 第 3 条的判据，**任何一条不到就是回归**）：
#   test-agent-readiness   6（Task 10 加了 pid 复用 / paw 归属三格：D / D2 / E —— 前 3 格是 Task 4D 的原判据）
#   test-edge-lab         77（Task 6 的 H 段把 pve 基质写成 25 条 ⇒ 51；Task 13 的 I 段给 qemu
#                              加了 22 条 ⇒ 73；**Task 16 把 I 段那 3 条既有 FAIL 修到全绿、
#                              并给"命令串逐字一致"那条判据加了一格 ⇒ 77**。
#                              ⚠️ Task 15 在 Linux 上实跑是 PASS=73 FAIL=3，那 3 条在起点
#                              `541c504` 上逐字相同（失败集 diff 为空）⇒ 是 Task 13 带进来的既有
#                              失败。Task 16 查清了三条的**根因各不相同**（见 Task 16 报告 §3.1）：
#                                ① `lab_down` 的 qemu 帮助文本里 `` `qm destroy --purge` `` 的反引号
#                                   **没转义** ⇒ 双引号里的命令替换**真的执行了**那条销毁命令
#                                   （这是**产物代码的真缺陷**，已修）；
#                                ② 夹具把"帮助文本"与"真被调用的命令"记进同一份日志 ⇒ 判据把
#                                   说明当成了命令（夹具缺陷，已用 `[invoke]` 前缀切开）；
#                                ③ 「基质串味」那条用的是 `[ -s "$D/pve.log" ]`，而该日志是
#                                   **累积**的（H 段写过就恒非空）⇒ 判据恒红（夹具缺陷，
#                                   已改成"本段没让它增长"的逐字节比较）；
#                                另有一条 `bash -c bash -c` 曾被当成双重包装 ⇒ Task 16 实测澄清
#                                **它是正确形态**（两格是调用方给的），并把这条钉进了判据。）
#   lab-diff              31
#   test-chain-derivation  8
#   test-edge-probe       20（它按 `ok` 行计数，没有 PASS= 汇总行）
#   test-matrix-classification 12（Task 8 的 7 格 + Task 10 的臂 3 格 + Task 11 的重复轴 2 格：H/I；
#                                 它在**缺陷版**（`SCEN_FACTORS_RAW="$( … ) "`）上必须红 ——
#                                 Task 8 当时（7 格版）实测 PASS=2 FAIL=5，修好后 PASS=7 FAIL=0；
#                                 Task 14 在**现在的 12 格版**上复测：缺陷版 **PASS=3 FAIL=9**（rc=1）、
#                                 修好版 **PASS=12 FAIL=0** —— 尾随空白把 `R-no-siem` 整行打翻：
#                                 它被判成 `recon_playbook`、分布塌成 0/25、臂与重复轴跟着一起塌）
#   test-agent-readiness    见上（Task 10 的 pid 复用/paw 归属三格）
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
export REPO

declare -A EXPECT=(
  [test-agent-readiness]=6
  [test-edge-lab]=77
  [test-edge-probe]=20
  [lab-diff]=31
  [test-chain-derivation]=8
  [test-matrix-classification]=12
)
ORDER=(test-agent-readiness test-edge-lab test-edge-probe lab-diff test-chain-derivation test-matrix-classification)

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
  echo "run-all: 全部通过（6 组：6/77/20/31/8/12）"
  exit 0
fi
echo "run-all: $TOTAL_FAIL 组未达标 —— 见上面的尾部输出" >&2
exit 1
