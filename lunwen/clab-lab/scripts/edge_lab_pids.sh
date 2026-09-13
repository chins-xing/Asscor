#!/bin/bash
# ============================================================================
# edge_lab_pids.sh —— 取目标内**当前活着**的进程 PID（Task 4D Step 4 的辅助脚本）
# ============================================================================
#
# 用法：
#   bash scripts/edge_lab_pids.sh <节点名> [comm 正则]
#
# 为什么单独做成一个脚本（而不是在 `edge_attack.sh` 里内联那几行）：**判据必须来自基质层**。
# "目标内当前有哪些 pid"在两种基质上是两条不同的命令（`docker exec` vs `lxc exec --`），
# 而调用方是 `python3` heredoc（它不该知道基质）。本脚本只做一件事：source 基质层、调
# `lab_node_pids`、把结果按 PID 升序打出来。
#
# 退出码：0 成功（含"没有匹配进程"⇒ 空输出）；2 参数/基质不可用（找不到目标、命令失败）。
# **"没有匹配进程"（空输出、rc=0）与"问不到"（rc=2）必须分开**：前者是"agent 没跑起来"，
# 后者是"节点都不可达" —— 把它们混成一个结论会让排障方向完全错。
set -uo pipefail

NODE="${1:-}"
PATTERN="${2:-.}"
if [ -z "$NODE" ]; then
  echo "用法: edge_lab_pids.sh <节点名> [comm 正则]" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/edge_lab.sh
# shellcheck disable=SC2154  # lab_target_bin/lab_substrate 由下面那行 source 赋值
. "$SCRIPT_DIR/edge_lab.sh"

command -v "$lab_target_bin" >/dev/null 2>&1 || { echo "edge_lab_pids: 找不到 $lab_target_bin" >&2; exit 2; }

out="$(lab_node_pids "$NODE" "$PATTERN")" || { echo "edge_lab_pids: 取 $NODE 的进程表失败" >&2; exit 2; }
[ -n "$out" ] && printf '%s\n' "$out"
exit 0
