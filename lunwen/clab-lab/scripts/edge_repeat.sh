#!/bin/bash
# ============================================================================
# edge_repeat.sh —— 每场景重复 N 次的驱动（Task 5 Step 1）
# ============================================================================
#
# 用法：
#   bash scripts/edge_repeat.sh                 # 全量 25 场景 × 3 次（默认）
#   bash scripts/edge_repeat.sh S0-baseline     # 只对选中场景重复（冒烟用）
#   EDGEEXP_REPEATS=1 bash scripts/edge_repeat.sh   # 单轮
#   EDGEEXP_DRY_RUN=1 bash scripts/edge_repeat.sh   # 只看计划（不碰实验室，由矩阵干跑承担）
#
# 它做什么：对 run=1..N **各跑一轮完整的 edge_matrix.sh**（每轮 25 场景，逐场景 reset → attack → collect），
# 并**逐轮隔离产物**：
#
#   records-<env>-<date>-r<k>.jsonl     第 k 轮记录（**必须逐轮一个文件**，理由见下）
#   run-<run-id>.json                   第 k 轮的运行级汇总（矩阵自己写的不可变副本）
#   repeats.json                        本驱动层的汇总（逐轮退出码/耗时/记录数/门禁结果）
#
# **为什么记录文件必须逐轮一个**（实测）：`edge_collect.sh` 的幂等守卫是
#   `grep -cE "\"scenario_id\":\"$SCENARIO" "$RECORDS"`
# —— 它按**场景名前缀**匹配，而 run=1/2/3 的场景标识是 `<场景>-01/-02/-03` ⇒ 三轮写进**同一个文件**
# 时第 2 轮会被判成"该场景已有记录"而拒绝（三条记录只剩一条）。所以 `--run k` 必须配一个**独立的
# 记录文件**；`EDGEEXP_ENV` 也要逐轮不同（`RUN_INDEX>1` 时矩阵**要求**显式给 ENV，否则重复样本
# 会被打上默认标签混进主数据集）。
#
# **重复样本不是独立样本**（口径要求，见 spec §5.4.15）：A-1 的 3 次是**同一宿主状态**的重复，
# 用来估方差/稳定性，不得当成 3 个独立样本虚增决策层 N。
#
# **中断续跑**：默认 `EDGEEXP_RESUME=1` —— 某一轮跑到一半断掉时，重跑同一轮会跳过"文件里已有记录"
# 的场景（矩阵把它记进 `scenarios_skipped_resume`）。整轮的记录条数门禁在结束时仍要求
# `文件行数 == 选中场景数`，故"跳过的那些"必须是**真的已经采到了**。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
BASE_ENV="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
REPEATS="${EDGEEXP_REPEATS:-3}"
MATRIX="$SCRIPT_DIR/edge_matrix.sh"

SCENARIOS=("$@")   # 空 = 全量
[ -f "$MATRIX" ] || { echo "edge_repeat: 缺少 $MATRIX" >&2; exit 1; }
case "$REPEATS" in
  ''|*[!0-9]*) echo "edge_repeat: EDGEEXP_REPEATS 必须是正整数（收到 '$REPEATS'）" >&2; exit 1 ;;
esac
[ "$REPEATS" -ge 1 ] || { echo "edge_repeat: EDGEEXP_REPEATS 必须 ≥ 1" >&2; exit 1; }

mkdir -p "$DATA_DIR"
# 注意：`${#SCENARIOS[@]:-全部}` 是**非法** bash（`:-` 不能与 `#` 一起用）—— 实测在这一行
# `bad substitution` 直接退出（好的一面：**没有**半途启动的扫描）。分成两支写清楚。
if [ "${#SCENARIOS[@]}" -gt 0 ]; then
  echo "edge_repeat: 重复 $REPEATS 轮 × ${#SCENARIOS[@]} 个选中场景｜env 基名 $BASE_ENV｜日期 $TODAY"
else
  echo "edge_repeat: 重复 $REPEATS 轮 × 全量场景（25 个，由 edge_matrix.sh 的名单决定）｜env 基名 $BASE_ENV｜日期 $TODAY"
fi
echo "edge_repeat: 数据目录 $DATA_DIR"

RUN_RESULTS="[]"
overall_rc=0
for k in $(seq 1 "$REPEATS"); do
  RUN_ENV="${BASE_ENV}-r${k}"
  RUN_RECORDS="$DATA_DIR/records-${BASE_ENV}-${TODAY}-r${k}.jsonl"
  RUN_ID="${TODAY}-r${k}"
  echo "============================================================"
  echo "edge_repeat: 第 $k/$REPEATS 轮（run_index=$k，env=$RUN_ENV）→ $RUN_RECORDS"
  t0=$(date -u +%s)
  rc=0
  # 逐轮导出：`RUN_INDEX>1` 必须显式 ENV（矩阵会查）；`RESUME` 默认 1（见头部说明）。
  EDGEEXP_RUN_INDEX="$k" EDGEEXP_ENV="$RUN_ENV" EDGEEXP_RECORDS="$RUN_RECORDS" \
    EDGEEXP_RUN_ID="$RUN_ID" EDGEEXP_RESUME="${EDGEEXP_RESUME:-1}" \
    bash "$MATRIX" "${SCENARIOS[@]}" || rc=$?
  t1=$(date -u +%s)
  lines=0; [ -f "$RUN_RECORDS" ] && lines=$(grep -c . "$RUN_RECORDS" || true)
  echo "edge_repeat: 第 $k 轮结束 rc=$rc（$((t1 - t0))s，记录 $lines 条）"
  # **失败不静默**：如实记进汇总并继续下一轮（"单场景失败 ⇒ 记下并继续"的轮级版本）。
  # `edge_matrix.sh` 自己的 run-<id>.json 里另有逐场景碎片，两者一起才是完整证据。
  RUN_RESULTS="$(python3 - "$RUN_RESULTS" "$k" "$RUN_ENV" "$RUN_RECORDS" "$rc" "$((t1 - t0))" "$lines" "$RUN_ID" <<'PY'
import json, sys
arr = json.loads(sys.argv[1])
arr.append({'run_index': int(sys.argv[2]), 'env': sys.argv[3], 'records_file': sys.argv[4],
            'exit_code': int(sys.argv[5]), 'elapsed_s': int(sys.argv[6]), 'records': int(sys.argv[7]),
            'run_id': sys.argv[8]})
print(json.dumps(arr))
PY
)"
  [ "$rc" -eq 0 ] || overall_rc=1
done

python3 - "$DATA_DIR/repeats.json" "$REPEATS" "$BASE_ENV" "$TODAY" "$RUN_RESULTS" "$overall_rc" \
  "${SCENARIOS[@]}" <<'PY'
import json, sys, time
out, repeats, env, today, results, overall = sys.argv[1:7]
scen = sys.argv[7:]
json.dump({
    'driver': 'edge_repeat.sh',
    'repeats': int(repeats), 'env_base': env, 'date': today,
    'scenarios': scen or '（全量，由 edge_matrix.sh 的 25 场景名单决定）',
    'runs': json.loads(results),
    'overall_exit_code': int(overall),
    'finished_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'notes': {
        'per_run_records_file': '逐轮一个记录文件：edge_collect.sh 的幂等守卫按场景名前缀匹配，'
                                'run=1/2/3 的 <场景>-01/-02/-03 同文件会被判成重复而拒写',
        'resume': 'EDGEEXP_RESUME 默认 1：中断后重跑同一轮会跳过"文件里已有记录"的场景',
        'repeat_is_not_independent': '重复样本不是独立样本（同一宿主状态），'
                                     '决策层 N 必须写成 N=<条数>（<场景数> 场景 × <重复数> 次）',
    },
}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print(f'edge_repeat: 汇总 → {out}')
PY

echo "============================================================"
if [ "$overall_rc" -eq 0 ]; then
  echo "edge_repeat: 全部 $REPEATS 轮完成"
else
  echo "edge_repeat: 有轮次失败（见 repeats.json 的 runs[].exit_code 与逐轮 run-<id>.json）" >&2
fi
exit "$overall_rc"
