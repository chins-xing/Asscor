#!/bin/bash
# ============================================================================
# edge_repeat.sh —— 每场景重复 N 次的驱动（Task 5 Step 1；Task 21 定案修订）
# ============================================================================
#
# 用法：
#   bash scripts/edge_repeat.sh                     # 全量 25 场景 × 3 次（默认）
#   bash scripts/edge_repeat.sh S0-baseline         # 只对选中场景重复（冒烟用）
#   EDGEEXP_REPEATS=2 bash scripts/edge_repeat.sh S1-selinux   # 2 轮冒烟
#   EDGEEXP_RECORDS=/path/records-...jsonl bash scripts/edge_repeat.sh ...  # 段级记录文件（两段各一份）
#   EDGEEXP_RUN_TAG=targeted bash scripts/edge_repeat.sh ...   # 段标识，进 run id 与汇总（可选）
#
# 它做什么：对 run=1..N **各跑一轮完整的 edge_matrix.sh**（每轮对选中的场景逐实例
# reset → attack → collect），并把同一场景的 N 次重复**写进同一份记录文件**。
#
# ---------------------------------------------------------------------------
# **口径定案（Task 21 Step 1，实测依据见 task-21 报告 §1）**：
#   **一份记录文件承载 1..REPEATS 各一遍**（原先的"逐轮一个记录文件"已废弃）。
#
# 为什么改（两条都是实测，不是推断）：
#   ① `edge_matrix.sh` 的记录条数门禁与 `run.json` 的 `record_counts_ok` 都按
#      **文件总行数 == 实例数 × 重复号** 判（`records_missing_for_selected`/`records_extra_in_file`
#      同口径）。若逐轮各写一个文件，第 k 轮那份只有「实例数」行、而门禁要「实例数 × k」行
#      ⇒ **第 2 轮起 `record_counts_ok` 恒为 false**（矩阵的硬门禁在 REPEAT>1 时改判
#      "本轮每个实例 id 恰好一条"，故 rc 仍是 0 —— 于是它是一台**不吭声的假红**：
#      退出码绿、运行级证据红）。
#   ② 逐轮一个文件的原理由（"`edge_collect.sh` 的幂等守卫按**场景名前缀**匹配，
#      三轮同文件会被判重复而拒写"）**已经不成立**：守卫比的是**完整实例 id**
#      `<场景>-<实例号>`（Task 10 起加臂时就改了），而实例号
#      `NN = (REPEAT-1)×NARMS + 臂 + 1`（Task 11 的重复轴）**逐轮不重叠**
#      ⇒ 第 2 轮写同一个文件不会被判重复。冒烟实测：同文件第 2 轮写入正常、
#      `record_counts_ok=True`、`rc=0`（任务报告里有原始输出）。
#
# 逐轮仍然隔离的**是别的东西**（这些照旧，别退回去）：
#   · `EDGEEXP_ENV=<base>-r<k>` —— 每条记录的 `meta.env` 标明它属于哪一遍
#     （`RUN_INDEX>1` 时矩阵**要求**显式 ENV，正是为了不让重复样本混进主批标签）；
#   · `EDGEEXP_RUN_ID=<date>-r<k>` —— run 级产物（`run-<id>.json`）逐轮独立，不互相覆盖；
#   · `meta.repeat`（只在 >1 时写）与 `scenario_id` 尾号（实例号）—— 记录内部就能逐轮分清。
#
# **中断续跑**：默认 `EDGEEXP_RESUME=1` —— 某一轮跑到一半断掉时，重跑同一轮会跳过"文件里
# 已有该实例记录"的实例（矩阵把它记进 `scenarios_skipped_resume` 并在 `record_counts_ok`
# 里算作已完成）。整轮结束时矩阵的硬门禁仍要求"本轮每个实例 id 在文件里恰好一条"。
#
# **重复样本不是独立样本**（口径要求，见 spec §5.4.15）：三次是**同一宿主状态**的重复，
# 用来估方差/稳定性，不得当成 3 个独立样本虚增决策层 N
# （决策层 N 写成 `N=<条数>（<场景数> × <重复数>）`，见 `edge_variance.py`）。
#
# **判 rc 绝不许用管道**：本驱动的每轮 rc 由 `|| rc=$?` 直接取，不用 `| tail`。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
BASE_ENV="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
REPEATS="${EDGEEXP_REPEATS:-3}"
RUN_TAG="${EDGEEXP_RUN_TAG:-}"
MATRIX="$SCRIPT_DIR/edge_matrix.sh"
# **一份文件承载 1..REPEATS**（定案，见头部）。段级隔离用 EDGEEXP_RECORDS 显式指定：
# 两段（targeted / 非 targeted）各一份，别把两段塞进同一份（门禁按段算）。
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-${BASE_ENV}-${TODAY}.jsonl}"

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
echo "edge_repeat: 记录文件（**一份承载 1..$REPEATS**）$RECORDS"
echo "edge_repeat: 数据目录 $DATA_DIR"
# 已有的记录文件不是错误（续跑），但要说出来：否则"文件里已经有 66 行"会被误读成本轮写的。
if [ -f "$RECORDS" ]; then
  echo "edge_repeat: 注意 —— 记录文件已存在（$(grep -c . "$RECORDS" || true) 行）；"
  echo "  EDGEEXP_RESUME=${EDGEEXP_RESUME:-1} 时会跳过「该实例已有记录」的那些，"
  echo "  ⇒ 想从零开始请换 EDGEEXP_RECORDS 或先归档旧文件。"
fi

RUN_RESULTS="[]"
overall_rc=0
for k in $(seq 1 "$REPEATS"); do
  RUN_ENV="${BASE_ENV}-r${k}"
  RUN_ID="${TODAY}${RUN_TAG:+-$RUN_TAG}-r${k}"
  RUN_JSON="$DATA_DIR/run-${RUN_ID}.json"
  echo "============================================================"
  echo "edge_repeat: 第 $k/$REPEATS 轮（run_index=$k，env=$RUN_ENV，run_id=$RUN_ID）→ 追加到 $RECORDS"
  t0=$(date -u +%s)
  rc=0
  # 逐轮导出：`RUN_INDEX>1` 必须显式 ENV（矩阵会查）；记录文件**逐轮相同**（定案）；
  # `RESUME` 默认 1（见头部说明）。
  EDGEEXP_RUN_INDEX="$k" EDGEEXP_ENV="$RUN_ENV" EDGEEXP_RECORDS="$RECORDS" \
    EDGEEXP_RUN_ID="$RUN_ID" EDGEEXP_RESUME="${EDGEEXP_RESUME:-1}" \
    bash "$MATRIX" "${SCENARIOS[@]}" || rc=$?
  t1=$(date -u +%s)
  lines=0; [ -f "$RECORDS" ] && lines=$(grep -c . "$RECORDS" || true)
  # 逐轮把矩阵自己写的运行级判据读回来（**不用 grep 猜**）：`record_counts_ok` 是
  # "文件行数 == 实例数 × 重复号"这条口径的唯一真源，也是本驱动要守的那条假红的哨兵。
  counts_ok="false"; total_lines="$lines"; insts=""; rfile=""
  if [ -f "$RUN_JSON" ]; then
    read -r counts_ok total_lines insts rfile < <(python3 - "$RUN_JSON" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    print('false\t0\t\t'); raise SystemExit
print('true' if d.get('record_counts_ok') else 'false',
      d.get('records_file_total_lines', 0),
      d.get('records_expected', ''),
      d.get('records_file', ''), sep='\t')
PY
)
  fi
  # **陈旧 run.json 的护栏**（Task 21 实测踩到）：`RUN_ID` 默认是 `<date>-r<k>`，
  # 同一个 `-r<k>` 在同一天里重跑时会**与上一轮同名** ⇒ 上面那行会读到**上一次**的
  # `record_counts_ok`（实测：干跑读到前一次冒烟的 true，一次"什么都没做"的干跑看起来"条数通过"）。
  # 判据取 run.json 自己记的 `records_file`：与本次要写的文件不同 ⇒ 视为**没有本轮判据**。
  if [ -n "$rfile" ] && [ "$rfile" != "$RECORDS" ]; then
    counts_ok="stale(run.json 属于 $rfile)"
  fi
  # 干跑（`EDGEEXP_DRY_RUN=1`）**不写任何记录、也不写 run-<id>.json** ⇒ 没有 `record_counts_ok`
  # 可读。这时**不许**把它当成 false（否则一次"只看计划"的干跑会被判成失败）：
  # 干跑只按矩阵的 rc 判，并在汇总里把该字段记成 null。
  DRY="${EDGEEXP_DRY_RUN:-0}"
  if [ "$DRY" = "1" ] && [ ! -f "$RUN_JSON" ]; then
    counts_ok="skip(dry-run 不写记录/不写 run.json)"
  fi
  echo "edge_repeat: 第 $k 轮结束 rc=$rc（$((t1 - t0))s，文件总行数 $total_lines，record_counts_ok=$counts_ok）"
  # **失败不静默**：如实记进汇总并继续下一轮（"单场景失败 ⇒ 记下并继续"的轮级版本）。
  # `edge_matrix.sh` 自己的 run-<id>.json 里另有逐场景碎片，两者一起才是完整证据。
  # **`record_counts_ok=false` 也算这一轮失败**：那正是"逐轮一个文件"时代留下的假红
  # （rc 绿、证据红），本驱动不再让它悄悄通过。
  round_ok=1
  [ "$rc" -eq 0 ] || round_ok=0
  if [ "$DRY" = "1" ]; then
    : # 干跑没有记录，条数口径不适用（见上）
  else
    [ "$counts_ok" = "true" ] || round_ok=0
  fi
  if [ "$round_ok" -eq 0 ]; then
    overall_rc=1
    [ "$rc" -eq 0 ] && echo "edge_repeat: 第 $k 轮 rc=0 但 record_counts_ok=false —— 记录条数口径没对上（见 run-${RUN_ID}.json 的 records_*），本轮记为失败" >&2
  fi
  RUN_RESULTS="$(python3 - "$RUN_RESULTS" "$k" "$RUN_ENV" "$RECORDS" "$rc" "$((t1 - t0))" "$total_lines" "$RUN_ID" "$counts_ok" "$insts" <<'PY'
import json, sys
arr = json.loads(sys.argv[1])
arr.append({'run_index': int(sys.argv[2]), 'env': sys.argv[3], 'records_file': sys.argv[4],
            'exit_code': int(sys.argv[5]), 'elapsed_s': int(sys.argv[6]),
            'records_file_total_lines': int(sys.argv[7] or 0), 'run_id': sys.argv[8],
            'record_counts_ok': (None if sys.argv[9].startswith(('skip', '(')) else sys.argv[9] == 'true'),
            'record_counts_ok_raw': sys.argv[9],
            'instances_this_round': (int(sys.argv[10]) if (len(sys.argv) > 10 and sys.argv[10].strip()) else None),
            'run_json': sys.argv[8]})
print(json.dumps(arr))
PY
)"
done

python3 - "$DATA_DIR/repeats.json" "$REPEATS" "$BASE_ENV" "$TODAY" "$RUN_RESULTS" "$overall_rc" \
  "$RECORDS" <<'PY'
import json, sys, time, os
out, repeats, env, today, results, overall, records = sys.argv[1:8]
runs = json.loads(results)
insts = {r['instances_this_round'] for r in runs if r.get('instances_this_round')}
expected_total = (sorted(insts)[-1] * int(repeats)) if insts else None
json.dump({
    'driver': 'edge_repeat.sh',
    'repeats': int(repeats), 'env_base': env, 'date': today,
    'records_file': records,
    'records_policy': 'one_file_carries_all_repeats',
    'runs': runs,
    'records_file_total_lines': (runs[-1]['records_file_total_lines'] if runs else 0),
    'instances_per_round': (sorted(insts)[-1] if insts else None),
    'records_expected_total': expected_total,
    'overall_exit_code': int(overall),
    'finished_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'notes': {
        'one_file_per_segment': '一份记录文件承载 1..REPEATS 各一遍（Task 21 定案）：'
                                '矩阵的门禁与 run.json 的 record_counts_ok 都按'
                                '"文件行数 == 实例数 × 重复号"判；逐轮各写一个文件会让第 2 轮起恒红。'
                                '段级隔离用 EDGEEXP_RECORDS 显式指定（targeted / 非 targeted 各一份）。',
        'why_per_round_file_was_dropped': '原理由（幂等守卫按场景名前缀匹配）已不成立：'
                                          '守卫比的是完整实例 id `<场景>-<实例号>`，'
                                          '而实例号 NN=(REPEAT-1)*NARMS+臂+1 逐轮不重叠。',
        'per_round_isolation': '逐轮仍然隔离 EDGEEXP_ENV=<base>-r<k>（记录的 meta.env）'
                               '与 EDGEEXP_RUN_ID（run-<id>.json）；记录内部另有 meta.repeat。',
        'resume': 'EDGEEXP_RESUME 默认 1：中断后重跑同一轮会跳过"文件里已有该实例记录"的实例',
        'record_counts_ok_is_enforced': '本轮 rc=0 但 record_counts_ok=false 也算失败'
                                        '（防"退出码绿、运行级证据红"的假红）',
        'repeat_is_not_independent': '重复样本不是独立样本（同一宿主状态），'
                                     '决策层 N 必须写成 N=<条数>（<场景数> 场景 × <重复数> 次）',
    },
}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print(f'edge_repeat: 汇总 → {out}')
PY

echo "============================================================"
if [ "$overall_rc" -eq 0 ]; then
  if [ "${EDGEEXP_DRY_RUN:-0}" = "1" ]; then
    echo "edge_repeat: 全部 $REPEATS 轮干跑通过（**没有**写记录 ⇒ 条数口径不适用，见 repeats.json）"
  else
    echo "edge_repeat: 全部 $REPEATS 轮完成（每轮 record_counts_ok=true）"
  fi
else
  echo "edge_repeat: 有轮次失败（见 repeats.json 的 runs[].exit_code / record_counts_ok 与逐轮 run-<id>.json）" >&2
fi
exit "$overall_rc"
