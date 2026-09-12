#!/bin/bash
# ============================================================================
# edge_threshold_sensitivity.sh —— 阈值敏感性行（spec §5.4.6 的强制行）
# ============================================================================
#
# 背景：`[acceptability] threshold = 80.0` 是**部署的真实判定线**（GB/T 22239-2019 Level 3）。
# 若该线让全部记录落进"不可接受"（漏判样本为 0 或误阻断样本为 0），报告必须**另附一行**
# `threshold = 60.0` 的敏感性结果，并明确标注那是敏感性分析 —— 换阈值改结论这件事必须
# 写在脸上，不能只报一组数字。
#
# 在 `-threshold` 之前这条要求**无法执行**（阈值只来自记录本体的 `observed.threshold`，
# 操作者只能手改 JSONL 副本）。本脚本把那一行变成一条**可复现的命令**：
# 同一份记录、同一份 `-factors`/`-weights`、同一组候选，只把判定线换掉。
#
# 用法（唯一入口；**不碰任何 lab 资源**：不调 clab、不碰 Caldera、不起容器）：
#
#   cd lunwen/clab-lab
#   EDGEEXP_SENSITIVITY_THRESHOLDS=60 bash scripts/edge_threshold_sensitivity.sh
#
# 只有显式给出 `EDGEEXP_SENSITIVITY_THRESHOLDS` 才会跑（**刻意**这样：敏感性结果不得
# 混进默认路径，见 §5.4.6）。多个阈值用逗号或空格分隔：`60,70`。
#
# 环境变量：
#   EDGEEXP_SENSITIVITY_THRESHOLDS  必填，本次要跑的判定线列表（每个 ∈ (0,100]）
#   EDGEEXP_RECORDS                 记录文件（默认与矩阵同款命名：records-$ENV-$TODAY.jsonl）
#   EDGEEXP_CONFIG                  采集配置（默认 configs/edgeexp/m0-baseline.ini）——
#                                   它同时提供 legacy 候选与 `-factors`/`-weights`
#   EDGEEXP_SENSITIVITY_DIR         产物目录（默认 $DATA_DIR/sensitivity）
#   EDGEEXP_EDGECOMPARE             edgecompare 二进制（默认 $REPO_ROOT/build/edgecompare）
#   EDGEEXP_RUN_ID                  运行标识（进 sensitivity.json；矩阵调用时继承本轮）
#   EDGEEXP_FACTORS_SPEC/_WEIGHTS_SPEC  已由调用方算出时直接复用（矩阵会导出，避免重算漂移）
#
# 产物（每个阈值一份报告 + 一份汇总；**文件名与报告头都带阈值**，故不可能被误当成主对比）：
#   $EDGEEXP_SENSITIVITY_DIR/report-threshold-<T>.md   带敏感性横幅 + edgecompare **逐字**输出
#   $EDGEEXP_SENSITIVITY_DIR/report-threshold-<T>.raw.md  工具原始 stdout（可逐字引用/对比）
#   $EDGEEXP_SENSITIVITY_DIR/report-threshold-<T>.log  工具 stderr（含"已覆盖 observed.threshold"提示）
#   $EDGEEXP_SENSITIVITY_DIR/sensitivity.json          汇总：记录/配置/指纹/两个 spec/逐阈值结果
#
# 失败语义：任一环节出错**立即非零退出**（缺参数/记录为空/工具缺失/某阈值复算失败），
# 不跳过、不吞错、不用 `|| true` 糊过去。已经写好的报告保留（它们是有效证据）。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
ENV_NAME="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
RUN_ID="${EDGEEXP_RUN_ID:-$TODAY-$$}"
CONFIG="${EDGEEXP_CONFIG:-$REPO_ROOT/configs/edgeexp/m0-baseline.ini}"
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-$ENV_NAME-$TODAY.jsonl}"
OUT_DIR="${EDGEEXP_SENSITIVITY_DIR:-$DATA_DIR/sensitivity}"
EDGECOMPARE="${EDGEEXP_EDGECOMPARE:-$REPO_ROOT/build/edgecompare}"

# `-factors`/`-weights` 与门禁① 同源同实现（共用的 edge_spec_lib.sh）；调用方给了就直接用。
# shellcheck source=scripts/edge_spec_lib.sh
. "$SCRIPT_DIR/edge_spec_lib.sh"

# --- 参数校验：全部前置（用法写错时不该先看见"文件打不开"）------------------------
THRESHOLDS_RAW="${EDGEEXP_SENSITIVITY_THRESHOLDS:-}"
if [ -z "$(printf '%s' "$THRESHOLDS_RAW" | tr -d ' ,')" ]; then
  echo "edge_threshold_sensitivity: 需要 EDGEEXP_SENSITIVITY_THRESHOLDS（例：EDGEEXP_SENSITIVITY_THRESHOLDS=60）。" >&2
  echo "  这是**刻意的显式开关**：敏感性行不得出现在默认路径上（spec §5.4.6）。" >&2
  echo "  用法：EDGEEXP_SENSITIVITY_THRESHOLDS=60 bash scripts/edge_threshold_sensitivity.sh" >&2
  exit 2
fi

# 阈值列表：逗号/空格分隔 → 逐个校验 ∈ (0,100]（与 config.validateRanges 同一区间）。
THRESHOLDS=()
for t in $(printf '%s' "$THRESHOLDS_RAW" | tr ',' ' '); do
  case "$t" in
    '' ) continue ;;
  esac
  ok="$(python3 -c 'import sys
try:
    v = float(sys.argv[1])
except ValueError:
    print("bad"); sys.exit(0)
print("ok" if 0 < v <= 100 else "range")' "$t")"
  if [ "$ok" = "bad" ]; then
    echo "edge_threshold_sensitivity: 阈值 $t 不是数字（本脚本不猜你想跑什么）" >&2; exit 2
  fi
  if [ "$ok" = "range" ]; then
    echo "edge_threshold_sensitivity: 阈值 $t 不在 (0,100] —— 与 [acceptability] threshold 的合法区间一致" >&2; exit 2
  fi
  THRESHOLDS+=("$t")
done
[ "${#THRESHOLDS[@]}" -gt 0 ] || { echo "edge_threshold_sensitivity: 阈值列表为空" >&2; exit 2; }

[ -f "$CONFIG" ] || { echo "edge_threshold_sensitivity: 采集配置不存在: $CONFIG" >&2; exit 1; }
[ -f "$RECORDS" ] || { echo "edge_threshold_sensitivity: 记录文件不存在: $RECORDS（本脚本只读它，不写）" >&2; exit 1; }
[ -x "$EDGECOMPARE" ] || {
  echo "edge_threshold_sensitivity: $EDGECOMPARE 不存在或不可执行 —— 先交叉编译：" >&2
  echo "  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags edgeexp -o build/edgecompare ./cmd/edgecompare" >&2
  exit 1
}
RECORD_COUNT="$(grep -c . "$RECORDS" || true)"
[ "$RECORD_COUNT" -gt 0 ] || { echo "edge_threshold_sensitivity: 记录文件为空（0 行）: $RECORDS —— 空集上算不出任何指标" >&2; exit 1; }

FACTORS_SPEC="${EDGEEXP_FACTORS_SPEC:-$(derive_factors_spec "$CONFIG")}"
WEIGHTS_SPEC="${EDGEEXP_WEIGHTS_SPEC:-$(derive_weights_spec "$CONFIG")}"
[ -n "$FACTORS_SPEC" ] || { echo "edge_threshold_sensitivity: -factors 推导为空（配置 $CONFIG 有问题）" >&2; exit 1; }
[ -n "$WEIGHTS_SPEC" ] || { echo "edge_threshold_sensitivity: -weights 推导为空（配置 $CONFIG 有问题）" >&2; exit 1; }

mkdir -p "$OUT_DIR"
CONFIG_HASH="sha256:$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$CONFIG")"

echo "edge_threshold_sensitivity: 阈值敏感性行（**非主对比**；不碰 lab）"
echo "  运行标识   : $RUN_ID"
echo "  记录文件   : $RECORDS（$RECORD_COUNT 条，只读）"
echo "  采集配置   : $CONFIG（$CONFIG_HASH）"
echo "  -factors   : $FACTORS_SPEC"
echo "  -weights   : $WEIGHTS_SPEC"
echo "  阈值       : ${#THRESHOLDS[@]} 个 → ${THRESHOLDS[*]}"
echo "  产物目录   : $OUT_DIR"

# --- 逐阈值复算 -----------------------------------------------------------------
for T in "${THRESHOLDS[@]}"; do
  RAW="$OUT_DIR/report-threshold-$T.raw.md"
  LOG="$OUT_DIR/report-threshold-$T.log"
  REPORT="$OUT_DIR/report-threshold-$T.md"
  echo "============================================================"
  echo "edge_threshold_sensitivity: 阈值 $T → $REPORT"
  # 与门禁① 逐项相同，唯一差别是 -threshold：候选、记录、-factors、-weights 都不动，
  # 这样"两份报告只在判定线上不同"才是可核对的事实。
  set +e
  "$EDGECOMPARE" -records "$RECORDS" \
    -candidate "legacy=$CONFIG" \
    -candidate "vector=$REPO_ROOT/configs/edgeexp/vector.ini" \
    -candidate "graph=$REPO_ROOT/configs/edgeexp/graph.ini" \
    -candidate "chain=$REPO_ROOT/configs/edgeexp/chain.ini" \
    -factors "$FACTORS_SPEC" -weights "$WEIGHTS_SPEC" \
    -threshold "$T" \
    > "$RAW" 2> "$LOG"
  RC=$?
  set -e
  if [ "$RC" -ne 0 ]; then
    echo "edge_threshold_sensitivity: 阈值 $T 的复算失败（exit $RC）—— 见 $LOG" >&2
    [ -s "$LOG" ] && tail -5 "$LOG" >&2
    exit "$RC"
  fi
  [ -s "$RAW" ] || { echo "edge_threshold_sensitivity: 阈值 $T 的报告为空（工具没输出）—— 拒绝写出空报告" >&2; exit 1; }
  # 横幅 + 工具**逐字**输出：文件级也不可能与主对比报告混淆（"换阈值改结论"必须写在脸上）。
  {
    echo "<!-- 阈值敏感性分析产物：本文件**不是**主对比报告。主对比用的是部署判定线，不带 -threshold。 -->"
    echo ""
    echo "# 阈值敏感性分析：\`threshold = $T\`（**覆盖**记录自带的 \`observed.threshold\`）"
    echo ""
    echo "> 本文件由 \`lunwen/clab-lab/scripts/edge_threshold_sensitivity.sh\` 生成，"
    echo "> 执行 spec §5.4.6 的强制敏感性行。**引用时必须标注这是敏感性分析** —— "
    echo "> 它换掉了部署的真实判定线（GB/T 22239-2019 Level 3），因此不得与主对比的结论混排。"
    echo ">"
    echo "> 输入：记录 \`$RECORDS\`（$RECORD_COUNT 条）｜候选与 \`-factors\`/\`-weights\` 与门禁① 逐项相同，"
    echo "> 唯一差别是 \`-threshold $T\`；工具原始输出（逐字）见 \`$(basename "$RAW")\`，"
    echo "> stderr（含覆盖提示）见 \`$(basename "$LOG")\`。"
    echo ""
    echo "---"
    echo ""
    cat "$RAW"
  } > "$REPORT"
  if [ -s "$LOG" ]; then tail -3 "$LOG" >&2; fi
  echo "edge_threshold_sensitivity: 阈值 $T 完成（exit 0，报告 $REPORT）"
done

# --- 汇总（含"用了哪个阈值"的显式记录）------------------------------------------
python3 - "$OUT_DIR/sensitivity.json" "$RUN_ID" "$RECORDS" "$RECORD_COUNT" "$CONFIG" \
  "$CONFIG_HASH" "$FACTORS_SPEC" "$WEIGHTS_SPEC" "$ENV_NAME" "$EDGECOMPARE" "${THRESHOLDS[@]}" <<'PY'
import json, sys, time
out, run_id, records, count, config, cfg_hash, factors, weights, env, tool = sys.argv[1:11]
thresholds = sys.argv[11:]
json.dump({
    'artifact_role': 'threshold-sensitivity',
    'is_primary_comparison': False,
    'run_id': run_id,
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'script': 'lunwen/clab-lab/scripts/edge_threshold_sensitivity.sh',
    'spec': 'docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md §5.4.6（阈值敏感性）',
    'env': env,
    'edgecompare': tool,
    'records_file': records,
    'records': int(count),
    'config': config,
    'config_hash_full': cfg_hash,
    'factors_spec': factors,
    'weights_spec': weights,
    'candidates': {'legacy': '采集模型（= EDGEEXP_CONFIG）', 'vector': 'vector.ini',
                   'graph': 'graph.ini', 'chain': 'chain.ini'},
    'thresholds': thresholds,
    'results': {t: {
        'threshold': float(t),
        'report': f'report-threshold-{t}.md',
        'tool_stdout': f'report-threshold-{t}.raw.md',
        'tool_stderr': f'report-threshold-{t}.log',
        'exit_code': 0,
    } for t in thresholds},
    'notes': {
        'not_primary': '本文件与同目录 report-threshold-*.md 都是**敏感性分析**产物：它们覆盖了'
                       '部署的真实判定线（记录自带的 observed.threshold）。主对比是不带 '
                       '-threshold 的那次运行（矩阵的 run.d/gate-gate1.json 与 run.d/.gate1.out）。'
                       '引用换阈值得到的那一行时**必须**标注这一点（spec §5.4.6）。',
        'same_inputs': '候选、记录、-factors/-weights 与门禁① 逐项相同，唯一差别是 -threshold；'
                       '-factors/-weights 由 edge_spec_lib.sh 推导（与矩阵同一份实现）。',
        'no_lab': '本脚本不调用 clab、不碰 Caldera、不起任何容器：只读记录 + 配置 + 离线工具。',
        'explicit_opt_in': '只有显式给出 EDGEEXP_SENSITIVITY_THRESHOLDS 才会运行，故默认路径不受影响。',
    },
}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print(f'edge_threshold_sensitivity: 汇总 → {out}')
PY

echo "============================================================"
echo "edge_threshold_sensitivity: 完成（阈值 ${THRESHOLDS[*]}）—— 引用这些结果时必须标注为敏感性分析"
