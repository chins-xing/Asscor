#!/bin/bash
# ============================================================================
# edge_collect.sh —— 单场景采集：把"配置 + 客观结果 + 宿主真实检查"join 成一条记录
# ============================================================================
#
# 用法：
#   ./scripts/edge_collect.sh <scenario> <config.ini> <attack.json> <run>
#
# 例（矩阵脚本用的就是这一条）：
#   ./scripts/edge_collect.sh S0-baseline ../../../configs/edgeexp/m0-baseline.ini \
#       data/edgefactors/attack-S0-baseline.json 1
#
# 做什么：
#   1. 幂等守卫：同一场景在目标 JSONL 里已有记录时**拒绝再写**（重复记录会让
#      "记录条数 == 场景数"这条断言失去意义；换一次运行请换 EDGEEXP_RECORDS 或归档旧文件）；
#   2. 调 `edgescen`（最小 tag 集 expr,engine,checks 构建）采集**一条**记录；
#   3. 采集后立刻做三件核对，写进 `run.d/collect-<scenario>.json`：
#      · **门禁⓪**：链上重复因子条目（按归一 ID 计数）—— 只看真实记录，不做静态推断；
#      · **注入时刻 < 采集时刻** + harness 报的注入时刻确实落进了记录（checks[]/链上 ts 逐条对齐）；
#      · 记录条数增量 == 1（多写或少写都失败）。
#
# 退出码：0 成功；1 任何一步失败（含 edgescen 非零退出、记录增量不等于 1）。
#
# 环境变量：
#   EDGEEXP_ENV       环境标识（进 meta.env），默认 wsl-clab-14
#   EDGEEXP_RECORDS   记录文件，默认 <lab>/data/edgefactors/records-<env>-<date>.jsonl
#   EDGEEXP_EDGESCEN  edgescen 二进制，默认 <repo>/build/edgescen
# ============================================================================
set -euo pipefail

SCENARIO="${1:-}"
CONFIG="${2:-}"
ATTACK="${3:-}"
RUN="${4:-1}"
if [ -z "$SCENARIO" ] || [ -z "$CONFIG" ] || [ -z "$ATTACK" ]; then
  echo "用法: edge_collect.sh <scenario> <config.ini> <attack.json> <run>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
RUN_D="$DATA_DIR/run.d"
ENV_NAME="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-$ENV_NAME-$TODAY.jsonl}"
EDGESCEN="${EDGEEXP_EDGESCEN:-$REPO_ROOT/build/edgescen}"

mkdir -p "$RUN_D"
FILLER="collect-$SCENARIO.json"
TMP_OUT="$RUN_D/.$FILLER.tmp"

[ -x "$EDGESCEN" ] || {
  echo "edge_collect: $EDGESCEN 不存在或不可执行 —— 先交叉编译：" >&2
  echo "  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags 'expr,engine,checks' -o build/edgescen ./cmd/edgescen" >&2
  exit 1
}
[ -f "$CONFIG" ] || { echo "edge_collect: 配置不存在: $CONFIG" >&2; exit 1; }
[ -f "$ATTACK" ] || { echo "edge_collect: harness 产物不存在: $ATTACK（先跑 edge_attack.sh）" >&2; exit 1; }

# --- 1. 幂等守卫 -------------------------------------------------------------
mkdir -p "$DATA_DIR"
BEFORE=0
if [ -f "$RECORDS" ]; then BEFORE=$(wc -l < "$RECORDS"); fi
if [ -f "$RECORDS" ]; then
  # 场景标识形如 "<scenario>-r<run>"（JSONL 是 json.Marshal 的紧凑形式，无空格）；
  # 同场景（不论 run 号）已有记录即拒绝。
  DUP=$(grep -cE "\"scenario_id\":\"$SCENARIO" "$RECORDS" || true)
  if [ "${DUP:-0}" -gt 0 ]; then
    echo "edge_collect: $RECORDS 里已经有 $DUP 条 $SCENARIO 的记录 —— 拒绝再写。" >&2
    echo "  同一场景每轮只采一条；重跑请归档旧文件（mv $RECORDS $RECORDS.done）或另给 EDGEEXP_RECORDS。" >&2
    exit 1
  fi
fi

# --- 2. 采集 -----------------------------------------------------------------
echo "edge_collect: 采集场景 $SCENARIO（配置 $(basename "$CONFIG")，run=$RUN，env=$ENV_NAME）"
T0=$(date -u +%s)
set +e
"$EDGESCEN" --scenario "$SCENARIO" --config "$CONFIG" \
  --attack-out "$ATTACK" --out "$RECORDS" --run "$RUN" --env "$ENV_NAME" \
  > "$RUN_D/.edgescen-$SCENARIO.out" 2> "$RUN_D/.edgescen-$SCENARIO.err"
RC=$?
set -e
ELAPSED=$(( $(date -u +%s) - T0 ))
cat "$RUN_D/.edgescen-$SCENARIO.out"
if [ "$RC" -ne 0 ]; then
  echo "edge_collect: edgescen 退出码 $RC —— 采集失败，整轮失败（不跳过继续）：" >&2
  cat "$RUN_D/.edgescen-$SCENARIO.err" >&2
  exit 1
fi
cat "$RUN_D/.edgescen-$SCENARIO.err" >&2 || true

# --- 3. 核对 -----------------------------------------------------------------
AFTER=$(wc -l < "$RECORDS")
ADDED=$((AFTER - BEFORE))
if [ "$ADDED" -ne 1 ]; then
  echo "edge_collect: 本次采集写入了 $ADDED 条记录（应为 1）—— 记录条数与场景数对不上，整轮失败" >&2
  exit 1
fi

export RECORDS SCENARIO ATTACK CONFIG ENV_NAME RUN ADDED ELAPSED TMP_OUT BEFORE AFTER
export EDGESCEN_OUT="$RUN_D/.edgescen-$SCENARIO.out"
export CONFIG_HASH="$(sha256sum "$CONFIG" | awk '{print $1}')"
python3 - <<'PY'
import json, os, re, sys

records_path = os.environ['RECORDS']
scenario = os.environ['SCENARIO']
tmp_out = os.environ['TMP_OUT']

def fail(msg):
    print('edge_collect: ' + msg, file=sys.stderr)
    sys.exit(1)

# 取最后一条记录（就是本次写的）
rec = None
with open(records_path, encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        if line.startswith('\ufeff'):
            line = line.lstrip('\ufeff')
        rec = json.loads(line)
if rec is None:
    fail('记录文件为空')
if not str(rec.get('scenario_id', '')).startswith(scenario):
    fail(f'最后一条记录的 scenario_id={rec.get("scenario_id")!r} 与本次场景 {scenario!r} 不符 —— 产物错位')

obs = rec.get('observed') or {}
chain = obs.get('edge_factor_chain') or []
checks = obs.get('checks') or []

# --- 门禁⓪：链上重复因子条目（按归一 ID） -----------------------------------
def norm(fid):
    return (fid or '').strip().upper()

per_id = {}
for ob in chain:
    per_id[norm(ob.get('factor'))] = per_id.get(norm(ob.get('factor')), 0) + 1
dups = {k: v for k, v in sorted(per_id.items()) if v >= 2}
gate0 = {
    'chain_entries': len(chain),
    'distinct_ids': len(per_id),
    'duplicate_entries': sum(v - 1 for v in dups.values()),
    'duplicate_ids': dups,
    'verdict': ('观察到重复条目: ' + ', '.join(f'{k}×{v}' for k, v in dups.items())) if dups
               else '未观察到重复条目',
    'method': '按归一化因子 ID（trim+upper，与 edgefactor.NormalizeFactorID 同义）统计链上条目数；只统计真实记录的链，不做静态推断',
}

# --- 注入时刻 vs 采集时刻 ----------------------------------------------------
harness = json.load(open(os.environ['ATTACK'], encoding='utf-8'))
injections = harness.get('injections') or []
collected_at = rec.get('meta', {}).get('timestamp', '')
check_ts = {c.get('id'): c.get('ts') for c in checks}
chain_ts = {ob.get('trigger_check'): ob.get('ts') for ob in chain}
clock = []
for inj in injections:
    cid, at = inj.get('check'), inj.get('at')
    cts = check_ts.get(cid)
    lts = chain_ts.get(cid)
    clock.append({
        'check': cid,
        'injected_at': at,
        'recorded_checks_ts': cts,
        'recorded_chain_ts': lts,
        'checks_ts_matches': cts == at,
        'before_collection': bool(at and collected_at and at < collected_at),
    })
clock_ok = all(e['before_collection'] for e in clock) and len(clock) == len(injections)
mismatch = [e['check'] for e in clock if e['recorded_checks_ts'] is not None and not e['checks_ts_matches']]

# --- 门禁②（采集侧证据）：edgescen 进程内自检的 round-trip 残差 -----------------
# 权威实现是采集器装配点的 `roundTripCheck`（不通过即**拒绝写出**），本行只是把那次
# 自检的残差落进 run.json，让"逐条 |复算 − 记录| == 0"在运行级证据里可见。
gate2 = {'source': 'edgescen 进程内自检（装配点；不通过即拒绝写出该条记录）', 'delta': None}
out_path = os.environ.get('EDGESCEN_OUT', '')
if out_path and os.path.exists(out_path):
    for line in open(out_path, encoding='utf-8'):
        if 'round-trip' in line:
            nums = re.findall(r'[-+]?\d+\.?\d*(?:[eE][-+]?\d+)?', line)
            if len(nums) >= 3:
                gate2 = {'source': gate2['source'], 'recomputed': float(nums[0]), 'recorded': float(nums[1]),
                         'delta': float(nums[2]),
                         'tolerance': float(nums[3]) if len(nums) >= 4 else 0.005,
                         'line': line.strip()}
            else:
                gate2 = {'source': gate2['source'], 'delta': None, 'line': line.strip(),
                         'note': '无法从该行解析出残差'}
            break

report = {
    'scenario': scenario,
    'phase': 'collect',
    'env': os.environ['ENV_NAME'],
    'run': int(os.environ['RUN']),
    'config': os.path.basename(os.environ['CONFIG']),
    'config_path': os.environ['CONFIG'],
    'config_hash': 'sha256:' + os.environ['CONFIG_HASH'],
    'records_file': records_path,
    'records_before': int(os.environ['BEFORE']),
    'records_after': int(os.environ['AFTER']),
    'record_added': int(os.environ['ADDED']),
    'elapsed_s': int(os.environ['ELAPSED']),
    'scenario_id': rec.get('scenario_id'),
    'factors': rec.get('factors'),
    'injection': rec.get('injection'),
    'chain_entries': len(chain),
    'failed_checks': len(checks),
    'final_score': obs.get('final_score'),
    'threshold': obs.get('threshold'),
    'acceptable': obs.get('acceptable'),
    'effective_weights': obs.get('effective_weights'),
    'spc_score': obs.get('spc_score'),
    'threat_coeff': obs.get('threat_coeff'),
    'weight_source': rec.get('meta', {}).get('weight_source'),
    'ts_source': rec.get('meta', {}).get('ts_source'),
    'collected_at': collected_at,
    'gate0_duplicate_factors': gate0,
    'injection_vs_collection': {
        'ok': clock_ok,
        'collection_time': collected_at,
        'injection_count': len(injections),
        'entries': clock,
        'note': ('本场景没有注入时刻（S0 无因子 / R 组是真实缺失而非注入）—— 记录的 checks[].ts 取采集时刻，'
                 '这是如实取值' if not injections else
                 '注入时刻全部早于采集时刻（meta.timestamp = 记录装配时刻，即本工具能拿到的唯一采集时间戳）；'
                 'recorded_checks_ts 与 harness 报的注入时刻逐条比较（采集器把 harness 时刻原样写进 checks[].ts）'),
    },
    'checks_ts_mismatch': mismatch,
    'gate2_round_trip': gate2,
    'ground_truth': rec.get('ground_truth'),
    'ef3fa_on_chain': 'EF-3FA' in per_id,
    'ef3fa_note': ('该记录的链上有 EF-3FA —— 它在出厂配置的 [edge_factors.custom] 里不是 CascadeOnly，'
                   '属于"EF-3FA 待用户裁定 ④"的子集：禁止把 EF-3FA 塞进 -factors（那会给 V/G/C 一个引擎从未施加的'
                   'fallback 向量惩罚），只把它单独列出并标注"待裁定后重跑"'
                   if 'EF-3FA' in per_id else '链上没有 EF-3FA，可进入 -factors 覆盖得住的数据集'),
}
with open(tmp_out, 'w', encoding='utf-8') as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
    fh.write('\n')

if not clock_ok:
    fail('注入时刻与采集时刻的核对未通过（见 run.d 里的 entries）—— 时间结构不成立，整轮失败')
if mismatch:
    fail('harness 报的注入时刻没有被写进记录的 checks[].ts：' + ','.join(mismatch))

print(f'edge_collect: 门禁⓪ {gate0["verdict"]}（链 {gate0["chain_entries"]} 条 / 去重 {gate0["distinct_ids"]} 个 ID）')
print(f'edge_collect: 注入时刻核对通过（{len(injections)} 条，全部早于 {collected_at}）')
print(f'edge_collect: 记录 {report["scenario_id"]} 总分 {report["final_score"]} 阈值 {report["threshold"]} 判 {report["acceptable"]}｜'
      f'链 {report["chain_entries"]} 条｜失败检查 {report["failed_checks"]} 条')
print(f'edge_collect: EF-3FA 子集：{report["ef3fa_note"]}')
PY
mv "$TMP_OUT" "$RUN_D/$FILLER"
echo "edge_collect: 完成（${ELAPSED}s，记录 $BEFORE→$AFTER 条）→ $RUN_D/$FILLER"
