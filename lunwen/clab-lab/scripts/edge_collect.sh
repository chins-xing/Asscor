#!/bin/bash
# ============================================================================
# edge_collect.sh —— 单场景采集：把"配置 + 客观结果 + 宿主真实检查"join 成一条记录
# ============================================================================
#
# 用法：
#   ./scripts/edge_collect.sh <scenario> <config.ini> <attack.json> <run>
#
# 例（矩阵脚本用的就是这一条；注意从 lunwen/clab-lab 起算，配置在 ../../configs/）：
#   ./scripts/edge_collect.sh S0-baseline ../../configs/edgeexp/m0-baseline.ini \
#       data/edgefactors/attack-S0-baseline.json 1
#
# 做什么：
#   1. **产物新鲜度**：harness 产物必须是**本轮**产生的（started_at/finished_at + 文件 mtime），
#      否则一份陈旧的 attack-<scenario>.json 会静默提供旧的注入时刻、哈希与客观结果，
#      而时钟核对照样通过；
#   2. 幂等守卫：同一场景在目标 JSONL 里已有记录时**拒绝再写**（重复记录会让
#      "记录条数 == 场景数"这条断言失去意义；换一次运行请换 EDGEEXP_RECORDS 或归档旧文件，
#      续跑用 EDGEEXP_RESUME=1，见 edge_matrix.sh）；
#   3. 调 `edgescen`（最小 tag 集 expr,engine,checks 构建）采集**一条**记录；
#   4. 采集后立刻做四条核对，写进 `run.d/collect-<scenario>.json`：
#      · **因子集相等断言**（Fix round 1 / C2）：链上出现的因子集（归一 ID）必须与场景声明的
#        集合**逐项相等**（S0 基线 ⇒ 空集）。采集器自己只要求"链 ⊇ 期望集"，于是"声明空集却采到
#        六个因子"的基线可以静默通过 —— 整轮实验的因子塌缩就是这样藏起来的；
#      · **门禁⓪**：链上重复因子条目（按归一 ID 计数）—— 只看真实记录，不做静态推断；
#      · **注入时刻 < 采集时刻** + harness 报的注入时刻确实落进了记录（checks[] 逐条对齐，
#        注入检查缺席即失败）；
#      · 记录条数增量 == 1（多写或少写都失败）。
#
# **任何"记录已经落盘之后"的断言失败都会回滚这一条**（文件回到采集前的行数），并把被拒的那一行
# 留档到 `run.d/rejected-<scenario>.jsonl`：失败场景不得在数据集里留下半条证据，
# 但"为什么被拒"必须可查。
#
# 退出码：0 成功；1 任何一步失败（含 edgescen 非零退出、记录增量不等于 1、断言失败并回滚）。
#
# 环境变量：
#   EDGEEXP_ENV       环境标识（进 meta.env），默认 wsl-clab-14；**run>1 时必须显式给出**
#   EDGEEXP_RECORDS   记录文件，默认 <lab>/data/edgefactors/records-<env>-<date>.jsonl
#   EDGEEXP_EDGESCEN  edgescen 二进制，默认 <repo>/build/edgescen
#   EDGEEXP_RUN_STARTED_AT  本轮运行的起始时刻（RFC3339，矩阵脚本导出）；给了就要求
#                           harness 产物产生在这一刻之后
#   EDGEEXP_ATTACK_MAX_AGE_S 没有 RUN_STARTED_AT 时的产物年龄上限（秒，默认 3600）
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
RUN_STARTED_AT="${EDGEEXP_RUN_STARTED_AT:-}"
MAX_AGE_S="${EDGEEXP_ATTACK_MAX_AGE_S:-3600}"

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

# --- 0. run 号与环境标识必须成对 ----------------------------------------------
# run>1 是 A-1 的重复样本（spec §5.3）；若 env 仍是默认值，重复样本会被打上 wsl-clab-14 的
# 标签混进主数据集 —— 那正是"重复性实验"最容易被读错的地方。故要求显式声明。
if [ "$RUN" -gt 1 ] && [ -z "${EDGEEXP_ENV:-}" ]; then
  echo "edge_collect: run=$RUN（>1，重复样本）必须显式给 EDGEEXP_ENV（例如 EDGEEXP_ENV=a1-ubuntu），" >&2
  echo "  否则重复样本会被打上默认标签 wsl-clab-14 混进主战场数据集。" >&2
  exit 1
fi

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
    echo "  同一场景每轮只采一条；重跑请归档旧文件（mv $RECORDS $RECORDS.done）或另给 EDGEEXP_RECORDS；" >&2
    echo "  续跑整轮矩阵用 EDGEEXP_RESUME=1（矩阵脚本会跳过本文件里已有记录的场景）。" >&2
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

# 产物新鲜度（I7）：陈旧 harness 产物会静默提供旧的注入时刻/哈希/客观结果，而时钟核对照样通过。
ATTACK_MTIME=$(stat -c %Y "$ATTACK")
NOW_S=$(date -u +%s)
ATTACK_AGE=$((NOW_S - ATTACK_MTIME))
if [ -n "$RUN_STARTED_AT" ]; then
  RUN_START_S="$(python3 -c 'import datetime,sys;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$RUN_STARTED_AT")"
  if [ "$ATTACK_MTIME" -lt "$RUN_START_S" ]; then
    echo "edge_collect: harness 产物 $ATTACK 的 mtime（$(date -u -d @"$ATTACK_MTIME" +%FT%TZ)）早于本轮起始（$RUN_STARTED_AT）——" >&2
    echo "  这是**上一轮**的产物：注入时刻、剧本哈希与客观结果都会是旧的，而时钟核对照样通过。整轮失败。" >&2
    exit 1
  fi
elif [ "$ATTACK_AGE" -gt "$MAX_AGE_S" ]; then
  echo "edge_collect: harness 产物 $ATTACK 已 ${ATTACK_AGE}s 未更新（上限 ${MAX_AGE_S}s）且未给 EDGEEXP_RUN_STARTED_AT ——" >&2
  echo "  无法证明它是本轮产物。整轮失败（手工单场景采集请把 EDGEEXP_ATTACK_MAX_AGE_S 调大或重跑 edge_attack.sh）。" >&2
  exit 1
fi

export RECORDS SCENARIO ATTACK CONFIG ENV_NAME RUN ADDED ELAPSED TMP_OUT BEFORE AFTER
export EDGESCEN_OUT="$RUN_D/.edgescen-$SCENARIO.out"
export REJECTED_OUT="$RUN_D/rejected-$SCENARIO.jsonl"
export CONFIG_HASH="$(sha256sum "$CONFIG" | awk '{print $1}')"
export ATTACK_MTIME ATTACK_AGE RUN_STARTED_AT
set +e
python3 - <<'PY'
import datetime, json, os, re, sys

records_path = os.environ['RECORDS']
scenario = os.environ['SCENARIO']
tmp_out = os.environ['TMP_OUT']
ROLLBACK = 3  # 退出码 3 = "记录已落盘但断言失败，请回滚"


def fail(msg, rollback=False):
    print('edge_collect: ' + msg, file=sys.stderr)
    sys.exit(ROLLBACK if rollback else 1)


def norm(fid):
    return (fid or '').strip().upper()


def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


# 取最后一条记录（就是本次写的）
last_line, rec = None, None
with open(records_path, encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        if line.startswith('\ufeff'):
            line = line.lstrip('\ufeff')
        last_line, rec = line, json.loads(line)
if rec is None:
    fail('记录文件为空')
if not str(rec.get('scenario_id', '')).startswith(scenario):
    fail(f'最后一条记录的 scenario_id={rec.get("scenario_id")!r} 与本次场景 {scenario!r} 不符 —— 产物错位（该行已回滚）',
         rollback=True)

obs = rec.get('observed') or {}
chain = obs.get('edge_factor_chain') or []
checks = obs.get('checks') or []
harness = json.load(open(os.environ['ATTACK'], encoding='utf-8'))

# --- 因子集相等断言（Fix round 1 / C2）---------------------------------------
# 采集器只要求 chain ⊇ expectedChainFactors（S0 的期望集是空集），故"声明空集却采到六个因子"
# 的基线与"单因子场景采到全因子"都能静默通过 —— 一轮冒烟下来没人发现整批数据的因子向量相同。
# 这里改成**相等**：链上出现的因子集必须与场景声明的集合逐项相等，多一个少一个都整轮失败。
expected_raw = harness.get('expected_chain_factors')
if expected_raw is None:
    fail('harness 产物缺 expected_chain_factors（场景声明的期望上链因子集）—— 无法做相等断言；'
         '请用本轮的 edge_attack.sh 重新生成产物（旧的/手写的产物没有这个字段）')
expected = {norm(f) for f in expected_raw if norm(f)}
actual = {norm(ob.get('factor')) for ob in chain if norm(ob.get('factor'))}
missing = sorted(expected - actual)
extra = sorted(actual - expected)
equality = {
    'ok': not missing and not extra,
    'expected': sorted(expected),
    'actual': sorted(actual),
    'missing': missing,
    'extra': extra,
    'source': harness.get('expected_chain_factors_source', '未注明'),
    'note': '链上的因子集必须与场景声明**相等**（不是包含）：多出来的因子说明这台宿主上还有'
            '别的检查在自然失败，本场景的数据与其他场景不可区分（见 spec §5.4.7 的诚实边界）',
}

# --- 门禁⓪：链上重复因子条目（按归一 ID） -----------------------------------
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
injections = harness.get('injections') or []
collected_at = rec.get('meta', {}).get('timestamp', '')
check_ts = {c.get('id'): c.get('ts') for c in checks}
chain_ts = {ob.get('trigger_check'): ob.get('ts') for ob in chain}
clock = []
for inj in injections:
    cid, at = inj.get('check'), inj.get('at')
    cts = check_ts.get(cid)
    clock.append({
        'check': cid,
        'injected_at': at,
        'injected_check_present': cid in check_ts,
        'recorded_checks_ts': cts,
        'recorded_chain_ts': chain_ts.get(cid),
        'checks_ts_matches': cts == at,
        'before_collection': bool(at and collected_at and at < collected_at),
    })
# 注入检查必须出现在 checks[] 里：注入就是把该检查判为失败，它缺席说明注入没生效或记录没落全
# （此前只在"检查在场"时才比时刻，缺席被静默放过 —— 现在缺席即失败）。
absent = [e['check'] for e in clock if not e['injected_check_present']]
mismatch = [e['check'] for e in clock
            if e['injected_check_present'] and not e['checks_ts_matches']]
if injections:
    clock_ok = all(e['before_collection'] for e in clock) and not absent and not mismatch
    clock_status = 'ok' if clock_ok else 'failed'
    clock_note = ('注入时刻全部早于采集时刻（meta.timestamp = 记录装配时刻，即本工具能拿到的唯一采集'
                  '时间戳）；recorded_checks_ts 与 harness 报的注入时刻逐条比较（采集器把 harness'
                  '时刻原样写进 checks[].ts）')
else:
    # 零注入场景（S0 基线 / R 组真实缺失）：时钟核对**不适用**，写 n/a 而不是"通过"——
    # 空集上的 all() 恒真，写成 ok:true 会让人以为这里做过一次有效的核对。
    clock_ok, clock_status = None, 'n/a'
    clock_note = ('本场景没有注入时刻（S0 无因子 / R 组是真实缺失而非注入）—— 记录的 checks[].ts '
                  '取采集时刻，这是如实取值；时钟核对**不适用**（n/a），不是"通过"')

# --- 门禁②（采集侧证据）：edgescen 进程内自检的 round-trip 残差 -----------------
# 权威实现是采集器装配点的 `roundTripCheck`（不通过即**拒绝写出**），本行只是把那次
# 自检的残差落进 run.json，让"逐条 |复算 − 记录| == 0"在运行级证据里可见。
# 离线那一半（`edgecompare -candidate legacy=…`）只是**复核**：记录根本写不出来就没得复核，
# 故它失败时列为 warning 而不是整轮失败（门禁② 的实质已由进程内自检承担）。
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

config_hash = os.environ['CONFIG_HASH']
attack_meta = harness.get('attack') or {}
report = {
    'scenario': scenario,
    'phase': 'collect',
    'env': os.environ['ENV_NAME'],
    'run': int(os.environ['RUN']),
    'config': os.path.basename(os.environ['CONFIG']),
    'config_path': os.environ['CONFIG'],
    # 两种精度都给出并**在名字里写明**（M1）：`config_hash` 是 16 位十六进制，与记录里的
    # `meta.config_hash` 同形（那是引擎侧的截断口径，不能改）；`config_hash_full` 是完整 64 位，
    # 供独立复核。此前两个脚本各用一个精度、名字却相同，交叉核对时极易读错。
    'config_hash': 'sha256:' + config_hash[:16],
    'config_hash_full': 'sha256:' + config_hash,
    'hash_precision': {'config_hash': 'sha256[:16]（= 记录 meta.config_hash 的口径）',
                       'config_hash_full': 'sha256[:64]',
                       'topology_hash': 'sha256[:64]', 'playbook_hash': 'sha256[:64]'},
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
    'attack_product': {
        'path': os.environ['ATTACK'],
        'mtime': datetime.datetime.fromtimestamp(int(os.environ['ATTACK_MTIME']),
                                                 datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'age_s': int(os.environ['ATTACK_AGE']),
        'started_at': attack_meta.get('started_at'),
        'finished_at': attack_meta.get('finished_at'),
        'run_started_at': os.environ.get('RUN_STARTED_AT') or None,
        'freshness': ('mtime ≥ 本轮起始时刻' if os.environ.get('RUN_STARTED_AT')
                      else f'年龄 {int(os.environ["ATTACK_AGE"])}s ≤ 上限（未给本轮起始时刻）'),
    },
    'chain_factor_set_equality': equality,
    'gate0_duplicate_factors': gate0,
    'injection_vs_collection': {
        'ok': clock_ok,
        'status': clock_status,
        'collection_time': collected_at,
        'injection_count': len(injections),
        'entries': clock,
        'note': clock_note,
    },
    'checks_ts_mismatch': mismatch,
    'injected_check_absent': absent,
    'gate2_round_trip': gate2,
    'ground_truth': rec.get('ground_truth'),
    'ef3fa_on_chain': 'EF-3FA' in per_id,
    'ef3fa_note': ('链上有 EF-3FA。四份实验模板都声明了 `vector.EF-3FA`，而出厂 [edge_factors.custom] '
                   '里的 `EF-3FA = 0.82` 使它成为一个**普通因子**（不是只有 CascadeOnly 那条）—— '
                   '故 `-factors` 必须带上 `EF-3FA=0.82`：漏掉它会让该条目被工具**静默丢弃**'
                   '（那条惩罚凭空消失、分数被抬高、漏判率被低估），而不是什么"fallback 向量惩罚"。'
                   '禁止的只是"为了把门禁凑绿而静默塞值"这种动作。'
                   if 'EF-3FA' in per_id else '链上没有 EF-3FA'),
}
with open(tmp_out, 'w', encoding='utf-8') as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
    fh.write('\n')

# --- 断言失败：留档被拒的那一行 + 请调用方回滚 --------------------------------
def reject(msg):
    with open(os.environ['REJECTED_OUT'], 'a', encoding='utf-8') as fh:
        fh.write(last_line + '\n')
    fail(f'{msg}（该行已留档到 {os.environ["REJECTED_OUT"]} 并从数据集回滚）', rollback=True)


if not equality['ok']:
    reject('因子集相等断言未通过：链上 = %s，场景声明 = %s（多出 %s；缺少 %s）—— '
           '这台宿主上还有别的检查在自然失败，本场景与其他场景的数据不可区分'
           % (equality['actual'], equality['expected'], equality['extra'] or '无', equality['missing'] or '无'))
if absent:
    reject('注入检查没有出现在记录的 checks[] 里：' + ','.join(absent))
if mismatch:
    reject('harness 报的注入时刻没有被写进记录的 checks[].ts：' + ','.join(mismatch))
if injections and not clock_ok:
    reject('注入时刻与采集时刻的核对未通过（见 run.d 里的 entries）—— 时间结构不成立')

print(f'edge_collect: 因子集相等断言通过（链 {len(actual)} 个 ID = 场景声明）')
print(f'edge_collect: 门禁⓪ {gate0["verdict"]}（链 {gate0["chain_entries"]} 条 / 去重 {gate0["distinct_ids"]} 个 ID）')
if injections:
    print(f'edge_collect: 注入时刻核对通过（{len(injections)} 条，全部早于 {collected_at}）')
else:
    print('edge_collect: 注入时刻核对 n/a（本场景无注入）')
print(f'edge_collect: 记录 {report["scenario_id"]} 总分 {report["final_score"]} 阈值 {report["threshold"]} 判 {report["acceptable"]}｜'
      f'链 {report["chain_entries"]} 条｜失败检查 {report["failed_checks"]} 条')
PY
RC=$?
set -e

if [ "$RC" -eq 3 ]; then
  # 记录已经落盘但断言失败：回到采集前的行数（被拒的那一行已留档到 run.d/rejected-*.jsonl）。
  mv "$TMP_OUT" "$RUN_D/$FILLER"
  if [ "$BEFORE" -eq 0 ]; then
    : > "$RECORDS"
  else
    head -n "$BEFORE" "$RECORDS" > "$RECORDS.rollback"
    mv "$RECORDS.rollback" "$RECORDS"
  fi
  echo "edge_collect: 场景 $SCENARIO 的断言未通过 ⇒ 已回滚该条记录（文件回到 $BEFORE 行），整轮失败" >&2
  exit 1
fi
if [ "$RC" -ne 0 ]; then
  echo "edge_collect: 采集核对失败（退出码 $RC）—— 整轮失败" >&2
  exit 1
fi
mv "$TMP_OUT" "$RUN_D/$FILLER"
echo "edge_collect: 完成（${ELAPSED}s，记录 $BEFORE→$AFTER 条）→ $RUN_D/$FILLER"
