#!/bin/bash
# ============================================================================
# edge_matrix.sh —— 场景矩阵驱动 + 数据集门禁（spec §5 / §5.4）
# ============================================================================
#
# 用法：
#   ./scripts/edge_matrix.sh                       # 全量 25 场景（S0–S5 = 22 + R = 3）
#   ./scripts/edge_matrix.sh S0-baseline S5-cascade-3fa R-no-ids   # 冒烟子集（只跑这几个）
#
# 每个场景做三件事（顺序即依赖，任一失败即整轮失败，**不跳过继续**）：
#   edge_reset.sh   → 干净环境（clab destroy+deploy + Caldera + sandcat agent）
#   edge_attack.sh  → 相位推进 + 固定剧本 + 客观结果
#   edge_collect.sh  → 用**同一份采集配置**采集一条记录（候选差异完全由离线比较覆盖）
#
# 为什么每场景只采**一条**记录（Task 3 实测修正）：
#   · 记录里的域分是**域级修正前的基分**、链与 E/T 与候选无关、`Evaluate` 也从不读
#     `final_score` ⇒ 四个候选的差异**完全**由离线 `edgecompare` 覆盖；
#   · `chain` 在线**不可执行**（C1 裁定：装配期 fail-fast）⇒ 拿 chain.ini 跑 edgescen
#     必然被拒；若"任何非零退出即整轮失败"，用 chain 模板采集会把整轮判死。
#
# 运行级产物（`data/edgefactors/`）：
#   run.json                     本次运行的汇总（拓扑/剧本/配置哈希、权重口径、逐场景耗时、
#                             门禁⓪ 重复因子计数、注入-采集时钟核对、记录条数、因子集相等断言……）
#   run-<run-id>.json            同一份内容的不可变副本（历史留档）
#   run.d/{reset,attack,collect,gate}-*.json   逐场景碎片（run.json 由它们汇总）
#   run.d/rejected-<scenario>.jsonl            被断言拒掉、已从数据集回滚的记录（留档）
#   records-<env>-<date>.jsonl   记录本体（每场景一条）
#
# 环境变量：见各子脚本；本脚本另有
#   EDGEEXP_RUN_ID      本次运行标识（默认 <date>-<pid>），进 run.json 与副本名
#   EDGEEXP_RUN_INDEX   重复号（>1 = A-1 的重复样本；此时**必须**显式给 EDGEEXP_ENV）
#   EDGEEXP_RESUME=1    续跑：跳过目标 JSONL 里已有记录的场景（幂等守卫不再把整轮判死）；
#                       被跳过的场景计入 `scenarios_skipped_resume`，并在 run.json 里如实标出
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
RUN_D="$DATA_DIR/run.d"
ENV_NAME="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
RUN_ID="${EDGEEXP_RUN_ID:-$TODAY-$$}"
CONFIG="${EDGEEXP_CONFIG:-$REPO_ROOT/configs/edgeexp/m0-baseline.ini}"
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-$ENV_NAME-$TODAY.jsonl}"
EDGESCEN="${EDGEEXP_EDGESCEN:-$REPO_ROOT/build/edgescen}"
EDGECOMPARE="${EDGEEXP_EDGECOMPARE:-$REPO_ROOT/build/edgecompare}"

# --- 场景名单（spec §5：S0–S5 = 22 组 + R = 3 组真实缺失对照，全列出，不留占位）----
SCENARIOS=(
  S0-baseline
  S1-2fa S1-apparmor S1-no-ids S1-no-siem S1-selinux S1-syn-cookie
  S2-2fa-selinux S2-apparmor-no-ids S2-no-siem-no-ids S2-selinux-apparmor
  S2-selinux-no-ids S2-selinux-no-siem S2-syn-cookie-no-ids S2-syn-cookie-no-siem
  S3-3fa-selinux-apparmor S3-selinux-apparmor-2fa S3-selinux-no-siem-no-ids S3-syn-cookie-no-siem-no-ids
  S4-all
  S5-2fa-only S5-cascade-3fa
  R-no-2fa R-no-ids R-no-siem
)
[ "${#SCENARIOS[@]}" -eq 25 ] || { echo "edge_matrix: 场景数必须是 25（S0–S5 = 22 + R = 3），实际 ${#SCENARIOS[@]}" >&2; exit 1; }

# 选中的场景（无参数 = 全量）
if [ "$#" -gt 0 ]; then
  SELECTED=("$@")
  MODE="smoke"
else
  SELECTED=("${SCENARIOS[@]}")
  MODE="sweep"
fi
for s in "${SELECTED[@]}"; do
  found=0
  for k in "${SCENARIOS[@]}"; do [ "$s" = "$k" ] && found=1 && break; done
  [ "$found" -eq 1 ] || { echo "edge_matrix: $s 不在 25 场景名单里" >&2; exit 1; }
done

# 场景名单必须与采集器的场景表**逐项相等**（不是包含）：两份名单漂移过就会"少场景而人不知"。
# 判据取 `edgescen -list`（采集器自己的视图），不是再抄一份 —— 这正是把它放在这里的原因。
if [ -x "$EDGESCEN" ]; then
  python3 - "$EDGESCEN" "${SCENARIOS[@]}" <<'PY'
import subprocess, sys
binary, declared = sys.argv[1], sys.argv[2:]
out = subprocess.run([binary, '-list'], capture_output=True, text=True, check=True).stdout
listed = []
for line in out.splitlines():
    if not line.startswith('  '):
        continue
    name = line.strip().split()[0] if line.strip() else ''
    if name:
        listed.append(name)
d, l = set(declared), set(listed)
if d != l:
    print('edge_matrix: 场景名单与采集器不一致 —— 只在本清单里的: %s；只在采集器里的: %s'
          % (sorted(d - l) or '无', sorted(l - d) or '无'), file=sys.stderr)
    sys.exit(1)
print(f'edge_matrix: 场景名单与采集器 edgescen -list 逐项相等（{len(d)} 组）')
PY
else
  echo "edge_matrix: 警告：$EDGESCEN 不存在，跳过与采集器场景表的名单核对" >&2
fi

# run>1 是 A-1 的重复样本：env 仍是默认值时重复样本会被打上 wsl-clab-14 混进主数据集。
if [ "${EDGEEXP_RUN_INDEX:-1}" -gt 1 ] && [ -z "${EDGEEXP_ENV:-}" ]; then
  echo "edge_matrix: EDGEEXP_RUN_INDEX=${EDGEEXP_RUN_INDEX}（>1）必须显式给 EDGEEXP_ENV —— 否则重复样本会被打上默认标签 $ENV_NAME 混进主战场数据集" >&2
  exit 1
fi

mkdir -p "$RUN_D"
# 清掉上一轮的逐场景碎片（不清理会产生"上一轮的片段混进本轮 run.json"的假证据）。
rm -f "$RUN_D"/reset-*.json "$RUN_D"/attack-*.json "$RUN_D"/collect-*.json "$RUN_D"/gate-*.json
[ -x "$EDGESCEN" ] || { echo "edge_matrix: $EDGESCEN 不存在（先交叉编译，见 edge_collect.sh 的提示）" >&2; exit 1; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
RUN_STARTED="$(now_iso)"
RUN_START_S=$(date -u +%s)

# 运行状态（供 EXIT trap 汇总）：逐场景进度 + 退出码
STATE="$RUN_D/.state.json"
python3 - "$STATE" "$RUN_ID" "$ENV_NAME" "$MODE" "$RECORDS" "$CONFIG" "$RUN_STARTED" "$RUN_START_S" "${SELECTED[@]}" <<'PY'
import json, sys
state = {
    'run_id': sys.argv[2], 'env': sys.argv[3], 'mode': sys.argv[4],
    'records_file': sys.argv[5], 'config': sys.argv[6],
    'started_at': sys.argv[7], 'start_s': int(sys.argv[8]),
    'scenarios_selected': sys.argv[9:], 'completed': [], 'failed': None,
}
json.dump(state, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY

# 逐场景进度落盘（中断也能看出跑到哪、哪一步花了多久）
state_add() { # state_add <scenario> <step> <elapsed_s>
  python3 - "$STATE" "$1" "$2" "$3" <<'PY'
import json, sys
p, scen, step, secs = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = json.load(open(p, encoding='utf-8'))
s.setdefault('progress', {}).setdefault(scen, {})[step] = secs
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
}
state_complete() { # state_complete <scenario>
  python3 - "$STATE" "$1" <<'PY'
import json, sys
p, scen = sys.argv[1], sys.argv[2]
s = json.load(open(p, encoding='utf-8'))
if scen not in s['completed']:
    s['completed'].append(scen)
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
}
state_fail() { # state_fail <退出码> <说明>
  python3 - "$STATE" "$1" "$2" <<'PY'
import json, sys
p = sys.argv[1]
s = json.load(open(p, encoding='utf-8'))
s['failed'] = {'exit_code': int(sys.argv[2]), 'reason': sys.argv[3]}
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
}

# --- run.json 汇总（EXIT trap 里无条件写；写不出来要**响亮地**说出来 ------------
write_run_json() {
  export RUN_D STATE DATA_DIR ENV_NAME TODAY RUN_ID RECORDS CONFIG REPO_ROOT EDGESCOMPARE
  export DECLARED_COUNT="${#SCENARIOS[@]}"
  python3 - "$RUN_D" "$DATA_DIR/run.json" "$DATA_DIR/run-$RUN_ID.json" <<'PY'
import glob, json, os, sys, time

run_d, out_stable, out_copy = sys.argv[1], sys.argv[2], sys.argv[3]
state = json.load(open(os.path.join(run_d, '.state.json'), encoding='utf-8'))

def frag(kind, scenario):
    p = os.path.join(run_d, f'{kind}-{scenario}.json')
    if not os.path.exists(p):
        return None
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception as exc:
        return {'_unparsable': str(exc), 'path': p}

scen = state['scenarios_selected']
per_scenario = []
gate0 = {'per_scenario': {}, 'duplicate_observed': [], 'chain_entries_total': 0}
clock = {'all_ok': True, 'per_scenario': {}}
gate2 = {'per_scenario': {}, 'max_abs_delta': 0.0, 'source': 'edgescen 进程内自检（装配点，容差 0.005，不通过即拒绝写出）'}
equality = {'per_scenario': {}, 'all_ok': True, 'failures': []}
records_expected = 0
ts_sources = {}
ts_from_dataset = {}   # 从记录本体读到的 ts 口径（续跑时没有 collect 碎片的兜底）

for s in scen:
    reset, attack, collect = frag('reset', s), frag('attack', s), frag('collect', s)
    entry = {'scenario': s, 'reset': reset, 'attack': attack, 'collect': collect,
             'timings_s': state.get('progress', {}).get(s, {})}
    entry['timings_s']['total'] = sum(v for v in entry['timings_s'].values() if isinstance(v, int))
    per_scenario.append(entry)
    if collect:
        g0 = collect.get('gate0_duplicate_factors') or {}
        gate0['per_scenario'][s] = g0
        gate0['chain_entries_total'] += g0.get('chain_entries', 0) or 0
        if g0.get('duplicate_ids'):
            gate0['duplicate_observed'].append({'scenario': s, 'duplicate_ids': g0['duplicate_ids']})
        eq = collect.get('chain_factor_set_equality') or {}
        if eq:
            equality['per_scenario'][s] = eq
            if not eq.get('ok'):
                equality['all_ok'] = False
                equality['failures'].append({'scenario': s, 'missing': eq.get('missing'),
                                             'extra': eq.get('extra')})
        ck = collect.get('injection_vs_collection') or {}
        clock['per_scenario'][s] = {'status': ck.get('status'), 'ok': ck.get('ok'),
                                    'injection_count': ck.get('injection_count'),
                                    'collection_time': ck.get('collection_time')}
        if ck.get('status') == 'failed':
            clock['all_ok'] = False
        g2 = collect.get('gate2_round_trip') or {}
        if g2:
            gate2['per_scenario'][s] = g2
            d = abs(float(g2.get('delta') or 0.0))
            gate2['max_abs_delta'] = max(gate2['max_abs_delta'], d)
        if collect.get('ts_source'):
            ts_sources.setdefault(collect['ts_source'], []).append(s)
        if collect.get('record_added') == 1:
            records_expected += 1

gate0['method'] = ('按归一化因子 ID 统计每条真实记录链上的条目数（只看记录，不做静态推断）；'
                   'per_scenario 只覆盖本次写过的场景，dataset_scan 覆盖整份记录文件')

# 记录条数（I6）：**目标 JSONL 的总行数**必须与本次选中的场景数一致 —— 只统计
# "本次 write 成功了几次"会漏掉文件里原有的其它场景行（续跑/换 run_id/共用文件时），
# 于是 record_counts_ok 会在一个装着别的记录的目录上照常报 true。
records_file = state['records_file']
file_lines = 0
gate0_dataset = {'per_record': {}, 'duplicate_observed': [], 'chain_entries_total': 0}
if os.path.exists(records_file):
    with open(records_file, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            file_lines += 1
            # 门禁⓪ 的**数据集级**扫描（Fix round 1）：逐场景碎片只覆盖"本次写过记录的场景"，
            # 续跑模式下整轮可能一条都没写 ⇒ 只看碎片会把"数据集里有重复条目"报成"未观察到重复条目"。
            # 重复条目是**记录本身**的性质，故直接按文件统计（与 edge_collect.sh 的口径同义：
            # 归一 ID = trim+upper）。
            try:
                rec = json.loads(line)
            except Exception:
                continue
            chain = (rec.get('observed') or {}).get('edge_factor_chain') or []
            counts = {}
            for ob in chain:
                fid = (ob.get('factor') or '').strip().upper()
                counts[fid] = counts.get(fid, 0) + 1
            gate0_dataset['chain_entries_total'] += len(chain)
            dups = {k: v for k, v in sorted(counts.items()) if v >= 2}
            sid = rec.get('scenario_id')
            # 链条目 ts 的口径也顺手从记录本体读（续跑模式下没有 collect 碎片，而 ts_source
            # 本来就写在记录的 meta 里 —— 不读它就只能报 None）。
            ts_from_dataset.setdefault((rec.get('meta') or {}).get('ts_source') or '(未注明)', []).append(sid)
            gate0_dataset['per_record'][sid] = {'chain_entries': len(chain),
                                                'distinct_ids': len(counts), 'duplicate_ids': dups}
            if dups:
                gate0_dataset['duplicate_observed'].append({'scenario_id': sid, 'duplicate_ids': dups})
skipped_resume = state.get('skipped_resume', [])

# 链条目 ts 的口径**逐场景**留档（M2）：同时注入场景与顺序注入场景的 ts 基准不同，
# 把它们聚成一个字符串只会得到"第一个场景的那句话"，读起来像全轮统一 —— 那是假的统一。
# 优先用本次采集碎片；续跑/空碎片时退回从记录本体读到的口径（扫描已完成，见上）。
if not ts_sources:
    ts_sources = ts_from_dataset
if len(ts_sources) == 1:
    ts_source_summary = next(iter(ts_sources))
elif ts_sources:
    ts_source_summary = '逐场景不同（见 per_scenario[].collect.ts_source）：' + '; '.join(
        f'{len(v)} 个场景 → {k}' for k, v in sorted(ts_sources.items()))
else:
    ts_source_summary = None

# 门禁⓪ 的裁决与口径汇总放在数据集扫描**之后**（扫描结果参与裁决）。
gate0['dataset_scan'] = gate0_dataset
if gate0['duplicate_observed']:
    gate0['verdict'] = ('观察到重复条目：'
                        + '; '.join(f"{d['scenario']}→{d['duplicate_ids']}" for d in gate0['duplicate_observed']))
elif gate0_dataset['duplicate_observed']:
    gate0['verdict'] = ('本次运行没有新采记录（续跑），但**数据集里**观察到重复条目：'
                        + '; '.join(f"{d['scenario_id']}→{d['duplicate_ids']}" for d in gate0_dataset['duplicate_observed']))
else:
    gate0['verdict'] = '未观察到重复条目（**不得**据静态溯源宣称引擎会重复乘——那只是配置层面的推断）'

gate1 = frag('gate', 'gate1') or {}
gate2_out = frag('gate', 'gate2') or {}

# run 级输入指纹：拓扑哈希 / 剧本哈希 / 配置哈希 / 权重口径 —— 一次运行的全部输入必须能
# 在这一个文件里查到，而不是散落在逐场景条目里（"这份记录是按哪个剧本采的"要能一眼回答）。
inputs_path = os.path.join(run_d, 'gate-inputs.json')
run_inputs = json.load(open(inputs_path, encoding='utf-8')) if os.path.exists(inputs_path) else {}
run_inputs.setdefault('env', state['env'])
for scen_name in scen:
    for kind, keys in (('reset', ['topology', 'topology_hash']),
                       ('attack', ['playbook_hash', 'playbook']),
                       ('collect', ['config_path', 'config_hash', 'config_hash_full',
                                    'weight_source', 'ts_source'])):
        node = frag(kind, scen_name)
        if not isinstance(node, dict):
            continue
        for k in keys:
            if node.get(k) and not run_inputs.get(k):
                run_inputs[k] = node[k]
if run_inputs.get('config_path'):
    run_inputs.setdefault('collection_config', run_inputs['config_path'])
run = {
    'run_id': state['run_id'],
    'env': state['env'],
    'mode': state['mode'],
    'started_at': state['started_at'],
    'finished_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'elapsed_s': int(time.time()) - int(state['start_s']),
    'scenarios_declared': int(os.environ['DECLARED_COUNT']),
    'scenarios_selected': scen,
    'scenarios_completed': state.get('completed', []),
    'scenarios_skipped_resume': skipped_resume,
    'failed': state.get('failed'),
    'progress_s': state.get('progress', {}),
    'records_file': records_file,
    'records_expected': len(scen),
    'records_written_this_run': records_expected,
    'records_file_total_lines': file_lines,
    'records_missing_for_selected': len(scen) - file_lines,
    # 记录条数（I6）：判据要同时看两件事 —— ① 这份文件里**至少**有本次选中场景数那么多条记录
    # （只统计"本次写了几次"会漏掉文件里原有的别的场景行）；② 本次写入 + 续跑跳过 == 选中场景数
    # （续跑模式下本次写入可以是 0，那不是缺口）。只看 ① 会在"文件里有别的场景行"时误报通过，
    # 只看 ② 会在续跑时误报失败。
    'record_counts_ok': (file_lines == len(scen)) and (records_expected + len(skipped_resume) == len(scen)),
    'run_inputs': run_inputs,
    'chain_factor_set_equality': equality,
    'gate0_duplicate_factors': gate0,
    'gate1_offline_compare': gate1,
    'gate2_round_trip': gate2,
    'gate2_offline_compare': gate2_out,
    'injection_vs_collection': clock,
    'chain_ts_source': ts_source_summary,
    'per_scenario': per_scenario,
    'notes': {
        'per_scenario_records': '每场景只采 1 条（chain 在线不可执行；候选差异由离线 edgecompare 覆盖）',
        'factor_set_equality': '链上的因子集必须与场景声明**相等**（edge_collect.sh 断言；多一个因子即整轮失败）',
        'ef3fa': 'EF-3FA 是普通因子（四份模板都声明 vector.EF-3FA；出厂 [edge_factors.custom] EF-3FA = 0.82）'
                 '⇒ -factors 必须含 EF-3FA=0.82。漏掉它会让该条目被工具静默丢弃（那条惩罚凭空消失、'
                 '分数被抬高），而不是什么"fallback 向量惩罚"；禁止的只是"为让门禁变绿而静默塞值"。',
        'weights': '离线复算以记录自带的 observed.effective_weights 为准；-weights 只是回退表',
        'gate1_dataset': '门禁① 跑在**全量**记录上（不再按 EF-3FA 切子集）',
    },
}
for path in (out_stable, out_copy):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(run, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
print(f'edge_matrix: run.json → {out_stable}')
print(f'edge_matrix: 记录条数 本次写入 {run["records_written_this_run"]}/{run["records_expected"]}｜'
      f'文件总行数 {run["records_file_total_lines"]}｜record_counts_ok={run["record_counts_ok"]}')
print(f'edge_matrix: 因子集相等断言 all_ok={equality["all_ok"]}')
print(f'edge_matrix: 门禁⓪ {gate0["verdict"]}')
print(f'edge_matrix: 注入-采集时钟核对 all_ok={clock["all_ok"]}')
if gate1:
    print(f'edge_matrix: 门禁① exit={gate1.get("exit_code")}（{gate1.get("dataset","?")}，{gate1.get("records","?")} 条）')
if gate2:
    print(f'edge_matrix: 门禁② 最大偏差 {gate2["max_abs_delta"]:.4g}（{len(gate2["per_scenario"])} 条）')
PY
}

FINISHED=0
# 失败原因只由"具体知道原因的那一处"写：trap 里的兜底说明**不得**覆盖门禁①/② 这类
# 已经写明的原因（此前 trap 无条件 state_fail，把"门禁① exit=1"改成了通用的
# "edge_matrix 中断/失败" —— run.json 里因此看不出是哪一道门禁红）。
FAIL_REASON=""
on_exit() {
  code=$?
  if [ "$FINISHED" -eq 0 ]; then
    if [ -n "$FAIL_REASON" ]; then
      state_fail "$code" "$FAIL_REASON" || true
    else
      state_fail "$code" "edge_matrix 中断/失败（见上面的 stderr）" || true
    fi
  fi
  if ! write_run_json; then
    echo "edge_matrix: run.json 写失败 —— 本次运行的运行级证据缺失（退出码仍为 $code）" >&2
  fi
  exit "$code"
}
trap on_exit EXIT

# --- 逐场景 -----------------------------------------------------------------
echo "edge_matrix: 运行 $RUN_ID（$MODE，${#SELECTED[@]} 个场景 / 声明的 ${#SCENARIOS[@]}）"
echo "edge_matrix: 记录文件 $RECORDS"
# 子脚本据此判断 harness 产物是不是**本轮**的（I7）：陈旧产物会静默提供旧的注入时刻与客观结果。
export EDGEEXP_RUN_STARTED_AT="$RUN_STARTED"
RESUME="${EDGEEXP_RESUME:-0}"
i=0
for s in "${SELECTED[@]}"; do
  i=$((i + 1))
  # 续跑（M9）：幂等守卫会拒绝"同一场景已有记录"，于是中断后的整轮只能从头再来。
  # EDGEEXP_RESUME=1 时跳过目标文件里已有记录的场景，并把跳过的事实写进 run.json。
  if [ "$RESUME" = "1" ] && [ -f "$RECORDS" ] && grep -qE "\"scenario_id\":\"$s" "$RECORDS"; then
    echo "edge_matrix: [$i/${#SELECTED[@]}] 场景 $s 已有记录 —— 续跑模式跳过（写入 run.json 的 scenarios_skipped_resume）"
    python3 - "$STATE" "$s" <<'PY'
import json, sys
p, scen = sys.argv[1], sys.argv[2]
s = json.load(open(p, encoding='utf-8'))
s.setdefault('skipped_resume', [])
if scen not in s['skipped_resume']:
    s['skipped_resume'].append(scen)
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
    continue
  fi
  echo "============================================================"
  echo "edge_matrix: [$i/${#SELECTED[@]}] 场景 $s"
  t0=$(date -u +%s)
  # 一律用 `bash <script>` 调用（不依赖可执行位）：lab 目录在 /mnt/f（drvfs）上，
  # 可执行位由挂载选项决定，靠它会让"脚本本身没跑"伪装成"实验失败"。
  bash "$SCRIPT_DIR/edge_reset.sh" "$s"
  t1=$(date -u +%s); state_add "$s" reset $((t1 - t0))
  bash "$SCRIPT_DIR/edge_attack.sh" "$s" "$DATA_DIR/attack-$s.json"
  t2=$(date -u +%s); state_add "$s" attack $((t2 - t1))
  bash "$SCRIPT_DIR/edge_collect.sh" "$s" "$CONFIG" "$DATA_DIR/attack-$s.json" "${EDGEEXP_RUN_INDEX:-1}"
  t3=$(date -u +%s); state_add "$s" collect $((t3 - t2))
  state_complete "$s"
  echo "edge_matrix: [$i/${#SELECTED[@]}] $s 完成（reset $((t1-t0))s / attack $((t2-t1))s / collect $((t3-t2))s）"
done

# --- 因子权重与权重表：从**采集配置**里解析（单一来源，不在脚本里抄第二份）--------
# `f_i` 的解析口径与引擎的 `ParamsFromConfig` 同构：
#   · 内置六因子取 [edge_factors]（EF-002FA 再被 [edge_factors.level4_override] 覆盖）；
#   · [edge_factors.custom] 里**不与内置同名**的条目进入因子集 —— 出厂模板里那 7 行
#     （六个同名 + EF-3FA）因此只有 `EF-3FA=0.82` 是新的。
# 这正是 review 的 I4 的那个修正：EF-3FA 是**普通因子**（四份模板都声明了 vector.EF-3FA），
# 它必须进 -factors；此前"不写 EF-3FA"的理由（"会给 V/G/C 一个引擎从未施加的 fallback 向量
# 惩罚"）不成立 —— 真正会发生的是**相反的**事：漏掉链上用到的因子会让工具**静默丢弃**那条
# 惩罚（分数被抬高、漏判率被低估）。禁止的动作只有一个：为了把门禁凑绿而静默塞值。
FACTORS_SPEC="$(python3 - "$CONFIG" <<'PY'
import sys
sections, current = {}, 'global'
for raw in open(sys.argv[1], encoding='utf-8'):
    line = raw.strip()
    if not line or line.startswith('#') or line.startswith(';'):
        continue
    if line.startswith('[') and line.endswith(']'):
        current = line[1:-1].strip().lower(); sections.setdefault(current, {}); continue
    if '=' not in line:
        continue
    k, v = line.split('=', 1)
    sections.setdefault(current, {})[k.strip().lower()] = v.strip()
ef = sections.get('edge_factors', {})
lvl = sections.get('edge_factors.level4_override', {})
custom = sections.get('edge_factors.custom', {})
mapping = [('EF-002FA', 'two_factor_failure'), ('EF-SYNCOOKIE', 'syn_cookie_disabled'),
           ('EF-SELINUX', 'selinux_disabled'), ('EF-APPARMOR', 'apparmor_disabled'),
           ('EF-NO-SIEM', 'no_siem'), ('EF-NO-IDS', 'no_ids')]
out, seen = [], set()
for fid, key in mapping:
    val = lvl.get(key, ef.get(key))
    if val is None:
        raise SystemExit(f'edge_matrix: 配置 {sys.argv[1]} 缺 [edge_factors] {key}')
    out.append(f'{fid}={val}')
    seen.add(fid.upper())
for raw_id, val in custom.items():
    fid = raw_id.strip().upper()
    if not fid or fid in seen:
        continue
    try:
        f = float(val)
    except ValueError:
        raise SystemExit(f'edge_matrix: [edge_factors.custom] {raw_id} = {val!r} 不是数字')
    out.append(f'{fid}={f}')
    seen.add(fid)
print(','.join(out))
PY
)"
WEIGHTS_SPEC="$(python3 - "$CONFIG" <<'PY'
import sys
sections, current = {}, 'global'
for raw in open(sys.argv[1], encoding='utf-8'):
    line = raw.strip()
    if not line or line.startswith('#') or line.startswith(';'):
        continue
    if line.startswith('[') and line.endswith(']'):
        current = line[1:-1].strip().lower(); sections.setdefault(current, {}); continue
    if '=' not in line:
        continue
    k, v = line.split('=', 1)
    sections.setdefault(current, {})[k.strip().lower()] = v.strip()
out = []
for dom in ('attack_surface', 'business_continuity', 'operation_trust', 'resilience', 'kernel_security'):
    for sec in ('weights', 'extension_weights'):
        val = sections.get(sec, {}).get(dom)
        if val is not None:
            out.append(f'{dom}={val}'); break
print(','.join(out))
PY
)"
echo "edge_matrix: -factors $FACTORS_SPEC"
echo "edge_matrix: -weights $WEIGHTS_SPEC"
python3 - "$RUN_D/gate-inputs.json" "$CONFIG" "$FACTORS_SPEC" "$WEIGHTS_SPEC" "$ENV_NAME" <<'PY'
import hashlib, json, sys
config_path, factors, weights, env = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
raw = open(config_path, 'rb').read()
digest = hashlib.sha256(raw).hexdigest()
json.dump({
    'config_path': config_path,
    # 两种精度都给出并在名字里写明（M1）：`config_hash` 与记录 meta.config_hash 同形（16 位），
    # `config_hash_full` 是完整 64 位供独立复核。此前两个脚本各用一个精度、名字却相同。
    'config_hash': 'sha256:' + digest[:16],
    'config_hash_full': 'sha256:' + digest,
    'hash_precision': {'config_hash': 'sha256[:16]（= 记录 meta.config_hash 的口径）',
                       'config_hash_full': 'sha256[:64]',
                       'topology_hash': 'sha256[:64]', 'playbook_hash': 'sha256[:64]'},
    'factors_spec': factors,
    'weights_spec': weights,
    'env': env,
    'note': '-factors 与 -weights 由采集配置解析而来（内置六因子取 [edge_factors] + '
            '[edge_factors.level4_override]，自定义因子取 [edge_factors.custom] 中不与内置同名的条目 '
            '⇒ 含 EF-3FA=0.82），避免脚本里再抄一份而漂移',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY

RECORD_COUNT=0
if [ -s "$RECORDS" ]; then RECORD_COUNT=$(wc -l < "$RECORDS"); fi

# 门禁①：工具能读**全量**记录、无 fail-fast（候选名必须是**模型名**，-factors 必填）。
# 2026-09-12 Fix round 1 起不再按 EF-3FA 切子集：EF-3FA 是普通因子，必须进 -factors
# （漏掉它才会让该条目被静默丢弃）。
if [ "$RECORD_COUNT" -gt 0 ]; then
  if [ -x "$EDGECOMPARE" ]; then
    set +e
    "$EDGECOMPARE" -records "$RECORDS" \
      -candidate "legacy=$CONFIG" \
      -candidate "vector=$REPO_ROOT/configs/edgeexp/vector.ini" \
      -candidate "graph=$REPO_ROOT/configs/edgeexp/graph.ini" \
      -candidate "chain=$REPO_ROOT/configs/edgeexp/chain.ini" \
      -factors "$FACTORS_SPEC" -weights "$WEIGHTS_SPEC" \
      > "$RUN_D/.gate1.out" 2> "$RUN_D/.gate1.err"
    G1=$?
    set -e
    tail -20 "$RUN_D/.gate1.out"
    if [ -s "$RUN_D/.gate1.err" ]; then tail -5 "$RUN_D/.gate1.err" >&2; fi
    python3 - "$RUN_D/gate-gate1.json" "$G1" "$RECORDS" "$RECORD_COUNT" "$FACTORS_SPEC" "$WEIGHTS_SPEC" <<'PY'
import json, sys, time
json.dump({
    'dataset': 'all-records', 'records': int(sys.argv[4]), 'records_file': sys.argv[3],
    'exit_code': int(sys.argv[2]), 'factors_spec': sys.argv[5], 'weights_spec': sys.argv[6],
    'candidates': {'legacy': 'm0-baseline.ini（= 采集模型）', 'vector': 'vector.ini',
                   'graph': 'graph.ini', 'chain': 'chain.ini'},
    'ran_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'note': '跑在全量记录上（不再切 EF-3FA 子集）；候选名必须是模型名（legacy|vector|graph|chain）；'
            '-factors 必填且必须覆盖链上用到的每个因子（含 EF-3FA=0.82）',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
    [ "$G1" -eq 0 ] || {
      echo "edge_matrix: 门禁① 失败（exit $G1）—— 见 $RUN_D/.gate1.err" >&2
      FAIL_REASON="门禁① 离线比较失败：exit=$G1（见 run.d/.gate1.err）"
      state_fail "$G1" "$FAIL_REASON" || true
      exit "$G1"
    }
  else
    echo "edge_matrix: 警告：$EDGECOMPARE 不存在，跳过门禁①（离线比较）" >&2
    python3 - "$RUN_D/gate-gate1.json" "$RECORDS" "$RECORD_COUNT" <<'PY'
import json, sys
json.dump({'dataset': 'all-records', 'records': int(sys.argv[3]), 'records_file': sys.argv[2],
           'exit_code': None, 'skipped': 'edgecompare 二进制不存在（未交叉编译）'},
          open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
  fi
else
  echo "edge_matrix: 记录文件为空 —— 门禁① 无从运行，如实记为 skipped" >&2
  python3 - "$RUN_D/gate-gate1.json" "$RECORDS" <<'PY'
import json, sys
json.dump({'dataset': 'all-records', 'records': 0, 'records_file': sys.argv[2], 'exit_code': None,
           'skipped': '记录文件为空：本轮一个场景都没采到记录'},
          open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
fi

# 门禁②：只在**采集模型**下复算（跨候选的分数差异不是数据缺陷），并用记录自带权重。
# 离线这一半是**复核**：逐条 |复算 − 记录| 的权威证据在 edgescen 的进程内自检（不通过即拒绝
# 写出记录），故这里失败只记 warning 并如实写进 run.json（M5）。
if [ "$RECORD_COUNT" -gt 0 ] && [ -x "$EDGECOMPARE" ]; then
  set +e
  "$EDGECOMPARE" -records "$RECORDS" -candidate "legacy=$CONFIG" \
    -factors "$FACTORS_SPEC" -weights "$WEIGHTS_SPEC" \
    > "$RUN_D/.gate2.out" 2> "$RUN_D/.gate2.err"
  G2=$?
  set -e
  python3 - "$RUN_D/gate-gate2.json" "$G2" "$RECORDS" "$RECORD_COUNT" <<'PY'
import json, sys, time
json.dump({
    'dataset': 'all-records', 'records': int(sys.argv[4]), 'records_file': sys.argv[3],
    'candidate': 'legacy=m0-baseline.ini（采集模型；门禁② 只在采集模型下执行）',
    'exit_code': int(sys.argv[2]), 'ran_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'note': '逐条 |复算 − 记录| 的权威证据在 edgescen 的进程内自检（run.d/collect-*.json 的 gate2_round_trip，'
            '不通过即拒绝写出该条记录）；此处是离线工具在**采集模型**下读全量记录不 fail-fast 的复核，'
            '失败只记 warning —— 记录写不出来就没得复核，门禁② 的实质已由进程内自检承担',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
  [ "$G2" -eq 0 ] || echo "edge_matrix: 警告：门禁②（离线复核）exit $G2 —— 见 $RUN_D/.gate2.err（记录本身已通过进程内自检）" >&2
fi

FINISHED=1
echo "============================================================"
echo "edge_matrix: 全部完成（$(( $(date -u +%s) - RUN_START_S ))s，$MODE，${#SELECTED[@]} 个场景）"
