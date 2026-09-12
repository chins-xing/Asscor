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
#                             门禁⓪ 重复因子计数、注入-采集时钟核对、记录条数……）
#   run-<run-id>.json            同一份内容的不可变副本（历史留档）
#   run.d/{reset,attack,collect,gate}-*.json   逐场景碎片（run.json 由它们汇总）
#   records-<env>-<date>.jsonl   记录本体（每场景一条）
#   records-<env>-<date>.coverable.jsonl       去掉 EF-3FA 记录后的子集（门禁① 只跑它）
#   records-<env>-<date>.ef3fa.jsonl           含 EF-3FA 的记录（**待用户裁定 ④ 后重跑**）
#
# 环境变量：见各子脚本；本脚本另有
#   EDGEEXP_RUN_ID      本次运行标识（默认 <date>-<pid>），进 run.json 与副本名
#   EDGEEXP_IGNORE_EF3FA=1  允许把含 EF-3FA 的记录也放进门禁① 的数据集（**默认禁用**：
#                           把 EF-3FA 塞进 -factors 会给 V/G/C 一个引擎从未施加的惩罚）
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
  export DECLARED_COUNT="${#SCENARIOS[@]}" IGNORE_EF3FA="${EDGEEXP_IGNORE_EF3FA:-0}"
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
records_expected = 0

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
        ck = collect.get('injection_vs_collection') or {}
        clock['per_scenario'][s] = {'ok': ck.get('ok'), 'injection_count': ck.get('injection_count'),
                                    'collection_time': ck.get('collection_time')}
        if ck.get('injection_count') and not ck.get('ok'):
            clock['all_ok'] = False
        g2 = collect.get('gate2_round_trip') or {}
        if g2:
            gate2['per_scenario'][s] = g2
            d = abs(float(g2.get('delta') or 0.0))
            gate2['max_abs_delta'] = max(gate2['max_abs_delta'], d)
        if collect.get('record_added') == 1:
            records_expected += 1

gate0['verdict'] = ('观察到重复条目：' + '; '.join(f"{d['scenario']}→{d['duplicate_ids']}" for d in gate0['duplicate_observed'])
                    if gate0['duplicate_observed'] else '未观察到重复条目（**不得**据静态溯源宣称引擎会重复乘——那只是配置层面的推断）')
gate0['method'] = '按归一化因子 ID 统计每条真实记录链上的条目数（只看记录，不做静态推断）'

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
                       ('collect', ['config_path', 'config_hash', 'weight_source', 'ts_source'])):
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
    'failed': state.get('failed'),
    'progress_s': state.get('progress', {}),
    'records_file': state['records_file'],
    'records_expected': len(scen),
    'records_written_this_run': records_expected,
    'record_counts_ok': records_expected == len(scen),
    'run_inputs': run_inputs,
    'gate0_duplicate_factors': gate0,
    'gate1_reads_all_records': gate1,
    'gate2_round_trip': gate2,
    'gate2_offline_compare': gate2_out,
    'injection_vs_collection': clock,
    'per_scenario': per_scenario,
    'notes': {
        'per_scenario_records': '每场景只采 1 条（chain 在线不可执行；候选差异由离线 edgecompare 覆盖）',
        'ef3fa': 'EF-3FA 待用户裁定 ④：含它的记录**不**进门禁① 数据集（塞进 -factors 会给 V/G/C 一个引擎从未施加的 fallback 向量惩罚），单独列为待重跑子集',
        'weights': '离线复算以记录自带的 observed.effective_weights 为准；-weights 只是回退表',
    },
}
for path in (out_stable, out_copy):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(run, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
print(f'edge_matrix: run.json → {out_stable}')
print(f'edge_matrix: 记录条数 {run["records_written_this_run"]}/{run["records_expected"]}（本次选中场景）')
print(f'edge_matrix: 门禁⓪ {gate0["verdict"]}')
print(f'edge_matrix: 注入-采集时钟核对 all_ok={clock["all_ok"]}')
if gate1:
    print(f'edge_matrix: 门禁① exit={gate1.get("exit_code")}（{gate1.get("dataset","?")}，{gate1.get("records","?")} 条）')
if gate2:
    print(f'edge_matrix: 门禁② 最大偏差 {gate2["max_abs_delta"]:.4g}（{len(gate2["per_scenario"])} 条）')
PY
}

FINISHED=0
on_exit() {
  code=$?
  if [ "$FINISHED" -eq 0 ]; then
    state_fail "$code" "edge_matrix 中断/失败（见上面的 stderr）" || true
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
i=0
for s in "${SELECTED[@]}"; do
  i=$((i + 1))
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

# --- 数据集分类 + 门禁① ------------------------------------------------------
# 含 EF-3FA 的记录单独成集（待裁定 ④）；门禁① 只在覆盖得住的数据集上跑。
python3 - "$RECORDS" "$DATA_DIR" "$RUN_ID" "${EDGEEXP_IGNORE_EF3FA:-0}" <<'PY'
import json, os, sys
records, data_dir, run_id, ignore = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == '1'
base = os.path.splitext(records)[0]
coverable_path, ef3fa_path = base + '.coverable.jsonl', base + '.ef3fa.jsonl'
coverable, pending, reasons = [], [], {}
with open(records, encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        chain = (rec.get('observed') or {}).get('edge_factor_chain') or []
        ids = {(c.get('factor') or '').strip().upper() for c in chain}
        if 'EF-3FA' in ids and not ignore:
            pending.append(line)
            reasons[rec.get('scenario_id')] = 'EF-3FA 在链上（待裁定 ④）'
        else:
            coverable.append(line)
for path, rows in ((coverable_path, coverable), (ef3fa_path, pending)):
    with open(path, 'w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(r + '\n')
out = {
    'dataset': 'coverable', 'records_file': records,
    'coverable_file': coverable_path, 'ef3fa_file': ef3fa_path,
    'coverable_records': len(coverable), 'ef3fa_records': len(pending),
    'ef3fa_reasons': reasons, 'ignore_ef3fa_override': ignore,
    'ef3fa_note': ('含 EF-3FA 的记录**待用户裁定 ④ 后重跑**：把 EF-3FA 塞进 -factors 会让 V/G/C 给它走'
                   '"全 1" fallback 向量 ⇒ 凭空产生引擎从未施加的惩罚、决策层指标被改。'
                   '门禁① 因此只在 coverable 子集上运行。') if pending else '本次运行没有含 EF-3FA 的记录',
}
json.dump(out, open(os.path.join(data_dir, 'run.d', 'gate-dataset.json'), 'w', encoding='utf-8'),
          ensure_ascii=False, indent=2)
print(f'edge_matrix: 数据集分类：coverable {len(coverable)} 条 / EF-3FA 待裁定 {len(pending)} 条')
PY

# 因子权重与权重表从**采集配置**里解析（单一来源：f_i 只在 [edge_factors]）
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
mapping = [('EF-002FA', 'two_factor_failure'), ('EF-SYNCOOKIE', 'syn_cookie_disabled'),
           ('EF-SELINUX', 'selinux_disabled'), ('EF-APPARMOR', 'apparmor_disabled'),
           ('EF-NO-SIEM', 'no_siem'), ('EF-NO-IDS', 'no_ids')]
out = []
for fid, key in mapping:
    val = lvl.get(key, ef.get(key))
    if val is None:
        raise SystemExit(f'edge_matrix: 配置 {sys.argv[1]} 缺 [edge_factors] {key}')
    out.append(f'{fid}={val}')
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
import hashlib, json, os, sys
config_path, factors, weights, env = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
raw = open(config_path, 'rb').read()
json.dump({
    'config_path': config_path,
    'config_hash': 'sha256:' + hashlib.sha256(raw).hexdigest()[:16],
    'factors_spec': factors,
    'weights_spec': weights,
    'env': env,
    'note': '-factors 与 -weights 由采集配置解析而来（f_i 的单一来源是 [edge_factors]，'
            'EF-002FA 已计入 [edge_factors.level4_override]），避免脚本里再抄一份而漂移',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY

COVERABLE="$DATA_DIR/$(basename "$RECORDS" .jsonl).coverable.jsonl"
COVERABLE_COUNT=0
if [ -s "$COVERABLE" ]; then COVERABLE_COUNT=$(wc -l < "$COVERABLE"); fi

# 门禁①：工具能读全量记录、无 fail-fast（候选名必须是**模型名**，-factors 必填）
if [ "$COVERABLE_COUNT" -gt 0 ]; then
  if [ -x "$EDGECOMPARE" ]; then
    set +e
    "$EDGECOMPARE" -records "$COVERABLE" \
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
    python3 - "$RUN_D/gate-gate1.json" "$G1" "$COVERABLE" "$COVERABLE_COUNT" "$FACTORS_SPEC" "$WEIGHTS_SPEC" <<'PY'
import json, sys, time
json.dump({
    'dataset': 'coverable', 'records': sys.argv[4], 'records_file': sys.argv[3],
    'exit_code': int(sys.argv[2]), 'factors_spec': sys.argv[5], 'weights_spec': sys.argv[6],
    'candidates': {'legacy': 'm0-baseline.ini（= 采集模型）', 'vector': 'vector.ini',
                   'graph': 'graph.ini', 'chain': 'chain.ini'},
    'ran_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'note': '候选名必须是模型名（legacy|vector|graph|chain）；-factors 必填；含 EF-3FA 的记录不在本子集里',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
    [ "$G1" -eq 0 ] || { echo "edge_matrix: 门禁① 失败（exit $G1）—— 见 $RUN_D/.gate1.err" >&2; state_fail "$G1" "门禁① exit=$G1"; exit "$G1"; }
  else
    echo "edge_matrix: 警告：$EDGECOMPARE 不存在，跳过门禁①（离线比较）" >&2
    python3 - "$RUN_D/gate-gate1.json" "$COVERABLE" "$COVERABLE_COUNT" <<'PY'
import json, sys
json.dump({'dataset': 'coverable', 'records': int(sys.argv[3]), 'records_file': sys.argv[2],
           'exit_code': None, 'skipped': 'edgecompare 二进制不存在（未交叉编译）'},
          open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
  fi
else
  echo "edge_matrix: coverable 子集为空（所有记录都含 EF-3FA）—— 门禁① 无从运行，如实记为 skipped" >&2
  python3 - "$RUN_D/gate-gate1.json" "$COVERABLE" <<'PY'
import json, sys
json.dump({'dataset': 'coverable', 'records': 0, 'records_file': sys.argv[2], 'exit_code': None,
           'skipped': 'coverable 子集为空：所有记录都含 EF-3FA（待用户裁定 ④）'},
          open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
fi

# 门禁②：只在**采集模型**下复算（跨候选的分数差异不是数据缺陷），并用记录自带权重
if [ "$COVERABLE_COUNT" -gt 0 ] && [ -x "$EDGECOMPARE" ]; then
  set +e
  "$EDGECOMPARE" -records "$COVERABLE" -candidate "legacy=$CONFIG" \
    -factors "$FACTORS_SPEC" -weights "$WEIGHTS_SPEC" \
    > "$RUN_D/.gate2.out" 2> "$RUN_D/.gate2.err"
  G2=$?
  set -e
  python3 - "$RUN_D/gate-gate2.json" "$G2" "$COVERABLE" "$COVERABLE_COUNT" <<'PY'
import json, sys, time
json.dump({
    'dataset': 'coverable', 'records': int(sys.argv[4]), 'records_file': sys.argv[3],
    'candidate': 'legacy=m0-baseline.ini（采集模型；门禁② 只在采集模型下执行）',
    'exit_code': int(sys.argv[2]), 'ran_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'note': '逐条 |复算 − 记录| 的权威证据在 edgescen 的进程内自检（run.d/collect-*.json 的 gate2_round_trip）；'
            '此处是离线工具在**采集模型**下读全量记录不 fail-fast 的复核',
}, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
  [ "$G2" -eq 0 ] || echo "edge_matrix: 警告：门禁②（离线复核）exit $G2 —— 见 $RUN_D/.gate2.err" >&2
fi

FINISHED=1
echo "============================================================"
echo "edge_matrix: 全部完成（$(( $(date -u +%s) - RUN_START_S ))s，$MODE，${#SELECTED[@]} 个场景）"
