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

# 【Fix round 3 / 第 2 项】**把记录文件钉死给整个运行**：子脚本会在 `edge_collect.sh` 里
# 自己重算 `date -u +%Y%m%d`，而一次 3–7 小时的 sweep 很容易跨 00:00 UTC ⇒ 父脚本数今天的文件、
# 子脚本写明天的文件：数据集被劈成两半，本轮的**记录条数门禁**会在跑完几小时之后才报错，
# 而 run.json 只描述第一份文件。导出之后子脚本一律用这一个路径（`EDGEEXP_RECORDS` 本就是
# 子脚本的既有开关，不需要改子脚本）。
export EDGEEXP_RECORDS="$RECORDS"

# --- 因子权重与权重表：从**采集配置**里解析（单一来源，不在脚本里抄第二份）--------
# 实现移入 `edge_spec_lib.sh`（与本脚本**共用的函数库**）：阈值敏感性行
# （`edge_threshold_sensitivity.sh`，spec §5.4.6）必须用**同一份** `-factors`/`-weights`，
# 而"两份报告只在阈值上不同"这句话只有在推导实现唯一时才能成立。两处各抄一份 Python，
# 漂移就表现为"两份报告用了不同的因子权重"，从报告文本里看不出来。
# 定义成函数是为了让**干跑**也能打印这两张表（干跑在逐场景循环之前就退出，
# 那时还没有 FACTORS_SPEC/WEIGHTS_SPEC 这两个变量）。调用点：干跑计划、门禁命令行、敏感性行。
# 口径（EF-3FA 是**普通因子**、必须进 -factors 等）逐条写在那个库里。
# shellcheck source=scripts/edge_spec_lib.sh
. "$SCRIPT_DIR/edge_spec_lib.sh"


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

# ---- 干跑（Fix round 3 / 第 3 项）-------------------------------------------
# `EDGEEXP_RESUME=1` **不是**干跑：它跳过"文件里已有记录"的场景，而对**没有**记录的场景
# 照样执行 reset+attack+collect（上一轮的 A5 就是这样误触发了一次真实复位）。真正"只看计划、
# 什么都不做"的开关是下面这个：打印解析后的计划，并在**第一个 edge_reset.sh 之前**退出 0 ——
# 不调用 clab、不碰 Caldera、不往数据目录写任何东西（连 `mkdir -p` 都还没发生）。
if [ "${EDGEEXP_DRY_RUN:-0}" = "1" ]; then
  echo "edge_matrix: DRY RUN（只看计划：不做任何 lab 动作，不写任何文件）"
  echo "  运行标识    : $RUN_ID（mode=$MODE）"
  echo "  记录文件    : $RECORDS"
  echo "  采集配置    : $CONFIG"
  echo "  环境/重复号 : $ENV_NAME / run=${EDGEEXP_RUN_INDEX:-1}"
  echo "  数据目录    : $DATA_DIR（干跑不创建、不清理）"
  echo "  场景        : ${#SELECTED[@]} 个（声明的 ${#SCENARIOS[@]}）/ 名单核对已通过"
  echo "  -factors    : $(derive_factors_spec "$CONFIG")（来源：$CONFIG）"
  echo "  -weights    : $(derive_weights_spec "$CONFIG")"
  # 干跑必须把"这一轮到底会不会跑敏感性行"也说清楚（§5.4.4 的承诺：先看计划）。
  if [ -n "${EDGEEXP_SENSITIVITY_THRESHOLDS:-}" ]; then
    echo "  阈值敏感性  : 启用（阈值 $EDGEEXP_SENSITIVITY_THRESHOLDS；产物 ${EDGEEXP_SENSITIVITY_DIR:-$DATA_DIR/sensitivity}）—— **非主对比**，见 §5.4.6"
  else
    echo "  阈值敏感性  : 未启用（默认路径不含它；需要时 EDGEEXP_SENSITIVITY_THRESHOLDS=60，见 §5.4.6）"
  fi
  # 子脚本继承校验：用**同一种机制**（bash 子进程继承导出的环境）确认它们看到的是同一个路径 ——
  # 这正是"父子各自算 TODAY"会分叉、而跨 00:00 UTC 才暴露的那条路径。
  echo "  子脚本继承  : EDGEEXP_RECORDS=$(bash -c 'printf "%s" "${EDGEEXP_RECORDS:-<未导出>}"')"
  echo "  计划："
  i=0
  for s in "${SELECTED[@]}"; do
    i=$((i + 1))
    if [ -f "$RECORDS" ] && grep -qE "\"scenario_id\":\"$s" "$RECORDS"; then
      printf '    [%2d/%2d] %-28s skip（文件里已有记录；仅当 EDGEEXP_RESUME=1 时才会真的跳过）\n' "$i" "${#SELECTED[@]}" "$s"
    else
      printf '    [%2d/%2d] %-28s collect（reset → attack → collect 三步都会跑）\n' "$i" "${#SELECTED[@]}" "$s"
    fi
  done
  echo "edge_matrix: dry run 结束（exit 0）—— 真实运行请去掉 EDGEEXP_DRY_RUN"
  exit 0
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
        if collect.get('record_added') == 1 and not collect.get('rolled_back'):
            # 回滚掉的记录**不算**"本次写入"（否则一次被回滚的采集会同时表现为"写了一条"
            # 与"文件里没有"，两个数各自看都对、合起来是错的 —— Fix round 2 的 Minor 项）。
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
            # **只统计本次选中的场景**：整份文件里可能有别的场景行，把它们的口径算进来会得到
            # 一个描述"文件"而不是"本轮"的汇总（Fix round 2 的 M2 项）。
            if any(str(sid or '').startswith(name) for name in scen):
                ts_from_dataset.setdefault(
                    (rec.get('meta') or {}).get('ts_source') or '(未注明)', []).append(sid)
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
# 阈值敏感性行（spec §5.4.6）：**只在显式 opt-in 时**存在（EDGEEXP_SENSITIVITY_THRESHOLDS）。
# 缺席如实写 null —— "没跑"与"跑了但没结果"必须能从 run.json 里区分开。
sensitivity = frag('gate', 'sensitivity')

# 父/子记录路径一致性（Fix round 3 / 第 2 项）：子脚本实际写入的路径必须等于父脚本解析出的路径。
# 不一致说明继承链上有人改回了"各自解析"（跨 00:00 UTC 时它以"少一条记录"的形式在几小时后才暴露）。
records_agreement = {'parent': state['records_file'], 'children': {}, 'ok': True}
for scen_name in scen:
    node = frag('collect', scen_name)
    if not isinstance(node, dict):
        continue
    child_path = node.get('records_file')
    if child_path:
        records_agreement['children'][scen_name] = child_path
        if child_path != state['records_file']:
            records_agreement['ok'] = False

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
    # 缺/多分开报（Fix round 2 的 Minor 项）：此前一个 `len(scen) - file_lines` 同时承担
    # 两种含义，文件里**多**了别的场景行时会变成负数（看起来像"缺了 −2 条"）。
    'records_missing_for_selected': max(0, len(scen) - file_lines),
    'records_extra_in_file': max(0, file_lines - len(scen)),
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
    'threshold_sensitivity': sensitivity,
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
        'records_file_pinned': '本脚本把解析出的记录路径 export 给子脚本（Fix round 3 / 第 2 项）：'
                               '父子各自算 date +%Y%m%d 时，跨 00:00 UTC 的 sweep 会把数据集劈成两份',
        'threshold_sensitivity': '阈值敏感性行（spec §5.4.6）**只在显式 opt-in 时**存在'
                                 '（EDGEEXP_SENSITIVITY_THRESHOLDS=60…）：它覆盖部署判定线，'
                                 '故其产物一律标注为敏感性分析、不得与主对比结论混排；'
                                 '本键为 null = 本轮没有跑敏感性行（默认路径不变）',
    },
    'records_file_agreement': records_agreement,
}
for path in (out_stable, out_copy):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(run, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
print(f'edge_matrix: run.json → {out_stable}')
print(f'edge_matrix: 记录条数 本次写入 {run["records_written_this_run"]}/{run["records_expected"]}｜'
      f'文件总行数 {run["records_file_total_lines"]}｜record_counts_ok={run["record_counts_ok"]}')
print(f'edge_matrix: 因子集相等断言 all_ok={equality["all_ok"]}')
print(f'edge_matrix: 父子记录路径一致={records_agreement["ok"]}（{state["records_file"]}）')
print(f'edge_matrix: 门禁⓪ {gate0["verdict"]}')
print(f'edge_matrix: 注入-采集时钟核对 all_ok={clock["all_ok"]}')
if gate1:
    print(f'edge_matrix: 门禁① exit={gate1.get("exit_code")}（{gate1.get("dataset","?")}，{gate1.get("records","?")} 条）')
if gate2:
    print(f'edge_matrix: 门禁② 最大偏差 {gate2["max_abs_delta"]:.4g}（{len(gate2["per_scenario"])} 条）')
if sensitivity:
    print(f'edge_matrix: 阈值敏感性行 阈值 {sensitivity.get("thresholds")}'
          f'（records={sensitivity.get("records")}，产物 {sensitivity.get("artifact_role")}）—— '
          '引用时必须标注为敏感性分析')
else:
    print('edge_matrix: 阈值敏感性行 未启用（run.json threshold_sensitivity = null）')
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
  # 每一步先写好兜底失败原因（含场景名与步骤名）：`set -e` 下子脚本失败会直接跳到 trap，
  # 那时只有这里写下的原因是可归因的（Fix round 2 的 M4 项）。
  FAIL_REASON="场景 $s 的 reset 步失败（见上面的 stderr）"
  bash "$SCRIPT_DIR/edge_reset.sh" "$s"
  FAIL_REASON=""
  t1=$(date -u +%s); state_add "$s" reset $((t1 - t0))
  FAIL_REASON="场景 $s 的 attack 步失败（见上面的 stderr）"
  bash "$SCRIPT_DIR/edge_attack.sh" "$s" "$DATA_DIR/attack-$s.json"
  FAIL_REASON=""
  t2=$(date -u +%s); state_add "$s" attack $((t2 - t1))
  FAIL_REASON="场景 $s 的 collect 步失败（记录已回滚；见上面的 stderr 与 run.d/rejected-$s.jsonl）"
  bash "$SCRIPT_DIR/edge_collect.sh" "$s" "$CONFIG" "$DATA_DIR/attack-$s.json" "${EDGEEXP_RUN_INDEX:-1}"
  FAIL_REASON=""
  t3=$(date -u +%s); state_add "$s" collect $((t3 - t2))
  state_complete "$s"
  echo "edge_matrix: [$i/${#SELECTED[@]}] $s 完成（reset $((t1-t0))s / attack $((t2-t1))s / collect $((t3-t2))s）"
done

# --- 记录条数门禁（**判死整轮**，不只是一个上报字段）----------------------------
# brief 的"记录条数 == 场景数"此前只是 run.json 里的一个布尔值：文件里少一条或多一条都不影响
# 退出码（Fix round 2 的 Important 项后半句）。这里把它变成硬闸门：文件总行数必须**恰好**
# 等于本次选中的场景数 —— 少一条说明有场景没采成，多一条说明文件里混进了别的场景
# （续跑/换 run_id/共用文件），两种都会让"每场景一条"这句结论失效。
FILE_LINES=0
if [ -f "$RECORDS" ]; then FILE_LINES=$(grep -c . "$RECORDS" || true); fi
if [ "$FILE_LINES" -ne "${#SELECTED[@]}" ]; then
  echo "edge_matrix: 记录条数门禁未通过：$RECORDS 有 $FILE_LINES 条，本次选中 ${#SELECTED[@]} 个场景 —— 整轮失败" >&2
  echo "  （少一条 = 有场景没采成；多一条 = 文件里混进了别的场景的记录。两者都会让\"每场景一条\"失效）" >&2
  FAIL_REASON="记录条数门禁未通过：文件 $FILE_LINES 条 ≠ 选中 ${#SELECTED[@]} 个场景"
  state_fail 1 "$FAIL_REASON" || true
  exit 1
fi
echo "edge_matrix: 记录条数门禁通过（$FILE_LINES 条 == 选中 ${#SELECTED[@]} 个场景）"

# --- 因子权重与权重表（实现在共用的 edge_spec_lib.sh；干跑也要用它，见 EDGEEXP_DRY_RUN）---
FACTORS_SPEC="$(derive_factors_spec "$CONFIG")"
WEIGHTS_SPEC="$(derive_weights_spec "$CONFIG")"
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

# --- 阈值敏感性行（**显式 opt-in**；spec §5.4.6）--------------------------------
# 部署判定线（[acceptability] threshold）若让**全部**记录落进"不可接受"（漏判样本为 0 或
# 误阻断样本为 0），报告必须**另附一行** `threshold = 60.0` 的敏感性结果并明确标注 ——
# 换阈值改结论这件事必须写在脸上，不能只报一组数字。
#
# 默认**不跑**（默认路径与默认对比一字不变），只有显式给出 EDGEEXP_SENSITIVITY_THRESHOLDS
# 才跑；此时它失败即整轮失败 —— 操作者明确要了这行产物，静默少一行比报错更糟。
# 它只用记录 + 配置 + 离线工具（不碰 clab/Caldera），故这条行在任何时候都能补跑：
#   EDGEEXP_SENSITIVITY_THRESHOLDS=60 bash scripts/edge_threshold_sensitivity.sh
if [ -n "${EDGEEXP_SENSITIVITY_THRESHOLDS:-}" ]; then
  SENS_DIR="${EDGEEXP_SENSITIVITY_DIR:-$DATA_DIR/sensitivity}"
  echo "============================================================"
  echo "edge_matrix: 阈值敏感性行（EDGEEXP_SENSITIVITY_THRESHOLDS=$EDGEEXP_SENSITIVITY_THRESHOLDS，**非主对比**）"
  export EDGEEXP_RECORDS EDGEEXP_CONFIG="$CONFIG" EDGEEXP_RUN_ID="$RUN_ID"
  export EDGEEXP_FACTORS_SPEC="$FACTORS_SPEC" EDGEEXP_WEIGHTS_SPEC="$WEIGHTS_SPEC"
  export EDGEEXP_SENSITIVITY_DIR="$SENS_DIR"
  FAIL_REASON="阈值敏感性行失败（阈值 ${EDGEEXP_SENSITIVITY_THRESHOLDS}；见上面的 stderr）"
  bash "$SCRIPT_DIR/edge_threshold_sensitivity.sh"
  FAIL_REASON=""
  # 汇总并入 run.json（逐场景碎片的同一机制：gate-<名>.json）。
  cp "$SENS_DIR/sensitivity.json" "$RUN_D/gate-sensitivity.json"
  echo "edge_matrix: 阈值敏感性行完成（$SENS_DIR，汇总并入 run.json 的 threshold_sensitivity）"
else
  echo "edge_matrix: 阈值敏感性行未启用（默认路径不含它）—— 需要时显式开启：EDGEEXP_SENSITIVITY_THRESHOLDS=60（spec §5.4.6）"
fi

FINISHED=1
echo "============================================================"
echo "edge_matrix: 全部完成（$(( $(date -u +%s) - RUN_START_S ))s，$MODE，${#SELECTED[@]} 个场景）"
