#!/bin/bash
# shellcheck disable=SC2154
#
# ↑ 文件级豁免 SC2154（"引用了但没赋值"）：`lab_*` 由 `. edge_lab.sh` 在 source 时赋值，
#   而 shellcheck 不跨文件跟踪变量。代价：本文件里拼错的 `$lab_xxx` 也不会被报出来
#   （ShellCheck 0.9 不支持按名字限定豁免）—— 基质的离线用例负责兜住这件事。
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
# 顺序（**采集前能判的一律在采集前判**，Fix round 2 / Important 项）：
#   0. run 号与环境标识必须成对（run>1 要求显式 EDGEEXP_ENV）；
#   1. harness 产物**预检**：必须是合法 JSON、必须带 `expected_chain_factors`（相等断言的依据）；
#   2. harness 产物**新鲜度**：mtime ≥ 本轮起始（`EDGEEXP_RUN_STARTED_AT`）或年龄 ≤ 上限 ——
#      陈旧产物会静默提供旧的注入时刻/哈希/客观结果，而时钟核对照样通过；
#   3. 幂等守卫：同一场景在目标 JSONL 里已有记录时拒绝再写；
#   4. 调 `edgescen` 采集**一条**记录；
#   5. 采集后核对（写进 `run.d/collect-<scenario>.json`）：
#      · **因子集相等断言**：链上因子集（归一 ID）== 场景声明集（S0 ⇒ 空集）；
#      · **配置指纹**：记录 `meta.config_hash` == 本次配置的指纹（"这份记录是这份配置采的"）；
#      · **门禁⓪**：链上重复因子条目（按归一 ID 计数）—— 只看真实记录，不做静态推断；
#      · **注入时刻 < 采集时刻** + harness 时刻确实落进了 `checks[]`（注入检查缺席即失败）；
#      · 记录条数增量 == 1。
#
# **记录一旦落盘，之后的任何失败都走回滚路径**（退出码 3）：文件回到采集前的行数、被拒的那一行
# 留档到 `run.d/rejected-<scenario>.jsonl`、片段里记 `rolled_back: true`。
# 此前只有"因子集不等"走回滚，而"新鲜度/必需字段/Python 异常"直接退出 1 ⇒ 一条带**上一轮**注入时刻
# 与客观结果的记录会留在数据集里，续跑模式还会把它当"已有记录"静默跳过（Fix round 2 的 Important 项）。
#
# 退出码：0 成功；1 失败（采集前失败时数据集未被改动；采集后失败时已回滚并留档）。
#
# 环境变量：
#   EDGEEXP_ENV       环境标识（进 meta.env），默认 wsl-clab-14；**run>1 时必须显式给出**
#   EDGEEXP_RECORDS   记录文件，默认 <lab>/data/edgefactors/records-<env>-<date>.jsonl
#   EDGEEXP_EDGESCEN  edgescen 二进制，默认 <repo>/build/edgescen
#   EDGEEXP_RUN_STARTED_AT  本轮运行的起始时刻（RFC3339，矩阵脚本导出）
#   EDGEEXP_ATTACK_MAX_AGE_S 没有 RUN_STARTED_AT 时的产物年龄上限（秒，默认 3600）
#   EDGEEXP_TARGET    被攻节点名（Task 4C：观测主体在它**内部**采样，默认空 = 本机）。
#                     传了它，`edgescen --target` 在节点内跑同一份二进制取回检查结果；取不到
#                     就**响亮失败**（绝不静默改用本机结果 —— 那会让记录看起来是节点数据、
#                     实际是宿主数据）。它必须与 edge_attack.sh 的 EDGEEXP_TARGET 一致：
#                     不一致时 condition_probes 的证据与 checks[] 的观测来自**两台机器**。
#   EDGEEXP_SUBSTRATE 实验基质：clab（默认）| lxd（A-1，见 edge_lab.sh）。它决定本脚本交给
#                     `edgescen` 的 target **语法**（`lab_target_spec`：clab 保持裸容器名，
#                     lxd 出 `lxd:<实例>`）—— 而 EDGEEXP_TARGET 始终是**基质层的节点名**。
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
# shellcheck source=scripts/edge_lab.sh
. "$SCRIPT_DIR/edge_lab.sh"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
RUN_D="$DATA_DIR/run.d"
ENV_NAME="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-$ENV_NAME-$TODAY.jsonl}"
EDGESCEN="${EDGEEXP_EDGESCEN:-$REPO_ROOT/build/edgescen}"
RUN_STARTED_AT="${EDGEEXP_RUN_STARTED_AT:-}"
MAX_AGE_S="${EDGEEXP_ATTACK_MAX_AGE_S:-3600}"
TARGET="${EDGEEXP_TARGET:-}"

mkdir -p "$RUN_D"
FILLER="collect-$SCENARIO.json"
TMP_OUT="$RUN_D/.$FILLER.tmp"
REJECTED_OUT="$RUN_D/rejected-$SCENARIO.jsonl"

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

# --- 1. harness 产物预检（**在调用 edgescen 之前**）----------------------------
read -r PRE_STATUS ATTACK_STARTED ATTACK_FINISHED INJ_COUNT <<EOF
$(python3 - "$ATTACK" <<'PY'
import json, sys
try:
    h = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    print('BADJSON\t\t\t0'); raise SystemExit
if h.get('expected_chain_factors') is None:
    print('MISSING\t\t\t0'); raise SystemExit
atk = h.get('attack') or {}
print('OK\t%s\t%s\t%d' % (atk.get('started_at') or '', atk.get('finished_at') or '',
                          len(h.get('injections') or [])))
PY
)
EOF
case "$PRE_STATUS" in
  OK) : ;;
  MISSING)
    echo "edge_collect: harness 产物 $ATTACK 缺 expected_chain_factors（场景声明的期望上链因子集）——" >&2
    echo "  没有它就无法做相等断言。请用本轮的 edge_attack.sh 重新生成产物（旧产物没有这个字段）；" >&2
    echo "  这次**没有调用 edgescen**，数据集未被改动。" >&2
    exit 1 ;;
  *)
    echo "edge_collect: harness 产物 $ATTACK 不是合法 JSON —— 这次**没有调用 edgescen**，数据集未被改动" >&2
    exit 1 ;;
esac

# --- 2. 产物新鲜度（同样在采集之前）-------------------------------------------
ATTACK_MTIME=$(stat -c %Y "$ATTACK")
NOW_S=$(date -u +%s)
ATTACK_AGE=$((NOW_S - ATTACK_MTIME))
if [ -n "$RUN_STARTED_AT" ]; then
  RUN_START_S="$(python3 -c 'import datetime,sys;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$RUN_STARTED_AT")"
  if [ "$ATTACK_MTIME" -lt "$RUN_START_S" ]; then
    echo "edge_collect: harness 产物 $ATTACK 的 mtime（$(date -u -d @"$ATTACK_MTIME" +%FT%TZ)）早于本轮起始（$RUN_STARTED_AT）——" >&2
    echo "  这是**上一轮**的产物：注入时刻、剧本哈希与客观结果都会是旧的，而时钟核对照样通过。" >&2
    echo "  这次**没有调用 edgescen**（也就没有需要回滚的记录），整轮失败。" >&2
    exit 1
  fi
elif [ "$ATTACK_AGE" -gt "$MAX_AGE_S" ]; then
  echo "edge_collect: harness 产物 $ATTACK 已 ${ATTACK_AGE}s 未更新（上限 ${MAX_AGE_S}s）且未给 EDGEEXP_RUN_STARTED_AT ——" >&2
  echo "  无法证明它是本轮产物；这次**没有调用 edgescen**。整轮失败" >&2
  echo "  （手工单场景采集请把 EDGEEXP_ATTACK_MAX_AGE_S 调大或重跑 edge_attack.sh）。" >&2
  exit 1
fi

# --- 3. 幂等守卫 -------------------------------------------------------------
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

# --- 4. 采集 -----------------------------------------------------------------
echo "edge_collect: 采集场景 $SCENARIO（配置 $(basename "$CONFIG")，run=$RUN，env=$ENV_NAME，基质=$lab_substrate，目标=${TARGET:-本机}）"
# `--target` 只在真的声明了节点时才加上：不传时 `edgescen` 的取数路径与今天**逐位一致**
# （本机登记表），而"显式传一个空 target"会让两份调用在日志上同形。
#
# 传的值是 **`lab_target_spec`**（clab 基质 = 裸容器名，逐位不变；lxd 基质 = `lxd:<实例>`）——
# `edgescen -target` 的语法由基质决定，别处不得再拼一次前缀（两处口径分叉会让观测主体断言
# 以"记录声称 X、声明 Y"的名义把每条记录判死）。
TARGET_ARGS=()
TARGET_SPEC=""
if [ -n "$TARGET" ]; then
  TARGET_SPEC="$(lab_target_spec "$TARGET")"
  TARGET_ARGS=(--target "$TARGET_SPEC")
fi
echo "edge_collect: edgescen 观测主体 target=${TARGET_SPEC:-（不传 = 本机）}（EDGEEXP_TARGET=${TARGET:-未声明}，基质 $lab_substrate）"
T0=$(date -u +%s)
set +e
"$EDGESCEN" --scenario "$SCENARIO" --config "$CONFIG" \
  --attack-out "$ATTACK" --out "$RECORDS" --run "$RUN" --env "$ENV_NAME" "${TARGET_ARGS[@]}" \
  > "$RUN_D/.edgescen-$SCENARIO.out" 2> "$RUN_D/.edgescen-$SCENARIO.err"
RC=$?
set -e
ELAPSED=$(( $(date -u +%s) - T0 ))
cat "$RUN_D/.edgescen-$SCENARIO.out"
if [ "$RC" -ne 0 ]; then
  echo "edge_collect: edgescen 退出码 $RC —— 采集失败，整轮失败（不跳过继续；它自己不写半条记录）：" >&2
  cat "$RUN_D/.edgescen-$SCENARIO.err" >&2
  exit 1
fi
cat "$RUN_D/.edgescen-$SCENARIO.err" >&2 || true

# --- 5. 核对（**从这里开始，任何失败都回滚**）---------------------------------
AFTER=$(wc -l < "$RECORDS")
ADDED=$((AFTER - BEFORE))
if [ "$ADDED" -ne 1 ]; then
  echo "edge_collect: 本次采集写入了 $ADDED 条记录（应为 1）—— 记录条数与场景数对不上，整轮失败" >&2
  exit 1
fi

export RECORDS SCENARIO ATTACK CONFIG ENV_NAME RUN ADDED ELAPSED TMP_OUT BEFORE AFTER
export TARGET
export EDGESCEN_OUT="$RUN_D/.edgescen-$SCENARIO.out"
export REJECTED_OUT
export CONFIG_HASH="$(sha256sum "$CONFIG" | awk '{print $1}')"
export ATTACK_MTIME ATTACK_AGE RUN_STARTED_AT ATTACK_STARTED ATTACK_FINISHED INJ_COUNT
set +e
python3 - <<'PY'
import datetime, json, os, re, sys, traceback

records_path = os.environ['RECORDS']
scenario = os.environ['SCENARIO']
tmp_out = os.environ['TMP_OUT']
TOLERANCE_DEFAULT = 0.005
ROLLBACK = 3  # 退出码 3 = "记录已落盘但核对失败，请回滚"


def fail(msg, rollback=False):
    print('edge_collect: ' + msg, file=sys.stderr)
    sys.exit(ROLLBACK if rollback else 1)


def norm(fid):
    return (fid or '').strip().upper()


def dump_fragment(report):
    with open(tmp_out, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write('\n')


def body():
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
    config_hash = os.environ['CONFIG_HASH']

    # --- 观测主体：这次评估到底在哪台机器上做的（Task 4C）------------------------
    # 四条判据（勘测实测的缺陷正是"记录描述的是 WSL 开发机"而没人发现）：
    #   1. 声明了 EDGEEXP_TARGET ⇒ 记录必须带 meta.observation_target，且它指的**就是这个节点**；
    #   2. 没声明 ⇒ 记录不得带该字段（默认路径逐位不变，不写"本机"这种新值）；
    #   3. **本场景应当有探针**（有相位或有真实缺失）却没探到 ⇒ 拒绝；
    #   4. harness 产物里的探针若在**另一个**节点上探的，本轮数据自相矛盾
    #      （R 组的证据与 checks[] 的观测来自两台机器）。
    target = os.environ.get('TARGET') or ''
    record_target = (rec.get('meta') or {}).get('observation_target') or ''
    probes = harness.get('condition_probes') or []
    probe_targets = sorted({(p.get('probe_target') or '') for p in probes if p.get('probe_target')})
    # Fix round 2 / 新 Important-2：**"没有探针"分两种**，判据必须先把它们分开。
    #
    #   · `probes_expected` = 本场景**应当**有探针：`edge_attack.sh` 只有两个探针产生点 ——
    #     相位循环（有 `PHASES` 才进）与 R 组闸门（有 `REAL_MISSING` 才进）。
    #     ⇒ `S0-baseline` 是**唯一**两者都没有的场景（`edge_attack.sh:81`），它必然产出
    #     `condition_probes: []`（作者自己的 `attack-S0-baseline.json` 就是这个形状）。
    #   · 旧的 M-3 判据只看"没有 probe_target"就拒绝 ⇒ 它会把 **S0 拒掉**，而 I-9 又让矩阵
    #     **默认**声明 `EDGEEXP_TARGET` ⇒ 按新默认路径跑全量矩阵会在**第一个场景**整轮失败
    #     （§9 的复现命令同样失败）。那是把"本来就该是空的"误判成"该有却没有"。
    #   ⇒ 现在只在"该有探针却没有"时拒绝，并把 `probes_expected` 写进片段 ——
    #     "这次为什么没有探针"因此成为**显式记录的事实**，而不是靠放行。
    phases = harness.get('phases') or []
    # `real_missing` 在这里先取（它在下面 R 组证据块里还要用一次）：`probes_expected` 依赖它，
    # 而"该不该有探针"这条判据必须在观测主体判定**之前**算出来（Fix round 2 / 新 Important-2）。
    real_missing = (harness.get('real_missing') or '').strip()
    real_missing_at = (harness.get('real_missing_verified_at') or '').strip()
    probes_expected = bool(phases) or bool(real_missing)
    observation = {
        'target_declared': target,
        'record_observation_target': record_target,
        'harness_probe_targets': probe_targets,
        'record_in_node': bool(record_target),
        'probes_expected': probes_expected,
        'phases': len(phases),
        'ok': True,
        'note': '观测主体口径：声明了 EDGEEXP_TARGET 时记录必须带 meta.observation_target 且指向该节点；'
                'condition_probes 的 probe_target 必须与它一致（R 组的证据与 checks[] 的观测必须在同一台机器上）。'
                'probes_expected=false（S0 基线：无相位也无真实缺失）表示**本场景没有探针可做**，'
                '此时 condition_probes 为空是如实结果、不是缺陷',
    }
    if target:
        if not record_target:
            observation['ok'] = False
            observation['reason'] = ('声明了 EDGEEXP_TARGET=%s，但记录的 meta.observation_target 为空 —— '
                                     '这条记录无法证明自己采自节点（可能静默采了宿主）' % target)
        elif target not in record_target:
            observation['ok'] = False
            observation['reason'] = ('记录声称观测主体是 %r，而本轮声明的节点是 %s' % (record_target, target))
        elif not probe_targets and probes_expected:
            # 声明了目标、记录也带字段，但 harness 的探针**该有却没有**（`condition_probes` 为空
            # 或全部 skipped）。触发场景现实存在：只给 edge_collect.sh 设了 EDGEEXP_TARGET，
            # 而 edge_attack.sh 是在（或没有）另一个环境下跑的。这里**拒绝**，并把出路写清楚。
            observation['ok'] = False
            observation['reason'] = ('声明了 EDGEEXP_TARGET=%s，且本场景**应当**有探针（phases=%d），'
                                     '但 harness 的 condition_probes 里没有任何 probe_target —— '
                                     '本次采集没有节点侧探针证据。请让 edge_attack.sh 在同一环境、同一 '
                                     'EDGEEXP_TARGET 下重跑（它会在节点内探一次）'
                                     % (target, len(phases)))
        elif probe_targets and probe_targets != [target]:
            # `probe_targets` 为空时**不走这条**（Fix round 2）：空集与"在别的节点上探"是两件事，
            # 前者已由上面那条"该有却没有"处理，后者才是真矛盾。少了 `probe_targets and`
            # 这个前提，S0 那种"本来就没有探针"的场景会被这条误报成"同一轮数据来自两台机器"
            # （离线夹具 G 用例实测到的形态）。
            observation['ok'] = False
            observation['reason'] = ('harness 的条件探针在 %s 上执行，而本次观测主体是 %s —— '
                                     '同一轮数据来自两台机器' % (probe_targets, target))
    else:
        if record_target:
            observation['ok'] = False
            observation['reason'] = ('未声明 EDGEEXP_TARGET（默认=本机），而记录却带 observation_target=%r' % record_target)
        # Fix round 1 / M-4：两条判据是**并列**的 if，后一条会把前一条的 reason 覆盖掉
        # （离线夹具实测：操作者看到的提示指向 harness，而不是"记录却带字段"这条真正的反常）。
        # 改成 elif：同一次判定只留一条、且是**最先命中**的那条。
        elif probe_targets:
            observation['ok'] = False
            observation['reason'] = ('未声明 EDGEEXP_TARGET，而 harness 的探针却标称在 %s 上执行' % probe_targets)

    # --- R 组：condition_probes 为空 ⇒ 不许声称"真实缺失已核实"（Task 4C Step 3）----
    # （`real_missing`/`real_missing_at` 在上面观测主体判定处已经取过，这里直接复用。）
    probe_evidence = {
        'real_missing': real_missing,
        'real_missing_verified_at': real_missing_at,
        'probe_count': len(probes),
        'probes': probes,
        'ok': True,
        'note': 'R 组的"真实缺失"必须有**节点侧**证据：condition_probes 至少一条、且 probe_host 非空'
                '（空数组却声称已核实，正是 Task 4C 之前的状态）',
    }
    if real_missing or real_missing_at:
        if not probes:
            probe_evidence['ok'] = False
            probe_evidence['reason'] = ('本场景声称真实缺失（%s），而 harness 的 condition_probes 是空数组 —— '
                                        '没有任何节点侧证据；不允许这种记录落盘' % (real_missing or '(未写)'))
        elif not all((p.get('probe_host') or '').strip() for p in probes):
            probe_evidence['ok'] = False
            probe_evidence['reason'] = 'condition_probes 里有条目没有 probe_host —— 无法证明探针在节点内执行过'

    # --- 配置指纹（溯源）：记录里的 meta.config_hash 必须与本次配置一致 -----------
    record_config_hash = (rec.get('meta') or {}).get('config_hash') or ''
    config_hash_check = {
        'ok': record_config_hash == config_hash[:16],
        'record': record_config_hash,
        'expected': config_hash[:16],
        'note': '记录 meta.config_hash（16 位）必须等于本次采集配置的 sha256 前 16 位 —— '
                '不等说明这条记录不是这份配置采的（配置在采集途中被换过），报告的权重口径会指向另一份配置',
    }

    # --- 因子集相等断言（Fix round 1 / C2；Fix round 2 修正级联期望集）----------
    # 采集器只要求 chain ⊇ expectedChainFactors（S0 的期望集是空集），故"声明空集却采到六个因子"
    # 的基线与"单因子场景采到全因子"都能静默通过 —— 一轮冒烟下来没人发现整批数据的因子向量相同。
    # 这里改成**相等**：多一个少一个都整轮失败。
    expected_raw = harness.get('expected_chain_factors')
    if expected_raw is None:
        fail('harness 产物缺 expected_chain_factors（预检应在采集前拦下，这是第二道防线）', rollback=True)
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

    # --- 注入时刻 vs 采集时刻 ---------------------------------------------------
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
    # 注入检查必须出现在 checks[] 里：注入就是把该检查判为失败，它缺席说明注入没生效或记录没落全。
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

    # --- 门禁②（采集侧证据）：edgescen 进程内自检的 round-trip 残差 ---------------
    # 权威实现是采集器装配点的 `roundTripCheck`（不通过即**拒绝写出**），本行只是把那次
    # 自检的残差落进 run.json，让"逐条 |复算 − 记录| == 0"在运行级证据里可见。
    gate2 = {'source': 'edgescen 进程内自检（装配点；不通过即拒绝写出该条记录）', 'delta': None}
    out_path = os.environ.get('EDGESCEN_OUT', '')
    if out_path and os.path.exists(out_path):
        for line in open(out_path, encoding='utf-8'):
            if 'round-trip' in line:
                nums = re.findall(r'[-+]?\d+\.?\d*(?:[eE][-+]?\d+)?', line)
                if len(nums) >= 3:
                    gate2 = {'source': gate2['source'], 'recomputed': float(nums[0]),
                             'recorded': float(nums[1]), 'delta': float(nums[2]),
                             'tolerance': float(nums[3]) if len(nums) >= 4 else TOLERANCE_DEFAULT,
                             'line': line.strip()}
                else:
                    gate2 = {'source': gate2['source'], 'delta': None, 'line': line.strip(),
                             'note': '无法从该行解析出残差'}
                break

    attack_meta = harness.get('attack') or {}
    report = {
        'scenario': scenario,
        'phase': 'collect',
        'env': os.environ['ENV_NAME'],
        'run': int(os.environ['RUN']),
        'config': os.path.basename(os.environ['CONFIG']),
        'config_path': os.environ['CONFIG'],
        # 两种精度都给出并**在名字里写明**（M1）：`config_hash` 是 16 位十六进制，与记录里的
        # `meta.config_hash` 同形（那是引擎侧的截断口径，不能改）；`config_hash_full` 是完整 64 位。
        'config_hash': 'sha256:' + config_hash[:16],
        'config_hash_full': 'sha256:' + config_hash,
        'hash_precision': {'config_hash': 'sha256[:16]（= 记录 meta.config_hash 的口径）',
                           'config_hash_full': 'sha256[:64]',
                           'topology_hash': 'sha256[:64]', 'playbook_hash': 'sha256[:64]'},
        'records_file': records_path,
        'records_before': int(os.environ['BEFORE']),
        'records_after': int(os.environ['AFTER']),
        'record_added': int(os.environ['ADDED']),
        'record_kept': True,
        'rolled_back': False,
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
        'config_hash_match': config_hash_check,
        'observation_subject': observation,
        'real_missing_evidence': probe_evidence,
        'attack_product': {
            'path': os.environ['ATTACK'],
            'mtime': datetime.datetime.fromtimestamp(int(os.environ['ATTACK_MTIME']),
                                                     datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'age_s': int(os.environ['ATTACK_AGE']),
            'started_at': os.environ.get('ATTACK_STARTED') or attack_meta.get('started_at'),
            'finished_at': os.environ.get('ATTACK_FINISHED') or attack_meta.get('finished_at'),
            'injections': int(os.environ.get('INJ_COUNT') or 0),
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
    dump_fragment(report)

    # --- 断言失败：留档被拒的那一行 + 请调用方回滚 --------------------------------
    # 【Fix round 3 / 第 1 项】`report[key]` 有的键是 dict（带 `ok`），有的键**是列表**
    # （`checks_ts_mismatch` / `injected_check_absent`）。此前无条件 `report[key]['ok'] = False`
    # 对列表键会抛 `TypeError: list indices must be integers…` —— 异常被外层 except 兜住、
    # 回滚照常发生（不会留下坏记录 ✓），但**恰好丢掉这条拒绝最需要的证据**：具体原因、
    # 富片段（相等断言/门禁⓪/时钟条目）与 rejected 留档行。故这里按类型分派，
    # 并**始终**把原因写进 `report['failures']`（不依赖键的形状）。
    def reject(key, msg):
        report['record_kept'] = False
        report['rolled_back'] = True
        report['rollback_reason'] = msg
        entry = report.get(key)
        if isinstance(entry, dict):
            entry['ok'] = False
        report.setdefault('failures', []).append({'key': key, 'reason': msg})
        dump_fragment(report)
        with open(os.environ['REJECTED_OUT'], 'a', encoding='utf-8') as fh:
            fh.write(last_line + '\n')
        fail(f'{msg}（该行已留档到 {os.environ["REJECTED_OUT"]} 并从数据集回滚）', rollback=True)

    if not config_hash_check['ok']:
        reject('config_hash_match',
               '配置指纹不一致：记录 meta.config_hash=%s，本次配置=%s —— 这条记录不是这份配置采的'
               % (config_hash_check['record'] or '(空)', config_hash_check['expected']))
    if not observation['ok']:
        reject('observation_subject',
               '观测主体不一致：%s（这条记录无法证明自己描述的是被攻节点，而"记录描述部署行为"'
               '正是本实验的前提）' % observation['reason'])
    if not probe_evidence['ok']:
        reject('real_missing_evidence',
               'R 组真实缺失缺节点侧证据：%s' % probe_evidence['reason'])
    if not equality['ok']:
        reject('chain_factor_set_equality',
               '因子集相等断言未通过：链上 = %s，场景声明 = %s（多出 %s；缺少 %s）—— '
               '这台宿主上还有别的检查在自然失败，本场景与其他场景的数据不可区分'
               % (equality['actual'], equality['expected'], equality['extra'] or '无', equality['missing'] or '无'))
    if absent:
        reject('injected_check_absent', '注入检查没有出现在记录的 checks[] 里：' + ','.join(absent))
    if mismatch:
        reject('checks_ts_mismatch', 'harness 报的注入时刻没有被写进记录的 checks[].ts：' + ','.join(mismatch))
    if injections and not clock_ok:
        reject('injection_vs_collection', '注入时刻与采集时刻的核对未通过（见片段里的 entries）—— 时间结构不成立')

    print(f'edge_collect: 配置指纹一致（{config_hash_check["record"]}）')
    print(f'edge_collect: 观测主体 {observation["record_observation_target"] or "本机（未声明 EDGEEXP_TARGET）"}'
          + (f'｜探针节点 {probe_targets}' if probe_targets else ''))
    print(f'edge_collect: 因子集相等断言通过（链 {len(actual)} 个 ID = 场景声明）')
    print(f'edge_collect: 门禁⓪ {gate0["verdict"]}（链 {gate0["chain_entries"]} 条 / 去重 {gate0["distinct_ids"]} 个 ID）')
    if injections:
        print(f'edge_collect: 注入时刻核对通过（{len(injections)} 条，全部早于 {collected_at}）')
    else:
        print('edge_collect: 注入时刻核对 n/a（本场景无注入）')
    print(f'edge_collect: 记录 {report["scenario_id"]} 总分 {report["final_score"]} 阈值 {report["threshold"]} '
          f'判 {report["acceptable"]}｜链 {report["chain_entries"]} 条｜失败检查 {report["failed_checks"]} 条')


try:
    body()
except SystemExit:
    raise
except Exception as exc:  # 记录已落盘：任何未预期异常都按"回滚"处理，绝不留下可疑记录
    traceback.print_exc()
    try:
        dump_fragment({'scenario': scenario, 'phase': 'collect', 'record_added': int(os.environ.get('ADDED') or 0),
                       'record_kept': False, 'rolled_back': True, 'error': repr(exc),
                       'rollback_reason': '采集核对出现未预期异常（例如最后一行 JSON 被截断）'})
    except Exception:
        pass
    fail(f'采集核对出现未预期异常：{exc!r} —— 记录已落盘，按回滚处理', rollback=True)
PY
RC=$?
set -e

if [ "$RC" -eq 3 ]; then
  # 记录已经落盘但核对失败：回到采集前的行数（被拒的那一行已留档到 run.d/rejected-*.jsonl）。
  if [ -f "$TMP_OUT" ]; then mv "$TMP_OUT" "$RUN_D/$FILLER"; fi
  if [ "$BEFORE" -eq 0 ]; then
    : > "$RECORDS"
  else
    head -n "$BEFORE" "$RECORDS" > "$RECORDS.rollback"
    mv "$RECORDS.rollback" "$RECORDS"
  fi
  echo "edge_collect: 场景 $SCENARIO 的核对未通过 ⇒ 已回滚该条记录（文件回到 $BEFORE 行），整轮失败" >&2
  exit 1
fi
if [ "$RC" -ne 0 ]; then
  echo "edge_collect: 采集核对失败（退出码 $RC）—— 整轮失败" >&2
  exit 1
fi
mv "$TMP_OUT" "$RUN_D/$FILLER"
echo "edge_collect: 完成（${ELAPSED}s，记录 $BEFORE→$AFTER 条）→ $RUN_D/$FILLER"
