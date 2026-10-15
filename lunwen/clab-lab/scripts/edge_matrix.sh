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
#   EDGEEXP_TARGET      **被攻节点的名字**（Task 4C）：默认为 `asc-asscor-host1` 并 export 给
#                       两个子脚本 —— 观测主体在节点内是本任务确立的**正确**形态（记录里的
#                       `meta.observation_target` 是权威证据），默认开启可以消除"看起来是节点
#                       数据、实际是宿主数据"这个最危险的静默形态；R 组（真实缺失对照）更是
#                       **必须**声明它（否则整轮失败，见 edge_attack.sh）。置空（`EDGEEXP_TARGET=`）
#                       即退回"在本机评估"的旧形态，但那时 R 组会硬失败。
#                       注意与 `edge_reset.sh` 的 `EDGEEXP_TARGET_HOST` **不是一回事**：后者是
#                       复位脚本的攻击目标（默认 `host1`），本变量是基质层的节点名。
#   EDGEEXP_SUBSTRATE   实验基质：clab（默认，今天的行为）| lxd（A-1，见 edge_lab.sh）|
#                       pve（dl360gen9 上的 PVE CT，经 `pct` —— Task 6）。它决定
#                       `edgescen -target` 的**语法**（见 edge_lab.sh 的 `lab_target_spec`）；
#                       `EDGEEXP_TARGET` 本身始终是基质层的节点名（clab: `asc-asscor-host1`；
#                       lxd: `probe-ot005`；pve: CT 的**名字**，如 `asc-tgt-c2`）。本脚本把它
#                       export 给三个子脚本 —— 「这一轮跑在哪种基质上」必须只有一处解析。
#
#   ---- Task 5 / Step 0：按场景驱动的**实验条件**（本步新增）----
#   背景（控制侧 2026-09-17 实测 + 复审 7.4 独立复核）：本脚本此前对
#   `EDGEEXP_BASIS|POLICY_ON|TARGET_ABILITY|ATTACK_GROUP` **零命中** ⇒ 25 个场景的"条件"
#   全是同一个值（甚至因为 `EDGEEXP_BASIS` 未设而**每个场景都 exit 1**）⇒ 耦合对的"条件 ⇒ 分数"
#   在矩阵层根本不成立。现在按**场景声明的注入因子集**（取自 `edgescen -list`，现成解析点）分类：
#     · 注入集含 `EDGEEXP_TTP_FACTORS`（默认 `EF-SELINUX,EF-APPARMOR`）⇒ **目标 TTP 口径**：
#       `EDGEEXP_BASIS=targeted_ttp` + 目标/对照 ability + pair 剧本 + `EDGEEXP_POLICY_ON=0`
#       （该场景声明"这个控制缺失"⇒ 真实策略也要卸掉，标签才与声明一致）；
#     · 其余场景 ⇒ `EDGEEXP_BASIS=recon_playbook`（**不得**带 target ability，逐场景 unset），
#       `EDGEEXP_POLICY_ON=1`（控制齐备的基线条件）。
#   三个开关（`TARGET_ABILITY` / `basis` / `POLICY_ON`）**逐场景成对设置**，不全局设一个 ——
#   这正是复审"开工必带"第 3 条要求的配对。配置项（在本脚本里是**输入**，不是每场景变量）：
#     **必需 3 个**（选中 targeted 场景时缺任一 ⇒ **干跑就 rc=2**，见下面那三条门禁）：
#       EDGEEXP_TTP_TARGET_ABILITY    目标 TTP 的 ability id（读 /etc/shadow）
#       EDGEEXP_TTP_PLAYBOOK_ID       pair 剧本（adversary）id
#       EDGEEXP_TTP_PLAYBOOK_NAME     它的名字（缺它 ⇒ `edge_attack.sh` 的漂移守卫在**攻击步**拒绝，
#                                     故 2026-10-13 起在矩阵层也拦一道，见下方第三条门禁）
#     **可选 2 个**（给了更好，缺了不会被拒；Task 8 复审核过源码）：
#       EDGEEXP_TTP_CONTROL_ABILITY   对照 ability id（写 marker，不撞策略）——
#                                     `edge_attack.sh:49` 自述"可选，只用于归类与报告"，`:816` 有
#                                     `not CONTROL_ABILITY or …` 分支
#       EDGEEXP_TTP_TARGET_ABILITY_NAME  目标 ability 的名字 —— 仅用于**核对 ID 没被换掉**，
#                                     `edge_attack.sh:852` 是 `if TARGET_ABILITY_NAME:`
#     其余开关：
#       EDGEEXP_TTP_GROUP             agent 分组名（默认 t4d-ttp；与 edge_target_prepare.sh 同源）
#       EDGEEXP_TTP_FACTORS           触发"目标 TTP 口径"的因子集（默认 EF-SELINUX,EF-APPARMOR）
#   选了目标 TTP 场景却没给**必需项** ⇒ **干跑前就响亮失败**（不许跑到一半才发现条件缺项）。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
# 基质层（Task 4D Step 1）：干跑要**在跑之前**把"这一轮跑在哪种基质上、观测主体会被翻成什么
# 语法"说清楚 —— 那正是"默认值是本轮引入的"这类变化最容易在几小时之后才暴露的地方。
# shellcheck source=scripts/edge_lab.sh
. "$SCRIPT_DIR/edge_lab.sh"
# 子脚本（各自 source 同一份 edge_lab.sh）必须看到**同一个**基质选择：export 一次，别处不再解析。
# shellcheck disable=SC2154  # lab_substrate 由上面那行 source 赋值
export EDGEEXP_SUBSTRATE="$lab_substrate"
DATA_DIR="${EDGEEXP_DATA_DIR:-$LAB_DIR/data/edgefactors}"
RUN_D="$DATA_DIR/run.d"
ENV_NAME="${EDGEEXP_ENV:-wsl-clab-14}"
TODAY="$(date -u +%Y%m%d)"
RUN_ID="${EDGEEXP_RUN_ID:-$TODAY-$$}"
CONFIG="${EDGEEXP_CONFIG:-$REPO_ROOT/configs/edgeexp/m0-baseline.ini}"
# **候选模板目录**（Task 5 Step 0 实测新增）：门禁①/② 要按四份模板各装一次候选，而 A-1 侧
# `$REPO_ROOT` 解析成 `/`（A-1 上只有 `/root/asscor` 这一份工作区）⇒ `$REPO_ROOT/configs/edgeexp/*.ini`
# 在 A-1 上是 `//configs/...`，实测报 `装载配置 //configs/edgeexp/chain.ini: no such file or directory`
# 而把**整轮判死**（门禁① 是硬闸门）。故候选目录可显式声明；默认仍是仓内 `configs/edgeexp`（本地不变）。
CANDIDATE_DIR="${EDGEEXP_CANDIDATE_DIR:-$REPO_ROOT/configs/edgeexp}"
RECORDS="${EDGEEXP_RECORDS:-$DATA_DIR/records-$ENV_NAME-$TODAY.jsonl}"
EDGESCEN="${EDGEEXP_EDGESCEN:-$REPO_ROOT/build/edgescen}"
EDGECOMPARE="${EDGEEXP_EDGECOMPARE:-$REPO_ROOT/build/edgecompare}"

# 【Task 4C / I-9】**观测主体默认在节点内**：把被攻节点的容器名钉给整个运行。
#
# 为什么默认开启（而不是"可选增强"）：`edge_attack.sh` 对 R 组（真实缺失对照）**要求**声明它，
# 而 `edge_collect.sh` 会把 `--target` 转成 `meta.observation_target` —— 那是"这条记录到底描述
# 哪台机器"的唯一机器可读证据。默认开启后，一次照手册跑的全量矩阵不会在第一个 R 场景整轮失败，
# 也不会产出"看起来是节点数据、实际是宿主数据"的记录。
# 置空（`EDGEEXP_TARGET=`）退回旧形态：S 组照常（探针不执行、如实留空），R 组**硬失败**。
TARGET="${EDGEEXP_TARGET-asc-asscor-host1}"
export EDGEEXP_TARGET="$TARGET"

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
#
# **Task 5 / Step 0**：同一个解析点顺便取回**每场景的注入因子集**（`-list` 已经打印 `因子=…`），
# 后面按它给每个场景分类条件。少写一个"因子表"的第二份真源 —— 矩阵的因子视图与采集器同源。
SCEN_FACTORS_RAW=""
if [ -x "$EDGESCEN" ]; then
  SCEN_FACTORS_RAW="$(python3 - "$EDGESCEN" "${SCENARIOS[@]}" <<'PY'
import subprocess, sys
binary, declared = sys.argv[1], sys.argv[2:]
out = subprocess.run([binary, '-list'], capture_output=True, text=True, check=True).stdout
listed, factors = [], {}
for line in out.splitlines():
    if not line.startswith('  '):
        continue
    parts = line.strip().split()
    if not parts:
        continue
    name = parts[0]
    listed.append(name)
    # `-list` 的既定形状：`<名> 注入=<kind> 因子=<A,B> [阶段=N] [级联目标=X]`；
    # 空因子表打印 `因子=(无)` ⇒ 归一成空串（"没有注入因子"是一等公民，不是解析失败）。
    fac = ''
    for tok in parts[1:]:
        if tok.startswith('因子='):
            fac = tok[len('因子='):]
    if fac in ('(无)', '-', ''):
        fac = ''
    factors[name] = fac
d, l = set(declared), set(listed)
if d != l:
    print('edge_matrix: 场景名单与采集器不一致 —— 只在本清单里的: %s；只在采集器里的: %s'
          % (sorted(d - l) or '无', sorted(l - d) or '无'), file=sys.stderr)
    sys.exit(1)
print(f'edge_matrix: 场景名单与采集器 edgescen -list 逐项相等（{len(d)} 组）', file=sys.stderr)
for name in declared:
    print('%s\t%s' % (name, factors.get(name, '')))
PY
)" || exit 1
else
  # **硬门禁（Task 8 Step ③）：缺采集器 ⇒ 直接失败，不再降级。**
  #
  # 为什么必须在这里失败（而不是只打一行警告）：复审复现过 —— 没有 `build/edgescen` 时本层
  # 只警告一句就继续，于是**拿不到每场景的注入因子集** ⇒ 条件分类**全部退化成
  # `recon_playbook + POLICY_ON=1`**（连含 `EF-SELINUX`/`EF-APPARMOR` 的 S2 也是），
  # 而矩阵照常把 25 个场景规划完，干跑那句
  # `条件分布 : targeted_ttp=0 个 ｜ recon_playbook=25 个 ｜ 合计 25 个（必须 == 25）`
  # **仍然通过** —— 它守的是"两列都不是常量"，而退化的结果恰恰是"两列都成了常量"。
  # 这是"看起来正常、其实全错"那一类，故必须在**分类发生之前**拦下。
  #
  # 原先的硬门禁（本文件后面那句 `[ -x "$EDGESCEN" ] || exit 1`）**在干跑里到不了**
  # （干跑在那之前就 exit 0）—— 所以"缺采集器"在干跑路径上是**没有任何拦截**的。
  echo "edge_matrix: $EDGESCEN 不存在或不可执行 —— **在条件分类之前就失败**（不降级）：" >&2
  echo "  没有采集器就拿不到每场景的注入因子集，条件分类会**全部**退化成" >&2
  echo "  recon_playbook + POLICY_ON=1（连 S2 也是），而干跑的场景数断言仍会通过 —— 静默的全错。" >&2
  echo "  先交叉编译它（见 edge_collect.sh 的提示），或用 EDGEEXP_EDGESCEN=<路径> 指定。" >&2
  exit 1
fi
declare -A SCEN_FACTORS=()
if [ -n "$SCEN_FACTORS_RAW" ]; then
  while IFS=$'\t' read -r _n _f; do
    [ -n "${_n:-}" ] || continue
    SCEN_FACTORS["$_n"]="${_f:-}"
  done <<< "$SCEN_FACTORS_RAW"
fi

# --- Task 5 / Step 0：把"每场景的实验条件"收在一处（分类规则 + 逐场景导出）------
# 分类与导出**只有这一处实现**：干跑用它打印计划，逐场景循环用它设环境 ——
# 两处各写一份分类，就会出现"干跑看到的条件"与"实际跑的条件"不一致（那正是本步要挡的形态）。
TTP_FACTORS_CSV="${EDGEEXP_TTP_FACTORS:-EF-SELINUX,EF-APPARMOR}"
TTP_TARGET_ABILITY="${EDGEEXP_TTP_TARGET_ABILITY:-}"
TTP_TARGET_ABILITY_NAME="${EDGEEXP_TTP_TARGET_ABILITY_NAME:-}"
TTP_CONTROL_ABILITY="${EDGEEXP_TTP_CONTROL_ABILITY:-}"
TTP_PLAYBOOK_ID="${EDGEEXP_TTP_PLAYBOOK_ID:-}"
TTP_PLAYBOOK_NAME="${EDGEEXP_TTP_PLAYBOOK_NAME:-}"
TTP_GROUP="${EDGEEXP_TTP_GROUP:-t4d-ttp}"
# scenario_is_targeted <场景名> —— 注入因子集里是否出现任一"目标 TTP 触发因子"。
scenario_is_targeted() {
  local csv=",${SCEN_FACTORS[$1]:-},"
  local f
  local IFS=','
  for f in $TTP_FACTORS_CSV; do
    f="$(printf '%s' "$f" | tr -d '[:space:]')"
    [ -n "$f" ] || continue
    case "$csv" in *",$f,"*) return 0 ;; esac
  done
  return 1
}

# --- Task 10：「策略在」的臂（用户 2026-10-13 裁定「甲」）------------------------
# **为什么需要它**：`targeted_ttp` 场景在 `POLICY_ON=0` 下，策略是卸掉的 ⇒ 目标 TTP
# （`head -1 /etc/shadow`）**必然成功** ⇒ Task 9 那 11 条记录的 `compromised` **全是 true**
# （标签零方差，决策层指标算不出东西）。故给**每个 targeted 场景**再加一条 **"策略在"
# （`POLICY_ON=1`）**的臂：同一个场景、同一个目标 TTP、同一个 pair 剧本、同一个攻击组、
# 同一份采集配置、同一个观察窗 —— **只差策略**（Step 1 已实测：策略在 ⇒ `compromised=false`
# 且目标 link `status=1`，对照 link 仍成功 ⇒ 是被策略挡住的）。
#
# **本块必须放在 `scenario_is_targeted` 定义之后**（它按分类展开实例）：放前面会变成前向引用，
# 结果是**每个场景都被判成非 targeted**（干跑实测 0 targeted / 25 recon，还顺手触发了方差门禁）。
#
# 四条纪律（每条都对应一种"看起来正常、其实错了"的形态）：
#  1. **既有臂一字不动**：`EDGEEXP_POLICY_ON_ARM=0` 时本段是**恒等变换**（实例 == 场景，
#     条件/产物/日志与 Task 9 逐字节相同）；默认 1 = 开臂（用户裁定后的口径）。
#  2. **实例要有独立身份**：两条臂**共用场景名**（`edgescen -s` 的表内查找必须用真名），
#     故臂的身份由**实例键**（`<场景>` / `<场景>-pon`）+ **run 号**（1 / 2）承载，
#     并在**记录本体**里留 `meta.policy_on`（Task 10 的 additive 字段）——
#     "哪条是哪一个臂"必须只看记录就能答，不许靠文件名或运行顺序。
#  3. **记账按实例**：记录条数门禁、`condition_summary`、干跑分布与"合计 N 个"都按实例数算。
#  4. **声明面不变**：两个臂的 `B` 都是 {EF-SELINUX, EF-APPARMOR}（`OT-005` 在 PVE CT 里恒假，
#     不随策略变）⇒ 两条臂的因子集相等断言**都必须过**（Step 1 已实测两臂都过）。
POLICY_ON_ARM="${EDGEEXP_POLICY_ON_ARM:-1}"
case "$POLICY_ON_ARM" in
  0|1) : ;;
  *) echo "edge_matrix: EDGEEXP_POLICY_ON_ARM 只认 0（= 与 Task 9 逐字相同的旧行为）或 1（默认：每个 targeted 场景加一条\"策略在\"的臂），收到 '$POLICY_ON_ARM'" >&2; exit 2 ;;
esac
# --- **重复轴**（Task 11）：`EDGEEXP_RUN_INDEX` 与「臂」是**两个独立的维度** --------
# 全量扫描是 `--run 1|2|3` × 2 个臂 ⇒ 每个 targeted 场景 **6 条**记录。而 Task 10 引入臂时，
# 实例的 run 号被**硬编码**成 1（策略不在）/ 2（策略在）⇒ `EDGEEXP_RUN_INDEX` **完全失效**：
# 重复第 2 遍仍拿 `-01`/`-02`，于是 ① 对已有记录的文件被幂等守卫拒掉（整轮失败，**跑到几小时后**才发现）；
# ② 碎片与 harness 产物的文件名里没有重复号 ⇒ 第 2 遍**覆盖**第 1 遍（run.json 台账串号，**静默**）。
# 现在把两个维度拆开：
#   · `run` 维度 = `EDGEEXP_RUN_INDEX`（默认 1）—— 语义不变（"同条件的第几次重复采样"）；
#   · `arm` 维度 = 该场景的第几条臂（0 = 策略不在 / 1 = 策略在）；
#   · 记录的 `scenario_id` 尾号 = **实例号** `NN = (REPEAT-1)*NARMS + arm + 1`（NARMS = 该场景的实例数）
#     ⇒ 三元组 (场景, 臂, 重复) **唯一**地映射到一个 id，且**单臂单 run 时 NN 退化成 1**
#     （`POLICY_ON_ARM=0` + `RUN_INDEX=1` ⇒ `-01`，与 Task 9 逐字节相同）；
#   · 实例键（碎片/产物文件名）= `<场景>` [+ `-pon`] [+ `-r<REPEAT>`]（REPEAT>1 才加）
#     ⇒ 重复之间也互不覆盖；
#   · 记录里三个维度分别可查：`scenario_id`（场景 + 实例号）、`meta.policy_on`（臂）、`meta.repeat`（重复号，
#     只在 >1 时写 ⇒ 单 run 的记录与 Task 9 逐字节不变）。
REPEAT="${EDGEEXP_RUN_INDEX:-1}"
case "$REPEAT" in
  ''|*[!0-9]*) echo "edge_matrix: EDGEEXP_RUN_INDEX 必须是非负整数（重复号），收到 '$REPEAT'" >&2; exit 2 ;;
esac
[ "$REPEAT" -ge 1 ] || { echo "edge_matrix: EDGEEXP_RUN_INDEX 必须 ≥ 1（收到 $REPEAT）—— 重复号 0 没有意义，且会让 scenario_id 尾号塌成 0" >&2; exit 2; }
INST_KEY=(); INST_SCEN=(); INST_BASIS=(); INST_POLICY=(); INST_RUN=(); INST_SUFFIX=(); INST_ARM=()
for s in "${SELECTED[@]}"; do
  NARMS=1
  if scenario_is_targeted "$s" && [ "$POLICY_ON_ARM" = "1" ]; then NARMS=2; fi
  RSFX=""
  [ "$REPEAT" -gt 1 ] && RSFX="-r$REPEAT"
  if [ "$NARMS" = "2" ]; then
    # targeted + 开臂：两条实例，arm 0 = 策略不在 / arm 1 = 策略在
    INST_KEY+=("$s$RSFX");     INST_SCEN+=("$s"); INST_BASIS+=("targeted_ttp"); INST_POLICY+=("0"); INST_ARM+=("0")
    INST_RUN+=("$(( (REPEAT - 1) * NARMS + 0 + 1 ))"); INST_SUFFIX+=("$RSFX")
    INST_KEY+=("$s-pon$RSFX"); INST_SCEN+=("$s"); INST_BASIS+=("targeted_ttp"); INST_POLICY+=("1"); INST_ARM+=("1")
    INST_RUN+=("$(( (REPEAT - 1) * NARMS + 1 + 1 ))"); INST_SUFFIX+=("-pon$RSFX")
  else
    # 单实例场景（NARMS=1）：targeted 但**关了臂** ⇒ 策略不在；其余（recon / R 组）本来就是
    # 策略在的既有口径（`policy_on=1`）—— 两者都不是"第二条臂"，故 arm 恒为 0
    # （arm 是"该场景的第几条臂"，不是策略状态；策略状态在 `INST_POLICY` 里）。
    if scenario_is_targeted "$s"; then
      INST_BASIS+=("targeted_ttp"); INST_POLICY+=("0")
    else
      INST_BASIS+=("recon_playbook"); INST_POLICY+=("1")
    fi
    INST_KEY+=("$s$RSFX"); INST_SCEN+=("$s"); INST_ARM+=("0")
    INST_RUN+=("$(( (REPEAT - 1) * NARMS + 0 + 1 ))"); INST_SUFFIX+=("$RSFX")
  fi
done
# 重复号 >1 时导出给子脚本（`edge_attack.sh` 会把它写进 harness 产物 ⇒ 采集器写进记录的 `meta.repeat`）。
# **只在 >1 时导出**：这样单 run 的产物与记录与 Task 9/10 逐字节不变（`repeat` 缺席 = 第 1 遍）。
if [ "$REPEAT" -gt 1 ]; then export EDGEEXP_REPEAT_INDEX="$REPEAT"; fi
TARGETED_SELECTED=0
for k in "${!INST_KEY[@]}"; do
  if [ "${INST_BASIS[$k]}" = "targeted_ttp" ]; then TARGETED_SELECTED=$((TARGETED_SELECTED + 1)); fi
done

# scenario_condition_line <场景名> —— 人类可读的一行（干跑与逐场景循环共用，措辞只此一份）。
scenario_condition_line() { # $1=场景 $2=策略状态（0/1；缺省 0 = 旧行为，输出逐字节不变）
  local s="$1" pol="${2:-0}" factors="${SCEN_FACTORS[$1]:-}"
  if scenario_is_targeted "$s"; then
    printf 'basis=%-14s policy=%-3s 目标=%s 对照=%s 剧本=%s 组=%s 因子=%s' \
      "targeted_ttp" "$pol" "${TTP_TARGET_ABILITY:-(未给)}" "${TTP_CONTROL_ABILITY:-(未给)}" \
      "${TTP_PLAYBOOK_ID:-(未给)}" "$TTP_GROUP" "${factors:-（无）}"
  else
    printf 'basis=%-14s policy=%-3s 目标=%s 对照=%s 剧本=%s 组=%s 因子=%s' \
      "recon_playbook" "1" "(不适用)" "(不适用)" "Discovery（脚本缺省）" "$TTP_GROUP" "${factors:-（无）}"
  fi
}

# apply_scenario_conditions <场景名> —— **导出**该场景的条件（三个开关逐场景成对设置）。
#
# 两条纪律：
#   · `recon_playbook` 场景**必须 unset** target/control/剧本 变量（`edge_attack.sh` 对
#     "声明了侦察口径却给了目标 ability"是**响亮失败**；靠"全局设一个值"会让 14 个非 AppArmor
#     场景直接判死或悄悄带上目标口径）—— 这就是复审"开工必带"第 3 条的落地；
#   · `EDGEEXP_ATTACK_GROUP` **两类都设**：投送范围钉在目标 agent 那一组，别的机器上的 agent
#     （A-1 上控制侧 `probe-ot005` 也有活 agent）不会执行本轮的剧本 ⇒ `nodes_affected` 不被污染。
#     闸门只在 basis=targeted_ttp 时**要求**它，但"条件里没有别的机器"对两类都是更好的实验。
apply_scenario_conditions() { # $1=场景 $2=策略状态（0/1；缺省 0 = 旧行为）
  local s="$1" pol="${2:-0}"
  if scenario_is_targeted "$s"; then
    export EDGEEXP_BASIS="targeted_ttp"
    export EDGEEXP_TARGET_ABILITY="$TTP_TARGET_ABILITY"
    export EDGEEXP_TARGET_ABILITY_NAME="$TTP_TARGET_ABILITY_NAME"
    export EDGEEXP_CONTROL_ABILITY="$TTP_CONTROL_ABILITY"
    export EDGEEXP_PLAYBOOK_ID="$TTP_PLAYBOOK_ID"
    export EDGEEXP_PLAYBOOK_NAME="$TTP_PLAYBOOK_NAME"
    export EDGEEXP_POLICY_ON="$pol"
    SCEN_BASIS_NOW="targeted_ttp"; SCEN_POLICY_NOW="$pol"; SCEN_ABILITY_NOW="$TTP_TARGET_ABILITY"
  else
    export EDGEEXP_BASIS="recon_playbook"
    unset EDGEEXP_TARGET_ABILITY EDGEEXP_TARGET_ABILITY_NAME EDGEEXP_CONTROL_ABILITY
    unset EDGEEXP_PLAYBOOK_ID EDGEEXP_PLAYBOOK_NAME
    export EDGEEXP_POLICY_ON=1
    SCEN_BASIS_NOW="recon_playbook"; SCEN_POLICY_NOW=1; SCEN_ABILITY_NOW=""
  fi
  export EDGEEXP_ATTACK_GROUP="$TTP_GROUP"
  # 攻击目标主机 = 观测主体（同一台机器）：`edge_attack.sh` 的 `(host, 活 pid)` 判据与投送范围
  # 闸门都用它。A-1 上两者都是实例名（`asc-tgt-1`）。
  export EDGEEXP_ATTACK_HOST="$TARGET"
}

# 目标 TTP 场景缺配置 ⇒ **干跑就失败**（不许跑到一半才发现条件缺项）。判据只看**选中的**场景：
# 只跑侦察场景时不该因为"没给 ability"而拒绝。
if [ "${TARGETED_SELECTED:-0}" -gt 0 ]; then
  [ -n "$TTP_TARGET_ABILITY" ] || {
    echo "edge_matrix: 选中的场景里有 $TARGETED_SELECTED 个目标 TTP 场景（注入因子含 $TTP_FACTORS_CSV），却没给 EDGEEXP_TTP_TARGET_ABILITY —— 目标 TTP 口径没有目标 ability 是自相矛盾的（edge_attack.sh 也会拒绝），整轮失败" >&2
    exit 2
  }
  [ -n "$TTP_PLAYBOOK_ID" ] || {
    echo "edge_matrix: 选中的场景里有 $TARGETED_SELECTED 个目标 TTP 场景，却没给 EDGEEXP_TTP_PLAYBOOK_ID（pair 剧本）—— 缺省剧本是固定的 Discovery（侦察口径），与 basis=targeted_ttp 不一致，整轮失败" >&2
    exit 2
  }
  # **为什么 `..._PLAYBOOK_NAME` 也要在这里拦**（Task 8 复审实测的缺口）：只给 ID 不给名字时，
  # 干跑**照样 rc=0**、规划表看起来完全正常 —— 因为名字要到**攻击步**才被用上：`edge_attack.sh`
  # 有一条**剧本漂移守卫**（`edge_attack.sh:628-629`，名字默认 `Discovery`，见 `:75`）：
  #
  #     剧本 ID … 现在的名字是 'T4D Step 3B pair (control + target TTP)'，与固定的 'Discovery' 不符
  #     —— 剧本漂移，拒绝在这种状态下采集
  #
  # 于是一整轮要在**第一个** targeted 场景的攻击步才以 rc=1 失败（矩阵"记录条数 0/2 整轮失败"），
  # 而前面已经跑过的 reset 全白费。这正是 Step ① 那条"干跑 rc=0"判据**没有覆盖**的一类缺项：
  # 判据只证明"给了五个变量时能跑通"，不证明"缺哪个会在干跑就被拦"。
  #
  # 判据只看**选中的**场景（与上面两条同源）：只跑侦察场景时不要求它（矩阵对 recon 场景会主动
  # unset 剧本变量）。**一处例外要写明**：如果操作者的 pair 剧本真的就叫 `Discovery`，缺名字本来
  # 也能跑通，但本门禁不做"猜名字"这件事（那要访问 C2 查 adversary）—— 显式给一个名字是更便宜的代价，
  # 而猜错的代价是整轮在攻击步失败。
  [ -n "$TTP_PLAYBOOK_NAME" ] || {
    echo "edge_matrix: 选中的场景里有 $TARGETED_SELECTED 个目标 TTP 场景，却没给 EDGEEXP_TTP_PLAYBOOK_NAME —— edge_attack.sh 的剧本漂移守卫拿 adversary 的**名字**与它比对（缺省 'Discovery'），只给 ID 不给名字会让每一个 targeted 场景在**攻击步**才被拒（干跑却是绿的）—— 整轮失败" >&2
    exit 2
  }
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
  # 基质必须在干跑里就看得见（Task 4D Step 1）：它决定"环境怎么建/毁、目标怎么被 exec、
  # `-target` 长什么样"，而默认值 clab = 今天的行为。换基质是**显式**动作，不是隐式继承。
  echo "  基质        : $lab_substrate（clab = 今天的行为；lxd = A-1 上的既有实例；pve = PVE CT（pct），见 edge_lab.sh）"
  # 基质基线活跃集必须在干跑里就看得见（Task 7）：它决定「声明面 = 基线活跃集 ∪ 注入集」的
  # **左边那一半**，而它是**按基质**定的（见 edge_lab.sh 的那段）。看不它，操作者就无法在跑之前
  # 判断"这批记录的因子向量会带上哪些天然因子"。空基线集也照打（"没声明"与"声明为空"
  # 在数据上必须能分开读，这里同理）。
  # shellcheck disable=SC2154  # EDGEEXP_BASELINE_FACTORS/_SOURCE 由 source edge_lab.sh 赋值/导出
  echo "  基线活跃集  : ${EDGEEXP_BASELINE_FACTORS:-（空）}｜来源：${EDGEEXP_BASELINE_FACTORS_SOURCE:-未声明（默认空基线集）}"
  # 两层 CLI 分别打印（Fix round 1 / M-2）：上一版只打一个 `$lab_bin`，读者看不出"拓扑级用哪个、
  # 容器级用哪个"——而那条区分正是 I-1 的根因（一个变量两义）。现在两个名字各打一个。
  # shellcheck disable=SC2154  # lab_topology_bin / lab_target_bin 由 source edge_lab.sh 赋值
  echo "  基质命令    : 拓扑级 $lab_topology_bin｜目标级 $lab_target_bin｜拓扑 $lab_topology"
  # 观测主体必须在干跑里就看得见（Task 4C / I-9 第 2 条）：它是"这批记录描述哪台机器"的答案，
  # 而默认值恰恰是本轮引入的 —— 操作者要能在跑之前就知道它、并知道怎么改。
  if [ -n "$TARGET" ]; then
    echo "  观测主体    : 节点内（EDGEEXP_TARGET=$TARGET；可用 EDGEEXP_TARGET=<节点名> 覆盖，置空=退回本机评估但 R 组会硬失败）"
    echo "  观测主体继承: EDGEEXP_TARGET=$(bash -c 'printf "%s" "${EDGEEXP_TARGET:-<未导出>}"')"
    echo "  -target 语法: $(lab_target_spec "$TARGET")（由基质 $lab_substrate 决定；见 edge_lab.sh 的 lab_target_spec）"
  else
    echo "  观测主体    : 本机（EDGEEXP_TARGET 被显式置空）—— R 组的真实缺失对照会因此整轮失败；S 组的 condition_probes 会如实留空（不是证据）"
  fi
  echo "  数据目录    : $DATA_DIR（干跑不创建、不清理）"
  echo "  场景        : ${#SELECTED[@]} 个（声明的 ${#SCENARIOS[@]}）/ 名单核对已通过"
  if [ "$REPEAT" -gt 1 ]; then
    echo "  重复轴      : REPEAT=$REPEAT（EDGEEXP_RUN_INDEX）—— 实例号 NN=(REPEAT-1)*NARMS+臂+1 ⇒ 本轮的 scenario_id 尾号与第 1 遍**不重叠**；实例键带 -r$REPEAT（碎片/产物不覆盖）"
  fi
  if [ "$POLICY_ON_ARM" = "1" ]; then
    echo "  场景实例    : ${#SELECTED[@]} 个场景 → ${#INST_KEY[@]} 个实例（targeted 场景各 2 条臂：POLICY_ON=0 / POLICY_ON=1；其余场景 1 个实例）"
  fi
  # **按场景驱动的实验条件**必须在干跑里逐场景看得见（Task 5 / Step 0 的判据）：复审 7.6 第 1 条
  # 要求"每个场景那一行能看出 basis/policy 两列，且两列都不是常量"。
  if [ "$POLICY_ON_ARM" = "1" ]; then
    echo "  条件分类    : 注入因子含 $TTP_FACTORS_CSV ⇒ targeted_ttp，**两条臂**（POLICY_ON=0 = 旧臂 / POLICY_ON=1 = 策略在的臂）；其余 ⇒ recon_playbook + POLICY_ON=1"
  else
    echo "  条件分类    : 注入因子含 $TTP_FACTORS_CSV ⇒ targeted_ttp + POLICY_ON=0；其余 ⇒ recon_playbook + POLICY_ON=1"
  fi
  echo "  目标 TTP    : ability=${TTP_TARGET_ABILITY:-(未给)}（${TTP_TARGET_ABILITY_NAME:-未给名字}）｜对照=${TTP_CONTROL_ABILITY:-(未给)}｜剧本=${TTP_PLAYBOOK_ID:-(未给)}（${TTP_PLAYBOOK_NAME:-未给名字}）｜组=$TTP_GROUP"
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
  echo "  计划（逐场景条件由本脚本按注入因子集决定；两列都必须不是常量）："
  i=0
  TGT=0; TGT_ON=0; REC=0
  COMBOS=""
  for k in "${!INST_KEY[@]}"; do
    i=$((i + 1))
    _s="${INST_SCEN[$k]}"; _pol="${INST_POLICY[$k]}"; _key="${INST_KEY[$k]}"; _run="${INST_RUN[$k]}"
    case "${INST_BASIS[$k]}" in
      targeted_ttp) if [ "$_pol" = "1" ]; then TGT_ON=$((TGT_ON + 1)); else TGT=$((TGT + 1)); fi ;;
      *) REC=$((REC + 1)) ;;
    esac
    COMBOS="$COMBOS
${INST_BASIS[$k]}/$_pol"
    if [ -f "$RECORDS" ] && grep -qE "\"scenario_id\":\"$_s-0$_run\"" "$RECORDS"; then
      printf '    [%2d/%2d] %-28s %s ｜skip（文件里已有记录；仅当 EDGEEXP_RESUME=1 时才会真的跳过）\n' \
        "$i" "${#INST_KEY[@]}" "$_key" "$(scenario_condition_line "$_s" "$_pol")"
    else
      printf '    [%2d/%2d] %-28s %s ｜collect（reset → attack → collect 三步都会跑）\n' \
        "$i" "${#INST_KEY[@]}" "$_key" "$(scenario_condition_line "$_s" "$_pol")"
    fi
  done
  if [ "$POLICY_ON_ARM" = "1" ]; then
    echo "  条件分布    : targeted_ttp(policy=0)=$TGT 个 ｜ targeted_ttp(policy=1)=$TGT_ON 个 ｜ recon_playbook=$REC 个 ｜ 合计 $((TGT + TGT_ON + REC)) 个（必须 == ${#INST_KEY[@]}）"
  else
    echo "  条件分布    : targeted_ttp=$TGT 个 ｜ recon_playbook=$REC 个 ｜ 合计 $((TGT + REC)) 个（必须 == ${#SELECTED[@]}）"
  fi
  [ "$((TGT + TGT_ON + REC))" -eq "${#INST_KEY[@]}" ] || { echo "edge_matrix: 条件分类没有覆盖全部选中场景实例（这是干跑门禁）" >&2; exit 3; }
  if [ "${#INST_KEY[@]}" -gt 1 ]; then
    _combos="$(printf '%s\n' "$COMBOS" | sed '/^$/d' | sort -u | wc -l)"
    [ "$_combos" -ge 2 ] || {
      echo "edge_matrix: 选中的 ${#INST_KEY[@]} 个场景实例里 (basis, policy) 只有**一种**组合（targeted(policy=0)=$TGT targeted(policy=1)=$TGT_ON recon=$REC）—— 实验条件没有方差，多场景扫描会产出条件无方差的数据（这是干跑门禁，见复审 7.6 第 1 条）" >&2
      exit 3
    }
  fi
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
python3 - "$STATE" "$RUN_ID" "$ENV_NAME" "$MODE" "$RECORDS" "$CONFIG" "$RUN_STARTED" "$RUN_START_S" "$TARGET" "${SELECTED[@]}" <<'PY'
import json, sys
state = {
    'run_id': sys.argv[2], 'env': sys.argv[3], 'mode': sys.argv[4],
    'records_file': sys.argv[5], 'config': sys.argv[6],
    'started_at': sys.argv[7], 'start_s': int(sys.argv[8]),
    # 观测主体（Task 4C / I-9 第 2 条）：照 `env` 的先例在运行级产物里留痕 ——
    # "这批记录描述哪台机器"必须能从 run.json 看出来，而不是只能去翻每条记录的 meta。
    'observation_target': sys.argv[9],
    'scenarios_selected': sys.argv[10:], 'completed': [], 'failed': None,
}
json.dump(state, open(sys.argv[1], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
# 场景**实例**表（Task 10）：台账与 run.json 按实例组装（targeted 场景两条臂）。
python3 - "$STATE" "${INST_KEY[@]}" <<'PY'
import json, os, sys
p, keys = sys.argv[1], sys.argv[2:]
s = json.load(open(p, encoding='utf-8'))
s['instances'] = list(keys)
# **重复轴**（Task 11）：台账要按"实例数 × 重复号"算期望行数（同一份记录文件会被 1..REPEAT 各跑一遍）。
s['repeat'] = int(os.environ.get('EDGEEXP_RUN_INDEX') or 1)
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
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
state_condition() { # state_condition <实例键> <basis> <policy_on> <ability> [场景名]
  python3 - "$STATE" "$1" "$2" "$3" "$4" "${5:-}" <<'PY'
import json, sys
p, key, basis, policy, ability, scenario = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
s = json.load(open(p, encoding='utf-8'))
s.setdefault('conditions', {})[key] = {
    'basis': basis, 'policy_on': int(policy), 'target_ability': ability or None,
    # 实例键与场景名分开记：targeted 场景有两条臂，键是 `<场景>` / `<场景>-pon`，
    # 而"这是哪个场景"必须另有字段（否则按场景去重统计时会把它算成两个场景）。
    'scenario': scenario or key,
}
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
  export RUN_D STATE DATA_DIR ENV_NAME TODAY RUN_ID RECORDS CONFIG REPO_ROOT EDGESCOMPARE CANDIDATE_DIR
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
# Task 10：台账按**实例**组装（`instances` 由矩阵在开跑时写入；老 state 没有这个键 ⇒
# 退回场景表，与加臂之前逐字相同）。碎片文件名也是按实例键来的（`<场景>` / `<场景>-pon`）。
insts = state.get('instances') or list(scen)
per_scenario = []
gate0 = {'per_scenario': {}, 'duplicate_observed': [], 'chain_entries_total': 0}
clock = {'all_ok': True, 'per_scenario': {}}
gate2 = {'per_scenario': {}, 'max_abs_delta': 0.0, 'source': 'edgescen 进程内自检（装配点，容差 0.005，不通过即拒绝写出）'}
equality = {'per_scenario': {}, 'all_ok': True, 'failures': []}
records_expected = 0
ts_sources = {}
ts_from_dataset = {}   # 从记录本体读到的 ts 口径（续跑时没有 collect 碎片的兜底）

for s in insts:
    reset, attack, collect = frag('reset', s), frag('attack', s), frag('collect', s)
    cond = (state.get('conditions') or {}).get(s) or {}
    entry = {'instance': s, 'scenario': cond.get('scenario') or s,
             'basis': cond.get('basis'), 'policy_on': cond.get('policy_on'),
             'reset': reset, 'attack': attack, 'collect': collect,
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
    # **重复轴**（Task 11）：这一轮是第几次重复采样（1..N）。全量扫描 = 同一份记录文件跑 1/2/3 各一遍。
    'repeat_index': int(state.get('repeat') or 1),
    'env': state['env'],
    # 观测主体（Task 4C / I-9）：空串 = 本机（旧形态、R 组会硬失败）。照 env 的先例放顶层。
    'observation_target': state.get('observation_target', ''),
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
    # **按实例 × 重复号算**（Task 10/11）：一个 targeted 场景两条臂，且同一份文件会被 1..REPEAT 各跑一遍。
    'records_expected': len(insts),
    'records_written_this_run': records_expected,
    'records_file_total_lines': file_lines,
    # 缺/多分开报（Fix round 2 的 Minor 项；Task 10 起分母是**实例数**）：此前一个 `len(scen) - file_lines` 同时承担
    # 两种含义，文件里**多**了别的场景行时会变成负数（看起来像"缺了 −2 条"）。
    'records_missing_for_selected': max(0, len(insts) * int(state.get('repeat') or 1) - file_lines),
    'records_extra_in_file': max(0, file_lines - len(insts) * int(state.get('repeat') or 1)),
    # 记录条数（I6）：判据要同时看两件事 —— ① 这份文件里**至少**有本次选中场景数那么多条记录
    # （只统计"本次写了几次"会漏掉文件里原有的别的场景行）；② 本次写入 + 续跑跳过 == 选中场景数
    # （续跑模式下本次写入可以是 0，那不是缺口）。只看 ① 会在"文件里有别的场景行"时误报通过，
    # 只看 ② 会在续跑时误报失败。
    # 期望**文件行数** = 实例数 × 重复号（同一份记录文件承载 1..REPEAT 各一遍）；
    # `records_expected` 仍是"**本轮**该写几条"（= 实例数，不含被续跑跳过的）。
    'record_counts_ok': (file_lines == len(insts) * int(state.get('repeat') or 1))
                        and (records_expected + len(skipped_resume) == len(insts)),
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
        'repeat_axis': 'Task 11：**重复轴与臂是两个独立维度**。`run` 维度 = EDGEEXP_RUN_INDEX（第几次重复采样），'
                       '`arm` 维度 = 0（POLICY_ON=0）/ 1（POLICY_ON=1）；记录的 `scenario_id` 尾号是'
                       '**实例号** NN=(REPEAT-1)*NARMS+arm+1（NARMS = 该场景的实例数，targeted 开臂时=2）；'
                       '实例键（碎片/`attack-*.json` 文件名）在 REPEAT>1 时带 `-r<N>` ⇒ 重复之间不覆盖。'
                       '记录里三个维度分别可查：`scenario_id` / `meta.policy_on` / `meta.repeat`'
                       '（`repeat` 只在 >1 时写 ⇒ 单 run 的记录与 Task 9 逐字节不变）。',
        'records_file_pinned': '本脚本把解析出的记录路径 export 给子脚本（Fix round 3 / 第 2 项）：'
                               '父子各自算 date +%Y%m%d 时，跨 00:00 UTC 的 sweep 会把数据集劈成两份',
        'threshold_sensitivity': '阈值敏感性行（spec §5.4.6）**只在显式 opt-in 时**存在'
                                 '（EDGEEXP_SENSITIVITY_THRESHOLDS=60…）：它覆盖部署判定线，'
                                 '故其产物一律标注为敏感性分析、不得与主对比结论混排；'
                                 '本键为 null = 本轮没有跑敏感性行（默认路径不变）',
    },
    'records_file_agreement': records_agreement,
}
# **条件台账**（Task 5 / Step 0）：逐场景的 basis/policy/目标 ability 进 run.json ——
# 决策层的记账判据（`参与决策层 == 带目标场景数 × 重复数`）必须能从运行级产物里**算出来**，
# 而不是靠读日志。`condition_summary` 给出两类的场景数与策略在/不在的场景数（都必须非零）。
run['conditions'] = state.get('conditions', {})
_conds = run['conditions']
# **Task 10 的口径变化要写明**：`conditions` 现在按**场景实例**登记（targeted 场景有两条臂
# ⇒ 同一场景两行）。故 `policy_on_scenarios`/`policy_off_scenarios` 这两个键从此是**实例**口径
# （加臂之前实例 == 场景，所以数值不变；`EDGEEXP_POLICY_ON_ARM=0` 时逐字回到旧值）。
_inst_keys = list(_conds.keys())
_scen_names = {v.get('scenario') or k for k, v in _conds.items()}
_def = lambda **kw: sum(1 for v in _conds.values() if all(v.get(f) == x for f, x in kw.items()))
run['condition_summary'] = {
    # 场景口径（**场景去重**；与 Task 9 的 run.json 同名同义）
    'targeted_ttp_scenarios': len({v.get('scenario') for v in _conds.values() if v.get('basis') == 'targeted_ttp'}),
    'recon_playbook_scenarios': len({v.get('scenario') for v in _conds.values() if v.get('basis') == 'recon_playbook'}),
    # 实例口径（Task 10 新增：`targeted_ttp` 场景各有两条臂）
    'instances_total': len(_inst_keys),
    'targeted_ttp_policy_off_instances': _def(basis='targeted_ttp', policy_on=0),
    'targeted_ttp_policy_on_instances': _def(basis='targeted_ttp', policy_on=1),
    'recon_playbook_instances': _def(basis='recon_playbook'),
    'policy_on_scenarios': _def(policy_on=1),
    'policy_off_scenarios': _def(policy_on=0),
    'policy_on_arm': os.environ.get('EDGEEXP_POLICY_ON_ARM', '1'),
}
run['notes']['scenario_conditions'] = (
    'Task 5 / Step 0 + Task 10：逐**场景实例**条件由 edge_matrix.sh 按 edgescen -list 的注入因子集决定 —— '
    '含 TTP 触发因子（默认 EF-SELINUX/EF-APPARMOR）⇒ basis=targeted_ttp + 目标/对照 ability，'
    '并且**每个场景两条臂**（POLICY_ON=0 与 POLICY_ON=1，后者是 Task 10 按用户裁定「甲」加的）；'
    '其余 ⇒ basis=recon_playbook + POLICY_ON=1（不得带 target ability）。'
    '`condition_summary` 的场景口径两列之和 == scenarios_selected 数，'
    '实例口径 `instances_total` == 选中实例数（干跑门禁同时查这两条）。'
    '两条臂只差策略、其余逐项相同；臂的身份写在记录的 **`meta.policy_on`** 里（additive），'
    '不许靠文件名或运行顺序区分。')
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
echo "edge_matrix: 运行 $RUN_ID（$MODE，${#SELECTED[@]} 个场景 / ${#INST_KEY[@]} 个场景实例 / 声明的 ${#SCENARIOS[@]}）"
[ "$REPEAT" -gt 1 ] && echo "edge_matrix: 重复轴 REPEAT=$REPEAT（EDGEEXP_RUN_INDEX）—— scenario_id 尾号从 $(( (REPEAT - 1) * 2 + 1 )) 起，与第 1 遍不重叠"
echo "edge_matrix: 记录文件 $RECORDS"
# 子脚本据此判断 harness 产物是不是**本轮**的（I7）：陈旧产物会静默提供旧的注入时刻与客观结果。
export EDGEEXP_RUN_STARTED_AT="$RUN_STARTED"
RESUME="${EDGEEXP_RESUME:-0}"
EXPECT_IDS=()
i=0
for k in "${!INST_KEY[@]}"; do
  i=$((i + 1))
  s="${INST_SCEN[$k]}"; KEY="${INST_KEY[$k]}"; POL="${INST_POLICY[$k]}"; RUN="${INST_RUN[$k]}"; SUF="${INST_SUFFIX[$k]}"
  INST_ID="$(printf '%s-%02d' "$s" "$RUN")"
  EXPECT_IDS+=("$INST_ID")
  # 续跑（M9）：幂等守卫会拒绝"同一**实例**已有记录"，于是中断后的整轮只能从头再来。
  # EDGEEXP_RESUME=1 时跳过已有记录的实例，并把跳过的事实写进 run.json。
  # 判据用**完整 scenario_id**（不是场景前缀）：加臂之后同一场景有两条记录（`-01`/`-02`），
  # 前缀匹配会把第二条臂当成"已有记录"而拒掉（那正是"看起来正常、其实少了一条臂"）。
  if [ "$RESUME" = "1" ] && [ -f "$RECORDS" ] && grep -qE "\"scenario_id\":\"$INST_ID\"" "$RECORDS"; then
    echo "edge_matrix: [$i/${#INST_KEY[@]}] 实例 $KEY 已有记录（$INST_ID）—— 续跑模式跳过（写入 run.json 的 scenarios_skipped_resume）"
    python3 - "$STATE" "$KEY" <<'PY'
import json, sys
p, inst = sys.argv[1], sys.argv[2]
s = json.load(open(p, encoding='utf-8'))
s.setdefault('skipped_resume', [])
if inst not in s['skipped_resume']:
    s['skipped_resume'].append(inst)
json.dump(s, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
    continue
  fi
  echo "============================================================"
  echo "edge_matrix: [$i/${#INST_KEY[@]}] 实例 $KEY（场景 $s，策略=$POL，run=$RUN）"
  # **按实例设条件**（Task 5 / Step 0 + Task 10 的臂）：三个开关逐实例成对设置，并在同一行打印
  # 出来 —— 日志里能看到"这个实例用的是什么条件"，而不是只能事后去翻记录。
  apply_scenario_conditions "$s" "$POL"
  echo "edge_matrix: [$i/${#INST_KEY[@]}] $KEY 条件 $(scenario_condition_line "$s" "$POL")"
  state_condition "$KEY" "$SCEN_BASIS_NOW" "$SCEN_POLICY_NOW" "$SCEN_ABILITY_NOW" "$s" || true
  t0=$(date -u +%s)
  # 一律用 `bash <script>` 调用（不依赖可执行位）：lab 目录在 /mnt/f（drvfs）上，
  # 可执行位由挂载选项决定，靠它会让"脚本本身没跑"伪装成"实验失败"。
  # 每一步先写好兜底失败原因（含实例与场景名）：`set -e` 下子脚本失败会直接跳到 trap，
  # 那时只有这里写下的原因是可归因的（Fix round 2 的 M4 项）。
  # `EDGEEXP_INSTANCE_SUFFIX`（Task 10）只用于**碎片文件名**：两条臂共用场景名，
  # 不带后缀的话第二条臂会覆盖第一条臂的 `reset-*.json`/`collect-*.json`（run.json 的台账
  # 按碎片组装 ⇒ 会把策略在的臂的数据挂到策略不在的臂上）。旧臂后缀为空 ⇒ 文件名逐字节不变。
  FAIL_REASON="实例 $KEY（场景 $s）的 reset 步失败（见上面的 stderr）"
  EDGEEXP_INSTANCE_SUFFIX="$SUF" bash "$SCRIPT_DIR/edge_reset.sh" "$s"
  FAIL_REASON=""
  t1=$(date -u +%s); state_add "$KEY" reset $((t1 - t0))
  FAIL_REASON="实例 $KEY（场景 $s）的 attack 步失败（见上面的 stderr）"
  bash "$SCRIPT_DIR/edge_attack.sh" "$s" "$DATA_DIR/attack-$KEY.json"
  FAIL_REASON=""
  t2=$(date -u +%s); state_add "$KEY" attack $((t2 - t1))
  FAIL_REASON="实例 $KEY（场景 $s）的 collect 步失败（记录已回滚；见上面的 stderr 与 run.d/rejected-$KEY.jsonl）"
  EDGEEXP_INSTANCE_SUFFIX="$SUF" bash "$SCRIPT_DIR/edge_collect.sh" "$s" "$CONFIG" "$DATA_DIR/attack-$KEY.json" "$RUN"
  FAIL_REASON=""
  t3=$(date -u +%s); state_add "$KEY" collect $((t3 - t2))
  state_complete "$KEY"
  echo "edge_matrix: [$i/${#INST_KEY[@]}] $KEY 完成（reset $((t1-t0))s / attack $((t2-t1))s / collect $((t3-t2))s）"
done

# --- 记录条数门禁（**判死整轮**，不只是一个上报字段）----------------------------
# brief 的"记录条数 == 场景数"此前只是 run.json 里的一个布尔值：文件里少一条或多一条都不影响
# 退出码（Fix round 2 的 Important 项后半句）。这里把它变成硬闸门：文件总行数必须**恰好**
# 等于本次选中的场景数 —— 少一条说明有场景没采成，多一条说明文件里混进了别的场景
# （续跑/换 run_id/共用文件），两种都会让"每场景一条"这句结论失效。
FILE_LINES=0
if [ -f "$RECORDS" ]; then FILE_LINES=$(grep -c . "$RECORDS" || true); fi
# **多重复的口径（Task 11）**：同一份记录文件会被 `EDGEEXP_RUN_INDEX=1..N` 各跑一遍 ⇒
# 第 2 遍之后"文件总行数 == 实例数"**本来就不成立**（那是第 1 遍的判据）。故：
#   · `REPEAT=1`：**逐字保持旧判据**（总行数 == 选中实例数）—— 它同时是"文件里混进了别的场景"的哨兵；
#   · `REPEAT>1`：改判"**本轮每个实例 id 在文件里恰好出现一次**"（少一条 = 有实例没采成；
#     多于一条 = 串号/重复写）。文件里**允许**出现其它重复号的行（那是前几遍的，正常）。
if [ "$REPEAT" -eq 1 ]; then
  if [ "$FILE_LINES" -ne "${#INST_KEY[@]}" ]; then
    echo "edge_matrix: 记录条数门禁未通过：$RECORDS 有 $FILE_LINES 条，本次选中 ${#INST_KEY[@]} 个场景实例（${#SELECTED[@]} 个场景）—— 整轮失败" >&2
    echo "  （少一条 = 有实例没采成；多一条 = 文件里混进了别的实例的记录。两者都会让\"每实例一条\"失效）" >&2
    FAIL_REASON="记录条数门禁未通过：文件 $FILE_LINES 条 ≠ 选中 ${#INST_KEY[@]} 个场景实例"
    state_fail 1 "$FAIL_REASON" || true
    exit 1
  fi
  echo "edge_matrix: 记录条数门禁通过（$FILE_LINES 条 == 选中 ${#INST_KEY[@]} 个场景实例）"
else
  BAD=""
  for id in "${EXPECT_IDS[@]}"; do
    n=$(grep -cE "\"scenario_id\":\"$id\"" "$RECORDS" || true)
    [ "$n" -eq 1 ] || BAD="$BAD $id(×$n)"
  done
  if [ -n "$BAD" ]; then
    echo "edge_matrix: 记录条数门禁未通过（REPEAT=$REPEAT）：这些**本轮实例**在文件里不是恰好一条：$BAD" >&2
    echo "  （×0 = 没采成；×2+ = 串号/重复写。文件里其它重复号的行是正常的历史遍）" >&2
    FAIL_REASON="记录条数门禁未通过（REPEAT=$REPEAT）：本轮实例不满足"恰好一条"：$BAD"
    state_fail 1 "$FAIL_REASON" || true
    exit 1
  fi
  echo "edge_matrix: 记录条数门禁通过（REPEAT=$REPEAT：本轮 ${#EXPECT_IDS[@]} 个实例各恰好 1 条；文件总行数 $FILE_LINES）"
fi

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
      -candidate "vector=$CANDIDATE_DIR/vector.ini" \
      -candidate "graph=$CANDIDATE_DIR/graph.ini" \
      -candidate "chain=$CANDIDATE_DIR/chain.ini" \
      -factors "$FACTORS_SPEC" -weights "$WEIGHTS_SPEC" \
      > "$RUN_D/.gate1.out" 2> "$RUN_D/.gate1.err"
    G1=$?
    set -e
    tail -20 "$RUN_D/.gate1.out"
    if [ -s "$RUN_D/.gate1.err" ]; then tail -5 "$RUN_D/.gate1.err" >&2; fi
    python3 - "$RUN_D/gate-gate1.json" "$G1" "$RECORDS" "$RECORD_COUNT" "$FACTORS_SPEC" "$WEIGHTS_SPEC" <<'PY'
# `os` 必须显式 import（Task 5 Step 0 实测踩到）：这个块里读 `os.environ['CANDIDATE_DIR']`，
# 而它在加 `candidate_dir` 之前只 import 了 json/sys/time ⇒ 门禁① 的**碎片文件写不出来**，
# `set -e` 下那一轮的 EXIT trap 就把整轮记成失败（而 edgecompare 本身其实是 rc=0）。
import json, os, sys, time
json.dump({
    'dataset': 'all-records', 'records': int(sys.argv[4]), 'records_file': sys.argv[3],
    'exit_code': int(sys.argv[2]), 'factors_spec': sys.argv[5], 'weights_spec': sys.argv[6],
    'candidates': {'legacy': 'm0-baseline.ini（= 采集模型）', 'vector': 'vector.ini',
                   'graph': 'graph.ini', 'chain': 'chain.ini'},
    'candidate_dir': os.environ.get('CANDIDATE_DIR', ''),
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
