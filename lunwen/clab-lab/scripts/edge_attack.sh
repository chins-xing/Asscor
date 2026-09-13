#!/bin/bash
# ============================================================================
# edge_attack.sh —— 场景攻击 harness：客观结果（ground truth）的唯一来源
# ============================================================================
#
# 用法：
#   ./scripts/edge_attack.sh <scenario> <out.json>
#
# 产物（harness 报告，由 `cmd/edgescen -attack-out` 解析）：
#   scenario / compromised / time_to_compromise_s / ttps_achieved / nodes_affected /
#   block_effective / playbook_hash / topology_hash / injections[{check,at}]
#   —— 前 5 项是必填（缺任何一个 `edgescen` 都会拒绝该次采集），后 3 项是溯源。
#
# 做什么：
#   1. 从 Caldera API 取**固定剧本**（默认 Discovery）的定义并算剧本哈希；
#      同时核对"剧本名 ↔ 剧本 ID"仍是那一对（漂移时报错，不静默换剧本）；
#   2. 按场景的**相位表**逐相位推进，记录每个注入检查的观测时刻（injections）；
#      —— 顺序注入场景的两相必须落在**不同秒**（chain 模型的 ts 只有秒精度：
#      `recordChain` 用 time.RFC3339 格式化，秒内差异会被抹平 ⇒ C 候选退化成 V）；
#   3. 对每个注入检查跑一次**真实条件探针**（该防护在这台主机上是否真的缺失）。
#      S 组按 spec §2.3 是"检查失败代理"，探针结果如实记录但不阻断；
#      R 组是"真实缺失对照"，条件**必须**成立，否则整轮失败（不造 ground truth）；
#   4. 触发固定剧本（Caldera operation），轮询到终态或超时；
#   5. 从 operation 的 chain 里派生客观结果（只有 status = 0 才算成功；状态码语义
#      逐条取自 `/opt/caldera/app/objects/secondclass/c_link.py` 的 states 表）；
#   6. 写 harness 报告。
#
# 退出码：0 成功；1 任何一步失败（攻击侧不可用、剧本漂移、相位时刻重叠、
# R 组真实缺失不成立、脚本一个 link 都没发出来……一律不降级）。
#
# 环境变量（全部可选）：
#   EDGEEXP_CONFIG        用来解析"因子→触发检查"的配置模板，默认 configs/edgeexp/m0-baseline.ini
#   EDGEEXP_PLAYBOOK_ID   固定剧本（默认 Discovery 0f4c3c67-845e-49a0-927e-90ed33c044e0）
#   EDGEEXP_PLAYBOOK_NAME 剧本名（默认 Discovery，用于核对 ID 没被换掉）
#   EDGEEXP_ATTACK_TIMEOUT_S  等 operation 结束的上限，默认 1800（冒烟可用 300 缩短）
#   EDGEEXP_PHASE_GAP_S   相位之间的最小间隔（秒），默认 3（必须 ≥ 1，见上）
#   EDGEEXP_TARGET        **被攻节点名**（Task 4C：条件探针在它内部执行，默认空 = 不执行）。
#                         R 组（真实缺失对照）**必须**给出：它的语义就是"目标节点上真的没有这个
#                         防护"，没有节点侧证据的"已核实"不算证据。实现见 scripts/edge_probe.sh。
#   EDGEEXP_SUBSTRATE     实验基质：clab（默认）| lxd（A-1，见 edge_lab.sh）。本脚本自己不直接
#                         发基质命令（节点内动作全部在 edge_probe.sh 里经基质层下发），但它
#                         **必须**校验这个名字：拼错的基质名若被静默降级，探针会在另一种基质上
#                         跑，而 condition_probes 里的 probe_host 看起来仍然正常。
#
#   ---- Task 4D Step 4：L2 标签口径（用户 2026-09-12 裁定）----
#   EDGEEXP_BASIS             `targeted_ttp`（默认，当声明了目标 ability）| `recon_playbook`
#   EDGEEXP_TARGET_ABILITY    目标 TTP 的 **ability_id**（L2：`compromised` 只由它决定）
#   EDGEEXP_TARGET_ABILITY_NAME  目标 ability 的名字（可选，仅用于**核对** ID 没被换掉）
#   EDGEEXP_CONTROL_ABILITY   对照/通道健康度 ability 的 id（可选，只用于归类与报告）
#   EDGEEXP_AGENT_FRESH_S      agent 新鲜度上限（秒，默认 180）：见下方"陈旧 agent"两条判据
# ============================================================================
set -euo pipefail

SCENARIO="${1:-}"
OUT="${2:-}"
if [ -z "$SCENARIO" ] || [ -z "$OUT" ]; then
  echo "用法: edge_attack.sh <scenario> <out.json>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
# 基质层：本脚本不直接调它，但**要在最前面把基质名校验掉**（见上面 EDGEEXP_SUBSTRATE 的说明）。
# shellcheck source=scripts/edge_lab.sh
# shellcheck disable=SC2154  # lab_substrate/lab_target_bin 由下面那行 source 赋值
. "$SCRIPT_DIR/edge_lab.sh"
TOPOLOGY="${EDGEEXP_TOPOLOGY:-$LAB_DIR/asscor.clab.yml}"
CONFIG="${EDGEEXP_CONFIG:-$REPO_ROOT/configs/edgeexp/m0-baseline.ini}"
PLAYBOOK_ID="${EDGEEXP_PLAYBOOK_ID:-0f4c3c67-845e-49a0-927e-90ed33c044e0}"
PLAYBOOK_NAME="${EDGEEXP_PLAYBOOK_NAME:-Discovery}"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://127.0.0.1:8888}"
CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-ADMIN123}"
ATTACK_TIMEOUT_S="${EDGEEXP_ATTACK_TIMEOUT_S:-1800}"
POLL_S="${EDGEEXP_POLL_S:-10}"
PHASE_GAP_S="${EDGEEXP_PHASE_GAP_S:-3}"
EDGESCEN="${EDGEEXP_EDGESCEN:-$REPO_ROOT/build/edgescen}"
TARGET_ABILITY="${EDGEEXP_TARGET_ABILITY:-}"
TARGET_ABILITY_NAME="${EDGEEXP_TARGET_ABILITY_NAME:-}"
CONTROL_ABILITY="${EDGEEXP_CONTROL_ABILITY:-}"
AGENT_FRESH_S="${EDGEEXP_AGENT_FRESH_S:-180}"

for bin in curl python3 sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "edge_attack: 缺少必需命令 $bin" >&2; exit 1; }
done
[ -f "$CONFIG" ] || { echo "edge_attack: 配置不存在: $CONFIG" >&2; exit 1; }
[ -f "$TOPOLOGY" ] || { echo "edge_attack: 拓扑不存在: $TOPOLOGY" >&2; exit 1; }
[ "$PHASE_GAP_S" -ge 1 ] || { echo "edge_attack: EDGEEXP_PHASE_GAP_S 必须 ≥ 1（链上 ts 只有秒精度）" >&2; exit 1; }

# ---------------------------------------------------------------------------
# L2 标签依据：**目标 TTP 与对照分开计**（Task 4D Step 4，用户 2026-09-12 裁定）
# ---------------------------------------------------------------------------
# 旧口径是"**任意** link 成功即 compromised=true"，而对照/侦察 ability 的成功也会被算进去 ——
# 两者在数据上同形：一条"目标被拦住、对照照常成功"的链与一条"目标达成"的链都落在 true 上。
# 现在的口径：
#   · `compromised`       := **目标 TTP** 的 link 里**存在** status == 0；
#   · `block_effective`   := **目标 TTP** 的 link **全部**未成功；
#   · 对照/侦察的 link 只用来回答"通道与执行器健不健康"，另存 `control`，**不参与标签**。
#
# **默认值的选择（要写清，否则会静默改变既有的 clab 矩阵行为）**：`EDGEEXP_TARGET_ABILITY`
# 未声明时 basis 只能是 `recon_playbook`（旧行为：任意 link 成功即 true），并**响亮警告** ——
# 那种记录**不得**进决策层指标（`cmd/edgecompare` 有依据守卫，见 metrics.go）。
# 两种组合都不许含糊：
#   · basis=targeted_ttp  ⇒ **必须**声明目标 ability（没有目标的"目标 TTP"是自相矛盾）；
#   · basis=recon_playbook ⇒ **不得**声明目标 ability（声明了却按侦察口径算 = 口径不一致）。
BASIS="${EDGEEXP_BASIS:-}"
if [ -z "$BASIS" ]; then
  if [ -n "$TARGET_ABILITY" ]; then BASIS="targeted_ttp"; else BASIS="recon_playbook"; fi
fi
LAB_PIDS_HELPER="$LAB_DIR/scripts/edge_lab_pids.sh"
[ -f "$LAB_PIDS_HELPER" ] || { echo "edge_attack: 缺少基质层 PID 助手 $LAB_PIDS_HELPER" >&2; exit 1; }
# ATTACK_HOST 是"agent 应该跑在哪台机器上"（= 被攻节点）。空 ⇒ 判据退化成"任意 host 的活 agent"，
# 那正是"打到别的容器上的 agent"这一形态；故与 EDGEEXP_TARGET 一起声明是本脚本的**正确**用法。
ATTACK_HOST="${EDGEEXP_ATTACK_HOST:-${EDGEEXP_TARGET:-}}"
case "$BASIS" in
  targeted_ttp)
    [ -n "$TARGET_ABILITY" ] || {
      echo "edge_attack: basis=targeted_ttp 但没给 EDGEEXP_TARGET_ABILITY —— 没有目标的『目标 TTP』是自相矛盾的，整轮失败" >&2
      exit 1
    } ;;
  recon_playbook)
    [ -z "$TARGET_ABILITY" ] || {
      echo "edge_attack: basis=recon_playbook 却给了 EDGEEXP_TARGET_ABILITY=$TARGET_ABILITY —— 口径不一致（侦察口径不得被当成目标 TTP），整轮失败" >&2
      exit 1
    }
    echo "edge_attack: 警告：本轮的标签依据是 recon_playbook（未声明 EDGEEXP_TARGET_ABILITY）——" >&2
    echo "  compromised 将是『任意 link 成功』的旧口径，**不得**进决策层指标（见 spec §2.1 的 L2）。" >&2 ;;
  *)
    echo "edge_attack: EDGEEXP_BASIS 只认 targeted_ttp | recon_playbook，收到 '$BASIS'" >&2
    exit 1 ;;
esac
export BASIS TARGET_ABILITY TARGET_ABILITY_NAME CONTROL_ABILITY AGENT_FRESH_S
export ATTACK_HOST LAB_PIDS_HELPER

# ---------------------------------------------------------------------------
# 场景相位表
# ---------------------------------------------------------------------------
# 每个元素是"同一时刻注入"的因子组，组的先后即注入顺序（与 `cmd/edgescen` 的
# `scenarioSpec.Inject` 一一对应）。**这份表是 harness 侧的重复声明，必须与采集器对齐**：
# 下面用 `edgescen -list` 做交叉核对（场景名存在 + 阶段数一致 + 因子覆盖面一致），
# 漂移一律报错而不是静默跑一个不一样的场景。
PHASES=""       # 相位之间用 | 分隔，相位内因子用 , 分隔
REAL_MISSING="" # R 组的真实缺失项（ids|siem|2fa）
case "$SCENARIO" in
  S0-baseline)                  PHASES="" ;;
  S1-selinux)                   PHASES="EF-SELINUX" ;;
  S1-apparmor)                  PHASES="EF-APPARMOR" ;;
  S1-syn-cookie)                PHASES="EF-SYNCOOKIE" ;;
  S1-no-siem)                   PHASES="EF-NO-SIEM" ;;
  S1-no-ids)                    PHASES="EF-NO-IDS" ;;
  S1-2fa)                       PHASES="EF-002FA" ;;
  S2-selinux-apparmor)          PHASES="EF-SELINUX,EF-APPARMOR" ;;
  S2-selinux-no-ids)            PHASES="EF-SELINUX,EF-NO-IDS" ;;
  S2-no-siem-no-ids)            PHASES="EF-NO-SIEM|EF-NO-IDS" ;;
  S2-syn-cookie-no-siem)        PHASES="EF-SYNCOOKIE,EF-NO-SIEM" ;;
  S2-apparmor-no-ids)           PHASES="EF-APPARMOR,EF-NO-IDS" ;;
  S2-selinux-no-siem)           PHASES="EF-SELINUX|EF-NO-SIEM" ;;
  S2-2fa-selinux)               PHASES="EF-002FA,EF-SELINUX" ;;
  S2-syn-cookie-no-ids)         PHASES="EF-SYNCOOKIE|EF-NO-IDS" ;;
  S3-selinux-apparmor-2fa)      PHASES="EF-SELINUX,EF-APPARMOR|EF-002FA" ;;
  S3-selinux-no-siem-no-ids)    PHASES="EF-SELINUX|EF-NO-SIEM,EF-NO-IDS" ;;
  S3-syn-cookie-no-siem-no-ids) PHASES="EF-SYNCOOKIE|EF-NO-SIEM|EF-NO-IDS" ;;
  S3-3fa-selinux-apparmor)      PHASES="EF-3FA|EF-SELINUX,EF-APPARMOR" ;;
  S4-all)                       PHASES="EF-002FA,EF-SYNCOOKIE,EF-SELINUX,EF-APPARMOR,EF-NO-SIEM,EF-NO-IDS" ;;
  S5-cascade-3fa)               PHASES="EF-3FA|EF-002FA" ;;
  S5-2fa-only)                  PHASES="EF-002FA" ;;
  R-no-ids)                     REAL_MISSING="ids" ;;
  R-no-siem)                    REAL_MISSING="siem" ;;
  R-no-2fa)                     REAL_MISSING="2fa" ;;
  *) echo "edge_attack: 未知场景 $SCENARIO（场景表见 cmd/edgescen/scenario.go）" >&2; exit 1 ;;
esac
# R 组**不注入**：真实缺失是"一整个会话的状态"，没有"注入时刻"这种东西可报 ——
# injections 留空，记录的 checks[].ts 于是取采集时刻（那是如实取值：检查是在采集那一刻
# 被观测到失败的）。REAL_FACTOR 只用于条件核实与场景表交叉核对。
REAL_FACTOR=""
if [ -n "$REAL_MISSING" ]; then
  case "$SCENARIO" in
    R-no-ids)  REAL_FACTOR="EF-NO-IDS" ;;
    R-no-siem) REAL_FACTOR="EF-NO-SIEM" ;;
    R-no-2fa)  REAL_FACTOR="EF-002FA" ;;
  esac
fi

phase_count() { [ -z "$1" ] && echo 0 || echo "$1" | tr '|' '\n' | wc -l; }
EXPECTED_PHASES=$(phase_count "$PHASES")

# 级联目标的两级来源（Fix round 3 的第 4 项：不再维护第二份真源）：
#   · **权威**：`edgescen -list` 输出的 `级联目标=<CascadeTo>`（本轮起该字段 additive 输出）；
#   · **兜底**：本脚本的 LOCAL_CASCADE_TARGET 表 —— 只在 `-list` 没有该字段时使用（旧二进制），
#     且会**响亮警告**（否则"两份真源"会以静默的方式重新长出来）。
# 只在一边加了级联场景时：权威来源立即生效（不必改本脚本）；若本脚本的表与权威值**冲突**，
# 直接报错 —— 那是"两份真源意见不一致"，不能猜。
LOCAL_CASCADE_TARGET=""
case "$SCENARIO" in
  S3-3fa-selinux-apparmor|S5-cascade-3fa) LOCAL_CASCADE_TARGET="EF-002FA" ;;
esac
LISTED_CASCADE_TARGET=""
CASCADE_TARGET=""
EXPECTED_CHAIN_FACTORS=""

# 配置的 `[edge_factors.custom]` 里是否**还有**一条 EF-3FA（出厂模板刻意保留的那条重复项）。
#
# 为什么这条判断决定了"期望上链因子集"怎么写（Fix round 2 / 关键项的根因）：
#   · 硬编码那条 EF-3FA 是 `CascadeOnly=true` —— 它自己**不**上链，只把 EF-002FA 压到 0.82；
#   · 而 `[edge_factors.custom]` 里的 `EF-3FA = 0.82` **不是** CascadeOnly（`ConfigToEdgeFactors`
#     对 custom 条目原样产出），所以它会作为**普通因子**自己上链。
# 采集器那边的 `scenarioSpec.expectedChainFactors()` 是给"链 ⊇ 期望集"这条**最小值**规则用的，
# 把 EF-3FA 替换成 EF-002FA 在那边是安全的；但采集脚本用的是**相等**判据，照抄那条替换就会把
# "合法的 EF-3FA 条目"判成多余项 ⇒ 在**任何**宿主上都会拒掉 S3-3fa-selinux-apparmor 与
# S5-cascade-3fa（Fix round 1 的实测遗漏：离线验证只覆盖了期望集为空的 S0）。
# 故级联场景的期望集 = 级联源（仅当配置里确实声明了自定义 EF-3FA）+ 级联目标。
# 若将来把那条自定义项去掉，这里会**自动**退回"只有级联目标"，不会反过来误拒。
HAS_CUSTOM_EF3FA=0
if awk '
  { line = tolower($0) }
  /^\[/ { sec = line; next }
  sec == "[edge_factors.custom]" && line ~ /^[[:space:]]*ef-3fa[[:space:]]*=/ { found = 1 }
  END { exit !found }
' "$CONFIG"; then
  HAS_CUSTOM_EF3FA=1
fi

# 把"声明的一个因子"展开成"期望在链上看到的因子"（可能 0/1/2 个）。
emit_expected_factor() {
  case "$1" in
    ""|"(无)") return 0 ;;
    EF-3FA)
      if [ "$HAS_CUSTOM_EF3FA" -eq 1 ]; then echo "EF-3FA"; fi
      if [ -n "$CASCADE_TARGET" ]; then echo "$CASCADE_TARGET"; fi
      ;;
    *) echo "$1" ;;
  esac
}

# 级联目标的来源裁决（**必须在展开之前调用**）：权威值优先；`-list` 没给该字段时退回本脚本的
# 兜底表并响亮警告；两者都给出但**不一致**时直接报错 —— 那是"两份真源意见冲突"，
# 猜哪一份都可能把一条合法的链判死。
resolve_cascade_target() {
  if [ -n "$LISTED_CASCADE_TARGET" ]; then
    if [ -n "$LOCAL_CASCADE_TARGET" ] && [ "$LOCAL_CASCADE_TARGET" != "$LISTED_CASCADE_TARGET" ]; then
      echo "edge_attack: 级联目标冲突：采集器声明 $SCENARIO → $LISTED_CASCADE_TARGET，而本脚本的兜底表写着 $LOCAL_CASCADE_TARGET ——" >&2
      echo "  两份真源不一致，不能猜（请同步本脚本的兜底表；该表在 -list 提供 级联目标= 之后本就不该再被使用）。" >&2
      exit 1
    fi
    CASCADE_TARGET="$LISTED_CASCADE_TARGET"
    return 0
  fi
  CASCADE_TARGET="$LOCAL_CASCADE_TARGET"
  if [ -n "$LOCAL_CASCADE_TARGET" ]; then
    echo "edge_attack: 警告：edgescen -list 未提供 级联目标= 字段（旧二进制？）—— 退回本脚本的兜底表（$SCENARIO → $LOCAL_CASCADE_TARGET）；请重新构建 build/edgescen" >&2
  fi
}

# --- 与采集器的场景表交叉核对 ------------------------------------------------
if [ -x "$EDGESCEN" ]; then
  LIST="$("$EDGESCEN" -list)"
  echo "$LIST" | grep -qE "^  $SCENARIO\b" || {
    echo "edge_attack: 场景 $SCENARIO 不在 edgescen 的场景表里 —— harness 与采集器已经漂移" >&2
    exit 1
  }
  LINE="$(echo "$LIST" | grep -E "^  $SCENARIO\b")"
  if echo "$LINE" | grep -q "阶段="; then
    WANT="$(echo "$LINE" | sed -n 's/.*阶段=\([0-9]*\).*/\1/p')"
    [ "$WANT" = "$EXPECTED_PHASES" ] || {
      echo "edge_attack: 场景 $SCENARIO 的相位表是 $EXPECTED_PHASES 相，而 edgescen 声明 $WANT 相 —— 两处表已经漂移（不是可以放过的不一致：顺序注入的时间结构取决于相位划分）" >&2
      exit 1
    }
  elif [ "$EXPECTED_PHASES" -gt 1 ]; then
    echo "edge_attack: 场景 $SCENARIO 在本脚本里是多相位，而 edgescen 的场景表里不是（无 阶段= 标记）—— 已漂移" >&2
    exit 1
  fi
  # 采集器声明的因子必须都出现在 harness 的声明面里（相位表 ∪ R 组的真实缺失因子）；
  # 相位表允许有额外的因子（级联目标 EF-002FA 就不在 edgescen 的 Factors 里，见 S5）。
  ALL_DECLARED="$(printf '%s\n%s\n' "$(echo "$PHASES" | tr '|,' '\n\n')" "$REAL_FACTOR")"
  for f in $(echo "$LINE" | sed -n 's/.*因子=\([^ ]*\).*/\1/p' | tr ',' ' '); do
    case "$f" in "(无)") continue ;; esac
    echo "$ALL_DECLARED" | grep -qx "$f" || {
      echo "edge_attack: edgescen 为 $SCENARIO 声明了因子 $f，而本脚本的声明面里没有它 —— 已漂移" >&2
      exit 1
    }
  done
  # 级联目标：**消费**采集器输出的 `级联目标=`（Fix round 3 的第 4 项），不再自己当第二份真源。
  # 必须在展开 EXPECTED_CHAIN_FACTORS **之前**裁决（展开要用到 CASCADE_TARGET）。
  LISTED_CASCADE_TARGET="$(echo "$LINE" | sed -n 's/.*级联目标=\([^ ]*\).*/\1/p')"
  resolve_cascade_target
  # EXPECTED_CHAIN_FACTORS = 采集器声明的因子，逐个经 emit_expected_factor 展开
  # （`因子=` 是采集器自己的声明面，比在 harness 里重抄一份更不容易漂移）。
  EXPECTED_CHAIN_FACTORS="$(echo "$LINE" | sed -n 's/.*因子=\([^ ]*\).*/\1/p' | tr ',' '\n' \
    | while read -r f; do emit_expected_factor "$f"; done | sort -u | paste -sd, -)"
  EXPECTED_CHAIN_FACTORS_SET=1
  EXPECTED_CHAIN_FACTORS_SOURCE="采集器 edgescen -list 的声明面 + 级联展开（EF-3FA：配置有自定义条目则为普通因子，另外展开 级联目标=）"
else
  echo "edge_attack: 警告：$EDGESCEN 不存在，跳过与采集器场景表的交叉核对" >&2
  resolve_cascade_target
fi

# `edgescen` 不可用时的退化路径：用本脚本的相位表推导"期望上链的因子集"（同一套展开规则）。
# **必须留有这一手**，否则采集脚本的相等断言会在"工具没编译"时把每条记录都判死，
# 而真正的原因（少了一个二进制）反而看不出来。代价如实写在 warning 里：此时相等断言的来源
# 从"采集器的声明面"变成"harness 自己的相位表"，两处漂移时不再有交叉核对。
if [ "${EXPECTED_CHAIN_FACTORS_SET:-0}" -eq 0 ]; then
  echo "edge_attack: 警告：expected_chain_factors 退化用本脚本的相位表推导（无采集器声明面交叉核对）" >&2
  DERIVED="$(echo "$PHASES" | tr '|,' '\n\n' | while read -r f; do emit_expected_factor "$f"; done \
    | sort -u | paste -sd, -)"
  if [ -n "$REAL_FACTOR" ]; then
    EXPECTED_CHAIN_FACTORS="$(printf '%s,%s\n' "$DERIVED" "$REAL_FACTOR" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)"
  else
    EXPECTED_CHAIN_FACTORS="$DERIVED"
  fi
  EXPECTED_CHAIN_FACTORS_SOURCE="退化路径：本脚本相位表推导（edgescen 不可用）"
fi
echo "edge_attack: 期望上链因子集 = [${EXPECTED_CHAIN_FACTORS:-（空集）}]（采集脚本用它做相等断言；配置里自定义 EF-3FA：$HAS_CUSTOM_EF3FA）"

# 只推导、不碰 Caldera/拓扑的入口（离线验证与操作者自查用）：
#   EDGEEXP_PRINT_EXPECTED=1 bash edge_attack.sh <scenario> /tmp/whatever.json
# 修 Fix round 2 的级联期望集问题时，正是靠这条在**没有 lab** 的情况下拿到真实推导结果
# （旧做法是手工造一个期望集喂给采集脚本，那恰好掩盖了 S5 的错误）。
if [ "${EDGEEXP_PRINT_EXPECTED:-0}" = "1" ]; then
  echo "expected_chain_factors: ${EXPECTED_CHAIN_FACTORS}"
  echo "expected_chain_factors_source: ${EXPECTED_CHAIN_FACTORS_SOURCE}"
  echo "has_custom_ef3fa: ${HAS_CUSTOM_EF3FA}"
  echo "cascade_target: ${CASCADE_TARGET:-（无）}"
  exit 0
fi

# --- 因子 -> 触发检查：从配置里解析，绝不在这里抄一份表 ----------------------
# [edge_factors.model] 的 trigger.<ID> 是两份实验模板里显式写出的完整映射
# （与解析层 config.ResolveEdgeFactorTriggerMap 同源同值），故 harness 直接读配置。
declare -A TRIGGER=()
while IFS='=' read -r k v; do
  key="$(echo "$k" | sed -E 's/^[[:space:]]*trigger\.//I' | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
  val="$(echo "$v" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
  if [ -n "$key" ] && [ -n "$val" ]; then TRIGGER["$key"]="$val"; fi
done < <(grep -iE '^[[:space:]]*trigger\.[A-Za-z0-9_-]+[[:space:]]*=' "$CONFIG")
[ "${#TRIGGER[@]}" -gt 0 ] || { echo "edge_attack: 配置 $CONFIG 里没有 trigger.<ID> 映射 —— 无法解析注入检查" >&2; exit 1; }

# --- 真实条件探针（**在节点上**执行，Task 4C Step 3） -------------------------
# 探针实现搬到了 `edge_probe.sh`：它用 `docker exec -i` 把判据送进**目标节点**执行，而不是在
# 跑脚本的这台机器上跑。原因是勘测实测的洞：脚本在 WSL 宿主上跑、被攻节点是 host1 容器，
# 而旧实现的 `cat /proc/sys/...` / `ps -eo comm` / `getenforce` 全部查的是本机 ——
# 于是 R 组"我们真的把 IDS 去掉了"这句话探的是**另一台机器**；而 `attack-R-no-ids.json` 里
# `condition_probes` 还是空数组（探针循环包在 `if [ -n "$PHASES" ]` 内，R 组的 PHASES 恒为空）
# ⇒ "真实缺失已核实"在数据里没有任何节点侧证据。
#
# 三类退出码（`probe_condition_holds`）：
#   0 = 条件成立（该防护在这台**节点**上确实缺失）  1 = 条件不成立  2 = 探针没跑成
# 2 与 1 必须分开：把"探针根本没执行"读成"条件不成立"会制造一条无效的否定证据。
# shellcheck source=/dev/null
. "$SCRIPT_DIR/edge_probe.sh" "${EDGEEXP_TARGET:-}"
PROBE_HOST=""
if [ -n "${EDGEEXP_TARGET:-}" ]; then
  probe_host_ready || exit 1
  PROBE_HOST="$(probe_host)" || {
    echo "edge_attack: 取不到节点 $EDGEEXP_TARGET 的 hostname —— 探针无从自证它在哪台机器上跑" >&2
    exit 1
  }
  echo "edge_attack: 条件探针将在节点 $EDGEEXP_TARGET（hostname=$PROBE_HOST）内执行"
else
  echo "edge_attack: 警告：未声明目标节点（EDGEEXP_TARGET）—— 条件探针**不执行**，condition_probes 为空。" >&2
  echo "  S 组是 spec §2.3 的『检查失败代理』，探针结果只记录不阻断，故这里不硬失败；" >&2
  echo "  但 R 组（真实缺失对照）必须声明目标节点：没有节点侧证据的『真实缺失已核实』不算证据。" >&2
  if [ -n "$REAL_MISSING" ]; then
    echo "edge_attack: R 组 $SCENARIO 的语义是『在目标节点上真的没有这个防护』，而目标节点未声明 ——" >&2
    echo "  旧实现此时探的是跑脚本的这台机器（勘测实测），那正是本任务要堵的洞。整轮失败。" >&2
    exit 1
  fi
fi

# probe_entry 取一次探针结论并落成 condition_probes 的一个条目。
#
# `if ...; then rc=0; else rc=$?; fi` 是本脚本取探针退出码的**必须**写法：
# `probe_condition_holds "$f"; rc=$?` 在 `set -e` 下会因 rc=1 直接把整个脚本带走
# （实测过：探针循环静默停在那一行，调用方只看到一次没有诊断的"运行失败"）。
probe_entry() {
  local factor="$1" check="$2" phase="${3:-null}" real_missing="${4:-false}" rc holds
  if probe_condition_holds "$factor"; then
    rc=0
  else
    rc=$?
  fi
  case "$rc" in
    0) holds="true" ;;
    1) holds="false" ;;
    *)
      echo "edge_attack: 探针 $factor 在节点 ${EDGEEXP_TARGET:-（未声明）} 内**没有跑成**（rc=$rc）—— 不得据此写任何结论" >&2
      exit 1 ;;
  esac
  # `phase` 默认 `null`（JSON 的 null，不是 0）：R 组**没有相位**，写 0 会被读成"第 1 相位"
  # （Fix round 1 / M-7）。R 组的条目另带 `real_missing: true` 与阶段语义区分开。
  python3 -c 'import json,sys;a=json.loads(sys.argv[1]);a.append(json.loads(sys.argv[2]));print(json.dumps(a))' \
    "$PROBES_JSON" "{\"factor\":\"$factor\",\"check\":\"$check\",\"condition_holds\":$holds,\"phase\":$phase,\"real_missing\":$real_missing,\"probe_target\":\"${EDGEEXP_TARGET:-}\",\"probe_host\":\"$PROBE_HOST\"}"
}

# probe_skipped_entry 是"探针没执行时不留空条目"的守卫：S 组未声明目标节点时**如实**记下未执行
# （而不是写一个 `condition_holds: false` 的假结论），R 组则根本走不到这里（上面已失败）。
#
# 名字里的 `skipped` 是关键字：条目里那三个字段（`condition_holds: null` / `phase: null` /
# `skipped`）合起来表达"这条不是证据"。函数名在 Fix round 1 / M-8 之前写作
# `probe_entry_on_node`，与实参语义不符（它恰恰是"**没**在节点上跑"的那条路径）。
probe_skipped_entry() {
  local factor="$1" check="$2" phase="${3:-null}"
  python3 -c 'import json,sys;a=json.loads(sys.argv[1]);a.append(json.loads(sys.argv[2]));print(json.dumps(a))' \
    "$PROBES_JSON" "{\"factor\":\"$factor\",\"check\":\"$check\",\"condition_holds\":null,\"phase\":$phase,\"real_missing\":false,\"probe_target\":\"\",\"probe_host\":\"\",\"skipped\":\"未声明 EDGEEXP_TARGET：探针不执行（S 组不阻断，但这条**不是**证据）\"}"
}

# --- 相位推进 ---------------------------------------------------------------
PHASES_JSON="[]"
PROBES_JSON="[]"
REAL_MISSING_AT=""
declare -A CHECK_AT=()   # 检查 -> 首次（也是唯一）注入时刻
if [ -n "$REAL_MISSING" ]; then
  REAL_MISSING_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

idx=0
if [ -n "$PHASES" ]; then
  IFS='|' read -ra PHASE_ARR <<< "$PHASES"
  for phase in "${PHASE_ARR[@]}"; do
    idx=$((idx + 1))
    at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    phase_factors="[]"; phase_checks="[]"
    IFS=',' read -ra FACTORS <<< "$phase"
    for f in "${FACTORS[@]}"; do
      check="${TRIGGER[$f]:-}"
      [ -n "$check" ] || { echo "edge_attack: 因子 $f 在 $CONFIG 里没有解析出触发检查" >&2; exit 1; }
      if [ -n "${CHECK_AT[$check]:-}" ]; then
        echo "edge_attack: 检查 $check 被两个相位注入（已排在 ${CHECK_AT[$check]}，现在又想排 $at）—— 一个检查只能有一个注入时刻，否则 injections 唯一性不成立" >&2
        exit 1
      fi
      CHECK_AT["$check"]="$at"
      if [ -n "${EDGEEXP_TARGET:-}" ]; then
        PROBES_JSON="$(probe_entry "$f" "$check" "$idx")"
      else
        PROBES_JSON="$(probe_skipped_entry "$f" "$check" "$idx")"
      fi
      phase_factors="$(python3 -c 'import json,sys;a=json.loads(sys.argv[1]);a.append(sys.argv[2]);print(json.dumps(a))' "$phase_factors" "$f")"
      phase_checks="$(python3 -c 'import json,sys;a=json.loads(sys.argv[1]);a.append(sys.argv[2]);print(json.dumps(a))' "$phase_checks" "$check")"
    done
    PHASES_JSON="$(python3 -c 'import json,sys;a=json.loads(sys.argv[1]);a.append(json.loads(sys.argv[2]));print(json.dumps(a))' \
      "$PHASES_JSON" "{\"index\":$idx,\"at\":\"$at\",\"factors\":$phase_factors,\"checks\":$phase_checks}")"
    echo "edge_attack: 相位 $idx/$EXPECTED_PHASES 已推进（$phase → $at）"
    if [ "$idx" -lt "${#PHASE_ARR[@]}" ]; then sleep "$PHASE_GAP_S"; fi
  done
fi

# 顺序注入场景的两个相位必须落在**不同秒**：链上 ts 由 recordChain 用 time.RFC3339
# 格式化（秒精度），秒内差异会被抹平 ⇒ 该记录的 C 候选退化成 V，而记录看起来完全正常。
if [ -n "$PHASES" ] && [ "${#PHASE_ARR[@]}" -gt 1 ]; then
  DISTINCT="$(echo "$PHASES_JSON" | python3 -c 'import json,sys;print(len({p["at"] for p in json.load(sys.stdin)}))')"
  [ "$DISTINCT" = "${#PHASE_ARR[@]}" ] || {
    echo "edge_attack: 顺序注入场景的 $EXPECTED_PHASES 个相位只落在 $DISTINCT 个不同的秒上 —— 链上 ts 只有秒精度，这条数据没有时间结构（调大 EDGEEXP_PHASE_GAP_S 重跑）" >&2
    exit 1
  }
fi

# R 组的真实缺失必须**真的成立**（对照的意义就在这里）—— 而且必须是在**目标节点上**成立。
#
# Task 4C 之前这里写的是 `if ! condition_holds "$probe_factor"`，而那段探针循环包在
# `if [ -n "$PHASES" ]` 内、R 组的 PHASES 恒为空 ⇒ 本闸门**从未执行**，`condition_probes`
# 也是空数组。现在探针无条件在节点内跑一次（无论 PHASES 是否为空），结论落进
# `condition_probes`，闸门据此判定。
if [ -n "$REAL_MISSING" ]; then
  probe_factor="$REAL_FACTOR"
  REAL_MISSING_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # 只探这一次（探针在节点里真的执行一次 docker exec）：结论既落进 condition_probes，
  # 也直接决定本闸门。`probe_entry` 在 rc=2（探针没跑成）时自己**响亮退出** ——
  # 那种情况绝不能被当成"条件不成立"，更不能被当成"空缺即通过"。
  PROBES_JSON="$(probe_entry "$probe_factor" "${TRIGGER[$probe_factor]:-}" "null" "true")"
  # 判据用"JSON 里最后一次探针的 condition_holds 是不是真布尔 true"，而不是拿 shell 里的
  # 字符串跟 python 打印的 `True` 比 —— 后者大小写不同 ⇒ 闸门会把 rc=0（条件成立）
  # **误判成不成立**（本任务实测踩到过：探针明明通过，闸门却报"防护仍然在位"）。
  if ! python3 -c 'import json,sys;r=json.loads(sys.argv[1]);sys.exit(0 if r and r[-1].get("condition_holds") is True else 1)' "$PROBES_JSON"; then
    echo "edge_attack: R 组的真实缺失**不成立**：$REAL_MISSING 的防护在节点 ${EDGEEXP_TARGET} 上仍然在位" >&2
    echo "  （探针对应 $probe_factor 的触发检查条件）—— 真实缺失对照不可得，整轮失败；" >&2
    echo "  不得用注入失败顶上（那就是伪造 ground truth 的对照面）。" >&2
    exit 1
  fi
  # 空数组必须变成"有证据"或明确报错 —— 这条守卫就是那句话的实现（旧实现在这里留了空数组）。
  COUNT="$(python3 -c 'import json,sys;print(len(json.loads(sys.argv[1])))' "$PROBES_JSON")"
  [ "$COUNT" -ge 1 ] || {
    echo "edge_attack: R 组声称『真实缺失已核实』，而 condition_probes 是空数组 —— 不允许存在这种记录" >&2
    exit 1
  }
  echo "edge_attack: 真实缺失已在节点 ${EDGEEXP_TARGET}（hostname=$PROBE_HOST）核实（$REAL_MISSING → $probe_factor，$REAL_MISSING_AT，$COUNT 条探针证据）"
fi

# --- 触发固定剧本并派生客观结果 ---------------------------------------------
TOPO_HASH="sha256:$(sha256sum "$TOPOLOGY" | awk '{print $1}')"
export SCENARIO OUT TOPOLOGY TOPO_HASH CONFIG CALDERA_URL CALDERA_KEY
export PLAYBOOK_ID PLAYBOOK_NAME ATTACK_TIMEOUT_S POLL_S PHASES_JSON PROBES_JSON
export REAL_MISSING REAL_MISSING_AT PHASE_GAP_S EXPECTED_PHASES EXPECTED_CHAIN_FACTORS
export EXPECTED_CHAIN_FACTORS_SET EXPECTED_CHAIN_FACTORS_SOURCE
python3 - <<'PY'
import datetime, hashlib, json, os, subprocess, sys, time, urllib.request, urllib.error

API = os.environ['CALDERA_URL'].rstrip('/') + '/api/v2'
KEY = os.environ['CALDERA_KEY']
SCENARIO = os.environ['SCENARIO']
OUT = os.environ['OUT']
PLAYBOOK_ID = os.environ['PLAYBOOK_ID']
PLAYBOOK_NAME = os.environ['PLAYBOOK_NAME']
TIMEOUT = int(os.environ['ATTACK_TIMEOUT_S'])
POLL = int(os.environ['POLL_S'])


def api(path, method='GET', body=None, timeout=15):
    req = urllib.request.Request(API + path, method=method, headers={'KEY': KEY, 'Content-Type': 'application/json'})
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or '{}')


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def parse_ts(ts):
    """RFC3339（含结尾 'Z' 与可选小数秒）→ epoch 秒；解析不了返回 None。

    这里**必须**用 fromisoformat 而不是 strptime('%Y-%m-%dT%H:%M:%SZ')：Python 的
    strptime 里 %Z 只认时区**名**（UTC/GMT），结尾那个字面 'Z' 会让它抛 ValueError。
    实测教训：用 strptime 版本时所有时间戳都解析失败 ⇒ `_seen_epoch` 一律返回 None
    ⇒ "没有活跃 agent"，而 Caldera 里 agent 明明在跳（trusted=True、last_seen 就在几秒前）。
    """
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


def fail(msg):
    print('edge_attack: ' + msg, file=sys.stderr)
    sys.exit(1)


def link_ability_id(l):
    """这条 link 属于哪条 ability（`ability.ability_id`，缺失 ⇒ 空串）。"""
    return ((l.get('ability') or {}).get('ability_id') or '').strip()


def link_ability_name(l):
    return ((l.get('ability') or {}).get('name') or '').strip()


def link_time(l):
    """这条 link 的"发生时刻"（按 collect → finish → decide 的优先级取第一个有值的）。"""
    for k in ('collect', 'finish', 'decide'):
        if l.get(k):
            return l[k]
    return None


# --- 固定剧本：定义 + 哈希 + 名字核对 ----------------------------------------
try:
    advs = api('/adversaries')
except Exception as exc:
    fail(f'Caldera API 不可达（{API}/adversaries）: {exc} —— 攻击侧不可用，整轮失败')
match = [a for a in advs if a.get('adversary_id') == PLAYBOOK_ID]
if not match:
    fail(f'固定剧本 {PLAYBOOK_ID} 不在 Caldera 的 adversary 列表里（{len(advs)} 个）—— 剧本被换掉或插件未加载')
playbook = match[0]
if playbook.get('name') != PLAYBOOK_NAME:
    fail(f'剧本 ID {PLAYBOOK_ID} 现在的名字是 {playbook.get("name")!r}，与固定的 {PLAYBOOK_NAME!r} 不符 —— 剧本漂移，拒绝在这种状态下采集')
ordering = list(playbook.get('atomic_ordering') or [])
canonical = '|'.join([PLAYBOOK_ID, PLAYBOOK_NAME] + ordering)
playbook_hash = 'sha256:' + hashlib.sha256(canonical.encode()).hexdigest()

# --- 触发 ---------------------------------------------------------------------
# 参数：目标 TTP / 对照 / 依据 / agent 新鲜度 —— 由 shell 侧经环境变量传进来（都已校验过）。
BASIS = os.environ['BASIS']
TARGET_ABILITY = (os.environ.get('TARGET_ABILITY') or '').strip()
TARGET_ABILITY_NAME = (os.environ.get('TARGET_ABILITY_NAME') or '').strip()
CONTROL_ABILITY = (os.environ.get('CONTROL_ABILITY') or '').strip()
AGENT_FRESH_S = int(os.environ.get('AGENT_FRESH_S') or 180)
ATTACK_HOST = (os.environ.get('ATTACK_HOST') or '').strip()

agents = api('/agents')


# **陈旧 agent 的判据（已知坑 2，Step 4 把它变成硬闸门）**
#
# Caldera 会保留已死 agent 的条目（`trusted=true`、`last_seen` 停在容器消失那一刻）。
# 只按"trusted"或"180 s 内有心跳"挑人都不够 —— 实测：`asc-tgt-1` 有过 8 条条目、只有 1 条
# 与容器内**当前活着的 pid** 一致。打到死 agent 上会得到 `status=-3`（EXECUTE），
# 而 `-3` **看起来像"被拦住"** —— 那正是本步要堵的形态。
#
# 三层判据（缺一层就有一种"看起来正常"的错法）：
#   ① `host` == 攻击目标（不然可能打到别的容器上的 agent）；
#   ② agent 的 `pid` **出现在目标内当前进程表里**（活着的才是活的）；
#   ③ `last_seen` 在 `AGENT_FRESH_S` 之内（pid 命中但心跳停了 ⇒ agent 卡死）。
def live_sandcat_pids():
    """目标内当前活着的 sandcat PID 集合（取不到 ⇒ 空集，调用方会据此响亮失败）。"""
    try:
        out = subprocess.run(['bash', os.environ['LAB_PIDS_HELPER'], ATTACK_HOST, 'sandcat'],
                             capture_output=True, text=True, timeout=30)
    except Exception:
        return set()
    return {int(x) for x in out.stdout.split() if x.strip().isdigit()}


def agent_alive(a, live_pids):
    if ATTACK_HOST and a.get('host') != ATTACK_HOST:
        return False
    pid = a.get('pid')
    if pid is None or int(pid) not in live_pids:
        return False
    seen = parse_ts(a.get('last_seen')) or 0
    return seen >= time.time() - AGENT_FRESH_S


def fail_if_no_live_agent(agents, stage):
    """攻击侧可用性的**唯一判据**：目标上有一只 `(host, 活 pid)` 且心跳新鲜的 agent。"""
    live_pids = live_sandcat_pids()
    alive = [a for a in agents if agent_alive(a, live_pids)]
    if not alive:
        fail(f'{stage}：目标 {ATTACK_HOST or "(未声明 EDGEEXP_TARGET)"} 上没有活着的 agent —— '
             f'判据是 `(host, 容器内活 pid)` 且 last_seen ≤ {AGENT_FRESH_S}s；'
             f'Caldera 共 {len(agents)} 条条目、容器内活 sandcat pid={sorted(live_pids)}。'
             f'攻击侧不可用（先跑 edge_reset.sh；注意"edget trusted=true 的陈旧条目"不算）')
    return alive


if not agents:
    fail(f'Caldera 里一条 agent 都没有（{API}/agents）—— 攻击侧不可用（先跑 edge_reset.sh）')
_alive = fail_if_no_live_agent(agents, '触发前')

attack_started_at = now()
start_epoch = time.time()
body = {
    'name': f'edgeexp-{SCENARIO}-{int(start_epoch)}',
    'adversary': {'adversary_id': PLAYBOOK_ID},
    'group': '',                  # 空 = 全体 agent；活 agent 的判据在下方用 (host, pid) 检查
    'state': 'running',
    'auto_close': True,
    'planner': {'planner_id': 'atomic'},
    'jitter': '0/0',
    'obfuscators': [],
    'source': {'id': 'edgeexp', 'name': 'edge factor coupling sweep', 'facts': []},
}
try:
    created = api('/operations', method='POST', body=body)
except urllib.error.HTTPError as exc:
    fail(f'创建 operation 被拒（{exc.code}）: {exc.read().decode()[:300]}')
except Exception as exc:
    fail(f'创建 operation 失败: {exc}')
op_id = created.get('id') if isinstance(created, dict) else None
if not op_id:
    fail(f'创建 operation 没拿到 id，响应: {json.dumps(created)[:300]}')

op = created
# 终态：finished / cleanup / stopped / paused。`cleanup` 也算终态是刻意的 ——
# Caldera v5 在 auto_close 下会先进 cleanup 再收尾，而那时全部 ability 已经决定完了。
terminal = {'finished', 'cleanup', 'stopped', 'paused'}
deadline = start_epoch + TIMEOUT
while True:
    state = (op or {}).get('state')
    if state in terminal:
        break
    if time.time() >= deadline:
        break
    time.sleep(POLL)
    try:
        op = api(f'/operations/{op_id}')
    except Exception as exc:
        fail(f'轮询 operation {op_id} 失败: {exc}')
attack_finished_at = now()
state = (op or {}).get('state')
window_timeout = state not in terminal
chain = (op or {}).get('chain') or []

# --- 派生客观结果（状态码语义取自 c_link.py 的 states 表）--------------------
STATES = {'-5': 'high_viz', '-4': 'untrusted', '-3': 'execute', '-2': 'discard',
          '-1': 'pause', '0': 'success', '1': 'error', '124': 'timeout'}
counts = {}
for l in chain:
    counts[STATES.get(str(l.get('status')), 'unknown')] = counts.get(STATES.get(str(l.get('status')), 'unknown'), 0) + 1

if not chain:
    fail(f'operation {op_id} 一个 link 都没发出（state={state}）—— 攻击侧没跑起来；这不能让 block_effective 静默变成 true')

# 攻击结束时再确认一次"agent 还活着"（判据同触发前，见 live_sandcat_pids 的说明）。
agents_at_end = api('/agents')
live_pids_at_end = live_sandcat_pids()
alive_at_end = [a for a in agents_at_end if agent_alive(a, live_pids_at_end)]
paws = {l.get('paw') for l in chain if l.get('paw')}
agents_live = sorted({a['paw'] for a in alive_at_end if a.get('paw') in paws})


def statuses(links):
    c = {}
    for l in links:
        c[STATES.get(str(l.get('status')), 'unknown')] = c.get(STATES.get(str(l.get('status')), 'unknown'), 0) + 1
    return c
# ---- 目标 TTP 与对照分开计（L2 口径；这是本文件 Step 4 的全部要点）-------------
target_links = [l for l in chain if TARGET_ABILITY and link_ability_id(l) == TARGET_ABILITY]
control_links = [l for l in chain if not (TARGET_ABILITY and link_ability_id(l) == TARGET_ABILITY)
                 and (not CONTROL_ABILITY or link_ability_id(l) == CONTROL_ABILITY)]
# 既不是目标也不是对照的 link（例如剧本里混进了别的 ability）：**单独列出来**而不是悄悄并进
# 对照 —— 混进对照会虚高"通道健康度"，而它可能只是另一个同样撞墙的 ability。
other_links = [l for l in chain if l not in target_links and l not in control_links]
target_successes = [l for l in target_links if l.get('status') == 0]
control_successes = [l for l in control_links if l.get('status') == 0]
successes = [l for l in chain if l.get('status') == 0]
attempted = [l for l in chain if l.get('status') not in (-2, -5)]


def link_time(l):
    for k in ('collect', 'finish', 'decide'):
        if l.get(k):
            return l[k]
    return None


# `status = -3`（EXECUTE）**绝不算"被拦住"**：它的含义是"这条 link 挂在那里没有决定"，
# 最常见的原因是 agent 已死（陈旧条目）或执行器不可用 —— 那是**攻击没跑起来**，不是防护起作用。
# 旧实现的兜底只看"整条链有没有成功 link"，于是"目标 -3 + 对照 0"会被读成"目标被拦住"。
target_execute_links = [l for l in target_links if l.get('status') == -3]
if target_execute_links and not target_successes:
    fail(f'operation {op_id} 的目标 link 全部停在 EXECUTE（status=-3，{len(target_execute_links)} 条）—— '
         f'那是"没有决定"，最常见的原因是 agent 已死/执行器不可用，**不是**"被防护拦住"；'
         f'不得据此写 block_effective=true（判据：目标上的活 agent 与 link 的 paw 是否一致）')

# 目标 TTP 判定（**唯一决定 compromised 的东西**）
if BASIS == 'targeted_ttp':
    if not target_links:
        fail(f'operation {op_id} 的链里**没有**目标 ability（{TARGET_ABILITY}）的 link —— '
             f'剧本里没跑它 / ability id 写错 / 计划器把它跳过了；'
             f'链上的 ability id = {sorted({link_ability_id(l) for l in chain})}。'
             f'没有目标 link 就无从谈"目标 TTP 是否成功"，不得写任何标签')
    compromised = len(target_successes) > 0
    block_effective = len(target_successes) == 0
    # 名字核对（可选）：防止"ID 没变但内容被换"或"声明与剧本不一致"
    if TARGET_ABILITY_NAME:
        got = {link_ability_name(l) for l in target_links}
        if got and TARGET_ABILITY_NAME not in got:
            fail(f'目标 ability {TARGET_ABILITY} 现在的名字是 {sorted(got)}，'
                 f'与 EDGEEXP_TARGET_ABILITY_NAME={TARGET_ABILITY_NAME!r} 不符 —— 剧本/ability 漂移，拒绝采集')
    # 零成功时必须排除"攻击没跑起来"（与旧实现的同一条纪律，但现在**逐目标 link** 判）
    if not target_successes:
        if all(l.get('status') in (-2, -5) for l in target_links):
            fail(f'operation {op_id} 的目标 link 全是 DISCARD/HIGH_VIZ（{statuses(target_links)}）—— '
                 f'没有任何目标 ability 真正尝试执行，这条客观结果无从解释为"被拦住"')
        if not agents_live:
            fail(f'operation {op_id} 目标零成功，且目标 agent 在攻击结束时已失联/已死'
                 f'（链上的 paws={sorted(paws)}，容器内活 sandcat pid={sorted(live_pids_at_end)}）—— '
                 f'这不是"攻击被拦住"，而是攻击没跑起来；不得据此写 block_effective=true')
else:
    # recon_playbook：旧口径（任意 link 成功即 true），但**必须在产物里留下依据**，
    # 且消费侧（cmd/edgecompare）默认拒绝把它算进决策层指标。
    compromised = len(successes) > 0
    block_effective = len(successes) == 0
    if not successes:
        if not attempted:
            fail(f'operation {op_id} 的所有 link 都是 DISCARD/HIGH_VIZ（{counts}）—— 没有任何 ability 真正尝试执行，'
                 f'这条客观结果无从解释为"被拦住"')
        if not agents_live:
            fail(f'operation {op_id} 零成功，且目标 agent 在攻击结束时已失联（paws={sorted(paws)}）—— '
                 f'这不是"攻击被拦住"，而是攻击没跑起来；不得据此写 block_effective=true')

ttc = 0
if successes:
    times = sorted(t for t in (parse_ts(link_time(l)) for l in successes) if t)
    if times:
        ttc = max(0, int(times[0] - start_epoch))

# 达成的 TTP：每条成功的 link 是一次真实执行过的 ability（TTP）；
# 另附去重后的 ATT&CK technique 数（供报告使用，不在 schema 必填项里）。
techniques = set()
for l in successes:
    for f in (l.get('facts') or []):
        if f.get('technique_id'):
            techniques.add(f['technique_id'])
target_techniques = sorted({f['technique_id'] for l in target_successes
                            for f in (l.get('facts') or []) if f.get('technique_id')})

report = {
    'scenario': SCENARIO,
    # **L2 口径**：这两个字段只由**目标 TTP** 的 link 决定（basis=targeted_ttp 时）。
    # basis=recon_playbook 时它们是旧口径（任意 link），而 `basis` 字段会如实写明 ——
    # 消费侧（cmd/edgecompare）默认**拒绝**把侦察口径的记录算进决策层指标。
    'compromised': compromised,
    'time_to_compromise_s': ttc,
    # `ttps_achieved` 是"链上成功的 ability 条数"（含对照）——它是**过程量**，不是标签。
    # 标签只看 `compromised`/`block_effective`（上面那一对）。
    'ttps_achieved': len(successes),
    'nodes_affected': len({l.get('paw') for l in successes if l.get('paw')}),
    'block_effective': block_effective,
    'basis': BASIS,
    'target_ttp': {
        'ability_id': TARGET_ABILITY or None,
        'ability_name': TARGET_ABILITY_NAME or None,
        'links': len(target_links),
        'success_links': len(target_successes),
        'status_counts': statuses(target_links),
        'techniques_achieved': target_techniques,
        'note': ('目标 TTP：`compromised`/`block_effective` **只**由这组 link 决定（L2 口径）。'
                 '`status=-3`（EXECUTE）**不算**被拦住 —— 脚本在"目标 link 全为 -3 且零成功"时直接失败。'
                 if BASIS == 'targeted_ttp' else
                 '未声明目标 ability ⇒ 本轮是侦察口径（basis=recon_playbook），这组统计为空。'),
    },
    'control': {
        'ability_id': CONTROL_ABILITY or None,
        'links': len(control_links),
        'success_links': len(control_successes),
        'status_counts': statuses(control_links),
        'note': ('对照/通道健康度：回答"通道与执行器能不能干活"，**不参与标签**。'
                 '实测用途：策略在时"对照 0 + 目标非 0"才排除了"command 被拒是 agent/执行器坏了"这一解释。'),
    },
    'other_links': {'count': len(other_links), 'status_counts': statuses(other_links),
                    'ability_ids': sorted({link_ability_id(l) for l in other_links})},
    'playbook_hash': playbook_hash,
    'topology_hash': os.environ['TOPO_HASH'],
    'injections': [
        {'check': c, 'at': p['at']}
        for p in json.loads(os.environ['PHASES_JSON'])
        for c in p['checks']
    ],
    # ---- 以下字段是诊断/溯源（读取层刻意忽略未知键），不参与 schema 必填项 ----
    # expected_chain_factors 是**采集脚本做相等断言**的依据：链上出现的因子集必须与它逐项相等
    # （不是"包含"）。采集器自己只要求 chain ⊇ expectedChainFactors，于是"声明空集却采到六个
    # 因子"的 S0 基线可以静默通过 —— 那正是整轮实验的因子塌缩被藏起来的路径（Fix round 1 / C2）。
    'expected_chain_factors': [f for f in os.environ.get('EXPECTED_CHAIN_FACTORS', '').split(',') if f],
    'expected_chain_factors_source': os.environ.get('EXPECTED_CHAIN_FACTORS_SOURCE') or '未注明',
    'playbook': {'id': PLAYBOOK_ID, 'name': PLAYBOOK_NAME, 'abilities': len(ordering)},
    'operation': {'id': op_id, 'state': state, 'finished': not window_timeout,
                  'timeout_s': TIMEOUT, 'chain_links': len(chain), 'status_counts': counts,
                  'window_timeout': window_timeout},
    'attack': {'started_at': attack_started_at, 'finished_at': attack_finished_at,
               'agents_available': len(agents), 'success_links': len(successes),
               'agents_live_at_end': sorted(agents_live), 'attempted_links': len(attempted),
               'techniques_achieved': sorted(techniques),
               'agent_pid_at_end': sorted(live_pids_at_end),
               'agent_alive_judgement': ('`(host, 容器内活 pid)` 且 last_seen ≤ %ds（Task 4D Step 4）：'
                                         'Caldera 保留已死 agent 条目，只看 trusted 会把 operation 打到死 agent 上，'
                                         '得到 status=-3 而**看起来像被拦住**' % AGENT_FRESH_S)},
    'phases': json.loads(os.environ['PHASES_JSON']),
    'condition_probes': json.loads(os.environ['PROBES_JSON']),
    'condition_probes_note': ('每条探针都在**被攻节点内**执行（经基质层下发：clab 基质是 docker exec、'
                              'lxd 基质是 lxc exec；判据与 internal/checks/linux '
                              '的同名检查逐条对齐）；probe_host 是节点内进程自证的 hostname，'
                              'probe_target 是节点名（clab: 容器名；lxd: 实例名）。condition_holds 为 null 表示**探针未执行**'
                              '（未声明 EDGEEXP_TARGET），那**不是**"条件不成立"，也不是证据。'),
    'real_missing': os.environ['REAL_MISSING'],
    'real_missing_verified_at': os.environ['REAL_MISSING_AT'],
    'probe_note': 'condition_holds = 该防护在**被攻节点内**真的缺失（用引擎同名检查的判据探测，见 condition_probes 的 probe_host）；S 组是 spec §2.3 的"检查失败代理"，探针结果只记录不阻断；R 组必须成立',
    'ground_truth_note': ('口径（Task 4D Step 4 / 用户裁定的 L2）：`compromised` = **目标 TTP 是否成功**'
                          '（basis=targeted_ttp 时只由目标 ability 的 link 决定，`status == 0` 才算成功），'
                          '`block_effective` = 目标 link **全部**未成功；`status=-3`（EXECUTE）**不算**被拦住。'
                          '对照/侦察 link 只作通道健康度，见 `control`。'
                          'basis=recon_playbook 时是旧口径（任意 link 成功即 true），**不得**进决策层指标。'
                          + ('本次观察窗**超时**（operation 未进终态）⇒ ttps_achieved 是"窗内已达成"的下界。' if window_timeout
                             else 'operation 已进终态，客观结果完整。')),
}
tmp = OUT + '.tmp'
os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
with open(tmp, 'w', encoding='utf-8') as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=False)
    fh.write('\n')
os.replace(tmp, OUT)
print(f'edge_attack: 客观结果 compromised={report["compromised"]} ttc={ttc}s ttps={report["ttps_achieved"]} '
      f'nodes={report["nodes_affected"]} block_effective={report["block_effective"]} '
      f'(basis={BASIS}, 目标 link {len(target_links)}/{len(target_successes)} 成功, 对照 link {len(control_links)}/{len(control_successes)}, '
      f'state={state}, links={len(chain)}, counts={counts})')
print(f'edge_attack: 目标 TTP ability={TARGET_ABILITY or "（未声明 ⇒ 侦察口径）"} '
      f'name={TARGET_ABILITY_NAME or "（未注明）"}')
print(f'edge_attack: agent 判据 (host={ATTACK_HOST or "任意"}, 活 pid={sorted(live_pids_at_end)}, ≤{AGENT_FRESH_S}s) '
      f'⇒ 结束时活着 {len(alive_at_end)} 只')
print(f'edge_attack: 剧本 {PLAYBOOK_NAME}/{PLAYBOOK_ID} abilities={len(ordering)} hash={playbook_hash[:23]}…')
print(f'edge_attack: 写出 {OUT}')
PY

echo "edge_attack: 完成（$SCENARIO）"
