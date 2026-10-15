#!/bin/bash
# ============================================================================
# edge_prebatch_check.sh —— **跑批前置**的唯一入口（Task 11 Step 3）
# ============================================================================
#
# 全量扫描是 36 个场景实例 × 3 个重复 ≈ 13 小时。历史上**开局就错**的三次都发生在
# "跑批之前的最后三十秒"里（Task 8 缺 `edgecompare` ⇒ 门禁①/② 静默 skipped；
# Task 9 跑批工作区的 Go 源码陈旧 ⇒ 采集器不认识 `pve:` 前缀、第 1 个场景就整轮失败；
# Task 10 的残留 agent 让 operation 打到已死的那只）。故把它们收成**一个入口**：
# 逐项给输出，任何一项不满足就 **NO-GO（非零退出）** —— 不许"先跑起来再说"。
#
# ## 四项前置（每项都有判据，不是"看一眼"）
#
# 1. **生效的二进制 == HEAD 构建**（Task 9 栽在这）
#    做法：从**干净 HEAD 检出**用 `-trimpath` 构建 `edgescen` / `edgecompare` 到临时目录，
#    再与跑批工作区里**真正会被用到**的那两个二进制**比 sha256**。
#    为什么必须 `-trimpath`：不加它时 Go 会把**构建目录**写进二进制 ⇒ 同一份源码换个目录构建
#    也会得到不同的 sha256，"比 sha256"就没法用了（实测：`/tmp/edgescen.head` vs
#    `/tmp/edgescen.argus` 在 `-trimpath` 下同源则相同、异源则不同）。⇒ 本入口把
#    "**`-trimpath` + 从干净检出构建**"定为**唯一**的安装配方，`--install` 会照它把二进制装进跑批工作区。
# 2. **残留 agent 复核**：转调 `edge_agent_preflight.sh`（判据：`host` + `trusted` +
#    `pid ∈ 容器内当前活 sandcat` + `last_seen ≤ EDGEEXP_AGENT_FRESH_S`）。
#    rc=1（没有活 agent）⇒ **NO-GO**；rc=10（有残留）⇒ 默认**响亮警告**并给出清理命令
#    （`--strict-agents` 时升级为 NO-GO）—— 残留不会让 operation 打错人（`≤180s` 的新鲜度判据
#    会滤掉死 paw），但它会污染每份产物里的 link 统计，所以**要看见**、并且能在开跑前清掉。
# 3. **TTP 三件实体**：转调 `edge_ttp_provision.sh`（幂等：已存在则核对关键字段，不一致**响亮失败**）。
#    rc≠0 ⇒ **NO-GO**（"C2 上的实体与夹具不是同一个东西"比"缺实体"更难发现）。
# 4. **门禁①/② 的前提**：`build/edgecompare` 在位可执行（第 1 项已经连它一起比过 sha256；
#    这里再单独确认**执行位**与**在跑批工作区里**，因为 Task 8 那轮就是它不在 ⇒ 门禁静默 skipped）。
#
# ## 用法
#   bash edge_prebatch_check.sh                 # 只复核（**不改现场**）
#   bash edge_prebatch_check.sh --install       # 先用规范配方重建并安装两个二进制，再复核
#   bash edge_prebatch_check.sh --strict-agents # 有残留 agent 也算 NO-GO
#
# 环境变量：
#   EDGEEXP_HEAD_CHECKOUT   干净 HEAD 检出。**没有默认值**（Task 14 修 D3）：它是"这一次
#                           跑批要用哪份检出"的信息，只有跑批的人知道 —— 给默认值等于把
#                           一个**陈旧路径**伪装成"约定"；缺省时本入口**响亮失败**并给示例。
#                           判据见下面 [1/4]：`git -C … rev-parse --git-dir`（**能认 worktree**；
#                           旧的 `[ -d "$HEADCO/.git" ]` 把 git worktree 的 `.git` **文件**
#                           当成"不是仓库"⇒ 对一份完全正常的检出误报 NO-GO）+ 有未提交改动
#                           直接判红（这条加固保留）。
#   EDGEEXP_REPO            跑批工作区（默认：本脚本所在**仓库根** `<repo>` = `$SCRIPT_DIR/../../..`）
#   EDGEEXP_CALDERA_URL     C2 API（默认 http://192.168.30.2:8888）
#   EDGEEXP_CALDERA_KEY     C2 API key。**没有默认值**（Task 14 修 D2/门禁红线）：取法见
#                           scripts/edge_c2_key.sh —— 环境变量 → 未跟踪的本地配置 → 缺则 NO-GO。
#                           ⚠️ 本入口此前 `export EDGEEXP_CALDERA_KEY="${…:-<明文默认值>}"`
#                           **自己把 key 补上**，于是"缺 key"
#                           永远不可能让它 NO-GO —— 那是门禁被自己绕过，已删除。
#   EDGEEXP_TARGET          目标节点名（默认 asc-tgt-c2）
#   EDGEEXP_SUBSTRATE       基质（默认 pve —— 本入口是给 dl360gen9 的 PVE CT 跑批用的；
#                           **必须转发**：不转发时子脚本退回 clab/docker，会去问一个不存在的
#                           容器，把"看错地方"报成"没有活 agent"）
#   EDGEEXP_AGENT_FRESH_S   agent 心跳新鲜度（默认 180）
#
# 退出码：0 = GO（可以开跑）；非零 = NO-GO（上面哪一项没满足就修哪一项，别绕过）。
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 仓库根 = 本脚本（<repo>/lunwen/clab-lab/scripts/）往上**三层** —— 与 tests/ 里那六组夹具
# （`$TESTS_DIR/../../..`）同一口径。曾经写成两层（落成 `<repo>/lunwen`）⇒ 四项前置**全部**
# 指向 `…/argus/lunwen/build`、`…/argus/lunwen/lunwen/clab-lab/scripts` 这种不存在的路径，
# 于是一运行就"五项全红"。这类"入口自己算错位置"的错**只有真跑一遍才会现形**。
REPO="${EDGEEXP_REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
# **没有默认值**（Task 14 修 D3）。旧默认 `/root/t6/t8/head` 是 Task 8 那一次的工作区：换任务/
# 换机器之后它会静默指向一个不存在或陈旧的目录，而错误现场看起来像"检出不完整"。真正只有
# 跑批的人知道"这一次该用哪份检出"，所以这题**必须显式回答**（缺省 ⇒ 下面 [1/4] 判红给示例）。
HEADCO="${EDGEEXP_HEAD_CHECKOUT:-}"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://192.168.30.2:8888}"
export EDGEEXP_CALDERA_URL="$CALDERA_URL"
# ---------------------------------------------------------------------------
# C2 API key：**门禁红线**（Task 14 脱敏 D2）
# ---------------------------------------------------------------------------
# 这里此前是 `export EDGEEXP_CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-<那个明文默认值>}"` —— 两件事一起坏：
#   ① 明文默认值 = 真凭据（脱敏铁律）；② **门禁自己把 key 补上** ⇒ "缺 key"永远不可能让这一轮
#      NO-GO，前置检查的结论因此是假的（跑完 13 小时才发现 C2 没通）。
# 现在取值只有两档（环境变量 → 未跟踪的本地配置），取不到就**不导出**，并把这一项记成 NO-GO：
# 下面的 [2/4]/[3/4] 需要问 C2，缺 key 时**整段跳过**（而不是退回空串去发请求 —— 空 key 打 C2
# 得到的 401/403 与"C2 挂了"同形，会把排障方向带歪）。
# shellcheck source=scripts/edge_c2_key.sh
. "$SCRIPT_DIR/edge_c2_key.sh"
C2_KEY_OK=0
if edge_c2_key_source; then
  export EDGEEXP_CALDERA_KEY
  C2_KEY_OK=1
fi
export EDGEEXP_TARGET="${EDGEEXP_TARGET:-asc-tgt-c2}"
# **基质必须跟着跑批走**：本入口是给 dl360gen9 的 **pve**（PVE CT）跑批用的（C2 的默认地址、
# 目标默认值都已经是 pve 那一套）。不转发它时 `edge_agent_preflight.sh` 会退回默认的
# `clab`（docker）⇒ 去问一个**不存在的容器**，于是"取不到活 pid"被当成
# **"目标上没有活着的 agent"**（rc=1 ⇒ 误报 NO-GO）—— 是**看错了地方**，不是现场真没 agent。
export EDGEEXP_SUBSTRATE="${EDGEEXP_SUBSTRATE:-pve}"
GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOPROXY

INSTALL=0
STRICT=0
for a in "$@"; do
  case "$a" in
    --install) INSTALL=1 ;;
    --strict-agents) STRICT=1 ;;
    *) echo "edge_prebatch_check: 未知参数 $a（只认 --install / --strict-agents）" >&2; exit 2 ;;
  esac
done

FAILED=()
ok()   { echo "  ✅ $*"; }
warn() { echo "  ⚠️  $*"; }
bad()  { echo "  ❌ $*"; FAILED+=("$*"); }   # `$*` 而不是 `$1`：万一消息里混进未转义的引号，摘要也不会被截断

echo "############ 跑批前置检查（Task 11 Step 3）"
echo "  跑批工作区   : $REPO"
echo "  干净 HEAD 检出: ${HEADCO:-（未给 EDGEEXP_HEAD_CHECKOUT —— 见下面 [1/4] 的 ❌）}"
# `-d "$HEADCO/.git"` 换掉（Task 14 修 D3）：**git worktree 的 `.git` 是一个文件**（46 字节，
# 内容是 `gitdir: /…/.git/worktrees/<名>`），`[ -d … ]` 判否 ⇒ 对一份**完全正常**的检出误报
# NO-GO（控制侧 2026-10-15 实测 rc=1，rc 还是从管道里读的 ⇒ 更不可信）。现在的判据是
# `git -C … rev-parse --git-dir`：它认 worktree、认子目录、认裸仓库，且不依赖 `.git` 的形态。
if git -C "$HEADCO" rev-parse --git-dir >/dev/null 2>&1; then
  echo "  检出 HEAD    : $(git -C "$HEADCO" log -1 --format='%h %s' 2>/dev/null | head -c 120)"
  # 把检出**形态**打出来：worktree 与主检出的差异正是 D3 的根因，操作者一眼就该看到。
  if [ -f "$HEADCO/.git" ]; then
    echo "  检出形态     : **git worktree**（.git 是文件：$(cat "$HEADCO/.git" 2>/dev/null | head -c 80)）"
  else
    echo "  检出形态     : 主检出/普通克隆（.git 是目录）"
  fi
fi
echo "  C2           : $CALDERA_URL ｜ 目标节点: $EDGEEXP_TARGET ｜ 基质: $EDGEEXP_SUBSTRATE"
echo
if [ "$C2_KEY_OK" != "1" ]; then
  bad "未提供 EDGEEXP_CALDERA_KEY（仓库**不再**有明文默认值）⇒ 无法核实 C2 连通性（[2/4]、[3/4] 会跳过）。修法：① export EDGEEXP_CALDERA_KEY='<C2 API 口令>'；或 ② 写进未跟踪的本地配置 $(edge_c2_key_local_env)（一行 EDGEEXP_CALDERA_KEY=…，chmod 600；文件名已在根 .gitignore 里）"
fi

# --- 前置 1：生效二进制 == HEAD 构建（-trimpath，从干净检出构建）---------------
echo "== [1/4] 生效的二进制 == 干净 HEAD 检出构建（-trimpath + tags）=="
command -v go >/dev/null 2>&1 || bad "找不到 go（构建需要它；GOPROXY=$GOPROXY）"
# 检出判据（Task 14 修 D3，逐条见文件头）：
#   · 缺 EDGEEXP_HEAD_CHECKOUT ⇒ 判红并给示例路径（**不再回落到某个任务的工作区**）；
#   · 不是 git 仓库 ⇒ 判红（`rev-parse --git-dir` 认 worktree）；
#   · **有未提交改动 ⇒ 直接判红**（原判据，保留：此时"HEAD 构建"名不副实，比 sha256 没意义）。
#     现场那份 build/edgescen 就是 042c3fe + 未提交改动（`go version -m` 报 `…042c3fe…+dirty`）
#     构出来的 —— 那时"比 sha256"比的是一个**没人能复现**的东西。
if [ -z "$HEADCO" ]; then
  bad "未给 EDGEEXP_HEAD_CHECKOUT —— 本检查必须知道**哪一份检出**算「干净 HEAD 检出」（此变量没有默认值）。修法：EDGEEXP_HEAD_CHECKOUT=/root/t6/t14/head bash $0"
elif ! git -C "$HEADCO" rev-parse --git-dir >/dev/null 2>&1; then
  bad "干净 HEAD 检出不是 git 仓库（或路径不存在）：$HEADCO —— 修法：把一份干净检出放在该路径（示例：/root/t6/t14/head），或把 EDGEEXP_HEAD_CHECKOUT 指过去"
elif [ -n "$(git -C "$HEADCO" status --porcelain 2>/dev/null)" ]; then
  bad "干净 HEAD 检出 $HEADCO **有未提交改动**（「HEAD 构建」名不副实，比 sha256 失去意义）—— 修法：git -C $HEADCO checkout -f && git -C $HEADCO clean -fd，或指向另一个真干净的检出"
fi
[ -z "$HEADCO" ] || [ -f "$HEADCO/cmd/edgescen/nodecollect.go" ] || bad "$HEADCO 里没有 cmd/edgescen（检出不完整？）"
if [ "${#FAILED[@]}" -eq 0 ]; then
  TMPB="$(mktemp -d)"
  declare -A TAG=( [edgescen]="expr,engine,checks" [edgecompare]="edgeexp" )
  declare -A SRC=( [edgescen]="./cmd/edgescen" [edgecompare]="./cmd/edgecompare" )
  for bin in edgescen edgecompare; do
    if ! ( cd "$HEADCO" && go build -trimpath -tags "${TAG[$bin]}" -o "$TMPB/$bin" "${SRC[$bin]}" ) 2>"$TMPB/$bin.err"; then
      bad "$bin 从 HEAD 检出构建失败：$(tail -2 "$TMPB/$bin.err" | tr '\n' ' ')"
      continue
    fi
    WANT="$(sha256sum "$TMPB/$bin" | cut -d' ' -f1)"
    # 三种情形要分清（否则"响亮"的那句话会指错方向）：不在位 / 没有执行位 / 逐字节不同。
    if [ ! -e "$REPO/build/$bin" ]; then
      HAVE='<缺失>'
      WHY="$REPO/build/$bin **不在位**（现场根本没有这个二进制）"
    elif [ ! -x "$REPO/build/$bin" ]; then
      HAVE="$(sha256sum "$REPO/build/$bin" | cut -d' ' -f1)"
      WHY="$REPO/build/$bin **没有执行位**（门禁/采集会以"命令找不到"或静默 skipped 收场）"
    else
      HAVE="$(sha256sum "$REPO/build/$bin" | cut -d' ' -f1)"
      WHY="$bin 与 HEAD 构建**逐字节不同** —— 这正是 Task 9 栽的那条（陈旧源码构出的采集器不认识 pve: 前缀）"
    fi
    echo "     $bin: HEAD 构建=$WANT"
    echo "             生效的  =$HAVE"
    # 不一致时补一行**现场那份的构建戳**：只说"不同"等于说了一半 ——
    #   · 二进制里盖着构建时的 `vcs.revision`（默认 `-buildvcs`）⇒ **每次提交后哈希都会变**，
    #     哪怕源码一个字没动。没有这一行，操作者会把"提交之后没重装"误读成"源码陈旧"，
    #     而这两件事的修法完全不同（前者 `--install` 即好，后者说明检出的东西根本不是这套代码）。
    if [ "$HAVE" != "$WANT" ] && [ -e "$REPO/build/$bin" ]; then
      STAMP="$(go version -m "$REPO/build/$bin" 2>/dev/null | grep -E 'vcs\.revision|vcs\.modified' | tr -s ' \t' ' ' | tr '\n' ' ')"
      echo "             现场那份: ${STAMP:-（读不出构建信息）}"
      echo "             ★ 二进制盖着构建时的 vcs 戳 ⇒ **换提交后要重新 --install**（源码没动也会哈希不同）"
    fi
    if [ "$HAVE" = "$WANT" ]; then
      ok "$bin 与 HEAD 构建**逐字节相同**（跑批用的是 HEAD 的代码）"
      continue
    fi
    if [ "$INSTALL" = "1" ]; then
      mkdir -p "$REPO/build"
      cp -f "$TMPB/$bin" "$REPO/build/$bin" && chmod 755 "$REPO/build/$bin"
      NEW="$(sha256sum "$REPO/build/$bin" | cut -d' ' -f1)"
      if [ "$NEW" = "$WANT" ] && [ -x "$REPO/build/$bin" ]; then
        ok "$bin 已用规范配方重建并安装（--install），现在与 HEAD 相同（且可执行）"
      else
        bad "$bin 安装后仍与 HEAD 构建不同或没有执行位（$NEW）"
      fi
    else
      bad "$bin: $WHY。修法：bash $0 --install"
    fi
  done
  rm -rf "$TMPB"
fi

# --- 前置 2：残留 agent 复核 ---------------------------------------------------
echo
echo "== [2/4] 残留 agent 复核（edge_agent_preflight.sh，判据见其文件头）=="
AP="$REPO/lunwen/clab-lab/scripts/edge_agent_preflight.sh"
if [ "$C2_KEY_OK" != "1" ]; then
  # **不许退回空 key 去问 C2**（Task 14 门禁红线）：那只会得到 401/403，与"C2 挂了"同形。
  # 跳过并不等于放行 —— 上面已经记了一条 ❌（缺 key），退出码照样是非零。
  bad "跳过 [2/4] 残留 agent 复核：缺 EDGEEXP_CALDERA_KEY（用空 key 问 C2 会得到与「C2 挂了」同形的错误）—— 修法见上面的 ❌（先 export 或写本地配置，再重跑本入口）"
elif [ ! -x "$AP" ] && [ ! -f "$AP" ]; then
  bad "找不到 edge_agent_preflight.sh：$AP"
else
  bash "$AP" 2>&1 | sed 's/^/     /'
  AP_RC=${PIPESTATUS[0]}
  case "$AP_RC" in
    0)  ok "agent 干净（恰好 1 只活着的、无残留）" ;;
    10) if [ "$STRICT" = "1" ]; then
          bad "有残留 agent（--strict-agents 下算 NO-GO）—— 清理：bash $AP --clean"
        else
          warn "有残留 agent（不会打错人：≤${EDGEEXP_AGENT_FRESH_S:-180}s 的新鲜度判据会滤掉死 paw；但会污染产物的 link 统计）—— 建议先清：bash $AP --clean"
        fi ;;
    1)  bad "目标上没有活着的 agent —— 先跑一次 reset（edge_reset.sh <场景>）再复核" ;;
    *)  bad "edge_agent_preflight.sh 退出码 $AP_RC（未知）" ;;
  esac
fi

# --- 前置 3：TTP 三件实体（幂等核对）-------------------------------------------
echo
echo "== [3/4] TTP 三件实体（edge_ttp_provision.sh，幂等：已存在则核对关键字段）=="
TP="$REPO/lunwen/clab-lab/scripts/edge_ttp_provision.sh"
if [ "$C2_KEY_OK" != "1" ]; then
  bad "跳过 [3/4] TTP 三件实体：缺 EDGEEXP_CALDERA_KEY（同上——不许用空 key 去问 C2）"
elif [ ! -f "$TP" ]; then
  bad "找不到 edge_ttp_provision.sh：$TP"
else
  TP_OUT="$(bash "$TP" 2>&1)"; TP_RC=$?
  echo "$TP_OUT" | grep -E '已存在|新建|就绪|失败' | sed 's/^/     /'
  if [ "$TP_RC" -eq 0 ]; then
    ok "三件实体就绪（rc=0）"
  else
    bad "edge_ttp_provision.sh rc=$TP_RC —— C2 上的实体与夹具/文档引用的不是同一个东西（不许绕过）"
  fi
fi

# --- 前置 4：edgecompare 在位可执行（门禁①/② 的前提）---------------------------
echo
echo "== [4/4] 门禁①/② 的前提：build/edgecompare 在位可执行 =="
EC="$REPO/build/edgecompare"
if [ -x "$EC" ]; then
  ok "build/edgecompare 在位可执行（$(stat -c %s "$EC") 字节）—— 门禁①/② 不会是 skipped"
else
  bad "build/edgecompare 不在位或不可执行：$EC —— 门禁①/② 会静默 skipped（Task 8 那轮就这么漏过）。修法：bash $0 --install"
fi

# --- 结论 ---------------------------------------------------------------------
echo
echo "############ 结论"
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "  **GO** —— 四项前置全部满足，可以开跑（命令示例见报告/README）"
  exit 0
fi
echo "  **NO-GO** —— 有 ${#FAILED[@]} 项没满足："
for f in "${FAILED[@]}"; do echo "    · $f"; done
exit 1
