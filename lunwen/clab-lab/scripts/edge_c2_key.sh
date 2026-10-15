#!/bin/bash
# ============================================================================
# edge_c2_key.sh —— C2 API key 的**唯一**取值点（Task 14 脱敏：D2）
# ============================================================================
#
# ## 为什么有它（用户 2026-10-15 的常设铁律：「追踪的文件只要带有敏感信息的内容必须脱敏」）
#
# 此前 18 个被跟踪的文件里写着同一个**明文口令** —— 而它是**真凭据**（Caldera 宿主
# `/opt/caldera/conf/default.yml` 里存的正是它的 argon2id 哈希）。也就是说：**仓库里带着
# 一个可用的 C2 口令**。改成"从环境变量/未跟踪的本地配置读、缺了就响亮失败"。
# （那个字面值本文件**不复述** —— 脱敏的判据是"被跟踪的文件里 grep 不到"，注释里复述一样是命中。）
#
# ## 取值顺序（**只有这三档，没有默认值**）
#   ① 环境变量 `EDGEEXP_CALDERA_KEY`（调用前 `export`，或命令前临时给）；
#   ② 未跟踪的本地配置文件 `EDGEEXP_LOCAL_ENV`（默认 `~/.config/asscor/edgeexp.local.env`，
#      文件名已在根 `.gitignore` 里 ⇒ 防误拷进仓库）；
#   ③ **响亮失败**（`exit 2`，消息里给出上面两档的修法与现成命令）。
#
# ## ⚠️ 三条红线（改这个文件时不许破）
#   R1 **不许补回任何明文默认值**（哪怕"只是方便"）—— 那等于把口令又写回仓库。
#   R2 **不许把"缺 key"降级成空串继续跑**：用空 key 打 C2 只会得到 401/403，错误现场与
#      "C2 挂了 / 网络不通"**同形**，排障方向完全错。必须在这一层就停下。
#   R3 **门禁不许自己把 key 补上**（`edge_prebatch_check.sh` 此前正是这么干的：它先
#      `export EDGEEXP_CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-<明文默认值>}"` ⇒ 前置门禁**永远不会**
#      因缺 key 而 NO-GO）。缺 key 就是要 NO-GO —— 否则会变成"跑完 13 小时才发现 C2 没通"。
#
# ## 用法（在调用脚本里 source 之后二选一）
#   . "$SCRIPT_DIR/edge_c2_key.sh"
#   edge_require_c2_key edge_reset.sh      # ⇒ 缺 key 时**当场 exit 2**
#   # 或者：只管取值、由调用者决定怎么上报（前置检查要把"缺 key"记成一项 NO-GO 时用这个）
#   if edge_c2_key_source; then …; else bad "…"; fi
#
# 本文件**只定义函数**：不 `set -e`、不打印、不在被 source 时做任何动作 —— 错误处置
# 一律交回调用脚本（它的退出码语义各不相同：0/1/2/10 都有约定）。
# ============================================================================

# 本地配置文件的路径（`EDGEEXP_LOCAL_ENV` 可覆盖）。
edge_c2_key_local_env() {
  printf '%s\n' "${EDGEEXP_LOCAL_ENV:-${HOME:-/root}/.config/asscor/edgeexp.local.env}"
}

# 取值：环境变量优先，其次未跟踪的本地配置。**不设任何默认值**。
# 回显 0 = `EDGEEXP_CALDERA_KEY` 现在非空；1 = 仍然没有（不打印、不退出）。
edge_c2_key_source() {
  if [ -n "${EDGEEXP_CALDERA_KEY:-}" ]; then
    return 0
  fi
  local f
  f="$(edge_c2_key_local_env)"
  if [ -r "$f" ]; then
    # shellcheck disable=SC1090  # 路径由环境变量/默认值决定，故意的（只读、非仓库文件）
    . "$f"
  fi
  [ -n "${EDGEEXP_CALDERA_KEY:-}" ]
}

# 取值 + 缺则**响亮失败**（exit 2）。$1 = 调用者名（只用于消息里点名，可省）。
edge_require_c2_key() {
  if edge_c2_key_source; then
    return 0
  fi
  local who="${1:-edge_exp}" f dir
  f="$(edge_c2_key_local_env)"
  dir="$(dirname "$f")"
  {
    echo "$who: **缺少 EDGEEXP_CALDERA_KEY** —— 仓库**不再**提供明文默认值（脱敏铁律）。"
    echo "  此前那个默认值是真凭据的明文，一直被追踪 ⇒ 已移除；用空 key 打 C2 只会得到"
    echo "  一个与「C2 挂了」同形的 401/403，所以这里**直接停下**，不猜、不降级。"
    echo "  修法（任选其一）："
    echo "    ① 本次调用显式给：export EDGEEXP_CALDERA_KEY='<C2 API 口令>'"
    echo "    ② 写进**未跟踪**的本地配置（推荐，一次配好；文件名已在根 .gitignore 里）："
    echo "         mkdir -p '$dir' && chmod 700 '$dir'"
    echo "         printf 'EDGEEXP_CALDERA_KEY=%s\\n' '<C2 API 口令>' > '$f' && chmod 600 '$f'"
    echo "       也可以放到别处，用 EDGEEXP_LOCAL_ENV=/path/to/edgeexp.local.env 指过去"
    echo "    ③ 在 C2 宿主上就地取（Caldera 的部署口令；**不要**抄回仓库）。"
  } >&2
  exit 2
}
