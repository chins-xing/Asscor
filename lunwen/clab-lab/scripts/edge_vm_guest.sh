#!/bin/bash
# ============================================================================
# edge_vm_guest.sh —— **qemu（VM）基质的客人侧助手**（Task 17 Step 1/2）
# ============================================================================
#
# 它跑在**被攻的那台 VM 里**（以 root 等价执行），由 `edge_target_prepare.sh` 的 qemu 分支
# 推送并调用。它把"VM 基质的复位需要做的几件事"固化成**一份可 review、可复跑**的东西。
#
# ## 为什么需要它（而不是像 lxd/pve 那样把命令内联在调用点）
#
# qemu 基质的"在目标内执行"由 `ssh` 承担，而 **ssh 不保留 argv 的格边界**：
# `edge_lab.sh:lab_target_exec` 的 qemu 分支把 argv 用空格拼成**一条命令串**交给客人侧的
# `bash -c` 再分词（那是 ssh 协议本身的结构，不是实现选择，见那一处的长注释）。
# 于是"多 token 的脚本"（本例里几乎每一段都是）**不能**靠 argv 送进去 —— `edge_probe.sh`
# 早就撞过同一堵墙，它的处置是"**落文件 → lab_push → 按路径执行**"（见它的 `probe_condition_holds`）。
# 本文件把同一处置固化成一件东西，而不是让 prepare 里长出三四个长 heredoc。
#
# ## 三条传输纪律（调用点必须照做）
#
#   1. 本文件**每次复位都重新推送**到 `/tmp/asscor-edge-vm-guest.sh`（内容 = 仓库里的这一份）
#      ⇒ 不会出现"客人里躺着一份旧版本、宿主上已经是新的"这种静默分叉；
#   2. 所有子命令都**以 root 等价执行**（`sudo -n bash <本文件> …`）——
#      与取数侧（`cmd/edgescen` 的 `sudo -n env EDGESCEN_NODE_NONCE=… /tmp/asscor-edgescen`）
#      **同一条口径**：VM 上的一切准备与观测都在 uid 0 下发生。这不是"图省事"：
#      沙箱里跑的 TTP 是 `head -1 /etc/shadow`，它**必须**以 root 跑才谈得上"策略挡住了它"
#      （以 `asc` 跑的话两臂都会被 DAC 挡住 ⇒ 两臂读数相同、实验测不出任何东西）。
#   3. **argv 里不放带空格的取值**：策略规则经**文件**传入（`policy-apply <rulefile>`），
#      口令经 `env` 的赋值格传入（`sudo -n env AVE_C2_KEY=… bash <本文件> c2-probe …`）——
#      两者都不进**本脚本**的 argv。
#
# ## 子命令（每个都只回一行结论，便于调用点做逐字判据）
#
#   policy-status                  loaded | absent        （判据 = **内核**策略表，不是盘上有没有文件）
#   policy-apply <rulefile>        applied               （写 profile + `apparmor_parser -r`）
#   policy-remove                  removed
#   policy-probe                   DENIED | ALLOWED | UNRESTRICTED （受限进程读 /etc/shadow）
#   agent-install <src>            installed             （把载荷落地成 /root/sandcat）
#   agent-start <server> <group> <profile|->  started pids=…
#   agent-stop                     stopped
#   route-add <cidr> <via> <dev>   route-ok
#   route-del <cidr>               route-del
#   net-report <iface>             三行：iface… / default… / routes…
#   c2-probe <url>                 HTTP 状态码（`000` = 没问到）
#
# 退出码：0 = 子命令成功；非零 = 失败（**不降级**：拿不到就说拿不到）。
# ============================================================================
set -uo pipefail

PROFILE_NAME="asscor-edge-policy"
PROFILE_PATH="/etc/apparmor.d/$PROFILE_NAME"
RULE_FILE="${AVE_RULE_FILE:-/tmp/asscor-edge-policy.rule}"
SANDCAT="/root/sandcat"
SANDCAT_LOG="/tmp/sandcat.log"

die() { echo "edge_vm_guest: $*" >&2; exit 1; }

# profile_loaded 的判据是**内核里的策略表**。为什么不能看"盘上有没有那个文件"：
# `apparmor_parser -r` 失败时文件仍在（甚至内容还是新的）⇒ "看起来装了、其实内核里没有"
# 正是这条路径最坏的形态（策略不在 ⇒ TTP 成功 ⇒ 却会被读成"策略没挡住"）。
profile_loaded() {
  [ -r /sys/kernel/security/apparmor/profiles ] \
    || die "读不到 /sys/kernel/security/apparmor/profiles —— AppArmor 在这台 VM 上不可用（先 `aa-status`）"
  grep -q "^${PROFILE_NAME} " /sys/kernel/security/apparmor/profiles
}

cmd_policy_status() {
  if profile_loaded; then echo "loaded"; else echo "absent"; fi
}

# cmd_policy_apply <rulefile> —— 策略规则的唯一来源是**一个文件**（argv 里不放带空格的取值）。
#
# profile 的形状（与 CT 侧的 `lxc.apparmor.raw: audit deny /etc/shadow r,` 对等）：
#   `file,` + `/** ix,` 让这个 profile 在**除 deny 之外**等同于不受限（这正是 CT 那边
#   `lxc.apparmor.raw` 的语义：往容器 profile 里**追加**一条 deny，而不是另造一个受限沙箱）；
#   `deny …` 的优先级高于任何 allow ⇒ 攻击进程（sandcat 及其子进程）读不到 /etc/shadow。
#
# ⚠️ **与 CT 侧的一处必须写明的差别**：CT 的策略是**容器级**的（所有进程都在那个 profile 里），
# 而 VM 上这条 profile 是**挂在攻击进程上**的（`aa-exec -p` 拉起 sandcat，子进程继承）。
# 理由是本项目在 VM 上不可把"取数进程"也一起关进去：取数走 `ssh + sudo -n`，把它套进一个
# 拒绝读 /etc/shadow 的 profile 会**同时**改掉 `checks[]` 的观测面（若干条检查会因此失败），
# 那会让"策略"从**实验条件**变成**测量扰动**。挂在攻击进程上，两件事就分开了：
#   策略在 ⇒ 目标 TTP 被拒（`compromised=false`）；策略不在 ⇒ 目标 TTP 成功（`compromised=true`）；
#   而 `checks[]` 与链在两臂上**逐项相同**（这正是两臂可比的前提）。
cmd_policy_apply() {
  local rulefile="${1:-$RULE_FILE}" rule
  [ -r "$rulefile" ] || die "策略规则文件不可读: $rulefile"
  # 只取第一行、去掉 CR（宿主侧可能是 CRLF）—— 规则本身是一行。
  rule="$(tr -d '\r' < "$rulefile" | head -n 1)"
  [ -n "$rule" ] || die "策略规则文件是空的: $rulefile"
  case "$rule" in
    *deny*) : ;;
    *) die "策略规则里没有 deny（收到 '$rule'）—— 这条路径存在的理由就是**拒绝**对 /etc/shadow 的读；没有 deny 的规则会产出一个『什么也没拦』的策略，而它看起来完全正常" ;;
  esac
  cat > "$PROFILE_PATH" <<EOF
#include <tunables/global>

profile $PROFILE_NAME flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  capability,
  network,
  file,
  /** ix,

  $rule
}
EOF
  apparmor_parser -r "$PROFILE_PATH" || die "apparmor_parser -r $PROFILE_PATH 失败（策略没进内核）"
  profile_loaded || die "apparmor_parser 返回 0，而内核策略表里没有 $PROFILE_NAME —— 不静默接受"
  echo "applied"
}

cmd_policy_remove() {
  if [ -f "$PROFILE_PATH" ]; then
    apparmor_parser -R "$PROFILE_PATH" 2>/dev/null || true
    rm -f "$PROFILE_PATH"
  fi
  if profile_loaded; then die "卸载后策略**仍在内核表里**（$PROFILE_NAME）—— 策略状态与声明不符时不静默"; fi
  echo "removed"
}

# cmd_policy_probe —— 结论是"**受限进程**读 /etc/shadow 的结果"，三种取值**互斥且可解释**：
#   DENIED       策略在内核里，且受限进程被拒（策略**在**那条臂要的就是这个）
#   ALLOWED      策略在内核里，但受限进程仍读得到（策略**没生效** —— 不许静默接受）
#   UNRESTRICTED 策略根本不在内核里（策略**不在**那条臂要的就是这个）
#
# 为什么必须有第三种：`aa-exec -p <名>` 在策略没加载时会**自己失败**（rc≠0），
# 若把它读成 DENIED，那么"策略不在"这条臂的自证会**空洞地通过** —— 一个没加载的策略
# 与一个成功挡住攻击的策略在数据上同形，正是这一类脚本最坏的形态。
cmd_policy_probe() {
  local rc=0
  if ! profile_loaded; then
    echo "UNRESTRICTED"
    return 0
  fi
  aa-exec -p "$PROFILE_NAME" -- head -1 /etc/shadow >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "ALLOWED"
    return 1
  fi
  echo "DENIED"
  return 0
}

cmd_agent_install() {
  local src="${1:-/tmp/sandcat.new}"
  [ -f "$src" ] || die "载荷不存在: $src"
  # **先落到临时名再 mv**（与 CT 侧同一条实测）：直接覆盖**正在执行**的 /root/sandcat 会
  # `text file busy`，而"有没有活着的 agent"这条判据可能恰好在这时候判成"没有"。
  mv -f "$src" "$SANDCAT" || die "把载荷落地成 $SANDCAT 失败"
  chmod 755 "$SANDCAT" || die "chmod $SANDCAT 失败"
  echo "installed"
}

# cmd_agent_start <server> <group> <profile|->
#   · profile = `-` ⇒ 直接跑 sandcat（**策略不在**那条臂）；
#   · profile = <名> ⇒ `aa-exec -p <名> -- /root/sandcat …`（**策略在**那条臂）。
# 用 `setsid` + 三个重定向：调用方那条 ssh 通道一断，没有 setsid 的子进程会被带走
# （edge_lab.sh 的 lab_target_exec_detached 已经 nohup 了本脚本本身，这一层是给 sandcat 的）。
cmd_agent_start() {
  local server="${1:-}" group="${2:-}" profile="${3:--}" pids
  [ -n "$server" ] || die "agent-start 需要 <server>（C2 地址）"
  [ -n "$group" ] || die "agent-start 需要 <group>（投送组名，与攻击侧同源）"
  [ -x "$SANDCAT" ] || die "$SANDCAT 不可执行（先 agent-install）"
  : > "$SANDCAT_LOG"
  if [ "$profile" = "-" ]; then
    setsid "$SANDCAT" --server "$server" --group "$group" >>"$SANDCAT_LOG" 2>&1 </dev/null &
  else
    profile_loaded || die "agent-start 指定了 profile=$profile，但它没进内核策略表"
    setsid aa-exec -p "$profile" -- "$SANDCAT" --server "$server" --group "$group" \
      >>"$SANDCAT_LOG" 2>&1 </dev/null &
  fi
  sleep 1
  pids="$(pgrep -x sandcat 2>/dev/null | tr '\n' ' ')"
  if [ -z "$pids" ]; then
    echo "edge_vm_guest: 拉起后没有 sandcat 进程；$SANDCAT_LOG 尾部：" >&2
    tail -20 "$SANDCAT_LOG" >&2 || true
    die "agent-start 失败"
  fi
  echo "started pids=$pids"
}

cmd_agent_stop() {
  pkill -x sandcat 2>/dev/null || true
  sleep 1
  echo "stopped"
}

# cmd_route_add <cidr> <via> <dev> —— 到 C2 网段的静态路由。
# 为什么需要它（Task 15 实测、Task 16 记进设计文档）：VM 挂在 `vmbr1`（192.168.1.0/24），
# 而 Caldera 只绑在宿主的 `vmbr0` 地址（192.168.30.2）上 ⇒ 客人要经**宿主自己在 vmbr1 上
# 的地址**（192.168.1.242）绕过去。这条路成立**只因为目标是宿主自己的地址**（本机投递，
# 不需要 `ip_forward`，而宿主上 `net.ipv4.ip_forward = 0`）。
cmd_route_add() {
  local cidr="${1:-}" via="${2:-}" dev="${3:-}"
  [ -n "$cidr" ] && [ -n "$via" ] && [ -n "$dev" ] || die "route-add 需要 <cidr> <via> <dev>"
  ip route replace "$cidr" via "$via" dev "$dev" || die "加路由失败: $cidr via $via dev $dev"
  echo "route-ok"
}

cmd_route_del() {
  local cidr="${1:-}"
  [ -n "$cidr" ] || die "route-del 需要 <cidr>"
  ip route del "$cidr" 2>/dev/null || true
  echo "route-del"
}

cmd_net_report() {
  local iface="${1:-}"
  [ -n "$iface" ] || die "net-report 需要 <iface>"
  printf 'iface=%s cidr=%s\n' "$iface" "$(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}')"
  printf 'default=%s\n' "$(ip route show default 2>/dev/null | head -n 1)"
  printf 'routes=%s\n' "$(ip route 2>/dev/null | tr '\n' ';')"
}

# cmd_c2_probe <url> —— 从**客人里**问一次 Caldera 的 API。
# 判据是"HTTP 200 + 正确的 KEY"，不是"TCP 通了"：8888 上可能是别的东西在听。
# 口令走 `AVE_C2_KEY` 环境变量（由调用点用 `env` 的赋值格传入），**不进本脚本的 argv**。
cmd_c2_probe() {
  local url="${1:-}" key="${AVE_C2_KEY:-}" code=""
  [ -n "$url" ] || die "c2-probe 需要 <url>"
  if command -v curl >/dev/null 2>&1; then
    code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' -H "KEY: $key" "$url/api/v2/abilities" 2>/dev/null || true)"
  elif command -v python3 >/dev/null 2>&1; then
    code="$(AVE_URL="$url" python3 -c '
import os, urllib.request
try:
    r = urllib.request.Request(os.environ["AVE_URL"] + "/api/v2/abilities",
                               headers={"KEY": os.environ.get("AVE_C2_KEY", "")})
    print(urllib.request.urlopen(r, timeout=8).status)
except Exception:
    print("000")
' 2>/dev/null || true)"
  else
    die "客人里既没有 curl 也没有 python3 —— 无法自证 C2 可达（不静默跳过：那一跳过会让一个地址给错的环境一路跑到 agent 超时）"
  fi
  printf '%s\n' "${code:-000}"
}

SUBCMD="${1:-}"
[ -n "$SUBCMD" ] || die "用法: edge_vm_guest.sh <子命令> [参数…]（子命令清单见文件头）"
shift

case "$SUBCMD" in
  policy-status)  cmd_policy_status ;;
  policy-apply)   cmd_policy_apply "$@" ;;
  policy-remove)  cmd_policy_remove ;;
  policy-probe)   cmd_policy_probe ;;
  agent-install)  cmd_agent_install "$@" ;;
  agent-start)    cmd_agent_start "$@" ;;
  agent-stop)     cmd_agent_stop ;;
  route-add)      cmd_route_add "$@" ;;
  route-del)      cmd_route_del "$@" ;;
  net-report)     cmd_net_report "$@" ;;
  c2-probe)       cmd_c2_probe "$@" ;;
  *) die "未知子命令 '$SUBCMD'（只认 policy-status|policy-apply|policy-remove|policy-probe|agent-install|agent-start|agent-stop|route-add|route-del|net-report|c2-probe）" ;;
esac
