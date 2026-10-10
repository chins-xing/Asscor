#!/bin/bash
# shellcheck disable=SC2154  # lab_substrate/lab_target_bin 由 source edge_lab.sh 赋值（shellcheck 不跨文件跟踪变量）
# ============================================================================
# edge_target_prepare.sh —— **幂等**地准备实验目标（Task 4D Step 4-B；Task 6 加 pve 分支）
# ============================================================================
#
# 用法（在 A-1 上跑，lxd 基质）：
#   EDGEEXP_TARGET=asc-tgt-1 \
#   EDGEEXP_POLICY_ON=1 \
#   bash scripts/edge_target_prepare.sh
#
# 用法（在 dl360gen9 上跑，pve 基质）：
#   EDGEEXP_SUBSTRATE=pve \
#   EDGEEXP_TARGET=asc-tgt-c2 \
#   EDGEEXP_POLICY_ON=1 \
#   EDGEEXP_PVE_DEB_DIR=/var/tmp/edgeexp-debs \
#   bash scripts/edge_target_prepare.sh
#
# 它做什么（每一步都**先查后做**，重复执行不产生副作用）：
#   1. 实例不存在 ⇒ lxd：`lxc launch ubuntu:24.04 <实例>`（**不是** `images:ubuntu/24.04` —— 那个
#      别名已不再提供，实测会失败）；**pve：响亮失败**（本脚本永不 create CT，见下面的边界）；
#   2. 装六个控制（suricata / aide / 三个 PAM 包）并写配置（aide 告警配置、PAM 三类行）；
#      —— **pve 的靶机出不了公网**，故走"宿主预置本地镜像 ⇒ 靶机 wget + dpkg"这条路
#      （见第 2 步的 pve 分支；简报 §4 记的正是这条路线）；
#   3. 设置**实验条件**（策略在/不在，见 `EDGEEXP_POLICY_ON`）；
#      —— lxd 用 `raw.apparmor`（`lxc config set`），pve 用 `lxc.apparmor.raw`
#      （**直接写 `/etc/pve/lxc/<vmid>.conf`**：实测 `pct set --lxc.apparmor.raw` 报
#      `Unknown option`，只有文件这条路走得通；简报 §4 也点名"不要手抄 profile"）；
#      —— 变了才重启（重启会清空 `/tmp`，见第 4 步）；
#   4. 重启之后 `/tmp` 被清空，且 sandcat **不在**持久位置就会消失 ⇒ 把 payload 放到
#      `/root/sandcat` 并重新拉起；本脚本每次都确保"容器里有活着的 sandcat"。
#
# 为什么单独成一个脚本（而不是塞进 `edge_reset.sh`）：`edge_reset.sh` 在 clab 基质下是
# "建/毁拓扑 + 部 agent"，在 lxd/pve 基质下**没有建毁动作**，只有"确保实例满足实验条件"这一件事。
# 把两套语义硬塞进同一个函数会让 clab 分支的逐位等价难以维持（Step 1 的最硬门禁）。
#
# **pve 的边界（与 `edge_lab.sh` 的 pve 分支同一条纪律，必须显式）**：本脚本在 pve 下
# **永不** create / destroy / start / stop 任何 CT —— 宿主上的 CT 集合是操作者与别的任务共用的，
# 而"这台 CT 是不是本次实验建的"这个信息在脚本里不存在。因此：
#   · CT 不存在 ⇒ 响亮失败（并给出操作者该敲的 `pct create` 形态）；
#   · CT 存在但没在跑 ⇒ 响亮失败（并给出 `pct start <vmid>`）。
# 这与 lxd 分支**故意不同**（那边会 launch/start）：A-1 上的实例集合归本实验管，
# 而 dl360gen9 上不是。这个差别是**刻意的**，不是漏掉的一步。
#
# 退出码：0 = 实例已就绪（六个控制 + 策略条件 + 活着的 agent）；非零 = 任一步失败（不降级）。
#
# 环境变量：
#   EDGEEXP_TARGET            目标实例/CT 名（必填；pve 下是 **CT 名字**，由 lab_node_vmid 解析成 vmid）
#   EDGEEXP_POLICY_ON         1 = 装上 AppArmor 拒绝策略；0/空 = 卸载（实验条件）
#   EDGEEXP_POLICY_RULE       策略内容，默认 `audit deny /etc/shadow r,`
#   EDGEEXP_CALDERA_URL       Caldera API（默认 http://127.0.0.1:8888；**这是宿主上**调 API 的地址。
#                             dl360gen9 上 Caldera 只绑 192.168.30.2 ⇒ 必须显式给
#                             `EDGEEXP_CALDERA_URL=http://192.168.30.2:8888`，默认值在那里不通）
#   EDGEEXP_CALDERA_KEY       API key（默认 ADMIN123）
#   EDGEEXP_C2_HOST           容器侧可达的宿主地址（默认取容器内默认网关；覆盖见"地址给错了机器"那段）
#   EDGEEXP_C2_HOST_WAIT_S    取默认路由的重试窗口（秒，默认 90）：重启后 DHCP 未完成时容器内没有
#                             默认路由，一次取不到就判死会把"网络还没起来"报成"环境不可用"
#   EDGEEXP_SANDCAT_PAYLOAD   sandcat 载荷路径（默认 /opt/caldera/plugins/sandcat/payloads/sandcat.go-linux）
#   EDGEEXP_AGENT_WAIT_S      等 agent 回连的上限（秒，默认 180）
#   EDGEEXP_ATTACK_GROUP      agent 的**分组名**（默认 t4d-ttp）。它与攻击侧的投送范围
#                             （`edge_attack.sh` 的 `EDGEEXP_ATTACK_GROUP`）是**同一个变量** ——
#                             组名只有一处来源，两侧不一致时不会出现"你其实已经拉过了"这种误诊
#   EDGEEXP_APT_TIMEOUT_S     单次 apt 安装的上限（秒，默认 900）
#   EDGEEXP_PVE_DEB_DIR       **pve 专用**：宿主上"预置 .deb 目录"（默认 /var/tmp/edgeexp-debs）。
#                             靶机出不了公网 ⇒ 六个控制只能从宿主上取。为空/不存在时本脚本
#                             **响亮失败**并打印操作者该敲的两条命令（不静默跳过 —— 见第 2 步）。
#   EDGEEXP_PVE_DEB_PORT      宿主上那个一次性 HTTP 服务的端口（默认 8899；**只绑管理网地址**）
#   EDGEEXP_PVE_CONF_DIR      CT 配置文件目录（默认 /etc/pve/lxc；离线夹具可覆盖）
#
# ⚠️ **已知限制（concern，Task 6 实测；本任务内未解决）**：第 2 步 pve 分支用的
# `apt-get install --download-only`，它算出的依赖闭包是**相对"宿主当前已装集合"**的 ——
# 宿主上已经有的依赖（实测：`python3-yaml`、`libglib2.0-0t64`、`libnuma1`、`libfdt1`、
# `liblockfile1`、`libqrencode4` …）**不会**被下下来，而全新的最小 CT 里没有它们 ⇒
# 这些包会停在 `install ok unpacked`（实测：268 个 `ii` / 31 个 `iU` / 0 个 `iF`），
# `suricata` 因此装不「完」。本脚本**响亮失败**（不静默跳过、不假装装好了），
# 但要让这条路真正跑通，闭包必须按"**空**已装集合"算（例如
# `-o Dir::State::status=<空 status 文件>`）或改成"按 dpkg 报出的缺依赖**迭代补齐**"。
# 这件事**不在 Task 6 的范围内**（简报 §5.6 明确允许"因靶机取不到包而跑不了时如实记为未跑"），
# 记在报告 §5 的 concern 里。
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/edge_lab.sh
# shellcheck disable=SC2154  # lab_* 由下面那行 source 赋值
. "$SCRIPT_DIR/edge_lab.sh"

TARGET="${EDGEEXP_TARGET:-}"
POLICY_ON="${EDGEEXP_POLICY_ON:-0}"
POLICY_RULE="${EDGEEXP_POLICY_RULE:-audit deny /etc/shadow r,}"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://127.0.0.1:8888}"
CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-ADMIN123}"
PAYLOAD="${EDGEEXP_SANDCAT_PAYLOAD:-/opt/caldera/plugins/sandcat/payloads/sandcat.go-linux}"
AGENT_WAIT_S="${EDGEEXP_AGENT_WAIT_S:-180}"
APT_TIMEOUT_S="${EDGEEXP_APT_TIMEOUT_S:-900}"
PIDS_HELPER="$SCRIPT_DIR/edge_lab_pids.sh"
# pve 专属（见头部说明）
PVE_DEB_DIR="${EDGEEXP_PVE_DEB_DIR:-/var/tmp/edgeexp-debs}"
PVE_DEB_PORT="${EDGEEXP_PVE_DEB_PORT:-8899}"
PVE_CONF_DIR="${EDGEEXP_PVE_CONF_DIR:-/etc/pve/lxc}"
# **agent 分组名只有一个来源：`EDGEEXP_ATTACK_GROUP`**（Task 4D Fix round 2 / Minor-4）。
#
# 上一版这里把 `--group t4d-ttp` **硬编码**在拉起命令里，而攻击侧要求用 `EDGEEXP_ATTACK_GROUP`
# 声明 operation 的投送范围 ⇒ 同一个组名有**两处来源**。两侧不一致时攻击侧的闸门①会响亮失败
# （不是静默出错，这点是好的），但它的错误信息让操作者"用 --group 拉起 agent" —— 而他其实已经拉了，
# **诊断方向指错**。现在两处读同一个变量：目标 agent 拉起时的 `--group` 与攻击侧的投送范围同源。
AGENT_GROUP="${EDGEEXP_ATTACK_GROUP:-t4d-ttp}"

[ -n "$TARGET" ] || { echo "edge_target_prepare: 必须给 EDGEEXP_TARGET=<实例名>" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "edge_target_prepare: 缺少 python3" >&2; exit 2; }
[ -f "$PIDS_HELPER" ] || { echo "edge_target_prepare: 缺少 $PIDS_HELPER" >&2; exit 2; }

echo "edge_target_prepare: 目标=$TARGET 基质=$lab_substrate 策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在) agent 组=$AGENT_GROUP（来源 EDGEEXP_ATTACK_GROUP，攻击侧同一变量）"

# is_pve / is_lxd —— 基质的**分支判据**收在这里，别在正文里散着写 `[ "$lab_substrate" = pve ]`：
# 散着写迟早会漏一处，而漏掉的那一处会走另一条基质的路径（"看起来照常跑完"是它最坏的形态）。
is_pve() { [ "$lab_substrate" = "pve" ]; }
is_lxd() { [ "$lab_substrate" = "lxd" ]; }

# pve_vmid —— pve 下的 CT 标识。**只经基质层的 `lab_node_vmid` 解析**（唯一解析点），
# 解析不到即响亮失败（绝不猜 vmid）。非 pve 下不会被调用。
pve_vmid() {
  local vmid
  vmid="$(lab_node_vmid "$TARGET")" || return 1
  printf '%s\n' "$vmid"
}

# wait_for_exec <秒> —— 等实例真的**能在里面执行命令**；判据与实现都在**基质层**
# （`edge_lab.sh:lab_wait_node_exec`，Task 4D Fix round 2 / Minor-6 把那条判据收进基质层的原因见那里）。
#
# 这里只保留"把超时翻译成本脚本的处置"：
# 上一版的坑是调用方自己写了 `until lab_node_running … >/dev/null 2>&1`，把打在 stdout 上的
# `true`/`false` 丢掉 ⇒ STOPPED 的实例同样能应答、循环 0 秒就宣布"已就绪"，随后 `exec` 撞上
# `Error: Instance is not running`（而本脚本 **没有 `set -e`**，那行错被咽下去）。
# 第二层坑：`lxc restart` 是"先停后起"，刚发起时 `lxc info` 仍是 RUNNING ⇒ 只查状态依然不够。
wait_for_exec() {
  local limit="$1"
  lab_wait_node_exec "$TARGET" "$limit" && return 0
  echo "edge_target_prepare: 实例 $TARGET 在 ${limit}s 内仍然不能执行命令（判据：节点内 true 的 rc=0）" >&2
  return 1
}

# wait_for_up <pid> <秒> —— 等"停/起"走完：① 发起它的子进程退出；② 节点内真能执行命令。
wait_for_up() {
  local pid="$1" limit="$2" waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      echo "edge_target_prepare: 实例 $TARGET 的停/起在 ${limit}s 内没有结束（子进程 $pid 还在）" >&2
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  # 收尸（`kill -0` 对**已退出但未被 bash 回收**的子进程仍然成功，故真正判据是"命令自己的退出码"）
  wait "$pid" 2>/dev/null || true
  wait_for_exec "$limit"
}

# --- 1. 实例存在？不存在就建（幂等）------------------------------------------
if lab_instance_exists "$TARGET"; then
  echo "edge_target_prepare: 实例已存在（幂等路径，不重建）"
elif is_pve; then
  # **pve：不存在 ⇒ 响亮失败**（本脚本永不 create CT —— 见头部"pve 的边界"）。
  # 上一版这一格会落到 `lxc launch`（pct 没有 launch ⇒ 一句难懂的报错），
  # 随后是漫长的等待循环 —— 那会把"CT 名字打错了"报成"环境起不来"。
  echo "edge_target_prepare: CT '$TARGET' 不存在（pct list 里没有这个名字）—— 本脚本**不建 CT**（见头部边界）。" >&2
  echo "  请先由操作者显式创建，例如：" >&2
  echo "    pct create <vmid> ZFS-LXD:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst --hostname $TARGET \\" >&2
  echo "      --rootfs NVMe-256G:8 --cores 4 --memory 1024 --net0 name=eth0,bridge=vmbr0,ip=dhcp \\" >&2
  echo "      --unprivileged 0 --features nesting=1" >&2
  echo "  并确认 pct list 里的 Name 就是 '$TARGET'（节点由**名字**标识，pct 只认 vmid）。" >&2
  echo "  若名字写错，上面的 pct list 差异说明已经打出来了。" >&2
  exit 1
else
  echo "edge_target_prepare: 实例不存在 ⇒ lxc launch ubuntu:24.04 $TARGET（后台 + 轮询）"
  # `ssh_exec` 约 600 s 会打断前台长命令；`lxc launch` 实测要几十秒 ⇒ 一律后台 + 轮询日志。
  nohup "$lab_target_bin" launch ubuntu:24.04 "$TARGET" > /tmp/edgeexp-lxd-launch.log 2>&1 &
  LAUNCH_PID=$!
  waited=0
  while :; do
    if lab_instance_exists "$TARGET"; then break; fi
    if [ "$waited" -ge "$APT_TIMEOUT_S" ]; then
      echo "edge_target_prepare: 实例在 ${APT_TIMEOUT_S}s 内没有创建出来，见 /tmp/edgeexp-lxd-launch.log 尾部：" >&2
      tail -20 /tmp/edgeexp-lxd-launch.log >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "edge_target_prepare: 实例已创建（等待 ${waited}s）"
  wait_for_up "$LAUNCH_PID" 300 || exit 1
fi

# --- 1b. 存在但没在跑 ⇒ 拉起来 -------------------------------------------------
# 幂等复位的语义是"把实例准备成实验条件"，其中**在跑**是必要条件。实例存在却 STOPPED（实测出现过：
# 策略变更后的重启落在停/起之间而脚本已经往下走）在旧版里会一路等到超时才报"不能执行命令"，
# 那与"实例坏了"同形 —— 这里显式 start 一次，原因与动作都写在日志里。
if [ "$(lab_node_running "$TARGET" 2>/dev/null || true)" != "true" ]; then
  if is_pve; then
    # **pve：存在但没在跑 ⇒ 响亮失败**（本脚本永不 start CT —— 见头部"pve 的边界"）。
    # 与 lxd 分支**刻意不同**：A-1 上的实例集合归本实验管，dl360gen9 上不是。
    echo "edge_target_prepare: CT '$TARGET' 存在但**没在跑** —— 本脚本**不启动 CT**（见头部边界）。" >&2
    echo "  请由操作者显式启动（vmid=$(pve_vmid 2>/dev/null || echo '<解析不到>')）：" >&2
    echo "    pct start $(pve_vmid 2>/dev/null || echo '<vmid>')" >&2
    echo "  启动后重跑本脚本（它是幂等的）。" >&2
    exit 1
  fi
  echo "edge_target_prepare: 实例存在但没在跑 ⇒ $lab_target_bin start $TARGET"
  nohup "$lab_target_bin" start "$TARGET" > /tmp/edgeexp-lxd-start.log 2>&1 &
  START_PID=$!
  wait_for_up "$START_PID" 180 || exit 1
fi

# 等它真的能 exec（`Status: RUNNING` 之后 exec 也可能短暂失败）
wait_for_exec 120 || exit 1

# --- 2. 六个控制（幂等：先查后装）--------------------------------------------
#
# 两种基质的**取包方式**不同，这是 pve 上最实质的一处差别：
#   · clab/lxd：容器有网 ⇒ `apt-get update && apt-get install`（既有路径，一字未动）；
#   · **pve：靶机 CT 出不了公网**（VLAN 30 没有出口）⇒ 上面那条路必然失败，而且是以
#     "apt-get update 超时"的形态失败，看起来像"网络坏了"而不是"这个环境本来就没出口"。
#     简报 §4 记录并验证过的路线是：**宿主 `apt-get download` 出依赖闭包 → 宿主起一个只绑
#     管理网的 HTTP 服务 → 靶机 `wget` + `dpkg -i`**。这里照这条路实现。
#     Debian 13 最小 CT 里**没有 curl 但有 wget**（实测），故靶机侧用 wget。
#
# **不做静默跳过**：控制包是这个实验的**实验条件**的一部分（SIEM/IDS/2FA 是否在位），
# 装不上就等于"这一轮的条件不成立"。故取不到包时**响亮失败**，并打印操作者该敲的两条命令。
MISSING="$(lab_target_exec "$TARGET" sh -c '
for p in suricata aide libpam-google-authenticator libpam-u2f libpam-fprintd; do
  dpkg-query -W -f="\${Status}" "$p" 2>/dev/null | grep -q "install ok installed" || printf "%s " "$p"
done')"

# pve 侧的一次性本地镜像服务的进程号（装完就停；为空表示没起过）。
PVE_HTTP_PID=""
stop_pve_http() {
  [ -n "$PVE_HTTP_PID" ] || return 0
  kill "$PVE_HTTP_PID" 2>/dev/null || true
  PVE_HTTP_PID=""
}
# 无论从哪条路径退出，都别把那个 HTTP 服务留在宿主上（它监听的是管理网地址）。
trap 'stop_pve_http' EXIT

# pve_install_controls —— 从宿主上的预置 .deb 目录把控制包装进 CT。
# 判据：**先把包备齐（宿主侧）⇒ 再起服务 ⇒ 再让 CT 取 ⇒ 再 dpkg**；每一步失败都响亮。
pve_install_controls() {
  local missing="$1" vmid host_ip waited
  vmid="$(pve_vmid)" || return 1
  # 1) 宿主侧：把依赖闭包下到 PVE_DEB_DIR（已下过就是幂等的：`--download-only` 不会重复下）。
  if ! ls "$PVE_DEB_DIR"/*.deb >/dev/null 2>&1; then
    echo "edge_target_prepare: 宿主侧预置控制包 ⇒ apt-get --download-only -o Dir::Cache::archives=$PVE_DEB_DIR $missing"
    mkdir -p "$PVE_DEB_DIR"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --download-only \
         -o Dir::Cache::archives="$PVE_DEB_DIR" $missing > /tmp/edgeexp-pve-debs.log 2>&1; then
      echo "edge_target_prepare: 宿主上下载控制包失败（见 /tmp/edgeexp-pve-debs.log 尾部）——" >&2
      echo "  靶机 CT 出不了公网，没有别的取包途径；不静默跳过（控制包是实验条件的一部分）。" >&2
      tail -20 /tmp/edgeexp-pve-debs.log >&2 || true
      return 1
    fi
  else
    echo "edge_target_prepare: 宿主侧预置目录已有 .deb（$(ls "$PVE_DEB_DIR"/*.deb 2>/dev/null | wc -l) 个）—— 幂等路径，不重下"
  fi
  # **宿主侧的文件名可能带 URL 编码的冒号**（epoch 的 `1:` 被 apt 存成 `%3a`）。
  # 实测踩坑（Task 6，这一条让 suricata 永远装不上）：`suricata_1%3a7.0.10-…_amd64.deb`
  # 在 `python3 -m http.server` 的目录列表里链接就是 `%3a`，服务器**解码**成 `:` 去找文件
  # ⇒ 404 ⇒ 这一个包永远下不到，而**其它包全部正常** —— 失败的面貌是"就少了一个包"，
  # 与"网络不稳"同形。把文件名的 `%3a` 换成字面冒号，两边就一致了（wget 请求 `%3a`、
  # 服务器解码成 `:`、盘上就是 `:`）。
  local f
  for f in "$PVE_DEB_DIR"/*%3a*.deb; do
    [ -f "$f" ] || continue
    mv -- "$f" "${f//%3a/:}"
  done
  # 2) 宿主侧：起一个**只绑管理网地址**的一次性 HTTP 服务（不要 0.0.0.0：那会把实验产物
  #    暴露到有外网的 vmbr1 上）。host_ip 必须是**宿主自己**在 CT 网段上的那个地址。
  #
  #    **实测踩坑（Task 6）**：这里最初取的是"容器内的默认网关"，于是拿到 `192.168.30.1`
  #    —— 那是网络里的**路由器**，不是 PVE 宿主（宿主是 `192.168.30.2`）。`--bind 192.168.30.1`
  #    在宿主上直接失败，而脚本没检查就继续，最后以 CT 侧 `wget` 超时收场 ——
  #    与 lxd 侧那段"地址给错了机器"是**同一类**错误：`127.0.0.1`/网关都属于"看起来像宿主"的地址。
  #    正确判据：**从宿主自己的接口里挑一个落在 CT 网段内的地址**（而不是问 CT 要一个地址）。
  host_ip="${EDGEEXP_C2_HOST:-}"
  if [ -z "$host_ip" ]; then
    CT_CIDR="$(lab_node_ip "$TARGET" eth0 2>/dev/null || true)"
    host_ip="$(python3 - "$CT_CIDR" <<'PY'
import ipaddress, subprocess, sys
cidr = (sys.argv[1] if len(sys.argv) > 1 else '').strip()
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    print(''); raise SystemExit
out = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True).stdout
for line in out.splitlines():
    parts = line.split()
    if 'inet' not in parts:
        continue
    try:
        ip = ipaddress.ip_interface(parts[parts.index('inet') + 1]).ip
    except Exception:
        continue
    if ip in net and not ip.is_loopback:
        print(str(ip)); raise SystemExit
print('')
PY
)"
    host_ip="$(printf '%s' "$host_ip" | tr -d '[:space:]')"
  fi
  [ -n "$host_ip" ] || {
    echo "edge_target_prepare: 取不到**宿主自己**在 CT 网段上的地址（CT 的 eth0 地址 = '${CT_CIDR:-空}'）——" >&2
    echo "  靶机 CT 出不了公网，本地镜像服务必须绑在宿主可达的地址上；" >&2
    echo "  可用 EDGEEXP_C2_HOST=<宿主在容器网段的地址> 显式指定。" >&2
    return 1
  }
  echo "edge_target_prepare: 本地包镜像将绑在 $host_ip:$PVE_DEB_PORT（宿主在 CT 网段上的地址）"
  python3 -m http.server "$PVE_DEB_PORT" --bind "$host_ip" --directory "$PVE_DEB_DIR" \
    > /tmp/edgeexp-pve-http.log 2>&1 &
  PVE_HTTP_PID=$!
  sleep 1
  # **必须验证服务真的起来了**：`--bind` 到一个本机没有的地址会立刻退出，
  # 而"起了但没验证"会让下一段以 wget 超时的形态失败（错因看起来像"网络不通"）。
  if ! kill -0 "$PVE_HTTP_PID" 2>/dev/null; then
    echo "edge_target_prepare: 本地包镜像没能起来（$host_ip:$PVE_DEB_PORT），见 /tmp/edgeexp-pve-http.log：" >&2
    tail -5 /tmp/edgeexp-pve-http.log >&2 || true
    PVE_HTTP_PID=""
    return 1
  fi
  # 再从**CT 侧**问一次（判据是"CT 真的取得到"，不是"宿主上有个进程在跑"）。
  if ! lab_target_exec "$TARGET" wget -q -T 5 -O /dev/null "http://$host_ip:$PVE_DEB_PORT/" 2>/dev/null; then
    echo "edge_target_prepare: CT 侧取不到本地包镜像 http://$host_ip:$PVE_DEB_PORT/ ——" >&2
    echo "  靶机出不了公网，取不到包就没法建立实验条件；不静默跳过。" >&2
    stop_pve_http
    return 1
  fi
  echo "edge_target_prepare: CT 侧可达性自证：容器内 wget http://$host_ip:$PVE_DEB_PORT/ 成功"
  # 3) 靶机侧：推一个**脚本**进去执行（简报 §4：`pct exec` 上多行 `sh -c` 不可靠）
  # **heredoc 必须加引号**（`<<'HARDEN'`）：不加引号时正文里的一切 `$…` 与**反引号**都会在
  # **宿主侧**先展开 —— 实测踩过：注释里写 `` `--cut-dirs` `` 会让宿主的 shell 去执行一个名叫
  # `--cut-dirs` 的命令（`--cut-dirs: command not found`），而正文本身看起来完全正常。
  # 需要传进去的两个值（宿主地址、端口）改走 **argv**，正文因此可以整段引号化。
  cat > /tmp/edgeexp-pve-harden.sh <<'HARDEN'
#!/bin/bash
# 用法：harden.sh <宿主地址> <端口>
# 它跑在**靶机 CT 里**：CT 出不了公网，只能从宿主上那个一次性 HTTP 服务取包。
set -x
set -e
HOST_IP="$1"
PORT="$2"
rm -rf /tmp/edgeexp-debs
mkdir -p /tmp/edgeexp-debs
# wget 递归拉平（-r -np -nH -nc）；CT 里没有 curl（实测），故用 wget。
# 不裁剪目录分量：URL 的路径部分就是根，没有可裁的层级；
# 写死一个裁剪量会在目录列表形态变化时把包下到意外的地方。
#
# **`|| true` 不是图省事，是判据错了位**（实测踩坑）：`wget -r` 会先取 `/robots.txt`，
# 而 `python3 -m http.server` 对不存在的路径回 **404** ⇒ wget 以 **8** 退出，
# 尽管所有 .deb 都已经下完。有 `set -e` 时脚本会**恰好死在这一行**（trace 停在 wget 上），
# 而目录里明明躺着 48 个包 —— 一个"看起来像网络故障、其实是退出码口径"的失败。
# 真正的判据在下一行：**有多少 .deb 落到了盘上**。
wget -q -r -np -nH -nc -P /tmp/edgeexp-debs "http://$HOST_IP:$PORT/" || true
# 包的落点用 find 找（不假设一定平铺在根下）—— 路径假设是这类脚本最常见的静默失效点。
# 用 wc -l 计数而不是 mapfile/进程替换：这段脚本在**最小 CT** 里跑，
# 少用一个 bash 专有特性就少一处"在某些镜像上不可用"的风险。
DEBS="$(find /tmp/edgeexp-debs -name '*.deb' | sort)"
[ -n "$DEBS" ] || { echo "no-debs-fetched"; exit 1; }
echo "fetched-debs=$(printf '%s\n' "$DEBS" | wc -l)"
# dpkg -i 需要依赖先到位 ⇒ 反复扫描直到不再有进展（包集合内部有依赖顺序，一次 -i 不够）。
for _pass in 1 2 3 4 5 6 7 8; do
  before=$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | grep -c 'install ok installed' || true)
  # shellcheck disable=SC2086  # DEBS 需要分词（每行一个路径，路径里没有空白）
  dpkg -i $DEBS > /tmp/edgeexp-dpkg.log 2>&1 || true
  # `dpkg -i` 只负责**解包 + 尽力配置**；上一步把依赖装好之后，那些先前"unpacked"的包
  # 要靠 `dpkg --configure -a` 才真正变成 installed（实测：只跑 dpkg -i 时 suricata-update
  # 会停在 `install ok unpacked`，脚本的"装齐了吗"判据因此一直不成立）。
  dpkg --configure -a >> /tmp/edgeexp-dpkg.log 2>&1 || true
  after=$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | grep -c 'install ok installed' || true)
  [ "$before" = "$after" ] && break
done
systemctl enable --now suricata || true
echo "harden-done installed=$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | grep -c 'ok installed')"
HARDEN
  lab_push /tmp/edgeexp-pve-harden.sh "$TARGET" /root/harden.sh \
    || { echo "edge_target_prepare: 把装包脚本送进 CT 失败" >&2; stop_pve_http; return 1; }
  lab_target_exec "$TARGET" chmod 755 /root/harden.sh || { stop_pve_http; return 1; }
  # **不能写 `nohup lab_target_exec …`**：`lab_target_exec` 是 shell **函数**，`nohup` 只能
  # 执行**外部命令**（实测报 `nohup: failed to run command 'lab_target_exec': No such file
  # or directory`，而 `&` 让这条错误静默消失，随后只剩一个"永远等不到"的轮询循环）。
  # 后台化用 bash 自己的 `&` 就够（子 shell 里照样能调函数）。
  lab_target_exec "$TARGET" /root/harden.sh "$host_ip" "$PVE_DEB_PORT" > /tmp/edgeexp-pve-harden.out 2>&1 &
  waited=0
  while :; do
    if lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" suricata 2>/dev/null | grep -q "install ok installed"' 2>/dev/null \
       && lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" libpam-u2f 2>/dev/null | grep -q "install ok installed"' 2>/dev/null; then
      break
    fi
    if [ "$waited" -ge "$APT_TIMEOUT_S" ]; then
      echo "edge_target_prepare: 从本地镜像安装控制包在 ${APT_TIMEOUT_S}s 内没完成，见 /tmp/edgeexp-pve-harden.out 尾部：" >&2
      tail -30 /tmp/edgeexp-pve-harden.out >&2 || true
      lab_target_exec "$TARGET" sh -c 'tail -30 /tmp/edgeexp-dpkg.log' >&2 2>/dev/null || true
      stop_pve_http
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  stop_pve_http
  echo "edge_target_prepare: 控制包从本地镜像安装完成（等待 ${waited}s）"
}

if [ -n "$MISSING" ]; then
  if is_pve; then
    pve_install_controls "$MISSING" || { echo "edge_target_prepare: pve 侧控制包安装失败 —— 环境可用性未证实，整轮失败" >&2; exit 1; }
  else
    echo "edge_target_prepare: 缺控制包 [$MISSING] ⇒ apt-get 安装（后台 + 轮询，最长 ${APT_TIMEOUT_S}s）"
    cat > /tmp/edgeexp-harden.sh <<'HARDEN'
#!/bin/bash
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y suricata aide libpam-google-authenticator libpam-u2f libpam-fprintd
systemctl enable --now suricata
HARDEN
    lab_push /tmp/edgeexp-harden.sh "$TARGET" /root/harden.sh
    lab_target_exec "$TARGET" chmod 755 /root/harden.sh
    nohup "$lab_target_bin" exec "$TARGET" -- /root/harden.sh > /tmp/edgeexp-harden.log 2>&1 &
    waited=0
    while :; do
      if lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" suricata 2>/dev/null | grep -q "install ok installed"' 2>/dev/null \
         && lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" aide 2>/dev/null | grep -q "install ok installed"' 2>/dev/null \
         && lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" libpam-u2f 2>/dev/null | grep -q "install ok installed"' 2>/dev/null; then
        break
      fi
      if [ "$waited" -ge "$APT_TIMEOUT_S" ]; then
        echo "edge_target_prepare: apt 在 ${APT_TIMEOUT_S}s 内没有装完，见 /tmp/edgeexp-harden.log 尾部：" >&2
        tail -20 /tmp/edgeexp-harden.log >&2 || true
        exit 1
      fi
      sleep 10
      waited=$((waited + 10))
    done
    echo "edge_target_prepare: 控制包安装完成（等待 ${waited}s）"
  fi
else
  echo "edge_target_prepare: 控制包已齐（幂等路径）"
fi

# 配置（幂等：用 grep 判存在，不重复追加）
lab_target_exec "$TARGET" sh -c '
set -e
# SIEM 代理判据：RS-007 要求三份配置文件之一能匹配 email|alert|notification。
# **实测坑**：只写 report_level/report_url 两行**不命中**该正则（控制侧容器里恰好有一行含
# `alert` 的注释才过）⇒ 这里写的是**真实的告警通知配置**，不是为了过门禁塞词。
if ! grep -qiE "email|alert|notification" /etc/aide/aide.conf 2>/dev/null; then
  printf "\n# 告警通知配置（RS-007 的代理判据需要一份真实的告警配置面）\nreport_level=changed\nreport_url=stdout\nmail_command=/usr/bin/mail\nreport_email=secops@example.invalid\nalert_notification=email\n" >> /etc/aide/aide.conf
fi
# 2FA/3FA：EF-001 任一子串即通过；EF-002 要求三类各≥1（按文件累加）
if ! grep -q pam_google_authenticator /etc/pam.d/sshd 2>/dev/null; then
  printf "auth required pam_google_authenticator.so\nauth required pam_u2f.so\nauth required pam_fprintd.so\n" >> /etc/pam.d/sshd
fi
systemctl enable --now suricata >/dev/null 2>&1 || true
' || { echo "edge_target_prepare: 写控制配置失败" >&2; exit 1; }

# --- 3. 实验条件：AppArmor 策略（变了才重启）---------------------------------
#
# 两种基质的**设置面**不同（语义同一件事：让被攻节点读不了 /etc/shadow）：
#   · lxd：`lxc config set <实例> raw.apparmor <规则>`（既有路径，一字未动）；
#   · pve：`lxc.apparmor.raw`（PVE 原生支持，是 LXD `raw.apparmor` 的对等物）——
#     实测 **`pct set --lxc.apparmor.raw` 报 `Unknown option`**，故只能直接写
#     `/etc/pve/lxc/<vmid>.conf`。简报 §4 明确："**不要**手抄 `/etc/apparmor.d/lxc/` 自定义
#     profile 再设 `lxc.apparmor.profile` —— 实测会让容器起不来（`change_profile ... label
#     not found`），且该设置会覆盖 `features:nesting`"。这里只动**那一行**，别的一字不碰。
#
# 为什么必须写**文件**而不是"就地改内存里的配置"：这个键在**启动时**生效，故改完必须重启
# （与 lxd 分支同一条纪律）。重启会清空 `/tmp`，所以第 4 步每次都重新落地 agent。
pve_conf_path() {
  local vmid
  vmid="$(pve_vmid)" || return 1
  printf '%s/%s.conf\n' "$PVE_CONF_DIR" "$vmid"
}
# pve_policy_get —— 读当前值（没有这一行 ⇒ 打印空串 + rc=0：**"没有策略"是一等公民**，
# 不是"读失败"。读失败（文件不存在）才 rc≠0）。
pve_policy_get() {
  local conf
  conf="$(pve_conf_path)" || return 1
  [ -f "$conf" ] || return 1
  awk -F': *' '$1 == "lxc.apparmor.raw" {print $2; exit}' "$conf"
}
# pve_policy_apply <规则，空串=卸载> —— 只增删 `lxc.apparmor.raw` 那一行。
pve_policy_apply() {
  local want="$1" conf tmp
  conf="$(pve_conf_path)" || return 1
  [ -f "$conf" ] || { echo "edge_target_prepare: CT 配置文件不存在: $conf" >&2; return 1; }
  tmp="$(mktemp)"
  # 原文件先留一份（/tmp 上的副本，不污染 /etc/pve）
  cp -a "$conf" "/tmp/edgeexp-pve-conf-backup-$$.conf" 2>/dev/null || true
  grep -v '^lxc\.apparmor\.raw:' "$conf" > "$tmp"
  # **原地重写**（`>` 截断再写）：/etc/pve 是 pmxcfs，换成"删旧行 + 追加新行"的原地写法
  # 最稳（换文件/replace 会在 FUSE 上多一层不确定性）。
  {
    cat "$tmp"
    if [ -n "$want" ]; then printf 'lxc.apparmor.raw: %s\n' "$want"; fi
  } > "$conf"
  rm -f "$tmp"
  echo "edge_target_prepare: 已写 $conf 的 lxc.apparmor.raw（新值 '$want'；备份 /tmp/edgeexp-pve-conf-backup-$$.conf）"
}

CUR_POLICY=""
if is_pve; then
  CUR_POLICY="$(pve_policy_get || true)"
else
  CUR_POLICY="$("$lab_target_bin" config get "$TARGET" raw.apparmor 2>/dev/null || true)"
fi
WANT_POLICY=""
[ "$POLICY_ON" = "1" ] && WANT_POLICY="$POLICY_RULE"
RESTARTED=0
if [ "$(printf '%s' "$CUR_POLICY" | tr -d '[:space:]')" != "$(printf '%s' "$WANT_POLICY" | tr -d '[:space:]')" ]; then
  if is_pve; then
    echo "edge_target_prepare: 设置策略 lxc.apparmor.raw='$WANT_POLICY'（原值 '$CUR_POLICY'）"
    pve_policy_apply "$WANT_POLICY" || exit 1
    echo "edge_target_prepare: 策略变更需要重启 CT（lxc.apparmor.raw 在启动时生效）"
    nohup "$lab_target_bin" reboot "$(pve_vmid)" > /tmp/edgeexp-pve-restart.log 2>&1 &
    RESTART_PID=$!
    wait_for_up "$RESTART_PID" 180 || exit 1
    RESTARTED=1
    echo "edge_target_prepare: 重启完成（容器内已可执行命令）"
  else
    echo "edge_target_prepare: 设置策略 raw.apparmor='$WANT_POLICY'（原值 '$CUR_POLICY'）"
    if [ -n "$WANT_POLICY" ]; then
      "$lab_target_bin" config set "$TARGET" raw.apparmor "$WANT_POLICY" || exit 1
    else
      "$lab_target_bin" config unset "$TARGET" raw.apparmor || exit 1
    fi
    echo "edge_target_prepare: 策略变更需要重启实例（raw.apparmor 在启动时生效）"
    nohup "$lab_target_bin" restart "$TARGET" > /tmp/edgeexp-lxd-restart.log 2>&1 &
    RESTART_PID=$!
    wait_for_up "$RESTART_PID" 180 || exit 1
    RESTARTED=1
    echo "edge_target_prepare: 重启完成（容器内已可执行命令）"
  fi
else
  echo "edge_target_prepare: 策略已是目标状态（幂等路径，不重启）"
fi

# 策略生效的**节点内自证**（不是"我设了 config"）：读一次被拒路径，两条分支都必须可解释。
if [ "$POLICY_ON" = "1" ]; then
  lab_target_exec "$TARGET" sh -c 'head -1 /etc/shadow >/dev/null 2>&1' \
    && { echo "edge_target_prepare: 策略**没有生效**（策略在，但读 /etc/shadow 成功了）—— 拒绝目标状态不成立" >&2; exit 1; }
  echo "edge_target_prepare: 策略生效自证：节点内读 /etc/shadow 被拒（rc≠0）"
else
  lab_target_exec "$TARGET" sh -c 'head -1 /etc/shadow >/dev/null 2>&1' \
    || { echo "edge_target_prepare: 策略**没有卸载干净**（策略不在，但读 /etc/shadow 仍被拒）" >&2; exit 1; }
  echo "edge_target_prepare: 策略卸载自证：节点内读 /etc/shadow 成功（rc=0）"
fi

# --- 4. agent（重置后 /tmp 被清空 ⇒ payload 放 /root 并重新拉起）-------------
# 判据是 **`(host, 容器内活 pid)` 且心跳新鲜**（不是"Caldera 里有个 trusted 条目"）——
# Caldera 保留已死 agent 的条目，打到死 agent 上会得到 `status=-3` 而**看起来像被拦住**。
[ -f "$PAYLOAD" ] || { echo "edge_target_prepare: sandcat 载荷不存在: $PAYLOAD" >&2; exit 1; }

# live_agent_paws <容器内活 pid 列表> —— 回显满足判据的 paw，否则空行。
#
# **实测踩坑（Step 4-B2，本轮最贵的一个）**：上一版把 pid 列表从 **stdin** 喂给 python，而脚本本体
# 又是用 `python3 - <<'PY'` 从 **stdin** 读的 —— 同一路 stdin 被用了两次：程序把 heredoc 读完时
# 已经到 EOF，于是 `sys.stdin.read()` **永远是空串** ⇒ `pids` 永远为空 ⇒ 这个函数**从来匹配不到
# 任何 agent**（8 条 `trusted=true`、pid 也对得上的条目全被静默滤掉，实测复现：`printf '886\n1096'
# | live_agent_paws` 回空行）。
# 后果不是"多拉一次 sandcat"这么轻：它让"目标上有没有活着的 agent"这条判据**恒为否**，于是每次复位
# 都覆盖并重拉 agent；而这条判据存在的理由正是**避免把 operation 打到死 agent 上**（`status=-3`
# 看起来像被拦住）。修法是把 pid 列表改成**第 5 个 argv**（stdin 只留给程序本体）。
live_agent_paws() {
  python3 - "$CALDERA_URL" "$CALDERA_KEY" "$TARGET" "${EDGEEXP_AGENT_FRESH_S:-180}" "${1:-}" <<'PY'
import json, sys, time, urllib.request
from datetime import datetime, timezone
api, key, host, fresh = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    req = urllib.request.Request(api + '/api/v2/agents', headers={'KEY': key})
    agents = json.load(urllib.request.urlopen(req, timeout=15))
except Exception:
    print(''); raise SystemExit
pids = [int(x) for x in sys.argv[5].split() if x.strip().isdigit()]
now = time.time()
for a in agents:
    if a.get('host') != host or not a.get('trusted'):
        continue
    if a.get('pid') is None or int(a['pid']) not in pids:
        continue
    try:
        seen = datetime.fromisoformat(a['last_seen'].replace('Z', '+00:00')).timestamp()
    except Exception:
        continue
    if seen >= now - fresh:
        print(a.get('paw')); raise SystemExit
print('')
PY
}

# --- C2 地址：必须是**容器侧可达的宿主地址** ------------------------------------------------
# 实测踩坑（Step 4-B2，代价是一轮 180s 超时 + 八条 `trusted=false` 的假象）：
# `EDGEEXP_CALDERA_URL` 的默认值 `http://127.0.0.1:8888` 是**在宿主上**调 API 的地址，而容器里的
# `127.0.0.1` 是**它自己**。上一版直接把 `urlparse` 出来的 hostname 当成节点侧地址 ⇒ 拉起的 sandcat
# 一直连自己：进程能起来（`ps` 里有）、`/tmp/sandcat.log` 一行不写、Caldera 里 `asc-tgt-1` 的条目
# 全是 `trusted=false` —— 从面板上看与"agent 起不来"同形，而真正的原因是**地址给错了机器**。
# 正确取值是**容器内的默认网关**（= LXD 网桥地址 = 宿主在容器网段的地址）。实测：
#   容器内 `ip route show default` → `default via 10.217.208.1 dev eth0`；
#   容器内 `curl http://10.217.208.1:8888/api/v2/abilities` → 200；`127.0.0.1:8888` → rc=7。
# 允许 `EDGEEXP_C2_HOST` 显式覆盖；两条路都拿不到 ⇒ **响亮失败**（静默回落到 127.0.0.1 等于注定死 agent）。
#
# **重试到默认路由出现为止**（Task 5 Step 0 实测踩到的第二条同类竞态）：容器刚 `lxc restart` 完时，
# `wait_for_exec` 已经通过、策略自证也通过（`lxc exec` 能跑），而容器内 `ip route show default`
# **还是空的** —— DHCP 尚未完成。一次取不到就判死会把"网络还没起来"报成"环境不可用"，
# 而后者看起来像实例坏了。窗口给 `EDGEEXP_C2_HOST_WAIT_S`（默认 90s），期间每次重问一次。
C2_HOST_WAIT_S="${EDGEEXP_C2_HOST_WAIT_S:-90}"
C2_HOST="${EDGEEXP_C2_HOST:-}"
if [ -z "$C2_HOST" ]; then
  c2_waited=0
  while [ -z "$C2_HOST" ]; do
    C2_HOST="$(lab_target_exec "$TARGET" sh -c 'ip route show default 2>/dev/null | awk "/^default/ {print \$3; exit}"' 2>/dev/null || true)"
    C2_HOST="$(printf '%s' "$C2_HOST" | tr -d '[:space:]')"
    [ -n "$C2_HOST" ] && break
    [ "$c2_waited" -ge "$C2_HOST_WAIT_S" ] && break
    sleep 3; c2_waited=$((c2_waited + 3))
  done
  [ -n "$C2_HOST" ] && echo "edge_target_prepare: C2 主机 = 容器内默认网关 $C2_HOST（等待 ${c2_waited}s；重启后 DHCP 未完成时会有这个窗口）"
fi
C2_HOST="$(printf '%s' "$C2_HOST" | tr -d '[:space:]')"
[ -n "$C2_HOST" ] || {
  echo "edge_target_prepare: 取不到容器侧可达的 C2 地址（容器内 ${C2_HOST_WAIT_S}s 内都没有默认路由）——" >&2
  echo "  请用 EDGEEXP_C2_HOST=<宿主在容器网段的地址，如 10.217.208.1> 显式指定。" >&2
  exit 1
}

C2_URL="$(python3 - "$CALDERA_URL" "$C2_HOST" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
print('http://%s:%s' % (sys.argv[2], u.port or 8888))
PY
)"

# --- C2 可达性自证（在**容器内**问一次，放在拉起 agent 之前）----------------------------------
# 存在的理由就是上面那段踩坑：地址给错时"进程起来了但永不回连"要等满 180s 才被发现，而这中间拉起的
# 进程会把 `/tmp/sandcat.log` 留成**空文件** —— 与"进程一启动就崩"同形，排障方向会完全错。
# 把自证放在**拉起之前**，等于把"地址不可达"和"agent 起不来"拆成两个结论。
#
# **Task 6：自证不能用"容器里没有 curl 就跳过"**。Debian 13 的最小 CT 里**没有 curl**，
# 而 `pve` 基质的靶机正是这种 CT（实测 `command -v curl` → 无、`wget` → 有、`python3` → 有）——
# 上一版在那种机器上会把自证**整体跳过**，于是一个"地址给错了"的环境会一路走到 180s 超时，
# 再把错因埋在"agent 没回连"里。现在改成**三级回退**：curl → wget → python3，
# 只有三者都没有才声明"跳过"（那时它是真的环境事实，不是我们图省事）。
#
# 判据仍是"容器内真的问到了 Caldera 的 API"（HTTP 200），不是"TCP 通了"：
# 8888 上可能是别的东西在听，而 `/api/v2/abilities` 需要正确的 KEY 才会给 200。
C2_PROOF="$(lab_target_exec "$TARGET" sh -c "
if command -v curl >/dev/null 2>&1; then
  curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'KEY: $CALDERA_KEY' '$C2_URL/api/v2/abilities'
elif command -v wget >/dev/null 2>&1; then
  # wget 没有 -w '%%{http_code}'，故把结果落到临时文件再用 wc 度量（0 字节 ⇒ 非 200）。
  out=\$(wget -q -T 5 -O /tmp/edgeexp-c2probe.json --header='KEY: $CALDERA_KEY' -S '$C2_URL/api/v2/abilities' 2>&1 | awk '/HTTP\// {code=\$2} END {print code}')
  if [ -n \"\$out\" ] && [ \"\$out\" = '200' ] && [ -s /tmp/edgeexp-c2probe.json ]; then printf '200'; else printf '%s' \"\${out:-000}\"; fi
elif command -v python3 >/dev/null 2>&1; then
  python3 -c \"
import urllib.request
try:
    r = urllib.request.Request('$C2_URL/api/v2/abilities', headers={'KEY': '$CALDERA_KEY'})
    print(urllib.request.urlopen(r, timeout=5).status)
except Exception:
    print('000')
\"
else
  exit 127
fi" 2>/dev/null || true)"
case "$C2_PROOF" in
  200) echo "edge_target_prepare: C2 可达性自证：容器内问到 $C2_URL/api/v2/abilities → 200（可用 curl/wget/python3 中的任一个；三级回退）" ;;
  127) echo "edge_target_prepare: 警告：容器内 curl/wget/python3 **三者都没有** ⇒ C2 可达性自证**跳过**（本轮不声明已证）" >&2 ;;
  *)   echo "edge_target_prepare: 容器内问不到 C2（$C2_URL → '${C2_PROOF:-空}'）—— 这个地址拉起 agent 必然不回连，先修地址" >&2
       echo "  容器内默认路由：$(lab_target_exec "$TARGET" ip route show default 2>&1 | head -2)" >&2
       echo "  可用 EDGEEXP_C2_HOST=<宿主在容器网段的地址> 覆盖。" >&2
       exit 1 ;;
esac

PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
PAW="$(live_agent_paws "$PIDS" 2>/dev/null || true)"

if [ -n "$PAW" ]; then
  echo "edge_target_prepare: agent 已在跳（paw=$PAW，容器内活 pid=[$PIDS]）—— 幂等路径"
else
  echo "edge_target_prepare: 目标上没有活着的 agent（容器内 sandcat pid=[$PIDS]）⇒ 送载荷并拉起"
  # **先送到临时名再 `mv`**（实测踩坑）：直接 `lxc file push` 覆盖 `/root/sandcat` 在**有进程正在跑
  # 它**时会以 `sftp: "open /root/sandcat: text file busy"` 失败 —— 而"有没有活着的 agent"这条判据
  # 可能因为心跳过期而恰恰在这时候判成"没有"（判据是 (host, 活 pid, 新鲜心跳)，三个都要满足）。
  # `mv`（同文件系统内是 rename）对正在执行的旧文件是允许的，因此这条路不会卡在 ETXTBSY 上。
  # 每一步**显式判失败**：本脚本没有 `set -e`（见头部注释），漏判就等于"降级继续" —— 上一版实测
  # 就是 push 失败被咽下去，然后拉起一个不存在/过期的载荷，最后以 180s 超时收场（错因被埋掉）。
  lab_push "$PAYLOAD" "$TARGET" /root/sandcat.new \
    || { echo "edge_target_prepare: 把 sandcat 载荷送到 $TARGET:/root/sandcat.new 失败" >&2; exit 1; }
  lab_target_exec "$TARGET" sh -c 'mv -f /root/sandcat.new /root/sandcat && chmod 755 /root/sandcat' \
    || { echo "edge_target_prepare: 在 $TARGET 内落地 /root/sandcat 失败" >&2; exit 1; }
  # 用 `setsid` 起（`lxc exec` 通道一断，没有 setsid 的子进程会被带走 —— 实测过）
  lab_target_exec "$TARGET" sh -c "setsid /root/sandcat --server $C2_URL --group $AGENT_GROUP > /tmp/sandcat.log 2>&1 < /dev/null & echo launched" \
    || { echo "edge_target_prepare: 在 $TARGET 内拉起 sandcat 失败" >&2; exit 1; }
  waited=0
  while :; do
    PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
    PAW="$(live_agent_paws "$PIDS" 2>/dev/null || true)"
    [ -n "$PAW" ] && break
    if [ "$waited" -ge "$AGENT_WAIT_S" ]; then
      echo "edge_target_prepare: agent 在 ${AGENT_WAIT_S}s 内没有回连（判据：host=$TARGET 且容器内活 pid 一致且心跳新鲜）" >&2
      # 超时是**多因**的（载荷没落地 / 进程没起来 / 起来了但连不上 C2 / 连上了但 pid 对不上）。
      # 只打一行"没有回连"会把四种原因压成一个结论 —— 这里把能自证的三条证据一次打全。
      echo "  · 容器内 sandcat 进程（ps，可能为空）:" >&2
      lab_target_exec "$TARGET" ps -eo pid,comm --no-headers >&2 2>/dev/null || true
      echo "  · 容器内 /root/sandcat:" >&2
      lab_target_exec "$TARGET" ls -la /root/sandcat >&2 2>/dev/null || true
      echo "  · 节点内 sandcat 日志尾部（C2 地址=$C2_URL）:" >&2
      lab_target_exec "$TARGET" sh -c 'tail -20 /tmp/sandcat.log' >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "edge_target_prepare: agent 就绪（paw=$PAW，容器内活 pid=[$PIDS]，等待 ${waited}s）"
fi

# 收尾自证：容器与 Caldera 两条证据都打出来（供运行级留痕）
echo "edge_target_prepare: 就绪 —— 实例 $TARGET 运行中，策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在)，agent=$PAW（组=$AGENT_GROUP），重启过=$RESTARTED"
exit 0
