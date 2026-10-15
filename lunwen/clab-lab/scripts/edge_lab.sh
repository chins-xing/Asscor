#!/bin/bash
# ============================================================================
# edge_lab.sh —— 实验**基质**抽象（被 edge_*.sh 共同 source 的函数库）
# ============================================================================
#
# 这不是可执行脚本，而是被 `edge_reset.sh` / `edge_attack.sh` / `edge_collect.sh` /
# `edge_matrix.sh` / `edge_probe.sh` **共用**的基质层。source 进来即用（`set -euo pipefail`
# 由调用方负责；本文件只定义函数与变量）。
#
# 为什么要有这一层（Task 4D Step 1）：2026-09-12 用户裁定实验基质搬到 **A-1 远程服务器（LXD，
# 环境真实）**，WSL2 Containerlab 退为开发与离线。矩阵脚本此前把 `clab` / `docker` 的命令**写
# 死在调用点**（建/毁拓扑、在目标内执行、把文件送进目标、取目标信息四处），换基质等于重写四个
# 脚本 —— 而"重写"正是把门禁与注入逻辑一起改坏的最短路径。
#
# 接口（**单一来源**：所有基质相关命令只能从这里出去，调用点不得再出现 `clab`/`docker`/`lxc`
# 命令字面 —— 需要新增一条基质命令时改本文件，不要在调用点写）：
#
#   lab_substrate                当前基质名（clab|lxd|pve|qemu，只读）
#   lab_topology                 拓扑文件路径（clab 用；lxd/pve/qemu 下是"占位"，不参与命令）
#   lab_topology_bin             拓扑级 CLI（clab: `clab`；lxd: `lxc`；pve: `pct`；qemu: `qm`）
#   lab_target_bin               目标级 CLI（clab: `docker`；lxd: `lxc`；pve: `pct`；qemu: `ssh`）
#   lab_require_bins             前置检查：当前基质需要的 CLI 都在 PATH 上吗（缺则返回非零）
#   lab_up                       建拓扑（clab: deploy）
#   lab_down                     毁拓扑（clab: destroy --cleanup）
#   lab_target_exec <node> <cmd…>   在目标内执行命令（stdout/stderr 原样透传）
#   lab_target_exec_detached <node> <cmd…>  在目标内起一个不随连接结束而退出的进程
#   lab_push <local> <node> <dest>  把文件送进目标
#   lab_node_ip <node> <iface>      取目标某接口的 CIDR（无则空、返回非零）
#   lab_node_pids <node> <comm>     取目标内**当前活着**的进程 PID（每行一个）
#   lab_instance_exists <node>      目标存在吗（只管存在性，不管在不在跑）
#   lab_node_running <node>         实例在跑吗（true/false；不存在则非零）
#   lab_wait_node_exec <node> <秒>  等"这个节点真的能执行命令"（rc=0 就绪；超时 rc=1）
#   lab_inspect <node>              取目标的基质视图（存在性/状态的权威判据）
#   lab_list                        列出目标（每行一个名字）
#   lab_node_counts                 回显 "total up down"（失败回显 "-1 -1 -1"）
#   lab_target_spec <node>          节点名 → `edgescen -target` 的语法
#                                   （clab 裸名 / lxd:<实例> / pve:<vmid> / qemu:<vmid>）
#   lab_node_vmid <node>            **pve 专属**：节点名 → VMID（唯一的解析点；解析不到/重名都失败）
#   lab_node_ssh_host <node>        **qemu 专属**：节点标识 → SSH 主机（唯一的解析点）
#
# 覆盖开关（**与抽象前逐条对应**，别把它们合并成一个）：
#   EDGEEXP_SUBSTRATE          clab（默认）| lxd | pve | qemu
#   EDGEEXP_TOPOLOGY           拓扑文件路径
#   EDGEEXP_LAB_TOPOLOGY_BIN   拓扑级 CLI 的可执行文件（离线夹具用）
#   EDGEEXP_LAB_TARGET_BIN     目标级 CLI 的可执行文件（离线夹具用；clab 下默认 = DOCKER_BIN）
#   EDGEEXP_DOCKER_BIN         **抽象前就有的**接缝：目标级的 `docker`（`edge_probe.sh` 用它）
#   EDGEEXP_LXC_BIN            lxd 基质的 `lxc`
#   EDGEEXP_PCT_BIN            pve 基质的 `pct`
#   EDGEEXP_QM_BIN             qemu 基质的 `qm`（拓扑/实例视图）
#   EDGEEXP_SSH_BIN            qemu 基质的 `ssh`（目标内执行）
#   EDGEEXP_SCP_BIN            qemu 基质的 `scp`（把文件送进目标）
#   EDGEEXP_VM_SSH_HOST        qemu 基质的 SSH 目标（含 `%s` 时按节点标识展开；缺省用
#                              `asc-vm<vmid>` —— 与 provisioning 写进宿主 /etc/hosts 的名字一致）
#   EDGEEXP_VM_SSH_KEY         qemu 基质的 SSH 私钥**路径**（**从不**进仓库）
#   EDGEEXP_VM_SSH_USER        qemu 基质的登录用户（默认 asc）
#   EDGEEXP_VM_SSH_PORT        qemu 基质的 SSH 端口（默认 22）
#   EDGEEXP_LAB_WAIT_STEP       `lab_wait_node_exec` 的轮询间隔（秒，默认 3；**只给离线夹具缩短用**）
#
# **clab 分支逐位等价**是最硬的门禁：函数体里每一条命令、参数顺序、重定向目标、日志文件名都
# 与抽象**之前**的调用点逐字相同（日志仍叫 `/tmp/edgeexp-clab-*.log` —— 名字里的 clab 只是历史
# 留痕，改名会让既有排障手册与错误串对不上；两份日志都是"最近一次调用的原文"）。这条有离线
# 复现夹具钉住（`build/lab-diff.sh`：从 `git archive <base>` 取**真基线**跑同一批假 CLI 做差分），
# 不是靠通读保证的。
#
# 基质选择的失败处置：`EDGEEXP_SUBSTRATE` 只认 `clab`（默认）、`lxd` 与 `pve`，别的值**在 source
# 时就响亮失败** —— 一个拼错的基质名如果被当成默认值静默降级，整轮矩阵会在 WSL 的 clab 上跑，
# 而记录里的 `env` 标签看起来仍然正常。**没有 `set -e` 的调用方也会被中止**（见下方实现）。
#
# lxd 分支的边界（**必须显式**，不能默默什么都不做）：
#   · `lab_up` / `lab_down` **不支持**：LXD 侧的"环境"是 A-1 上既有的实例集合（控制侧已裁定
#     `probe-ot005` 等实例不得被删改），没有"建/毁拓扑"这个动作。两者一律**响亮失败**并说明
#     原因，绝不静默返回 0 —— 一次"复位成功"但环境其实没被动过的假象，比一次失败危险得多。
#   · `lab_node_counts` 对 lxd 回显 `-1 -1 -1`（"Node status cannot be determined"）。
#     `-1` 的既有语义在 `edge_reset.sh` 里是"查不出来 ≠ 已清空"，调用方据此失败；这与
#     `clab inspect` 自己失败时的取值一致。
#   · `lab_target_exec` / `lab_push` / `lab_node_ip` / `lab_inspect` / `lab_list` 支持：
#     它们只要求"实例存在"，正是 LXD 上取数与探针路径需要的四件事。
#   · 本文件的 lxd 分支只**访问既有实例**：不 launch、不 delete、不 stop、不 restart，
#     也不改任何实例的配置。
#
# pve 分支的边界（Task 6；节点是 **PVE CT**，`pct`）：**逐条照搬 lxd 的边界**，理由同源 ——
# PVE 上"环境"同样是既有 CT 的集合，本层**永不** create/destroy/start/stop 任何 CT：
#   · `lab_up` / `lab_down` 与 lxd 同样**响亮失败**（rc=2）；
#   · `lab_node_counts` 同样回显 `-1 -1 -1`；
#   · 其余原语全部支持，只把 `lxc …` 换成等价的 `pct …`（对照表见各函数体内的注释）。
#
# **pve 的节点标识（唯一一处"名字 → vmid"解析）**：既有脚本用**名字**（`asc-tgt-c2`）标识节点，
# 而 `pct` 的原生标识是 **VMID（数字）**。`pct list` 同时给出两者，故 `lab_node_vmid` 是**唯一**
# 的解析点，所有 `pct` 命令都从它拿 vmid。解析不到（或名字匹配到**多个** VMID）时**响亮失败**，
# **绝不猜一个 vmid** —— 猜错会作用到别人的 CT 上，而那看起来与正确执行完全一样。
#
# qemu 分支的边界（Task 13；节点是 **QEMU/KVM VM**，`qm` + `ssh`/`scp`）：这是方向② 的
# **生产基质**（用户 2026-10-15 裁定：CT = 快速验证/轻量模拟/临时；VM = 长线/中重型拓扑/重要任务），
# 在**脚本层**的边界与 lxd/pve **刻意不同**，逐条写明理由：
#   · `lab_up` / `lab_down` **仍然不支持**（rc=2）—— 但理由与 lxd/pve 不同：这里**不是**
#     "怕碰别人的东西"，而是**建机/清机有它自己的单一来源**：
#     `lunwen/clab-lab/scripts/edge_vm_provision.sh`（幂等、带 VMID 下限、带 `--destroy`）。
#     把"建拓扑"塞进基质层会让同一件事有两个入口，而两者对"哪些 VMID 属于本任务"的
#     判据一旦分叉，一次 `lab_down` 就能拆掉别人的 VM。故本层**永不** create/start/destroy。
#   · `lab_node_counts` 回显 `-1 -1 -1`（同 lxd/pve：PVE 上没有"拓扑"对象，节点集合由 VM 列表定义）。
#   · 其余原语全部支持，取值手段换成 `qm`（实例视图）与 **`ssh`/`scp`**（目标内执行/送文件）。
#   · ⚠️ **取数地址是 qemu 专属的一处解析**（`lab_node_ssh_host`）：节点标识（vmid）与
#     "SSH 连哪台机器"是**两件事**。默认规则是 `asc-vm<vmid>` —— **与 provisioning 脚本写进
#     宿主 `/etc/hosts` 的 hostname 同源**（故不需要 DNS：管理 VLAN 30 上实测 DNS FAIL）。
#     解析不出来时**响亮失败**，绝不回落成"裸 vmid 当主机名"（`ssh 910` 会去解析一个叫
#     "910" 的主机名，而那条错误看起来像网络问题）。
# ============================================================================

# lab_substrate —— 当前基质（变量名带 lab_ 前缀：避免与调用方自己的 SUBSTRATE/SUBSTRATE_*
# 撞名，同 edge_probe.sh 的 probe_target/probe_docker_bin 约定）。
lab_substrate="${EDGEEXP_SUBSTRATE:-clab}"
case "$lab_substrate" in
  clab|lxd|pve|qemu) : ;;
  *)
    echo "edge_lab: EDGEEXP_SUBSTRATE 只认 clab（默认）、lxd、pve 与 qemu，收到 '$lab_substrate' ——" >&2
    echo "  基质名拼错时静默退回默认值会让整轮矩阵在另一种基质上跑（记录里的 env 标签照常），" >&2
    echo "  故这里直接失败。用法：EDGEEXP_SUBSTRATE=clab|lxd|pve|qemu。" >&2
    # 三种加载方式都要**中止调用方**（Fix round 1 / M-4）：
    #   · 被 source + 调用方有 `set -e` ⇒ `return 2` 就能带走调用方；
    #   · 被 source + 调用方**没有** `set -e` ⇒ `return` 只返回这一层，调用方会**继续跑**，
    #     于是整轮矩阵在默认基质（clab）上跑起来，而记录里的 env 标签照常 —— 这正是本守卫
    #     要堵的东西。故这里**主动结束调用方的 shell**（`kill -TERM $$`）。
    #     非交互式 shell 才 kill：交互式会话语境下把操作者的 shell 打死是过度惩罚，
    #     那时 `return 2` + 上面三行 stderr 已经足够（人看得见）。
    #   · 被 `bash edge_lab.sh` 直接执行 ⇒ `return` 会报错，故退回 `exit 2`。
    # 判据是 shell 的既有约定：source 进来的脚本 `$0` 仍是**调用方**的名字。
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then
      case $- in *i*) return 2 ;; esac
      kill -TERM $$
      return 2
    fi
    exit 2 ;;
esac

# ---------------------------------------------------------------------------
# 两条 CLI：**拓扑级**与**目标级**（Fix round 1 / I-1 + M-3）
# ---------------------------------------------------------------------------
# 抽象前每个路径上的覆盖效力必须**逐条保留**，这条纪律决定了下面的结构：
#
#   · 拓扑级（`lab_up` / `lab_down` / `lab_node_counts`）在 clab 下跑的是 `clab`；
#   · 目标级（`lab_target_exec(_detached)` / `lab_push` / `lab_node_ip` / `lab_node_running`
#     / `lab_inspect` / `lab_list`）在 clab 下跑的是 **`docker`**、在 lxd 下是 `lxc`。
#
# 抽象前这两类**没有任何共用开关**：`clab` 那几条命令写死 `clab`，容器级命令写死 `docker`
# （`edge_probe.sh` 另有一个 `EDGEEXP_DOCKER_BIN` 专门覆盖**容器级**的 `docker`）。
# 修复前的实现把两者塞进同一个 `lab_bin`，于是 `edge_probe.sh` 把 `EDGEEXP_LAB_BIN=docker`
# 钉进来之后：容器级命令**完全看不到**这个覆盖（clab 分支写死 `docker`），而拓扑级命令
# **反而被它带偏**（去调 `docker inspect -t <拓扑>`）—— 一个变量同时造成"覆盖失效"与"错 CLI"，
# 这就是评审 I-1/M-3 的根因。现在两个名字各管一层，互不影响。
lab_topology_bin="${EDGEEXP_LAB_TOPOLOGY_BIN:-}"
if [ -z "$lab_topology_bin" ]; then
  case "$lab_substrate" in
    clab) lab_topology_bin="clab" ;;
    lxd)  lab_topology_bin="${EDGEEXP_LXC_BIN:-lxc}" ;;
    # pve：拓扑级与目标级是**同一个** CLI（`pct`）—— PVE 上没有"拓扑"这个对象，
    # 与 lxd 同形（那边两级都是 `lxc`）。覆盖开关 `EDGEEXP_PCT_BIN` 供离线夹具用。
    pve)  lab_topology_bin="${EDGEEXP_PCT_BIN:-pct}" ;;
    # qemu：拓扑级是 **`qm`**（VM 列表与实例状态），目标级是 **`ssh`**（在客人里执行）——
    # 这两级**不是同一个** CLI（与 lxd/pve 的形态不同，与 clab 的 clab/docker 同形）。
    # PVE 上同样没有"拓扑"对象（节点集合由 VM 列表定义），故 `lab_up`/`lab_down` 不支持，
    # 但 `lab_list`/`lab_inspect`/`lab_node_running`/`lab_instance_exists` 要从 `qm` 取值。
    qemu) lab_topology_bin="${EDGEEXP_QM_BIN:-qm}" ;;
  esac
fi

# 目标级 CLI 在 clab 下就是 `docker` —— **保留抽象前的覆盖开关 `EDGEEXP_DOCKER_BIN`**
# （它是 `edge_probe.sh` 的既有接缝，也是"用两个可分辨的假 docker 证明覆盖有牙"那条判据的入口）。
# lxd 下是 `lxc`（`EDGEEXP_LXC_BIN` 可覆盖，供离线夹具用）；pve 下是 `pct`（`EDGEEXP_PCT_BIN`）；
# qemu 下是 `ssh`（`EDGEEXP_SSH_BIN`；送文件那个 `scp` 单独用 `EDGEEXP_SCP_BIN`，见 lab_push）。
lab_docker_bin="${EDGEEXP_DOCKER_BIN:-docker}"
lab_target_bin="${EDGEEXP_LAB_TARGET_BIN:-}"
if [ -z "$lab_target_bin" ]; then
  case "$lab_substrate" in
    clab) lab_target_bin="$lab_docker_bin" ;;
    lxd)  lab_target_bin="${EDGEEXP_LXC_BIN:-lxc}" ;;
    pve)  lab_target_bin="${EDGEEXP_PCT_BIN:-pct}" ;;
    qemu) lab_target_bin="${EDGEEXP_SSH_BIN:-ssh}" ;;
  esac
fi

# ---------------------------------------------------------------------------
# qemu 专属：SSH 连接参数与目标解析（**唯一**的"节点标识 → SSH 主机"解析点）
# ---------------------------------------------------------------------------
#
# 为什么不复用 `lab_target_bin` 那两格：qemu 需要**两个**二进制（`ssh` 执行、`scp` 送文件），
# 而 `lab_target_bin` 只表达"目标级 CLI 是哪一个"。把 `scp` 也塞进去会让
# "lab_push 用哪个二进制"取决于一个为别的语义准备的变量。
lab_scp_bin="${EDGEEXP_SCP_BIN:-scp}"

# lab_ssh_conn_args —— ssh/scp **共用**的几格连接参数（与 cmd/edgescen 的
# `qemuSSHConnArgs` **逐项同源**：同一套环境变量、同一套默认值、同一套硬编码选项）。
#
# 为什么两边各写一份（而不是互相调用）：一侧是 bash（基质层）、一侧是 Go（取数层），
# 没有共享代码的手段。故**判据**是"两边对同一组环境变量给同一个解释"，
# 由两边的用例各自钉住（Go 侧 `TestQEMU*`；bash 侧 `test-edge-lab.sh` 的 qemu 段）。
#
# **不接受**任何"SSH 选项串"环境变量：那种变量会被当成 `-o` 的值，于是
# `-o ProxyCommand=…` 能在操作者看不见的地方把取数目标改到别处。
lab_ssh_conn_args() {
  printf '%s\n' -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10
  printf '%s\n' -l "${EDGEEXP_VM_SSH_USER:-asc}"
  if [ -n "${EDGEEXP_VM_SSH_PORT:-}" ]; then
    printf '%s\n' -p "$EDGEEXP_VM_SSH_PORT"
  fi
  if [ -n "${EDGEEXP_VM_SSH_KEY:-}" ]; then
    # 私钥**路径**（不是内容）。路径不可读时**响亮失败**，绝不退回 ssh 自己的默认钥匙 ——
    # 退回之后大概率也能连上（同一个操作者的同一把钥匙），于是"这条记录是哪把钥匙采的"
    # 就没人知道了。
    [ -r "$EDGEEXP_VM_SSH_KEY" ] || {
      echo "edge_lab: EDGEEXP_VM_SSH_KEY=$EDGEEXP_VM_SSH_KEY 不可读 ——" >&2
      echo "  私钥路径由环境变量给出（**从不**写进仓库）；建机脚本 edge_vm_provision.sh" >&2
      echo "  会把生成的私钥路径写进未跟踪的本地 env 文件，跑批前 source 它。" >&2
      return 1
    }
    printf '%s\n' -o IdentitiesOnly=yes -i "$EDGEEXP_VM_SSH_KEY"
  fi
  return 0
}

# lab_node_ssh_host <node> —— **qemu 专属**：节点标识 → SSH 主机（本层唯一的解析点）。
#
# 规则与 cmd/edgescen 的 `qemuSSHHost` 逐条一致（两边必须同源，否则"脚本取数"与"记录里的
# observation_target"会指向两台不同的机器，而两边都看起来正常）：
#   1. `EDGEEXP_VM_SSH_HOST` 给了 ⇒ 用它（含 `%s` 时按节点标识展开）；
#   2. 没给 + 节点标识是**纯数字** ⇒ `asc-vm<vmid>`（与 provisioning 写进 /etc/hosts 的名字同源）；
#   3. 没给 + 非数字 ⇒ **原样**当主机名（`qemu:asc-vm910` 里的标识本身就是一个主机名）。
lab_node_ssh_host() {
  local node="$1" host
  if [ -n "${EDGEEXP_VM_SSH_HOST:-}" ]; then
    host="${EDGEEXP_VM_SSH_HOST//%s/$node}"
  else
    case "$node" in
      ''|*[!0-9]*)
        host="$node"
        echo "edge_lab: 节点标识 '$node' 不是纯数字 vmid ⇒ 按**主机名**使用（基质 qemu）；" >&2
        echo "  要用默认规则（asc-vm<vmid>）请给 vmid，或显式设 EDGEEXP_VM_SSH_HOST。" >&2
        ;;
      *) host="asc-vm$node" ;;
    esac
  fi
  [ -n "$host" ] || return 1
  printf '%s\n' "$host"
}

# lab_require_bins —— 前置检查（**单一来源**：调用脚本不再自己写一份命令清单）。
#
# 抽象前 `edge_reset.sh` 里那句 `for bin in clab docker curl python3 sha256sum` 就是一份
# 硬编码清单；搬进本层之后，清单按基质派生，调用脚本里不再出现基质命令字面（Fix round 1 / M-2）。
# 缺命令即返回 1 并说明缺的是哪一个 —— 调用方自己决定退出码（脚本侧一律 `exit 1`）。
lab_require_bins() {
  local bins=() bin
  case "$lab_substrate" in
    clab) bins=("$lab_topology_bin" "$lab_target_bin") ;;
    # lxd / pve：两级是同一个 CLI，故清单里只出现一次（重复一项没有额外语义）。
    lxd)  bins=("$lab_topology_bin") ;;
    pve)  bins=("$lab_topology_bin") ;;
    # qemu：**两级是两个不同的二进制**（`qm` 取实例视图、`ssh`/`scp` 进目标），
    # 故清单里必须三项都在 —— 缺 `qm` 会让 lab_list/lab_inspect 全盘失败，
    # 缺 `scp` 会让 lab_push 失败，而缺 `ssh` 会让"目标内执行"失败；
    # 三种失败的症状（"节点列表是空的"/"文件推不进去"/"命令跑不了"）看起来互不相干，
    # 一条前置检查比三次排障便宜。
    qemu) bins=("$lab_topology_bin" "$lab_target_bin" "$lab_scp_bin") ;;
  esac
  for bin in "${bins[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || {
      echo "edge_lab: 缺少必需命令 $bin（基质 $lab_substrate）—— 先装好基质 CLI 再跑。" >&2
      return 1
    }
  done
  return 0
}

# ---------------------------------------------------------------------------
# 基线活跃集：**按基质如实声明**（用户 2026-10-10 裁定，Task 7）
# ---------------------------------------------------------------------------
#
# 为什么这一条属于**基质层**：一个因子"不看场景也该在链上"，取决于**这个基质能不能观测到它背后
# 的那条检查** —— 那是**基质**的事实，不是场景的事实，更不是某一台机器的偶然。既然"当前是哪一
# 种基质"只有本层知道，基线集也就只有本层能如实声明。
#
# **pve 基质为什么是这两个因子**：`OT-005`（强制执行的可见性）在 **PVE CT** 里
# **结构性不可观测** —— LXC 的 apparmor 命名空间不向容器暴露 profile（`aa-status` 报
# `Failed to get profiles: 2`、可见策略数 0；装包解决不了），而配置里
# `trigger.EF-SELINUX` 与 `trigger.EF-APPARMOR` **都指向 `OT-005`**
# ⇒ 这两个因子**恒在链上**，与场景无关。
# 用户裁定的处置是**如实声明**（而不是去改 `internal/checks` 让 OT-005 在 CT 里"可测" ——
# 那条路要动底座文件、影响 main/ARC 的一致性审计，用户已明确否决）。
#
# 声明的两个变量就是 `edge_attack.sh` 读的那两个（Task 4D Step 4-B3 做好的机制，
# 故**声明本身零代码改动**）：它们进 harness 产物的 `expected_baseline_factors` /
# `expected_baseline_factors_source`，采集脚本据此把相等断言的右边从「注入集」扩成
# 「**声明面 = 基线活跃集 ∪ 注入集**」。
#
# 三条纪律（每条都对应一种"看起来正常、其实声明错了"的形态）：
#
#  1. **只在 pve 下设置**：clab/lxd 的这两个变量**不设、不导出**（一个字节都不动）——
#     Task 6 的硬不变式在 Task 7 仍然成立。
#  2. **操作者显式给的值优先**，判据用 `+set` 而**不是** `:-`：显式给**空串**是有意义的
#     （回到"没有基线声明"的老路径），不能把它当成"没设"而被默认值盖掉 ——
#     那会把一个诊断/复现入口变成不可能（Task 7 Step 1 的反证正是靠它）。
#  3. **非空声明必须带来源**：只给了因子、没给来源 ⇒ 响亮警告。产物里的
#     `expected_baseline_factors_source` 在那种情况下会退化成"未声明（默认空基线集）"，
#     而那与**真的**空基线集同形 —— 读数据的人分不出"声明了但没写为什么"与"没声明"。
#     这正是本层要堵的"安静"：**不会失败，只会让事后无从判断**。
lab_pve_baseline_factors="EF-SELINUX,EF-APPARMOR"
lab_pve_baseline_factors_source="PVE CT 基质：LXC 的 apparmor 命名空间不向容器暴露 profile（aa-status 报 Failed to get profiles: 2、可见策略数 0）⇒ OT-005 结构性不可观测；而 trigger.EF-SELINUX 与 trigger.EF-APPARMOR 都指向 OT-005 ⇒ 这两个因子恒在链上。用户 2026-10-10 裁定『按基质如实声明基线活跃集』，不去改 internal/checks"
case "$lab_substrate" in
  pve)
    if [ -z "${EDGEEXP_BASELINE_FACTORS+set}" ]; then
      EDGEEXP_BASELINE_FACTORS="$lab_pve_baseline_factors"
      EDGEEXP_BASELINE_FACTORS_SOURCE="$lab_pve_baseline_factors_source"
      export EDGEEXP_BASELINE_FACTORS EDGEEXP_BASELINE_FACTORS_SOURCE
    elif [ -n "$EDGEEXP_BASELINE_FACTORS" ] && [ -z "${EDGEEXP_BASELINE_FACTORS_SOURCE+set}" ]; then
      echo "edge_lab: 警告：EDGEEXP_BASELINE_FACTORS='$EDGEEXP_BASELINE_FACTORS' 是**非空**的基线声明，" >&2
      echo "  却没有给 EDGEEXP_BASELINE_FACTORS_SOURCE —— 产物里的来源会退化成" >&2
      echo "  『未声明（默认空基线集）』，与**真的**空基线集在数据上无法区分。" >&2
      echo "  基线集按基质声明，来源必须与它一起写出来（用户 2026-10-10 裁定）。" >&2
    fi ;;
  qemu)
    # **qemu 基质刻意不设默认基线集**（Task 13），理由是原则性的而不是"还没填"：
    #
    # 在 pve（LXC）上，`B = {EF-SELINUX, EF-APPARMOR}` 是**推导**出来的（LXC 的 apparmor
    # 命名空间不向容器暴露 profile ⇒ OT-005 结构性不可观测 ⇒ 那两个因子恒在链上），
    # 而那个推导只依赖"这是 LXC"这一件事 —— 所以在基质层写死是对的。
    #
    # 在 VM 上**没有**可推导的默认值：LSM 是否真的 enforcing、`OT-005` 过不过、
    # 有几个 profile 可见，全都取决于**这一批 VM 的实际配置**（镜像、cloud-init 装的包、
    # 有没有加载自定义 profile）。把它写死成 `∅` 或 `{EF-APPARMOR}` 等于**把一次实测结果
    # 当成前提**，而实测结果会随镜像与配置变 —— 那时脚本仍然"有个基线集"，
    # 只是它已经与事实不符，且**不会**有任何症状（链只是安静地多算/少算一个因子）。
    #
    # ⇒ 这里的处置与用户 2026-10-10「按基质如实声明」的裁定同源，只是把"如实"落到**跑批时**
    #   而不是**写代码时**：VM 基质上 `EDGEEXP_BASELINE_FACTORS` 必须**显式给**
    #   （通常由一个"先测 VM 基线"的步骤产出），并**必须**带 `_SOURCE`。
    #   ⇒ **不设**默认值（保持未设置），故 `edge_matrix.sh` 的既有行为不变：
    #      未声明 = 空基线集，而产物里的来源会如实写成"未声明（默认空基线集）"。
    if [ -n "${EDGEEXP_BASELINE_FACTORS:-}" ] && [ -z "${EDGEEXP_BASELINE_FACTORS_SOURCE+set}" ]; then
      echo "edge_lab: 警告：EDGEEXP_BASELINE_FACTORS='$EDGEEXP_BASELINE_FACTORS' 是**非空**的基线声明，" >&2
      echo "  却没有给 EDGEEXP_BASELINE_FACTORS_SOURCE —— 产物里的来源会退化成" >&2
      echo "  『未声明（默认空基线集）』，与**真的**空基线集在数据上无法区分。" >&2
      echo "  基线集**随基质变化**：VM 基质上的取值必须由实测得出（不许照抄 CT 基质的两个因子）。" >&2
    elif [ -z "${EDGEEXP_BASELINE_FACTORS+set}" ]; then
      echo "edge_lab: 提示：qemu（VM）基质上 EDGEEXP_BASELINE_FACTORS **没有默认值** ——" >&2
      echo "  VM 上 LSM 是**真的**能 enforcing 的，基线活跃集取决于这一批 VM 的实际配置，" >&2
      echo "  写死等于把一次实测结果当前提。跑批前请显式给：EDGEEXP_BASELINE_FACTORS=<实测集>" >&2
      echo "  （空集就写空串）**并**给 EDGEEXP_BASELINE_FACTORS_SOURCE=<为什么是这个集>。" >&2
      echo "  当前按『未声明（空基线集）』继续 —— 与 CT 基质的两个因子**不可混算**。" >&2
    fi ;;
esac

# lab_lab_dir / lab_topology —— lab 目录与拓扑文件。
#
# 路径的解析基准是本文件自己的位置（`edge_lab.sh` 与四个调用脚本同在 scripts/ 下），
# 因此调用方不必先把 `LAB_DIR` 算好再 source 本文件 —— source 顺序不再影响取到的是哪个路径。
lab_lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lab_topology="${EDGEEXP_TOPOLOGY:-$lab_lab_dir/asscor.clab.yml}"

# lab_inspect_log —— clab `inspect` 的 stderr 落点。**与抽象前的 `edge_reset.sh` 逐字相同**：
# `edge_reset.sh` 的 I9 分支与多句错误串都直接引用这个路径。
#
# `lab_tmp` 是本层临时文件的目录（默认 `/tmp`，抽象前写的就是这个值）。它**必须**可覆盖：
# 离线复现夹具要用自己的目录跑同一条命令（本机 /tmp 里躺着历史上 root 写下的同名文件，
# 夹具会以一个与"命令序列变了"完全无关的 Permission denied 变红 —— 那正是假证据的形态）。
lab_tmp="${EDGEEXP_LAB_TMP:-/tmp}"
lab_inspect_json="$lab_tmp/edgeexp-clab-inspect.json"
lab_inspect_log="$lab_tmp/edgeexp-clab-inspect.log"

# lab_node_vmid <node> —— **pve 专属**：节点名 → VMID（本层**唯一**的名字解析点）。
#
# 为什么需要它（简报 §1「节点标识的坑」）：既有脚本用**名字**（`asc-tgt-c2`）标识节点，而 `pct`
# 的原生标识是 **VMID（数字）**——`pct exec/list/push/status/config` 全都要数字。`pct list` 同时
# 给出两者，故解析只在这里做一次；其余每个 pve 分支都调它，**不得**各自再写一份。
#
# 三条判据（每一条都对应一种"看起来能跑、其实作用到别处"的形态）：
#
#  1. **只认 `pct list` 里真的存在的那个名字**。解析不到 ⇒ 响亮失败并**列出当前可见的节点**，
#     绝不猜一个 vmid：猜错会把命令下到**别人的 CT** 上，而它对调用方与正确执行完全同形。
#  2. **重名 ⇒ 也失败**（匹配到多个 VMID 时报错而不是取第一个）。PVE 不强制 hostname 唯一，
#     两个 CT 同名时"取第一个"就是一次静默的任意选择。
#  3. **列位置不写死**。实测 `pct list` 的输出是**四列** `VMID Status Lock Name`，而 `Lock` 为空
#     时整行塌成**三格**（`904  stopped  asc-tgt-c2`）—— 故判据是"第 1 格是纯数字 + **最后**一格
#     等于名字"（`$NF`），而不是任何固定列号（简报把它写成"VMID + Name 两列"，与实测不符）。
#     表头行 `VMID Status Lock Name` 被第 1 格的纯数字判据自然滤掉。
#
# 输出（成功时）：**只有 vmid**，一行一个（正常恰好一行）—— 供调用方 `$( )` 直接取用。
lab_node_vmid() {
  local node="$1" listing matches count
  listing="$("$lab_target_bin" list 2>/dev/null)" || {
    echo "edge_lab: 取节点清单失败（$lab_target_bin list，基质 $lab_substrate）——" >&2
    echo "  名字 '$node' 无法解析成 VMID；本层不会在『问不清』的情况下继续（那会变成一次盲操作）。" >&2
    return 1
  }
  matches="$(printf '%s\n' "$listing" | awk -v n="$node" '$1 ~ /^[0-9]+$/ && $NF == n {print $1}')"
  count="$(printf '%s\n' "$matches" | awk 'NF {c++} END {print c+0}')"
  case "$count" in
  1)
    printf '%s\n' "$matches"
    return 0 ;;
  0)
    echo "edge_lab: 在 $lab_target_bin list 里找不到名字为 '$node' 的节点（基质 pve）——" >&2
    echo "  节点由**名字**标识，而 pct 的原生标识是 VMID；名字对不上时本层**绝不猜一个 vmid**" >&2
    echo "  （猜错会把命令下到别的 CT 上，而那与正确执行看起来完全一样）。" >&2
    echo "  当前可见的节点（VMID Name）：" >&2
    printf '%s\n' "$listing" | awk '$1 ~ /^[0-9]+$/ {printf "    %s %s\n", $1, $NF}' >&2
    return 1 ;;
  *)
    echo "edge_lab: 名字 '$node' 在 $lab_target_bin list 里匹配到 $count 个 VMID（$(printf '%s' "$matches" | tr '\n' ' ')）——" >&2
    echo "  同名时无法判定该操作哪一个，本层**响亮失败**而不是取第一个（那是一次静默的任意选择）。" >&2
    return 1 ;;
  esac
}

# lab_target_spec <node> —— 把基质层的节点名翻成 **`edgescen -target` 的语法**
# （`docker:<容器>` / `lxd:<实例>` / `pve:<vmid>`；见 cmd/edgescen 的 `parseNodeTarget`）。
#
# 为什么必须有一个**单一来源**做这件事（而不是在采集脚本里手工拼前缀）：记录里的
# `meta.observation_target` 来自 `edgescen` 那侧的解析结果，而 `edge_collect.sh` 的观测主体
# 断言拿 `EDGEEXP_TARGET` 去比对它 —— 两处对"这个节点叫什么"的口径一旦分叉，
# 断言就会以"记录声称观测主体是 X，而本轮声明的节点是 Y"的名义把每条记录都判死，
# 而真正的原因只是少了一个前缀。**clab 基质保持裸名字**：`docker exec <容器名>` 是既有语义，
# 也是抽象前的字节（题面要求 `docker:` 前缀下逐位不变）。
#
# pve 这里**必须**做名字→vmid 的解析（`edgescen` 那侧只认数字 vmid），失败即往外传非零 ——
# 采集侧会因此整轮失败，**不会**退回本机结果（那正是这条路径最危险的静默形态）。
lab_target_spec() {
  local node="$1" vmid
  case "$lab_substrate" in
    clab) printf '%s\n' "$node" ;;
    lxd)  printf 'lxd:%s\n' "$node" ;;
    pve)
      vmid="$(lab_node_vmid "$node")" || return $?
      printf 'pve:%s\n' "$vmid"
      ;;
    qemu)
      # `qemu:<vmid>`（见 cmd/edgescen 的 parseNodeTarget）。**不在这里做名字→vmid 的解析**：
      # qemu 那一格**既收 vmid 也收名字**（VM 的标识同时存在于 `qm list` 的 VMID 列与 Name 列），
      # 故节点标识可以原样传下去 —— pve 需要解析是因为 `pct` **只认数字**。
      # 但"SSH 连哪台机器"要在这一层先算出来（唯一解析点 `lab_node_ssh_host`）：
      # 算不出来就**响亮失败并往外传非零**，采集侧据此整轮失败，
      # **不会**退回本机结果（那正是这条路径最危险的静默形态）。
      lab_node_ssh_host "$node" >/dev/null || return $?
      printf 'qemu:%s\n' "$node"
      ;;
  esac
}

# lab_node_counts —— 节点计数（回显 "total up down"），**clab 分支与抽象前的 `clab_node_counts`
# 逐字等价**（同一份 python 解析、同一个 `--format json`、同一个 stderr 落点）。
#
# 为什么解析仍然留在基质层：`clab inspect --format json` 是拓扑自己的视图，它的形状
# （`{<lab 名>: [节点…]}` / 0.78 实测）是基质知识；换基质时"节点数"本来就要求另一套说法。
#
# **inspect 本身失败时回显 `-1 -1 -1`**（而不是 0 0 0）：0 节点的含义是"拓扑已清空"，那是一条
# 会被"destroy 之后断言拓扑为空"采信的结论 —— inspect 挂了却报 0 会让那条断言**空洞地通过**
# （Fix round 2 的 I9 项）。等待循环只看 total > 0，-1 会被当作"还没就绪"继续等。
lab_node_counts() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" inspect -t "$lab_topology" --format json > "$lab_inspect_json" 2>>"$lab_inspect_log"
    local rc=$?
    python3 - "$rc" "$lab_inspect_json" <<'PY'
import json, sys
rc = int(sys.argv[1])
if rc != 0:
    print(-1, -1, -1); raise SystemExit
try:
    data = json.load(open(sys.argv[2]))
except Exception:
    print(-1, -1, -1); raise SystemExit
# clab 的 --format json 是 {<lab 名>: [节点…]}（0.78 实测）；同时兼容 {containers:[…]} 形态
nodes = []
if isinstance(data, dict):
    if isinstance(data.get('containers'), list):
        nodes = data['containers']
    else:
        for value in data.values():
            if isinstance(value, list):
                nodes.extend(value)
elif isinstance(data, list):
    nodes = data
up = sum(1 for c in nodes if (c.get('state') or '').lower() in ('running', 'up'))
print(len(nodes), up, len(nodes) - up)
PY
    ;;
  lxd)
    # LXD 侧没有"拓扑"这个对象，节点数不是能从这个基质问出来的东西。回显 -1（"查不出来"）
    # 并**响亮说明** —— 调用方把它读成"环境不可用"而失败，正是这里想要的处置。
    echo "edge_lab: lab_node_counts 对 lxd 不适用（LXD 上没有拓扑对象；节点集合由实例列表定义）——" >&2
    echo "  返回 -1 -1 -1（=『查不出来』，不是『0 个节点』），调用方不得据此断言环境已清空。" >&2
    printf '%s\n' "-1 -1 -1"
    ;;
  pve)
    # 与 lxd **逐条同源**：PVE 上也没有"拓扑"这个对象（节点集合由 CT 列表定义），
    # 故同样回显 -1 而不是 0 —— 0 的含义是"拓扑已清空"，那是一条会被
    # `edge_reset.sh` 的 I9 补断言采信的结论，而 inspect 类的失败绝不能空洞地满足它。
    echo "edge_lab: lab_node_counts 对 pve 不适用（PVE 上没有拓扑对象；节点集合由 CT 列表定义）——" >&2
    echo "  返回 -1 -1 -1（=『查不出来』，不是『0 个节点』），调用方不得据此断言环境已清空。" >&2
    printf '%s\n' "-1 -1 -1"
    ;;
  qemu)
    # 同 lxd/pve 的处置（PVE 上没有"拓扑"对象，节点集合由 VM 列表定义）。这里**不**去用
    # `qm list` 的行数冒充"拓扑节点数"：那两件事只在"这一批 VM 就是全部节点"时才碰巧相等，
    # 而一旦相等，调用方就会拿它做"拓扑已建好/已清空"的断言 —— 那条断言的真实含义
    # （"**本任务**的节点都在/都不在"）与 `qm list` 的（"这台宿主上有几台 VM"）不是一回事。
    echo "edge_lab: lab_node_counts 对 qemu 不适用（PVE 上没有拓扑对象；节点集合由 VM 列表定义，" >&2
    echo "  而那与『本任务的节点』不是同一个集合 —— 宿主上还有别人的 VM）——" >&2
    echo "  返回 -1 -1 -1（=『查不出来』，不是『0 个节点』），调用方不得据此断言环境已清空。" >&2
    printf '%s\n' "-1 -1 -1"
    ;;
  esac
}

# lab_up —— 建拓扑（clab: `deploy`；幂等性由 clab 自己负责）。
#
# 关键路径：**不做任何容错**（`edge_reset.sh` 的既有契约：deploy 失败即整轮失败）。
# 不用 `--reconfigure`：后者不重建 veth，上一场景的接口状态会带进下一场景（Task 3 之前实测过）。
lab_up() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" deploy -t "$lab_topology"
    ;;
  lxd)
    echo "edge_lab: lab_up 对 lxd 不适用 —— A-1 上的实验环境是【既有实例集合】（控制侧裁定" >&2
    echo "  probe-ot005 等实例不得被删改），LXD 侧没有『建拓扑』这个动作，本层不会 launch 任何实例。" >&2
    echo "  这不是可以放过的不一致：静默返回 0 会让一次『复位成功』的假象进入记录。" >&2
    return 2 ;;
  pve)
    # 与 lxd 同处置、理由同源：PVE 上的实验环境同样是【既有 CT 集合】，本层不会 create 任何 CT。
    echo "edge_lab: lab_up 对 pve 不适用 —— PVE 上的实验环境是【既有 CT 集合】，" >&2
    echo "  PVE 侧没有『建拓扑』这个动作，本层不会 create/start 任何 CT（新建 CT 是操作者的动作，" >&2
    echo "  不在实验脚本的路径上：脚本建了 CT 就得由脚本销毁，而『谁建的谁来销毁』在这里没有单一来源）。" >&2
    echo "  这不是可以放过的不一致：静默返回 0 会让一次『复位成功』的假象进入记录。" >&2
    return 2 ;;
  qemu)
    # **理由与 lxd/pve 不同（Task 13 写明）**：这里不是"怕碰别人的东西"，而是"建机有它自己的
    # 单一来源"。VM 是**要建**的（与 CT 不同），而建机/清机在
    # `lunwen/clab-lab/scripts/edge_vm_provision.sh` 里已经有一套**幂等 + 带 VMID 下限 +
    # 带 --destroy** 的实现。基质层再做一遍"建 VM"就有了两个入口，而两者对
    # "哪些 VMID 属于本任务"的判据一旦分叉，一次 lab_down 就能拆掉别人的 VM ——
    # 故本层只**访问**，永不 create/start/destroy。
    echo "edge_lab: lab_up 对 qemu 不适用 —— VM 的建/清有**单一来源**：" >&2
    echo "  lunwen/clab-lab/scripts/edge_vm_provision.sh（幂等、VMID 从 910 起、带 --destroy）。" >&2
    echo "  本层不会 create/start 任何 VM：两个入口对『哪些 VMID 属于本任务』的判据一旦分叉，" >&2
    echo "  一次误操作就会作用到别人的 VM 上。建机请跑那个脚本。" >&2
    return 2 ;;
  esac
}

# lab_down —— 毁拓扑（clab: `destroy --cleanup`）。
#
# 与抽象前一致：这里的失败**由调用方容忍**（没部署过时 destroy 本来就会报错），
# 故本函数不自己判断、不打印、不吞错 —— 退出码原样交给调用方（它要据此走 I9 的补断言）。
lab_down() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" destroy -t "$lab_topology" --cleanup
    ;;
  lxd)
    echo "edge_lab: lab_down 对 lxd 不适用 —— 本层**永不**删除 A-1 上的实例（probe-ot005 等是" >&2
    echo "  控制侧的对照容器）。需要清理实例时由操作者显式手工执行，不在实验脚本的路径上。" >&2
    return 2 ;;
  pve)
    # 与 lxd 同处置、理由同源（且更硬）：一次猜测性的 destroy 会**销毁别人的 CT**，
    # 而 PVE 上没有"这台 CT 是本任务建的吗"这个信息 —— 故本层永不 destroy。
    echo "edge_lab: lab_down 对 pve 不适用 —— 本层**永不**销毁 PVE 上的 CT（宿主上的 CT 集合是" >&2
    echo "  操作者与别的任务共用的；一次猜测性的 destroy 会把**别人的** CT 删掉，而脚本没有" >&2
    echo "  『这台 CT 是不是本次实验建的』这个信息）—— 需要清理时由操作者显式手工执行。" >&2
    return 2 ;;
  qemu)
    # 与 pve 同处置（一次猜测性的 destroy 会删掉**别人的** VM），但**额外**说明清机该走哪里：
    # `edge_vm_provision.sh --destroy` 有"前缀 + VMID 下限"两道护栏，能在拆之前确认
    # "这台 VM 是本任务建的吗"。基质层没有那个信息，故永不 destroy。
    echo "edge_lab: lab_down 对 qemu 不适用 —— 本层**永不**销毁 VM（`qm destroy --purge` 会连磁盘" >&2
    echo "  一起删，而宿主上还有别人的 VM/CT）。清机请跑有护栏的那一个：" >&2
    echo "  lunwen/clab-lab/scripts/edge_vm_provision.sh --destroy（只拆带本任务前缀、VMID ≥ 910 的）。" >&2
    return 2 ;;
  esac
}

# lab_target_exec <node> <cmd…> —— 在目标内部执行命令（stdout/stderr 原样透传给调用方）。
#
# 两条等价性纪律（clab 分支）：
#   · 参数**逐条**透传（`"$@"`）：调用方写的是 `lab_target_exec "$NODE" bash -c "…"`，
#     而不是把一整串命令交给某个 shell 再分词 —— 后者会让含空格/引号的判据体被拆开。
#   · 不自己重定向 stdout/stderr：抽象前的调用点各自决定 `2>/dev/null` 或 `>/dev/null 2>&1`
#     （有的故意要看错误），本层一律不做决定。
lab_target_exec() {
  local node="$1"; shift
  case "$lab_substrate" in
  clab)
    # 用 `$lab_target_bin`（clab 下默认 `docker`，`EDGEEXP_DOCKER_BIN` 可覆盖），
    # **不是**写死的 `docker` —— 写死会让抽象前那个覆盖开关在容器级路径上失效（I-1）。
    "$lab_target_bin" exec "$node" "$@"
    ;;
  lxd)
    # `--` 把命令与 lxc 自己的开关分开：`lxc exec <实例> -- <cmd…>`。少了它，
    # 一条以 `-` 开头的命令串会被 lxc 当成自己的参数（实测 rc=1）。
    "$lab_target_bin" exec "$node" -- "$@"
    ;;
  pve)
    # 形状与 lxd **逐项对应**：`pct exec <vmid> -- <cmd…>`。
    # `--` 在这里同样**不是可选的**（实测）：`pct exec` 把 `--` 之后的整串当 `<extra-args>`
    # 原样交给容器，故以 `-` 开头的参数（`-emit-checks`、`ip -4 -o addr …` 里的 `-4`）
    # 不会被 `pct` 自己吃掉。少了它，那些参数会被 pct 的选项解析器截走。
    # 节点是**名字**、vmid 是**数字** ⇒ 必经 lab_node_vmid（唯一解析点）；解析失败即往外传非零。
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" exec "$vmid" -- "$@"
    ;;
  qemu)
    # `ssh <连接参数> -- <主机> bash -c '<命令串>'`。
    #
    # ⚠️ **这里是 qemu 分支唯一一处"不能与 docker/lxd/pve 逐项对应"的地方**，理由必须写清：
    # 前三者都有一个"把 argv 原样交给客人"的 CLI（`docker exec <容器> <argv…>` /
    # `lxc exec <实例> -- <argv…>` / `pct exec <vmid> -- <argv…>`），而 **`ssh` 没有** ——
    # ssh 把 `-- <主机>` 之后的**所有格**拼成一个字符串，交给**客人侧的登录 shell** 去再分词。
    # 于是同一个调用点
    #     `lab_target_exec <节点> bash -c "echo 'a b'"`
    # 在 ssh 侧得到的不是 `bash` 收到 `-c` 与那一段脚本，而是一行被远端 shell 重新解析过的文本。
    #
    # ⇒ 本分支把 argv **显式**重建成一条**引号正确**的命令串（`"$*"`：argv 是调用方给的，
    #   `$*` 是"用空格拼起来"的那个语义），再交给客人侧的 `bash -c` 当**一整段脚本**执行。
    #   逐条对应关系：
    #     · clab/lxd/pve：argv 逐格透传（客人侧进程直接收到调用方写的那些格）；
    #     · qemu：argv 先**拼成一条命令串**，再由客人侧 `bash -c` 解释 —— 引号/空格/
    #       重定向的语义因此落在**调用方写的那条命令串**上，而不是落在 argv 的格边界上。
    #   这条差别是**结构性**的（ssh 协议本身如此，不是实现选择），故写在这里而不是藏在注释里：
    #   需要"格边界精确保真"的调用点（现在的调用点都不是）在 qemu 基质上要自己保证引号。
    #   三种基质的**共同契约**（"命令在目标里被执行了、stdout/stderr 原样透传、失败非零"）
    #   在 qemu 侧逐条成立；`set -o pipefail` 由调用方与客人侧各自负责。
    #
    # `--` 必须在主机名之前：`ssh <主机> -c …` 里以 `-` 开头的那一格会被 ssh 当成自己的选项。
    local host args=()
    host="$(lab_node_ssh_host "$node")" || return $?
    mapfile -t args < <(lab_ssh_conn_args) || return $?
    "$lab_target_bin" "${args[@]}" -- "$host" bash -c "$*"
    ;;
  esac
}

# lab_push <local> <node> <dest> —— 把文件送进目标（dest 是**目标内**绝对路径）。
#
# 两种基质的语法不同（clab: `docker cp <local> <node>:<dest>`；lxd: `lxc file push <local> <node><dest>`）
# —— 这正是本层存在的理由：调用方只说"把这个文件放到那个位置的节点里"。
lab_push() {
  local local_path="$1" node="$2" dest="$3"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" cp "$local_path" "$node:$dest"
    ;;
  lxd)
    "$lab_target_bin" file push "$local_path" "$node$dest"
    ;;
  pve)
    # `pct push <vmid> <本地> <目标> --perms 755` —— 注意**参数顺序与 lxd 相反**
    # （`lxc file push <本地> <实例><目标>` 是"本地在前"，`pct push` 是"vmid 在前"），
    # 且目标路径是**独立的第三个参数**（没有 lxc 那种"实例名与路径拼在一起"的写法）。
    # `--perms 755` 与调用点随后的 `chmod 755`（如 edge_reset.sh）语义一致，且把权限在
    # **送进去的那一刻**就定下来 —— 省掉一个"推成功但没执行权限"的中间态。
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" push "$vmid" "$local_path" "$dest" --perms 755
    ;;
  qemu)
    # `scp <连接参数> -O <本地> <主机>:<dest>` + 紧随其后的 `ssh <连接参数> -- <主机> chmod 0755 <dest>`。
    #
    # 两条都是**必需**的，各自对应一种"看起来成功、其实没到位"的形态：
    #   · **`-O`**（强制 legacy SCP 协议）：OpenSSH 9.0+ 默认走 SFTP 子系统，而 cloud image 里
    #     `sftp-server` 的位置随发行版变；缺了就报 `subsystem request failed` ——
    #     那条错误指向"子系统没配"，与真正的原因（本机 scp 的默认协议）差得很远。
    #   · **`chmod 0755`**：`scp` 保留源文件的权限位而**不**保证可执行。少了这一条，
    #     症状是客人侧的 `Permission denied`（看起来像"权限不足"），而不是"没传进来"。
    #     pve 侧靠 `pct push --perms 755` 一次到位，VM 侧没有等价开关（`scp -p` 保留的是
    #     **宿主上那个文件**的权限，而宿主上它是 0644 的构建产物）。
    local host args=()
    host="$(lab_node_ssh_host "$node")" || return $?
    mapfile -t args < <(lab_ssh_conn_args) || return $?
    "$lab_scp_bin" "${args[@]}" -O "$local_path" "$host:$dest"
    "$lab_target_bin" "${args[@]}" -- "$host" chmod 0755 "$dest"
    ;;
  esac
}

# lab_target_exec_detached <node> <cmd…> —— 在目标内起一个**不随本次连接结束而退出**的进程
# （调用方立即返回，不等它跑完）。
#
# 为什么不能复用 `lab_target_exec`：两种基质的"脱离"机制不同，而错的机制会**静默**失效——
# 进程被 SIGHUP 带走后，调用方只看到"agent 一直没回连"，那与"agent 起不来"同形。
#
#   · clab（`docker exec -d`）：docker 在容器内起进程后立即返回，stdin 为 /dev/null，
#     不随客户端断开而终止 —— 与抽象前的调用点逐字等价。
#   · lxd（`lxc exec` 没有 -d）：走**shell 的脱离惯用法**。实测过
#     `lxc exec <实例> -- nohup bash -c 'sleep 5; …' &`（**必须**加 nohup 与重定向：
#     只写 `&` 的话命令的 stdio 还挂在掉线即断的 exec 通道上，客户端一断进程就被带走）。
#
# **argv 必须逐条保真**（Fix round 1 / I-2）：修复前这里把 `"$@"` 压成 `"$*"` 再拼成
# `nohup sh -c '<整串>'`，于是同一个调用点（`lab_target_exec_detached <node> bash -c "…"`）
# 在两种基质下**语义不同** —— lxd 侧节点内拿到的是"`bash -c` + 若干分离参数"，
# `bash -c` 只取第一个参数当脚本、其余变成 `$0/$1…`，命令串本身被丢掉；而调用点**返回 0**，
# 兜底只剩 180 s 的 agent 回连超时。评审用假 CLI 直接复现（sandcat 收到空 argv）。
# 现在与 clab 同语义：把调用方给的 **argv** 原样转交节点内的 `sh -c`（`"$@"` 放在
# `sh -c` 的脚本位置之后，于是 `sh` 的 `$@` 就是这些 argv；`_` 占位 `$0`）。
#
# **返回码语义（Fix round 1 / M-6，逐条写明）**：两种基质返回的都是"**交付这条启动请求**的结果"，
# 不是"被启动的进程后来怎么样了"：
#   · clab：`docker exec -d` 的退出码（docker CLI 自己起不来/容器不在 ⇒ 非零；它把请求交给
#     daemon 之后立刻返回 0，**之后**进程崩掉与这个 rc 无关）；
#   · lxd：`lxc exec …` 的退出码（实例不存在/连不上 ⇒ 非零；节点内那段 `nohup … &` 把命令挂进
#     后台后立即返回 0，**它自己**是否成功不由这个 rc 表达）。
#   ⇒ 两侧**都**不能用 rc 判断"agent 有没有起来"。既有兜底（`edge_reset.sh` 的 `AGENT_WAIT_S`）
#   就是为这件事存在的，本轮**没有**给它加第二套判据 —— 加"启动后立刻查一次"会把两件事混成一个
#   结论（实例活着 ≠ 命令跑成功），而要真正区分它得让节点内进程把结果写回来，那是 Step 3/4 的事
#   （真机上验证"会话断开后进程仍在跑"也必须在那时候做）。
lab_target_exec_detached() {
  local node="$1"; shift
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" exec -d "$node" "$@"
    ;;
  lxd)
    "$lab_target_bin" exec "$node" -- sh -c 'nohup "$@" >/dev/null 2>&1 </dev/null &' _ "$@"
    ;;
  pve)
    # 与 lxd **逐字同形**（`pct exec` 同样没有 `-d`）：脱离靠 shell 惯用法 ——
    # `nohup` + 三个重定向 + `&`。没有它们的话，命令的 stdio 仍挂在"掉线即断"的 exec 通道上，
    # `pct exec` 一返回进程就被带走，而调用方只看到"agent 一直没回连"（与"agent 起不来"同形）。
    # `"$@"` 放在 `sh -c` 的脚本位置**之后**（`_` 占位 `$0`），故节点内 `sh` 的 `$@` 就是调用方
    # 给的 argv —— 与 clab/lxd 两侧的 argv 保真纪律一致（Fix round 1 / I-2）。
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" exec "$vmid" -- sh -c 'nohup "$@" >/dev/null 2>&1 </dev/null &' _ "$@"
    ;;
  qemu)
    # 与 lxd/pve **同源地照搬这个 shell 惯用法**（`nohup` + 三个重定向 + `&`）：没有它们的话，
    # 命令的 stdio 仍挂在"掉线即断"的 ssh 通道上，ssh 一返回进程就被带走 ——
    # 而调用方只看到"agent 一直没回连"（与"agent 起不来"同形）。
    #
    # ⚠️ 前缀是 **`nohup sh -c '…' _ "$@"`**（引号在**客人侧的 sh** 那一段里），
    # 与上面 `lab_target_exec` 的 `bash -c "$*"` **刻意不同**：这里的命令是"起一个后台进程"，
    # 而"起"这个动作的 argv 保真纪律来自 lxd/pve 那一轮（Fix round 1 / I-2：
    # `"$@"` 放在 `sh -c` 的脚本位置**之后**，`_` 占位 `$0`，于是客人侧 `sh` 的 `$@`
    # 就是调用方给的 argv）。但 ssh 会把整串交给远端 shell，故这里必须**再包一层**
    # `bash -c`，让"引号"落在正确的解释层：
    #     ssh <主机> bash -c 'nohup "$@" >/dev/null 2>&1 </dev/null &' _ cmd arg…
    # 于是远端 bash 把整串当脚本执行，脚本里的 `"$@"` 展开成 `cmd arg1 arg2…`。
    # 若少了外层 `bash -c`，远端 shell 会把 `'nohup "$@" …'` 里的引号**自己**吃掉，
    # 于是 `"$@"` 在远端 shell 里变成"当前 shell 的位置参数"（通常为空）——
    # 命令被丢掉、返回 0，而症状与"agent 起不来"完全同形。
    local host args=()
    host="$(lab_node_ssh_host "$node")" || return $?
    mapfile -t args < <(lab_ssh_conn_args) || return $?
    "$lab_target_bin" "${args[@]}" -- "$host" bash -c \
      'nohup "$@" >/dev/null 2>&1 </dev/null &' _ "$@"
    ;;
  esac
}

# lab_node_ip <node> <iface> —— 取目标某接口的 IPv4 CIDR（例如 `10.217.208.42/24`）。
#
# 无地址/接口不存在 ⇒ 打印空行并返回非零（调用方据此走"探测候选为空"的既有分支）；
# clab 分支的命令、重定向与抽象前的 `docker exec "$NODE" ip -4 -o addr show eth0 2>/dev/null` 逐字相同。
lab_node_ip() {
  local node="$1" iface="$2"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" exec "$node" ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  lxd)
    "$lab_target_bin" exec "$node" -- ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  pve)
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" exec "$vmid" -- ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  qemu)
    # 与 pve 那行的**取值形状完全一致**（`ip -4 -o addr show <iface>` + `awk '{print $4}'`），
    # 只是"在客人里执行"由 ssh 承担。**接口名不改**：cloud image 的网卡在客人里叫 `eth0`
    # （cloud-init 的 netplan 用 `eth0`），而 `lab_node_ip <node> <iface>` 的 `iface` 由调用方给 ——
    # 故这里不替调用方做"vmbr1 的网卡该叫 eth0 还是 ens18"的猜测（猜错会拿到空地址，
    # 而空地址的既有语义是"这个接口没有 IPv4"，与"接口名写错了"完全同形）。
    local host args=()
    host="$(lab_node_ssh_host "$node")" || return $?
    mapfile -t args < <(lab_ssh_conn_args) || return $?
    "$lab_target_bin" "${args[@]}" -- "$host" ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  esac
}

# lab_node_pids <node> <comm-regex> —— 目标内**当前活着**的进程 PID（每行一个，按 PID 升序）。
#
# 为什么需要它（Task 4D Step 4 / 已知坑 2）：Caldera **保留已死 agent 的条目**（`trusted=true`
# 但 `last_seen` 停在容器消失那一刻）。攻击脚本若只按"有心跳的 agent"挑人，就可能把 operation
# 打到一只**已经死掉的** agent 上 —— 链里出现 `status=-3`（EXECUTE），而 `-3` **看起来像"被拦住"**。
# 正确的判据是 **`(host, 容器内当前活着的 pid)`**：先问目标"你里面现在有哪些 pid"，再去 agent
# 表里按 `(host, pid)` 精确匹配。
#
# `comm-regex` 过滤进程名（例如 `sandcat`）；`ps` 的 comm 字段被内核截断到 15 字符，故用 `grep -E`
# 做子串匹配而不是精确相等。取不到（实例不存在/ps 不可用）⇒ **非零退出**，调用方据此响亮失败。
lab_node_pids() {
  local node="$1" pattern="${2:-.}"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" exec "$node" ps -eo pid,comm --no-headers 2>/dev/null \
      | awk -v p="$pattern" '$2 ~ p {print $1}' | sort -n
    ;;
  lxd)
    "$lab_target_bin" exec "$node" -- ps -eo pid,comm --no-headers 2>/dev/null \
      | awk -v p="$pattern" '$2 ~ p {print $1}' | sort -n
    ;;
  pve)
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" exec "$vmid" -- ps -eo pid,comm --no-headers 2>/dev/null \
      | awk -v p="$pattern" '$2 ~ p {print $1}' | sort -n
    ;;
  qemu)
    # 形状与 pve 逐项对应（同一条 `ps -eo pid,comm --no-headers` + 同一个 awk 过滤 + `sort -n`）。
    # ⚠️ **这一格在 VM 上比在 CT 上更重要**：VM 里跑的进程是**真的**（launchd/systemd/内核线程
    # 都会出现在 `ps` 里），而 CT 里只有容器命名空间内的进程 —— 于是"按 PID 匹配 agent"这条
    # 判据在 VM 上更容易撞上**别人的**进程（例如宿主侧别的任务在客人里起的工具）。
    # 故调用点用的 `(host, pid)` 精确匹配纪律在 VM 基质上**不是**可选的。
    local host args=()
    host="$(lab_node_ssh_host "$node")" || return $?
    mapfile -t args < <(lab_ssh_conn_args) || return $?
    "$lab_target_bin" "${args[@]}" -- "$host" ps -eo pid,comm --no-headers 2>/dev/null \
      | awk -v p="$pattern" '$2 ~ p {print $1}' | sort -n
    ;;
  esac
}

# lab_instance_exists <node> —— 目标存在吗（**只管存在性**，不管在不在跑）。
#
# 与 `lab_node_running` 的分工：本函数回答"要不要建"，后者回答"能不能进去"。把两者混成一个
# 会让"实例存在但没在跑"被读成"不存在"⇒ 一次多余的 launch（那会以 `Instance already exists`
# 失败，看起来像环境问题）。
lab_instance_exists() {
  local node="$1" vmid
  case "$lab_substrate" in
  clab) "$lab_target_bin" inspect "$node" >/dev/null 2>&1 ;;
  lxd)  "$lab_target_bin" info "$node" >/dev/null 2>&1 ;;
  pve)
    # "存在"的判据 = 名字能解析出 vmid **且** `pct status` 能应答。
    # 解析失败即"不存在"（同一个 `pct list` 就是存在性的权威来源）—— 这与 lxd 的
    # `lxc info` 失败即"不存在"同形，且**不猜** vmid。
    vmid="$(lab_node_vmid "$node" 2>/dev/null)" || return 1
    "$lab_target_bin" status "$vmid" >/dev/null 2>&1
    ;;
  qemu)
    # "存在"的判据 = `qm status <vmid|名字>` 能应答（**权威来源就是 PVE 自己**）。
    # 与 pve 侧**刻意不同**：这里**不做**"这个名字必须唯一"的解析 —— `qm` 原生同时接受
    # VMID 与 Name，`qm status <不存在的名字>` 自己会返回非零。多加一层解析只会多一处
    # 可能与 `qm` 自己的判据分叉的地方（分叉时症状是"节点明明在、脚本说不在"）。
    # ⚠️ **只管存在性**，不管在不在跑 —— 那是 `lab_node_running` 的事（两者混成一个
    # 会让"存在但没在跑"被读成"不存在"⇒ 一次多余的 start，而它看起来像环境问题）。
    "$lab_topology_bin" status "$node" >/dev/null 2>&1
    ;;
  esac
}
# lab_wait_node_exec <node> <秒> —— 等"这个节点真的能执行命令"（rc=0 = 就绪；rc=1 = 超时）。
#
# **为什么把"等就绪"收进基质层**（Task 4D Fix round 2 / Minor-6 的钉子）：`lab_node_running` 的取值
# 打在 **stdout**（`true`/`false`），rc 只表达"问得到/问不到"。调用方一旦写成
# `until lab_node_running "$node" >/dev/null 2>&1; do …` 就把**值**丢掉了 —— 而 **STOPPED 的实例
# 同样能应答**（`lxc info` 照常返回），于是那个循环 **0 秒就认为"已就绪"**。
# 实测（Step 4-B2）：`lxc restart` 刚发起时容器还是 RUNNING ⇒ 检查通过，随后的 `exec` 正好落在
# 停/起之间（`Error: Instance is not running`），而调用方是 `set -uo pipefail`（**没有 -e**）⇒
# 那行错被咽下去，整轮以"agent 180s 没回连"收场（真正的错因埋在中间一行里）。
#
# 就绪的唯一判据是"节点内 `true` 的 rc=0"（真正的能力），不是"某个状态的字符串" ——
# 这也顺带盖住了"状态已 RUNNING 但 exec 仍短暂失败"的窗口。
lab_wait_node_exec() {
  local node="$1" limit="${2:-120}" step="${EDGEEXP_LAB_WAIT_STEP:-3}" waited=0
  while ! lab_target_exec "$node" true >/dev/null 2>&1; do
    if [ "$waited" -ge "$limit" ]; then
      return 1
    fi
    sleep "$step"
    waited=$((waited + step))
  done
  return 0
}
#
# 两种基质的取值手段不同、形状也不同（clab: `docker inspect -f {{.State.Running}}`；
# lxd: `lxc info` 的 `Status:` 行），这正是本层要收口的东西：调用方（探针）只问"能不能在里面执行"，
# 不该知道 `true` 是从哪来的。**判据必须把"不存在"与"在跑/没跑"分开**：
# 假 docker 夹具（`build/test-edge-probe.sh`）注入的假可执行文件正是按 `inspect -f` 应答的，
# 故 clab 分支的命令形状与抽象前逐字相同。
lab_node_running() {
  local node="$1"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" inspect -f '{{.State.Running}}' "$node"
    ;;
  lxd)
    local out status
    out="$("$lab_target_bin" info "$node" 2>/dev/null)" || return 1
    status="$(printf '%s\n' "$out" | awk -F': *' '$1 ~ /^ *Status$/ {print tolower($2); exit}')"
    [ -n "$status" ] || return 1
    case "$status" in
      running) printf 'true\n' ;;
      *)       printf 'false\n' ;;
    esac
    ;;
  pve)
    # 形状与 lxd 逐项对应，只是取值来源换成 `pct status <vmid>`（实测输出 `status: running`）。
    # 三条判据（缺一条就会把"问不到"读成"没在跑"或反之）：
    #   · 名字解析不到 ⇒ **非零**（不是 `false`）：解析不到与"存在但没在跑"是两件事，
    #     后者会让调用方去 start 一个不存在的 CT；
    #   · `pct status` 本身失败 ⇒ **非零**（同上，`pct status` 对不存在的 vmid 是 rc=2）；
    #   · 解析不出 status 行 ⇒ **非零**（拿不到取值 ≠ false）。
    # `[Ss]tatus`：`pct` 打的是小写 `status:`，而 lxd 的 `lxc info` 打的是 `Status:` ——
    # 两种都吃（pve 分支是新的，没有"不许变"的历史包袱，说得更宽不会掩盖问题：
    # 真正要防的是"没有 status 行"这条，它仍然 return 1）。
    local vmid out status
    vmid="$(lab_node_vmid "$node" 2>/dev/null)" || return 1
    out="$("$lab_target_bin" status "$vmid" 2>/dev/null)" || return 1
    status="$(printf '%s\n' "$out" | awk -F': *' '$1 ~ /^ *[Ss]tatus$/ {print tolower($2); exit}')"
    [ -n "$status" ] || return 1
    case "$status" in
      running) printf 'true\n' ;;
      *)       printf 'false\n' ;;
    esac
    ;;
  qemu)
    # 形状与 pve 逐项对应，只是取值来源是 `qm status <vmid|名字>`（实测输出 `status: running`）。
    # 三条判据（与 pve 侧同源，缺一条就会把"问不到"读成"没在跑"或反之）：
    #   · `qm status` 本身失败（VMID 不存在）⇒ **非零**（不是 `false`）；
    #   · 解析不出 status 行 ⇒ **非零**（拿不到取值 ≠ false）；
    #   · 只把 `running` 判成 true，其余（`stopped`/`paused`/`prelaunch`…）一律 false。
    # ⚠️ 最后一条在 VM 上比在 CT 上更要紧：`paused`（QEMU 的挂起）**不是**"能进去执行"，
    # 而把它读成 true 会让调用方跳过 start，随后的 ssh 超时会被记成"agent 起不来"。
    local out status
    out="$("$lab_topology_bin" status "$node" 2>/dev/null)" || return 1
    status="$(printf '%s\n' "$out" | awk -F': *' '$1 ~ /^ *[Ss]tatus$/ {print tolower($2); exit}')"
    [ -n "$status" ] || return 1
    case "$status" in
      running) printf 'true\n' ;;
      *)       printf 'false\n' ;;
    esac
    ;;
  esac
}

# lab_inspect <node> —— 目标的基质视图（存在性/运行状态的**权威**判据），打印 JSON。
#
# 调用方只用它的退出码回答"这个节点存在吗"（clab 是 `docker inspect`、lxd 是 `lxc info`）；
# 打印出来的 JSON 留在日志里供排障。抽象前该处是 `docker inspect "$NODE" >/dev/null 2>&1`，
# 本函数把输出**收下**再交给调用方重定向 —— 退出码语义不变。
#
# pve 侧取 `pct config <vmid>`（PVE 的 `pct` 没有 `inspect`）。它**不是 JSON**（是 `key: value`
# 的配置视图）—— 与 lxd 侧取回的 `lxc info`（YAML）处境相同：调用方只用退出码，
# 内容是排障留痕，故这里不为了"看起来像 JSON"去转换（转换会引入一个新的解析层，
# 而它一旦与 pct 的输出格式漂移，就会以"节点不存在"的形态失败）。
lab_inspect() {
  local node="$1"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" inspect "$node"
    ;;
  lxd)
    "$lab_target_bin" info "$node"
    ;;
  pve)
    local vmid
    vmid="$(lab_node_vmid "$node")" || return $?
    "$lab_target_bin" config "$vmid"
    ;;
  qemu)
    # `qm config <vmid|名字>`：PVE 的 VM 配置视图（同样是 `key: value`，不是 JSON —— 与 pve 侧
    # 的处境相同，调用方只用退出码，内容是排障留痕）。
    # **额外价值**（VM 基质独有）：这一份输出就是"这台 VM 挂在哪条桥、几核几内存、
    # balloon 下限多少"的**唯一**权威来源 —— 跑批后追查"这批数据采自什么环境"时，
    # 它是比记录里的 env 标签**硬**得多的证据（标签是手填的，这份是 PVE 自己写的）。
    "$lab_topology_bin" config "$node"
    ;;
  esac
}

# lab_list —— 列出目标（每行一个名字，**含非 running 的**：调用方自己判断状态）。
#
# clab 的 `docker ps -a` 是"这台机器上所有容器"，不是"本拓扑的节点"；拓扑视图请用
# `lab_node_counts`（它才是 `clab inspect` 的拓扑视图）。这里刻意给出两种基质的"实例名字面"，
# 供干跑与排障使用。
#
# pve 侧：**契约是"每行一个名字"，而 `pct list` 打的是四列表格**（`VMID Status Lock Name`，
# `Lock` 为空时那一格会消失）—— 故这里按 `lab_node_vmid` 的同一条判据（第 1 格纯数字、
# 名字在**最后**一格）把名字抽出来，而不是把整张表原样吐出去（原样吐出去会让每个调用方
# 各自实现一次同一套解析，那正是本层要收口的东西）。表头行由"第 1 格是纯数字"自然滤掉。
lab_list() {
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" ps -a --format '{{.Names}}'
    ;;
  lxd)
    "$lab_target_bin" list --format csv -c n
    ;;
  pve)
    "$lab_target_bin" list | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {print $NF}'
    ;;
  qemu)
    # `qm list` 的实测形状：一行表头 `VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID` +
    # 每台一行（名字在第 2 格、**不是**最后一格 —— 与 `pct list` 的"名字在最后一格"相反）。
    # 故判据是"第 1 格纯数字 ⇒ 取第 2 格"，与 pve 那条**不能共用**（共用会让名字变成 PID，
    # 而那个"名字"看起来只是个奇怪的字符串，不会有任何报错）。
    "$lab_topology_bin" list | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {print $2}'
    ;;
  esac
}
