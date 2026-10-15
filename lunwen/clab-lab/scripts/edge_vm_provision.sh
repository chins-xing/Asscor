#!/bin/bash
# ============================================================================
# edge_vm_provision.sh —— 方向② 的 **QEMU/KVM 靶机基质**：建机 / 清机（Task 13）
# ============================================================================
#
# 为什么有这个脚本（用户 2026-10-15 两条裁定的落地）：
# ① 「如果 CT 用起来难受或者受限太多直接用 VM，不然我为啥会选择 PVE 作为系统」；
# ② 「CT 的作用本来就是快速验证和轻量模拟，应该作为临时短期任务的选择。长线和中重型拓扑
#    模拟和重要任务本来就应该交给拥有完整环境的 VM 来保证数据的准确性和环境和可靠性」。
# ⇒ 全量批次跑在 **VM** 上；CT 只是"快速验证"那一格的现成靶机（`asc-tgt-c2` / VMID 904，
#   **本脚本永不触碰它**）。
#
# ---------------------------------------------------------------------------
# 技术路线（全自动、几分钟，不需要人工装系统、不需要下载安装 ISO）
# ---------------------------------------------------------------------------
# 宿主走 `vmbr1` **能直连公网**（实测 `cloud-images.ubuntu.com` 可达）⇒
#   拉 Ubuntu cloud image → `qemu-img convert` 成 raw → `qm importdisk` 成 VM 磁盘 →
#   用 `genisoimage` 造一个 **NoCloud seed ISO**（`meta-data` + `user-data`，卷标 `cidata`）
#   → 作为 CD-ROM 挂上 → `qm create` / `qm start` → 等客人自助配置完 → 等 SSH。
#
# **seed 走 NoCloud ISO 而不是 PVE 原生 cloud-init（`ciuser`/`sshkeys` + `cicustom`）**，理由：
#   · 原生路线要把 `snippets` 加进某个存储的 `content`（本机 `local` 是
#     `content import,vztmpl,backup`，**没有** snippets，且 `/var/lib/vz/snippets` 不存在）
#     ⇒ 一次建机要改**宿主存储配置**，而那是全局状态；ISO 是每台 VM 一个自包含文件。
#   · `qm set --sshkeys` 是**交互式**的（它读 stdin 追加公钥），放进脚本里必须走
#     "`cat | qm set`" 那种形状 —— 而那正是最容易把"追加失败"读成"设置成功"的地方。
#   · NoCloud 是 cloud-init 的**标准**数据源，云镜像本来就能识别（卷标 `cidata` 即触发），
#     不依赖 PVE 对云镜像的支持程度。
#   · 代价：`qm cloudinit dump/update` 这类 PVE 原生命令看不到我们的 user-data。
#     这是**有意**的取舍 —— 脚本自己写并自己销毁，唯一真源就在本文件里。
#
# ---------------------------------------------------------------------------
# 与实验代码的契约（**接口，不是巧合**）
# ---------------------------------------------------------------------------
#   · 每台 VM 的 hostname = `$NAME_PREFIX<vmid>`（默认 `asc-vm910`…），
#     而 `cmd/edgescen` 的 qemu 基质在没有 `EDGEEXP_VM_SSH_HOST` 时用的默认规则
#     **就是** 这个形状（`asc-vm<vmid>`，见 nodecollect.go 的 `newNodeHostnamePattern`）。
#   · 脚本会把 `<ip> <hostname>` 写进宿主 `/etc/hosts`（**带标记的区块**，可重复执行、
#     可干净移除）⇒ 取数**不需要 DNS**（管理 VLAN 30 上没有 DNS，实测 CT 内 DNS FAIL）。
#   · 客人的登录用户 = `asc`（与 `EDGEEXP_VM_SSH_USER` 的默认值一致）。
#   · **取数用户是 root 等价（Task 16）**：cloud-init 给 `asc` 的是 `NOPASSWD` sudo，
#     取数侧（`cmd/edgescen`）因此在客人里以 `sudo -n env … -emit-checks` 执行 ——
#     与 CT 基质的 `pct exec`（天生 root）**等价**。理由：`OT-005`/`KS-012` 的判定随取数用户
#     翻转（实测 10/80 条翻转，含决定基线活跃集 `B` 的那两条）⇒ 权限不对齐就是在换测量语义。
#     本脚本每次建机都会**实测** `id -u` 与 `sudo -n id -u` 并把结果打印出来。
#   · 私钥路径写进**未跟踪**的本地 env 文件（默认 `~/.config/asscor/edgeexp.local.env`），
#     供跑批前 `source` —— 私钥内容**从不**进仓库、不进 argv、不进记录。
#
# ---------------------------------------------------------------------------
# 宿主侧的**持久**改动（只要一处，Task 16 起）
# ---------------------------------------------------------------------------
#   · 自建一条**专用 ISO 存储** `asscor-vmseed`（`dir` + `path /RAID-Mirror/asscor-vmseed`，
#     `content iso`；写法参照 `ZFS-ISO` 的 `dir:` + `path /RAID-Mirror/<名>`）。seed ISO 必须落在带 `iso`
#     内容的存储里（PVE 9 起 `qm set --ide2` 不收裸路径），而 `ZFS-ISO`/`Backup-320G`/
#     `ZFS-LXD` 一律不碰 ⇒ 自建一条是**additive、幂等**的，也是唯一不翻转全局状态的做法。
#     **不再**有任何"临时改 `local` 的 content、--destroy 时写回"的动作（Task 15 的做法已删）。
#     要撤：`pvesm remove asscor-vmseed && rm -rf /RAID-Mirror/asscor-vmseed`。
#
# ---------------------------------------------------------------------------
# 用法
# ---------------------------------------------------------------------------
#   sudo bash lunwen/clab-lab/scripts/edge_vm_provision.sh              # 建 1 台（VMID 910）
#   sudo bash lunwen/clab-lab/scripts/edge_vm_provision.sh --count 3    # 建 3 台（910/911/912）
#   sudo bash ... --name-prefix asc-vm --first-vmid 920 --count 2
#   sudo bash ... --mgmt-bridge vmbr0                                   # 额外挂管理 VLAN
#   sudo bash ... --no-guest-packages                                   # 跳过客人侧装包
#   sudo bash ... --dry-run                                             # 只打印要做什么
#   sudo bash ... --destroy                                             # 拆掉自己建的（同参数）
#
# 幂等判据（本任务 Step 3 的三条）：
#   ① 重跑**不产生第二台 VM**（VMID 已存在 ⇒ 只做"确保在跑 + 等 SSH + 打印指标"）；
#   ② `--destroy` 后 `qm list` 回到 0 台（只拆本脚本的 VMID 区间内的、且名字带前缀的）；
#   ③ 跑批前确认基质的口径见文件末尾「跑批前怎么确认用的是 VM 基质」。
#
# ---------------------------------------------------------------------------
# 纪律与边界（**硬约束，不许放宽**）
# ---------------------------------------------------------------------------
#   · **只许动自己建的 VMID**：默认 910 起；`FIRST_VMID` 最小值写死 **910**，
#     改小一律**拒绝执行**。`904`（CT `asc-tgt-c2`）与任何别人的 VM/CT 一律不碰。
#     本脚本只调用 `qm`（**从不**调用 `pct`），且 `qm` 与 `pct` 的 VMID 空间虽同源，
#     `qm destroy` 对 CT 也会失败 —— 故"不碰 CT"有两道（不调 pct + vmid 下限）。
#   · **iLO 绝对不许动**：脚本不登录、不探测、不扫描任何带外管理地址；它只连
#     `vmbr0`/`vmbr1` 上自己那台 VM 的 SSH。
#   · `Backup-320G` **只收备份** ⇒ 绝不把 VM 磁盘或镜像放上去（默认 `local-lvm`）。
#   · 私钥/口令**从不**写进仓库：私钥由脚本生成到 `$SSH_KEY`（默认 `~/.ssh/asc-vm_ed25519`），
#     路径经环境变量 / 未跟踪的本地 env 文件传播。
#   · **算内存账**（本机 ~7.6 GiB RAM，见下方 §内存账）：
set -euo pipefail

# ============================================================================
# 参数
# ============================================================================
COUNT=1
NAME_PREFIX="${EDGEEXP_VM_NAME_PREFIX:-asc-vm}"
FIRST_VMID="${EDGEEXP_VM_FIRST_VMID:-910}"
# **硬下限**：VMID 必须 ≥ 910（避开 CT 904 与 PVE 自用的低位区间）。
MIN_VMID=910
NET_BRIDGE="${EDGEEXP_VM_BRIDGE:-vmbr1}"
MGMT_BRIDGE="${EDGEEXP_VM_MGMT_BRIDGE:-}"
MEM_MB="${EDGEEXP_VM_MEM_MB:-2048}"
BALLOON_MB="${EDGEEXP_VM_BALLOON_MB:-512}"
CORES="${EDGEEXP_VM_CORES:-2}"
DISK_STORAGE="${EDGEEXP_VM_DISK_STORAGE:-local-lvm}"
DISK_SIZE="${EDGEEXP_VM_DISK_SIZE:-8G}"
IMG_STORAGE_DIR="${EDGEEXP_VM_IMG_DIR:-/var/lib/vz/import}"
# seed ISO 的落点与**存储引用**（Task 15 修正 + Task 16 收口；PVE 9.2.2 实测）：
#   · PVE 9 起 `qm set --ide2` **不再接受裸绝对路径** —— 报
#     `ide2: unable to associate path '/var/lib/vz/import/x.iso' to any storage`；
#     ISO 必须落在一条**带 `iso` 内容**的存储里，并写成 `<存储>:iso/<文件名>`。
#   · 宿主上唯一带 `iso` 内容的存储是 `ZFS-ISO`，而**项目规则不许动它**
#     （`ZFS-ISO` / `Backup-320G` / `ZFS-LXD` 一律不碰）。
#
#   ⇒ **Task 16 的收口改动（concern 5）**：不再"临时给 `local` 补 `iso`、`--destroy` 时逐字写回"，
#     而是**一次性、持久**地自建一条**专用 ISO 存储** `asscor-vmseed`，路径
#     `/RAID-Mirror/asscor-vmseed`（`content iso`），写法**参照 `ZFS-ISO`**
#     （`dir:` + `path /RAID-Mirror/<名>`，用户 2026-09 定的存储规则）。
#
#   为什么不是"继续临时改 `local`"（代价对比，Task 16 的报告里也抄了一份）：
#     · 临时改是**对全局状态的一次翻转**，且必须在**另一个进程**（`--destroy`）里翻回来 ——
#       只要有人没走 `--destroy` 而手工 `qm destroy`，`local` 就会**永久**停在 `iso` 状态
#       （Task 15 专门留了一个状态文件来兜这件事，那个文件的存在本身就是这条风险的形状）；
#     · 专用存储是 **additive 且幂等** 的：加的是**新名字**，`local`/`ZFS-ISO`/`Backup-320G`/
#       `ZFS-LXD` 的 content 一个字节都不动；建机与清机都不再需要"记住并还原"这类跨进程状态
#       ⇒ 上面那个状态文件与它的恢复路径**整个删掉**（少一条只在故障时才暴露的代码路径）；
#     · 代价：`/etc/pve/storage.cfg` 里多一条存储定义（**持久**）。要撤：先
#       `rm -f /etc/pve/storage.cfg` 里那一段（或 `pvesm remove asscor-vmseed`），再删目录。
#   · **不带 `--is_mountpoint 1`**（Task 16 实测：带上它这条存储**根本建不出来**）：
#     那个开关是给 `Backup-320G` 那种"存储 path **就是**挂载点"的形态用的 —— PVE 会拒绝激活：
#     `create storage failed: unable to activate storage '…' - directory is expected to be a
#      mount point but is not mounted`。我们这条存储的 path 是 ZFS 池 `RAID-Mirror` **里面**的
#     目录（与 `ZFS-ISO` / `ZFS-LXD` 同形），池没挂上时"落到根文件系统的挂载点目录"这件事
#     由**建机前的 mkdir + PVE 激活失败**双重兜住（激活失败即响亮失败，不会静默写进根 FS）。
SEED_STORAGE="${EDGEEXP_VM_SEED_STORAGE:-asscor-vmseed}"
SEED_STORAGE_PATH="${EDGEEXP_VM_SEED_STORAGE_PATH:-/RAID-Mirror/asscor-vmseed}"
# ISO 的落点：**不猜**，建机时从 PVE 自己的 API 问出来（见 ensure_seed_storage 的末尾）。
# ⚠️ Task 16 实测踩到的一条**假设错误**：`dir` 存储里的 ISO **不是**放在 `<path>/iso/`，
# 而是 `<path>/template/iso/`。我按 `<path>/iso` 写了一次 ⇒ `genisoimage` 把 ISO 写进了那条
# "看起来对"的目录，而 PVE 随后报
#     volume 'asscor-vmseed:iso/asc-vm910-seed.iso' does not exist
# （`pvesm list asscor-vmseed` 回**空表**）⇒ 建机当场停住，留下一台 `stopped` 的半成品 VM
# （BOOTDISK=0.00）。对照本机唯一既有的 iso 存储 `ZFS-ISO` 确认：它的 ISO 全在
# `/RAID-Mirror/iso/template/iso/`。
# ⇒ 这个变量只是**默认值**，真值由 `pvesm path <存储>:iso/` 在运行时替换 —— 存储布局随
#   PVE 版本与存储类型变，把它写死就等于把一次观察当前提。
SEED_DIR="${EDGEEXP_VM_SEED_DIR:-$SEED_STORAGE_PATH/template/iso}"
# 客人侧网卡名（Task 15 修正）：**不是 `eth0`**。PVE 的 virtio 网卡在客人里按 PCI 槽位取
# **可预测名**，实测（PVE 9.2.2 + Ubuntu noble cloud image）是 **`ens18`** ——
# `qm guest cmd 910 network-get-interfaces` 逐字报 `name='ens18'`。
# 原来写死 `guest_ip … eth0` ⇒ python 那句 `nic["name"] != want` 恒真 ⇒ **永远**取不到 IP，
# 而报错文案却写"guest agent 没能报出 **eth0** 的 IPv4"，把根因指到了 agent 身上（实测 agent 是好的）。
# 列表里保留 `eth0` 兜底（别的镜像/别的总线可能真的叫 eth0）。
GUEST_IFACE="${EDGEEXP_VM_GUEST_IFACE:-ens18}"
GUEST_IFACE_ACCEPT="$GUEST_IFACE,eth0"
# cloud-init 首启要装包（qemu-guest-agent / apparmor-utils / auditd …），实测**超过 240 s**
# 才把 guest agent 起来；原值 240 会在冷启动时**必定**超时并让整轮建机 die（Task 15 实测）。
GUEST_AGENT_WAIT_S="${EDGEEXP_VM_GUEST_AGENT_WAIT_S:-600}"
CLOUD_IMG_URL="${EDGEEXP_VM_CLOUD_IMG_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
CLOUD_IMG_SHA_URL="${EDGEEXP_VM_CLOUD_IMG_SHA_URL:-https://cloud-images.ubuntu.com/noble/current/SHA256SUMS}"
SSH_USER="${EDGEEXP_VM_SSH_USER:-asc}"
SSH_KEY="${EDGEEXP_VM_SSH_KEY:-/root/.ssh/asc-vm_ed25519}"
LOCAL_ENV="${EDGEEXP_VM_LOCAL_ENV:-/root/.config/asscor/edgeexp.local.env}"
SSH_WAIT_S="${EDGEEXP_VM_SSH_WAIT_S:-300}"
# known_hosts 那一份文件（Task 16 / concern 3）：建机时在这里删掉该主机的旧条目，
# 取数侧（cmd/edgescen 的 EDGEEXP_VM_KNOWN_HOSTS）读**同一份** ⇒ 同名重建不再炸。
# 为什么必须清：这台基质的正常循环是"建机 → 清机 → 用同一个 vmid/名字重建"，而重建之后
# **客人 host key 必然变**，`StrictHostKeyChecking=accept-new` **只接受新主机、不接受变更后
# 的主机** ⇒ 直接 `Host key verification failed.`，而那条错误与"私钥不对 / 机器不可达"同形。
KNOWN_HOSTS="${EDGEEXP_VM_KNOWN_HOSTS:-/root/.ssh/asscor-edge-vm_known_hosts}"
INSTALL_PACKAGES=1
GUEST_TOOL_PKGS="${EDGEEXP_VM_TOOL_PKGS:-apparmor-utils auditd qemu-guest-agent}"
DRY_RUN=0
DESTROY=0
HOSTS_MARK="asscor-edge-vm"

usage() {
  sed -n '2,80p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --count)      COUNT="${2:?--count 需要一个数字}"; shift 2 ;;
    --name-prefix) NAME_PREFIX="${2:?--name-prefix 需要一个前缀}"; shift 2 ;;
    --first-vmid) FIRST_VMID="${2:?--first-vmid 需要一个数字}"; shift 2 ;;
    --bridge)     NET_BRIDGE="${2:?--bridge 需要一个网桥}"; shift 2 ;;
    --mgmt-bridge) MGMT_BRIDGE="${2:?--mgmt-bridge 需要一个网桥}"; shift 2 ;;
    --memory)     MEM_MB="${2:?--memory 需要 MiB}"; shift 2 ;;
    --balloon)    BALLOON_MB="${2:?--balloon 需要 MiB}"; shift 2 ;;
    --cores)      CORES="${2:?--cores 需要数字}"; shift 2 ;;
    --disk-storage) DISK_STORAGE="${2:?--disk-storage 需要存储名}"; shift 2 ;;
    --disk-size)  DISK_SIZE="${2:?--disk-size 需要尺寸（如 8G）}"; shift 2 ;;
    --ssh-key)    SSH_KEY="${2:?--ssh-key 需要私钥路径}"; shift 2 ;;
    --ssh-user)   SSH_USER="${2:?--ssh-user 需要用户名}"; shift 2 ;;
    --no-guest-packages) INSTALL_PACKAGES=0; shift ;;
    --dry-run)    DRY_RUN=1; shift ;;
    --destroy)    DESTROY=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "edge_vm_provision: 未知参数 '$1'（--help 看用法）" >&2; exit 2 ;;
  esac
done

log()  { printf '%s\n' "$*"; }
warn() { printf 'edge_vm_provision: %s\n' "$*" >&2; }
die()  { printf 'edge_vm_provision: %s\n' "$*" >&2; exit 1; }

# run 执行一条命令（dry-run 下只打印）。**所有**外部命令都从这里出去 ——
# 于是 "--dry-run 不产生任何副作用"这条判据只需要在这里守一次。
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

# ============================================================================
# 前置校验
# ============================================================================
[ "$(id -u)" -eq 0 ] || die "必须以 root 运行（qm/pvesm 需要）"
command -v qm >/dev/null 2>&1 || die "找不到 qm —— 这不是一台 PVE 宿主？"
command -v genisoimage >/dev/null 2>&1 || die "找不到 genisoimage（NoCloud seed ISO 靠它造；装 genisoimage 或 mkisofs）"
command -v qemu-img >/dev/null 2>&1 || die "找不到 qemu-img（cloud image 转 raw 靠它）"

case "$COUNT" in ''|*[!0-9]*) die "--count 必须是正整数，收到 '$COUNT'" ;; esac
[ "$COUNT" -ge 1 ] || die "--count 必须 ≥ 1"
case "$FIRST_VMID" in ''|*[!0-9]*) die "--first-vmid 必须是数字，收到 '$FIRST_VMID'" ;; esac
[ "$FIRST_VMID" -ge "$MIN_VMID" ] || die "--first-vmid=$FIRST_VMID 小于硬下限 $MIN_VMID ——
  那一区间里有 CT 904（asc-tgt-c2，**不许动**）与 PVE 自用 VMID；本脚本拒绝在低区间里干活。
  要少建几台就调 --count，不要调 --first-vmid。"

case "$NAME_PREFIX" in
  ''|*[!A-Za-z0-9-]*) die "--name-prefix 只允许字母/数字/连字符，收到 '$NAME_PREFIX'" ;;
esac

# 客人侧的主机名与"取数地址"都由 vmid 派生 ⇒ 上限 4 位数（0000~9999 之外 PVE 也不收）。
LAST_VMID=$((FIRST_VMID + COUNT - 1))
[ "$LAST_VMID" -le 999999999 ] || die "VMID 上界超出 PVE 允许范围（末台 $LAST_VMID）"

VMIDS=()
for i in $(seq 0 $((COUNT - 1))); do
  VMIDS+=("$((FIRST_VMID + i))")
done

# 与现有 VM **不得**撞号。撞号时**响亮失败**而不是"跳过那一个再建下一台"：
# 后者会让"第 3 台其实叫 913 而不是 912"这种偏移静默成立，而 `edge_matrix.sh` 逐台指定的
# 取数地址是按 vmid 推的 —— 偏移一次，后面每一台都错位，且看起来完全正常。
for vmid in "${VMIDS[@]}"; do
  if qm status "$vmid" >/dev/null 2>&1; then
    if [ "$DESTROY" -eq 0 ]; then
      # 已存在**不是**错误：这是幂等重跑的**正常路径**（判据①）。但要确认它确实是我们的 VM：
      name="$(qm config "$vmid" 2>/dev/null | awk -F': *' '$1=="name"{print $2; exit}')"
      case "$name" in
        "$NAME_PREFIX"*) : ;;
        *) die "VMID $vmid 已被占用，而它的 name='$name' **不带**前缀 '$NAME_PREFIX' ⇒
  这不是本脚本建的 VM（可能是别人的）。本脚本**绝不**碰别人的 VM/CT。
  换一个 --first-vmid（≥ $MIN_VMID）或换一个 --name-prefix。" ;;
      esac
    fi
  fi
done

# `--destroy` 的护栏：只拆"本脚本自己会建的"那一批（前缀 + VMID 下限），别的都不许动。
if [ "$DESTROY" -eq 1 ]; then
  for vmid in "${VMIDS[@]}"; do
    qm status "$vmid" >/dev/null 2>&1 || continue
    name="$(qm config "$vmid" 2>/dev/null | awk -F': *' '$1=="name"{print $2; exit}')"
    case "$name" in
      "$NAME_PREFIX"*) : ;;
      *) die "--destroy 拒绝拆除 VMID $vmid（name='$name' 不带前缀 '$NAME_PREFIX'）——
  本脚本只拆自己建的那一批；别人的 VM/CT 一律不碰。" ;;
    esac
  done
  [ "$FIRST_VMID" -ge "$MIN_VMID" ] || die "--destroy 的 VMID 下限低于 $MIN_VMID"
fi

# ============================================================================
# 内存账（**算给报告看**，也是"别把宿主撑爆（会连带影响 904）"这条边界的依据）
# ============================================================================
#   host total   ≈ 7.6 GiB（实测 `free -m` 7795 MiB）
#   CT 904       ≈ 1.0 GiB（`pct config 904` 的 memory: 1024）
#   PVE 自身     ≈ 0.6~0.8 GiB
#   ⇒ 可分配给 VM 的**实际**上限 ≈ 5.5~5.9 GiB
#   ⇒ 本脚本默认 2 GiB/台 + balloon 512 MiB ⇒ 可行上界 **2 台**（4 GiB），
#     3 台（6 GiB）已进入"要靠 balloon 与内核回收挤出来"的区间，
#     4 台（8 GiB）**必然**触发宿主 OOM 与换页 —— 而宿主一旦换页，
#     CT 904 与所有 VM 的测量都会被拖慢，"数据准确性"这条前提直接失效。
#   ⇒ 用的是 **balloon（动态）** 而不是固定分配：见 vm_memory_args 的说明。
memory_plan() {
  local total_mb
  total_mb="$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  log "内存账：宿主 MemTotal=${total_mb} MiB；本批 ${#VMIDS[@]} 台 × ${MEM_MB} MiB = $(( ${#VMIDS[@]} * MEM_MB )) MiB（balloon 下限 ${BALLOON_MB} MiB/台）"
  if [ "$total_mb" -gt 0 ]; then
    local budget=$(( total_mb - 2560 )) # 给 CT 904（1024）+ PVE 自身 + 页缓存留 ~2.5 GiB
    if [ "$(( ${#VMIDS[@]} * MEM_MB ))" -gt "$budget" ]; then
      warn "本批 VM 的配置内存（$(( ${#VMIDS[@]} * MEM_MB )) MiB）超过保守预算 ${budget} MiB ——"
      warn "  宿主会靠 balloon 与页回收挤，压力大时会连带拖慢 CT 904 与所有 VM 的测量。"
      warn "  建议：调小 --memory 或 --count；本机按 2 GiB/台算，**可行上界是 2 台**。"
    fi
  fi
}

# ============================================================================
# --destroy
# ============================================================================
teardown_vm() {
  local vmid="$1" idx="$2"
  log "== 销毁 VM $vmid（$NAME_PREFIX$vmid）"
  run qm stop "$vmid" --skiplock 2>/dev/null || true
  # 停不下来就等一会儿（PVE 的 stop 是 ACPI/强制双段）
  if [ "$DRY_RUN" -eq 0 ]; then
    local waited=0
    while qm status "$vmid" 2>/dev/null | grep -q running; do
      [ "$waited" -ge 30 ] && break
      sleep 2; waited=$((waited + 2))
    done
  fi
  # `--purge 1` 连同 VM 的磁盘（在 local-lvm 上）一起删；**不动**任何存储配置。
  run qm destroy "$vmid" --purge 1 --skiplock
  [ "$DRY_RUN" -eq 0 ] && run rm -f "$SEED_DIR/$NAME_PREFIX$vmid-seed.iso" \
                                 "$IMG_STORAGE_DIR/$NAME_PREFIX$vmid.raw"
  : "$idx"
}

# ============================================================================
# 取数地址：宿主 /etc/hosts 的托管区块
# ============================================================================
# 为什么写 /etc/hosts 而不是改 DNS：管理 VLAN 30 上没有 DNS（实测 CT 内 DNS FAIL），
# 而宿主自己的 `/etc/hosts` 是本地的、可重复执行、可干净移除。区块带标记，
# 故**重跑**不会堆积（先删旧块再写新块），`--destroy` 之后能把块**整个**移掉。
write_hosts_block() {
  local tmp
  tmp="$(mktemp)"
  # ⚠️ **不许写成"先 awk > $tmp、再 `{ cat $tmp; printf 新区块; } >> $tmp`"**（Task 15 实测）：
  # 那是把 `$tmp` **同时**当输入与输出，GNU `cat` 会直接拒绝并报
  # `cat: /tmp/tmp.xxx: input file is output file`。本机（GNU coreutils）上这个错误**恰好**
  # 让结果正确（过滤后的内容已经由 awk 写进 $tmp，`cat` 失败后只追加了新区块）；
  # 但在允许"自己读自己"的 `cat`（如 BusyBox）上，过滤后的内容会被**再追加一遍**，
  # 于是 `/etc/hosts` 整份**重复**。故这里改成**一次重定向**写全（语义完全相同、不依赖 cat 的行为）。
  {
    awk -v mark="$HOSTS_MARK" '
      $0 == "# >>> " mark " >>>" { skip = 1; next }
      $0 == "# <<< " mark " <<<" { skip = 0; next }
      !skip { print }
    ' /etc/hosts
    printf '# >>> %s >>>\n' "$HOSTS_MARK"
    printf '# 由 edge_vm_provision.sh 管理（Task 13）：本脚本建的 VM 的 <ip> <hostname>。\n'
    printf '# 手改这里的内容会在下一次建机/清机时被覆盖；要留别的条目请写在块外。\n'
    local i
    for i in "${!VMIDS[@]}"; do
      local vmid="${VMIDS[$i]}" ip="${VM_IPS[$i]:-}"
      [ -n "$ip" ] && printf '%s\t%s%s\n' "$ip" "$NAME_PREFIX" "$vmid"
    done
    printf '# <<< %s <<<\n' "$HOSTS_MARK"
  } > "$tmp"
  run cp "$tmp" /etc/hosts
  rm -f "$tmp"
}

clear_hosts_block() {
  local tmp
  tmp="$(mktemp)"
  awk -v mark="$HOSTS_MARK" '
    $0 == "# >>> " mark " >>>" { skip = 1; next }
    $0 == "# <<< " mark " <<<" { skip = 0; next }
    !skip { print }
  ' /etc/hosts > "$tmp"
  run cp "$tmp" /etc/hosts
  rm -f "$tmp"
}

# ============================================================================
# seed ISO 专用存储（Task 16 收口）：**自建、幂等、additive**，不碰任何既有存储
# ============================================================================
# 这条路换掉了 Task 15 的"临时给 local 补 iso、--destroy 逐字写回"（理由见文件顶部那一段）。
# 三条纪律：
#   · **只加新名字**：`asscor-vmseed` 不存在才创建；已存在则只核对它的 path/content，
#     **绝不**去改它（更不会去改 `local`/`ZFS-ISO`/`Backup-320G`/`ZFS-LXD`）；
#   · **幂等**：重跑、多台、`--destroy` 之后再建，都只在"不存在"那一次动手；
#   · **写不进去就响亮失败**：底下的 ZFS 池没挂上（`/RAID-Mirror` 不存在）或目录建不出来时，
#     宁可当场失败，也不把 seed ISO 落到根文件系统的挂载点目录里（那种形态看起来一切正常，
#     直到宿主重启 —— 而那时症状是"所有 VM 的 seed 都不见了"）。
ensure_seed_storage() {
  local existing
  existing="$(awk -v s="$SEED_STORAGE" '
    $0 == "dir: " s      { f = 1; print "dir"; next }
    f && /^[[:space:]]*path / { sub(/^[[:space:]]*path[[:space:]]*/, ""); print; exit }
    f && /^[^[:space:]]/  { exit }
  ' /etc/pve/storage.cfg)"
  if [ -n "$existing" ]; then
    local cur_path
    cur_path="$(printf '%s\n' "$existing" | sed -n '2p')"
    if [ "$cur_path" != "$SEED_STORAGE_PATH" ]; then
      die "存储 $SEED_STORAGE 已存在，但它的 path='$cur_path' 与本脚本期望的 '$SEED_STORAGE_PATH' 不同 ——
  本脚本**不猜**：换一个 --seed-storage，或先把这个名字让出来。它**不会**去改一条既有存储的定义。"
    fi
    log "== seed ISO 存储 $SEED_STORAGE 已存在（path=$cur_path）—— 不动它"
  else
    # ⚠️ **池没挂上时不要建目录**（Task 16 加固）：`mkdir -p` 会成功地把挂载点目录造在
    # **根文件系统**上（看起来一切正常，直到宿主重启 —— 而那时症状是"所有 VM 的 seed 都不见了"）。
    # 判据：`$SEED_STORAGE_PATH` 的**父目录**必须已经存在（ZFS 池挂上了才有它）；
    # 不存在就**响亮失败**，让操作者先去看池。
    if [ "$DRY_RUN" -eq 0 ] && [ ! -d "$(dirname "$SEED_STORAGE_PATH")" ]; then
      die "存储落点的父目录 $(dirname "$SEED_STORAGE_PATH") 不存在 ——
  底下的池很可能**没挂上**。本脚本**不猜**：宁可当场失败，也不把 seed ISO 落到根文件系统上
  （那种形态看起来一切正常，直到宿主重启）。诊断：\`zfs list\` / \`ls $(dirname "$SEED_STORAGE_PATH")\`。"
    fi
    log "== 创建 seed ISO 专用存储 $SEED_STORAGE（dir:$SEED_STORAGE_PATH，content iso；参照 ZFS-ISO 的写法）"
    log "   ⚠️ 这是本脚本唯一的**持久**宿主改动（additive；既有存储一个字节都不动）。要撤："
    log "      pvesm remove $SEED_STORAGE && rm -rf $SEED_STORAGE_PATH"
    if [ "$DRY_RUN" -eq 0 ]; then
      pvesm add dir "$SEED_STORAGE" --path "$SEED_STORAGE_PATH" --content iso
    fi
  fi
  # ISO 的落点**不写死**：`dir` 存储把 ISO 放在 `<path>/template/iso`，但这条布局是 PVE 的
  # 实现细节（Task 16 实测：按 `<path>/iso` 写会让 `pvesm list <存储>` 回空表、随后
  # `qm set --ide2` 报 `volume '<存储>:iso/<文件>' does not exist`，而 ISO 已经生成好了
  # —— 症状像"文件没了"，真正的原因是目录不对）。
  # 判据用 PVE 自己的**目录列表**：`find <每个候选>/ -maxdepth 1 -name '*.iso' | head -1`
  # 会给出一个**真实存在**的 iso 文件，把它所在目录当 $SEED_DIR。
  # ⚠️ 这条判据是**只读**的：不去创建目录（否则会在错的候选上造出一个空目录，而
  # `find` 又会把它当成"存在"）。一个 iso 都没有时回落到默认值（`<path>/template/iso`）。
  if [ "$DRY_RUN" -eq 0 ] && [ -z "${EDGEEXP_VM_SEED_DIR:-}" ]; then
    local cand probe
    for cand in "$SEED_STORAGE_PATH/template/iso" "$SEED_STORAGE_PATH/iso"; do
      [ -d "$cand" ] || continue
      probe="$(find "$cand" -maxdepth 1 -name '*.iso' 2>/dev/null | head -n1)"
      if [ -n "$probe" ]; then
        SEED_DIR="$cand"
        log "== seed ISO 落点（按 PVE 自己的目录列表判定）：$SEED_DIR（样例：$(basename "$probe")）"
        break
      fi
    done
    if [ -z "$probe" ]; then
      log "== seed ISO 落点（没有任何 iso 文件可参照 ⇒ 按 PVE 的 dir 布局用默认）：$SEED_DIR"
    fi
  fi
  run mkdir -p "$SEED_DIR"
}

# ============================================================================
# 本地 env 文件（**未跟踪**）：把私钥路径 / SSH 用户传播给跑批脚本
# ============================================================================
write_local_env() {
  local dir; dir="$(dirname "$LOCAL_ENV")"
  run mkdir -p "$dir"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] 写 %s（EDGEEXP_VM_SSH_HOMES…/EDGEEXP_VM_SSH_KEY）\n' "$LOCAL_ENV"
    return 0
  fi
  # **不用 `>>` 追加**：同一批机重复建时会把旧块留着，于是"文件里的私钥路径"有两个取值，
  # 而 `source` 只生效最后一个 —— 那种"看起来配好了、实际用的是上一批"的形态最难查。
  # 故先删本脚本的块，再写新的。
  # 同 write_hosts_block 那条：**一次重定向**写全，不要"`cat $tmp` 再 `>> $tmp`"。
  local tmp; tmp="$(mktemp)"
  {
    if [ -f "$LOCAL_ENV" ]; then
      awk -v mark="$HOSTS_MARK" '
        $0 == "# >>> " mark " >>>" { skip = 1; next }
        $0 == "# <<< " mark " <<<" { skip = 0; next }
        !skip { print }
      ' "$LOCAL_ENV"
    fi
    printf '# >>> %s >>>\n' "$HOSTS_MARK"
    printf '# 由 edge_vm_provision.sh 写出（Task 13）。**本文件未跟踪、不在仓库里** ——\n'
    printf '# 它只放"路径"与"用户名"，**从不**放私钥内容或任何口令。\n'
    printf 'export EDGEEXP_VM_SSH_KEY=%q\n' "$SSH_KEY"
    printf 'export EDGEEXP_VM_SSH_USER=%q\n' "$SSH_USER"
    # known_hosts（Task 16 / concern 3）：建机侧在这里删旧键，取数侧读**同一份** ⇒ 同名重建不炸。
    printf 'export EDGEEXP_VM_KNOWN_HOSTS=%q\n' "$KNOWN_HOSTS"
    # 取数权限（Task 16）：客人侧 root 等价那一格。写出来是为了"用的是默认值"这件事
    # 在环境里**看得见**（取数侧读不到就响亮失败，绝不降级）。
    # ⚠️ **不用 `%q`**（Task 16 实测）：`%q` 会把 `sudo -n` 写成 `sudo\ -n`，而
    # `grep -c '\\ '` 实测 **count=1** —— 也就是说那份 `source` 之后**真的**会得到
    # `sudo\ -n`。本脚本自己的 shell 在展开 `$'\t'` 时把反斜杠吃掉了，所以打印出来看是
    # `sudo -n`（同一个坑的两种面孔）：本脚本能跑到、别的读者拿到的是 `sudo\ -n`。
    # 这一格是"拼进客人侧 shell 的命令"（见 cmd/edgescen 的 qemuSSHSudoArgs），
    # 值必须**逐字**是 `sudo -n` ⇒ 用单引号把它整段括起来。
    printf "export EDGEEXP_VM_SSH_SUDO='%s'\n" "sudo -n"
    printf 'export EDGEEXP_SUBSTRATE=qemu\n'
    printf 'export EDGEEXP_VM_IMAGE_URL=%q\n' "$CLOUD_IMG_URL"
    printf '# 取数地址：默认由 vmid 推 `%s<vmid>`（与宿主 /etc/hosts 的托管区块一致）。\n' "$NAME_PREFIX"
    printf '# 要用别的写法（例如写死 IP）就取消下面这行的注释并填上 —— 含 %%s 时按 vmid 展开：\n'
    printf '# export EDGEEXP_VM_SSH_HOST=%%s\n'
    printf '# <<< %s <<<\n' "$HOSTS_MARK"
  } > "$tmp"
  cp "$tmp" "$LOCAL_ENV"
  rm -f "$tmp"
  chmod 600 "$LOCAL_ENV"
  log "本地 env 已写：$LOCAL_ENV（未跟踪；跑批前 source 它）"
}

# ============================================================================
# 建机
# ============================================================================
ensure_ssh_key() {
  if [ -f "$SSH_KEY" ]; then
    log "复用已有私钥：$SSH_KEY"
  else
    run mkdir -p "$(dirname "$SSH_KEY")"
    log "生成新私钥：$SSH_KEY（ed25519、无口令；**不进仓库**）"
    run ssh-keygen -t ed25519 -N '' -C "asscor-edge-vm@$(hostname)" -f "$SSH_KEY" >/dev/null
  fi
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -f "$SSH_KEY.pub" ] || die "缺少公钥 $SSH_KEY.pub —— 请手工生成（ssh-keygen -t ed25519 -f $SSH_KEY）"
  # cloud-init 的 ssh_authorized_keys 要的是一行**纯公钥**：多行/带选项/空行都会让
  # `authorized_keys` 里出现一行垃圾（而 sshd 只在**登录时**才报错，看起来像"钥匙不对"）。
  local lines; lines="$(grep -cve '^[[:space:]]*$' "$SSH_KEY.pub" || true)"
  [ "$lines" = "1" ] || die "$SSH_KEY.pub 必须**恰好一行**（实际 $lines 行非空）"
  grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-)' "$SSH_KEY.pub" || die "$SSH_KEY.pub 不是一把可识别的公钥"
}

ensure_cloud_image() {
  local img="${CLOUD_IMG_URL##*/}"
  CLOUD_IMG_LOCAL="$IMG_STORAGE_DIR/$img"
  local raw="$IMG_STORAGE_DIR/${img%.img}.raw"
  CLOUD_RAW_LOCAL="$raw"
  run mkdir -p "$IMG_STORAGE_DIR"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] 取 cloud image %s → %s（已有则跳过）\n' "$CLOUD_IMG_URL" "$CLOUD_IMG_LOCAL"
    printf '  [dry-run] qemu-img convert -O raw %s %s\n' "$CLOUD_IMG_LOCAL" "$raw"
    return 0
  fi
  if [ ! -f "$CLOUD_IMG_LOCAL" ]; then
    log "拉取 cloud image：$CLOUD_IMG_URL"
    curl -fL --retry 3 -o "$CLOUD_IMG_LOCAL.part" "$CLOUD_IMG_URL"
    mv "$CLOUD_IMG_LOCAL.part" "$CLOUD_IMG_LOCAL"
  else
    log "复用已有 cloud image：$CLOUD_IMG_LOCAL"
  fi
  # 校验（**只在校验和拿得到时**）：一个被截断的镜像会让建出来的 VM 起不来，
  # 而症状是"SSH 一直连不上"—— 与"cloud-init 坏了"完全同形，故这里先验。
  local sums="$IMG_STORAGE_DIR/SHA256SUMS"
  if curl -fsSL --retry 2 -o "$sums" "$CLOUD_IMG_SHA_URL" 2>/dev/null; then
    local want got
    want="$(awk -v f="$img" '$2 == f || $2 == "*"f {print $1; exit}' "$sums")"
    if [ -n "$want" ]; then
      got="$(sha256sum "$CLOUD_IMG_LOCAL" | awk '{print $1}')"
      [ "$want" = "$got" ] || die "cloud image 校验和不符（want $want got $got）—— 删掉 $CLOUD_IMG_LOCAL 重跑"
      log "cloud image 校验和 OK（$want）"
    else
      warn "SHA256SUMS 里没有 $img 这一行 ⇒ 跳过校验（**不是**校验通过）"
    fi
  else
    warn "取不到 SHA256SUMS ⇒ 跳过镜像校验（**不是**校验通过）"
  fi
  [ -f "$raw" ] || { log "转 raw：$raw"; qemu-img convert -O raw "$CLOUD_IMG_LOCAL" "$raw"; }
}

# build_seed_iso 造 NoCloud seed（`meta-data` + `user-data`，卷标 `cidata`）。
build_seed_iso() {
  local vmid="$1" host="$2" out="$3"
  local work; work="$(mktemp -d)"
  # ---- meta-data ----
  # instance-id 里带 vmid + 时间戳：cloud-init 只在 instance-id 变化时重跑 per-instance 模块
  # （网络、hostname、用户）。用固定值时，**将来**把同一块盘挂到另一台 VM 上会带着旧身份起来。
  cat > "$work/meta-data" <<EOF
instance-id: asscor-edge-$vmid-$(date +%s)
local-hostname: $host
EOF
  # ---- user-data ----
  # 三条纪律：
  #   · ssh_authorized_keys 的**唯一**来源是 $SSH_KEY.pub（一行），私钥从不出现在任何地方；
  #   · 不写 `chpasswd`：这个用户**只能**靠钥匙登录（口令会让"谁进得去"这件事多一个入口）；
  #   · `package_update`/`package_install` 放在 user-data 里而不是 `runcmd` 里 —— 让 cloud-init
  #     自己保证"装完才算完成"（`runcmd` 是 fire-and-forget，脚本会以为装好了）。
  #     这是本基质与 CT 的关键差别之一：**客人有外网，直接 apt 装**。
  {
    printf '#cloud-config\n'
    printf 'hostname: %s\n' "$host"
    printf 'preserve_hostname: false\n'
    printf 'manage_etc_hosts: true\n'
    printf 'ssh_pwauth: false\n'
    printf 'disable_root: true\n'
    printf 'users:\n'
    printf '  - name: %s\n' "$SSH_USER"
    printf '    groups: [adm, sudo]\n'
    printf '    shell: /bin/bash\n'
    printf '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
    printf '    lock_passwd: true\n'
    printf '    ssh_authorized_keys:\n'
    printf '      - %s\n' "$(cat "$SSH_KEY.pub")"
    printf 'qemu-guest-agent: true\n'
    printf 'package_update: true\n'
    printf 'packages:\n'
    printf '  - qemu-guest-agent\n'
    printf '  - openssh-server\n'
    printf '  - curl\n'
    printf '  - jq\n'
    if [ "$INSTALL_PACKAGES" -eq 1 ]; then
      # 工具链包（Step 2 第 4 条的判据就在这一层）：**直接 apt 装**，不需要 CT 上那套
      # "宿主下载闭包 + 送进去 + dpkg --configure -a" 的绕法。
      local p
      for p in $GUEST_TOOL_PKGS; do printf '  - %s\n' "$p"; done
    fi
    printf 'runcmd:\n'
    printf '  - [ systemctl, enable, --now, qemu-guest-agent ]\n'
    printf '  - [ sh, -c, "growpart /dev/sda 1 || growpart /dev/vda 1 || true" ]\n'
    printf '  - [ sh, -c, "resize2fs /dev/sda1 || resize2fs /dev/vda1 || true" ]\n'
    printf 'final_message: "asscor-edge-vm ready ($host)"\n'
  } > "$work/user-data"
  # `-volid cidata` 是 NoCloud 的触发条件（cloud-init 靠卷标认这个盘）；
  # `-J -R`：Joliet + Rock Ridge（两种读取路径都能拿到正确的长文件名）。
  run genisoimage -quiet -output "$out" -volid cidata -joliet -rock -input-charset utf-8 \
      "$work/meta-data" "$work/user-data"
  rm -rf "$work"
}

# vm_memory_args —— **balloon（动态）而不是固定分配**，理由：
#   · 靶机在被攻击/装包时确实要用内存，但**空转时不需要** —— 而"空转"正是 VM 在整轮跑批里
#     占比最大的状态（等 SSH、等 Caldera、等下一场景）。固定分配会把 2 GiB × N 一直占着，
#     宿主 7.6 GiB 的余量本来就只有 ~5.5 GiB ⇒ 3 台就已经在换页边缘。
#   · balloon 的下限（`--balloon`，默认 512 MiB）是**保底可用内存**，不是"一定会降到那儿"：
#     客人只在宿主有压力时才被回收。故 `memory=` 是**上限**、`balloon=` 是**下限**，
#     两边都是显式写死的，不存在"PVE 默认值随版本漂移"的形态。
#   · ⚠️ balloon 会让**内存相关的测量**带上一个额外变量（同一台 VM 在不同时刻的可用内存不同）。
#     本方向② 的检查表里没有以内存占用为判据的检查项（`KS-*`/`OT-*` 看的是内核参数、
#     LSM 状态、文件权限），所以这个变量不进任何因子的读数。若将来加了内存类检查，
#     必须改成固定分配 —— 那一条写在这里，作为约束而不是建议。
vm_memory_args() {
  printf '%s\n' --memory "$MEM_MB" --balloon "$BALLOON_MB"
}

create_vm() {
  local vmid="$1" host="$2" seed="$3"
  log "== 建 VM $vmid（$host）：${CORES} vCPU / ${MEM_MB} MiB（balloon ${BALLOON_MB}）/ 磁盘 $DISK_STORAGE:$DISK_SIZE"
  # 磁盘：从 raw 导入到 $DISK_STORAGE（默认 local-lvm）。
  # ⚠️ **绝不放 `Backup-320G`**（那条存储 `content backup`，项目规则是"只收备份"）——
  # 这里不去"防"操作者显式传它（那是操作者的决定），但默认值与本脚本的所有示例都不用它。
  run qm importdisk "$vmid" "$CLOUD_RAW_LOCAL" "$DISK_STORAGE" >/dev/null
  local diskref
  # ⚠️ **不许用 `awk -F': *' '$1=="unused0"{print $2}'`**（Task 15 实测踩坑，PVE 9.2.2）：
  # 卷引用**自身就带冒号**（`local-lvm:vm-910-disk-0`），按 `:` 切分时 `$2` 会在**第一个**
  # 冒号处被截断成 `local-lvm`。于是下一行变成
  #   qm set 910 --scsi0 "local-lvm,discard=on,ssd=1,iothread=1"
  # 而 `qm` 回 `400 Parameter verification failed. / scsi0: invalid format … unable to parse
  # volume ID 'local-lvm'` —— `set -e` 让整轮建机**当场中止**，留下一台"有 `unused0`、
  # 没有 `scsi0`、`qm list` 里 BOOTDISK=0.00"的半成品 VM（看起来只是"卡住了"）。
  # `sed` 取"键之后**整段**值"，没有"值里含分隔符"这个形状。
  diskref="$(qm config "$vmid" 2>/dev/null | sed -n 's/^unused0: //p' | head -n1)"
  [ -n "$diskref" ] || diskref="$DISK_STORAGE:vm-$vmid-disk-0"
  run qm set "$vmid" --scsihw virtio-scsi-single --scsi0 "$diskref,discard=on,ssd=1,iothread=1"
  run qm resize "$vmid" scsi0 "$DISK_SIZE"
  # ⚠️ `--ide2` 的**正确形状**（Task 15 实测，PVE 9.2.2）：
  #   · **不能**给裸绝对路径 —— `--ide2 /var/lib/vz/import/x.iso,media=cdrom` 报
  #     `unable to associate path '…' to any storage`；必须写成 `<存储>:iso/<文件名>`
  #     （故 seed 落在 $SEED_DIR 并挂 $SEED_STORAGE，见文件顶部那两格的说明）。
  #   · **不能**加 `readonly=1` / `ro=1` —— 两者**都不是** ide2 的合法属性，报
  #     `ide2.readonly: property is not defined in schema`（CD-ROM 介质本身只读，
  #     本来也不需要这个开关）。
  run qm set "$vmid" --ide2 "$SEED_STORAGE:iso/$(basename "$seed"),media=cdrom"
  run qm set "$vmid" --boot order=scsi0 --bootdisk scsi0
  # 网络：默认只挂 $NET_BRIDGE（默认 vmbr1 —— 宿主在这条桥上**有外网**，装包靠它）。
  run qm set "$vmid" --net0 "virtio,bridge=$NET_BRIDGE"
  # 可选的第二块网卡（管理 VLAN，与 CT 904 同网段）—— 用于"VM 能不能到 C2（192.168.30.2）"
  # 这条实测。**不做默认**：多一块网卡就多一条"数据从哪条路出去的"不确定性，
  # 只有在真的需要时才显式打开。
  if [ -n "$MGMT_BRIDGE" ]; then
    run qm set "$vmid" --net1 "virtio,bridge=$MGMT_BRIDGE"
  fi
  run qm set "$vmid" --serial0 socket --vga serial0
  run qm set "$vmid" --agent enabled=1
  run qm set "$vmid" --onboot 0
  # `--ciupgrade 0`：cloud-init 的 package_upgrade 关掉 —— 跑批基质不该在每次开机时
  # 自己升级一遍（那会让"同一配置两次跑"之间多出一个不受控的变量）。
  run qm set "$vmid" --ciupgrade 0
  # 内存那几格用数组展开（见 vm_memory_args 的说明）。
  # shellcheck disable=SC2046
  run qm set "$vmid" $(vm_memory_args)
  run qm set "$vmid" --cores "$CORES" --cpu host
  run qm set "$vmid" --name "$host"
}

guest_ip() {
  # 客人 IP 的权威判据是 **guest agent**（cloud-init 装并起的就是它）。
  # 失败时**不猜**：猜错会让 /etc/hosts 与后续取数锁到**另一台**机器上。
  #
  # ⚠️ 接口名由 $2 给（调用方传 $GUEST_IFACE_ACCEPT，默认 `ens18,eth0`）——**别改回写死 `eth0`**：
  # PVE virtio 上客人网卡的可预测名是 `ens18`，写死 eth0 会让过滤条件恒真、永远取不到 IP。
  # 输出是 `<网卡名>\t<IP>` 两格（调用方要拿网卡名打日志，故不能只回 IP）。
  local vmid="$1" iface="$2" out
  out="$(qm guest cmd "$vmid" network-get-interfaces 2>/dev/null | python3 -c '
import json,sys
want = [w for w in sys.argv[1].split(",") if w]
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
fallback = None
for nic in data:
    name = nic.get("name")
    if name in ("lo", "lo0"):
        continue
    for a in nic.get("ip-addresses", []):
        if a.get("ip-address-type") != "ipv4":
            continue
        addr = a.get("ip-address", "")
        if addr.startswith("127."):
            continue
        # 只取"要挂的那条桥"上的地址：客人可能有第二块网卡（管理 VLAN），
        # 取错了就会把 /etc/hosts 与取数地址锁到一条不通的路上。
        # 故**先**按名字精确匹配；名字都不匹配时**不静默**回退 ——
        # 记下第一个候选，只有在整个列表里没有任何一个名字命中时才用它，
        # 并把"回退到了哪个网卡"打到 stderr（回退必须看得见）。
        if want and name not in want:
            if fallback is None:
                fallback = (name, addr)
            continue
        sys.stdout.write("%s\t%s\n" % (name, addr))
        raise SystemExit(0)
if fallback is not None:
    sys.stderr.write("guest_ip: 没有一个网卡叫 %s —— 回退用 %s\n" % (",".join(want), fallback[0]))
    sys.stdout.write("%s\t%s\n" % fallback)
    raise SystemExit(0)
raise SystemExit(1)
' "$iface")" || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out"
}

wait_guest_agent() {
  local vmid="$1" limit="${2:-180}" waited=0
  while ! qm guest cmd "$vmid" ping >/dev/null 2>&1; do
    [ "$waited" -ge "$limit" ] && return 1
    sleep 5; waited=$((waited + 5))
  done
  return 0
}

wait_ssh() {
  # 就绪的判据是"**真的能跑一条命令**"（与 edge_lab.sh 的 lab_wait_node_exec 同一条口径），
  # 不是"22 端口开着"：sshd 在 cloud-init 收敛过程中会出现"端口开着但 key 还没落盘"的窗口。
  local host="$1" limit="${SSH_WAIT_S}" waited=0
  while ! ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
              -o "UserKnownHostsFile=$KNOWN_HOSTS" -o "IdentitiesOnly=yes" -i "$SSH_KEY" \
              -l "$SSH_USER" -- "$host" true >/dev/null 2>&1; do
    [ "$waited" -ge "$limit" ] && return 1
    sleep 5; waited=$((waited + 5))
  done
  return 0
}

# forget_host_key —— 在**我们那一份** known_hosts 里删掉这个主机的旧条目（Task 16 / concern 3）。
#
# 为什么必须在**建机时**做（而不是等取数时撞上再处理）："建机 → 清机 → 用同一个 vmid/名字
# 重建"是正常循环，重建之后 host key 必然变；`accept-new` 只接受**新主机**、不接受**变更后的
# 主机** ⇒ 不清的话整条基质哑火，而错误（`REMOTE HOST IDENTIFICATION HAS CHANGED`）与
# "私钥不对 / 机器不可达"**同形**。
#
# 为什么只清**自己那一条**、且只清**我们那一份**文件：`ssh-keygen -R` 只删这个主机的条目
# （不动别人的 host key，也不动 `/etc/ssh/ssh_known_hosts`）；用专用文件则意味着
# **不去碰操作者 `~/.ssh/known_hosts` 里记着的其它机器**。
# ⚠️ 代价（写清）：这一份文件里该主机的**历史** host key 会被丢掉 —— 而它本来就是"一次性靶机"
# 的键（每次重建必变），所以没有可保护的历史。别有用心的人冒充该主机时，`accept-new`
# 仍然会拒（它只免掉"首次见面"一次询问），本条**不削弱**这一层。
forget_host_key() {
  local host="$1"
  if [ ! -f "$KNOWN_HOSTS" ]; then
    : # 还没有这份文件（第一次建机）⇒ 没有什么可清的
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] ssh-keygen -R %s -f %s\n' "$host" "$KNOWN_HOSTS"
    return 0
  fi
  # `-R` 在没有该条目时也返回 0；`-f` 指定文件，故**不会**去动 ~/.ssh/known_hosts。
  if ssh-keygen -R "$host" -f "$KNOWN_HOSTS" >/dev/null 2>&1; then
    log "   已清掉 $KNOWN_HOSTS 里 $host 的旧 host key（同名重建的必踩项）"
  else
    warn "清 $KNOWN_HOSTS 里 $host 的旧条目失败（继续；取数侧若撞上 `Host key verification failed` 就是这里没做成）"
  fi
}

# guest_root_equivalence —— **实测**客人侧的 root 等价，并把证据打出来（Task 16 Step 2）。
#
# 为什么要实测而不是"看 cloud-init 脚本写了 NOPASSWD 就认为成立"：这一格决定的是
# **测量语义**（谁能读 `/etc/shadow`、谁能跑 `dmesg`/`aa-status`），而它的失败形态是
# **安静的**：取数照常成功、记录照常落盘，只是 `OT-005`/`KS-012` 变成假失败、
# 另有 6 条被跳过的检查被算作通过 ⇒ 基线活跃集 B 与那个 −30 跟着一起变。
# 故这里**每次都真跑一遍**，并把 `id -u` 与 `sudo -n id -u` 两行原文留在日志里（就是证据）。
# 拿不到就**响亮失败**：绝不把一台"取数只能是 asc"的 VM 交给跑批
# （那会让这一批数据与 CT 的数据按两套语义混在一起）。
guest_root_equivalence() {
  local host="$1" out rc=0
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] ssh … %s `id -u` + `sudo -n id -u`（root 等价实测）\n' "$host"
    return 0
  fi
  out="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
            -o "UserKnownHostsFile=$KNOWN_HOSTS" -o "IdentitiesOnly=yes" -i "$SSH_KEY" \
            -l "$SSH_USER" -- "$host" \
            'id -un; echo "login-uid=$(id -u)"; if command -v sudo >/dev/null 2>&1; then echo "sudo-uid=$(sudo -n id -u 2>&1)"; else echo "sudo-uid=(没有 sudo)"; fi' 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    die "取数权限自检连不上 $host（rc=$rc）：$out"
  fi
  printf '%s\n' "$out" | sed 's/^/      /'
  case "$out" in
    *"sudo-uid=0"*)
      log "   ✅ **root 等价成立**（登录用户是 $SSH_USER，取数走 sudo -n ⇒ uid 0）——"
      log "      与 CT 基质的 \`pct exec\`（天生 root）**等价**，两套基质的 B 可比。"
      ;;
    *)
      die "客人 $host 上**拿不到 root 等价权限** —— 实测输出：
$(printf '%s\n' "$out" | sed 's/^/        /')
  为什么这是**响亮失败而不是警告**：本项目的 qemu 基质必须与 CT 基质的 \`pct exec\`（天生 root）
  **等价**取数。实测同一份二进制、同一台 VM，只换取数用户（asc vs root）会让 80 条检查里
  **10 条翻转且双向**：6 条在 asc 下被跳过却**算通过**、4 条（含决定基线活跃集 B 的
  OT-005/KS-012）**假失败** ⇒ 记录里的 detail 会写成「SELinux和AppArmor均未检测到」
  （看起来像机器真的没装），而 B 与那个 −30 会跟着一起变。
  **绝不**降级成 $SSH_USER 去取数。修法：确认 cloud-init 的 \`sudo: \"ALL=(ALL) NOPASSWD:ALL\"\`
  生效（重建该 VM），或手工在客人里放 \`/etc/sudoers.d/90-asscor-edgeexp\`：
      printf '%%s ALL=(ALL) NOPASSWD:ALL\\n' $SSH_USER > /etc/sudoers.d/90-asscor-edgeexp
      chmod 0440 /etc/sudoers.d/90-asscor-edgeexp" ;;
  esac
}

guest_side_metrics() {
  local host="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
      -o "UserKnownHostsFile=$KNOWN_HOSTS" -o "IdentitiesOnly=yes" -i "$SSH_KEY" \
      -l "$SSH_USER" -- "$host" \
      'set -e
       echo "  hostname      : $(hostname)"
       echo "  os            : $(. /etc/os-release; echo "$PRETTY_NAME")"
       echo "  kernel        : $(uname -r)"
        echo "  systemd       : $(systemctl is-system-running 2>/dev/null || echo unknown)（CT 里 systemd 是残缺的）"
       echo "  aa-status rc  : $(aa-status >/dev/null 2>&1; echo $?)（**以登录用户**跑；非 root 常见 rc=4 —— 见下一行）"
       echo "  aa-status(root): $(sudo -n aa-status 2>/dev/null | grep -m1 -E 'profiles are loaded|profiles are in enforce' || echo '取不到')（**以 root 等价**跑；这一行才是『VM 上真能 enforce』的证据）"
       echo "  apparmor      : $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo n/a)"
       echo "  lsm           : $(cat /sys/kernel/security/lsm 2>/dev/null || echo n/a)"
       echo "  nproc/mem     : $(nproc) vCPU / $(awk "/^MemTotal:/{printf \"%d MiB\", \$2/1024}" /proc/meminfo)"
       echo "  disk(/)       : $(df -h / | awk "NR==2{print \$2\" total, \"\$4\" avail\"}")"
       echo "  ip -4         : $(ip -4 -o addr show scope global | awk "{printf \"%s=%s \", \$2, \$4}")"' 2>/dev/null
}

# ============================================================================
# 主流程
# ============================================================================
if [ "$DESTROY" -eq 1 ]; then
  for i in "${!VMIDS[@]}"; do
    teardown_vm "${VMIDS[$i]}" "$i"
  done
  run clear_hosts_block
  # ⚠️ **这里不再有任何"存储 content 的恢复"**（Task 16 收口）：seed ISO 落在**专用存储**
  # `asscor-vmseed` 上，建机时也没有改过任何既有存储的 content ⇒ "恢复"这件事**不存在**，
  # 于是也不会再有"没走 --destroy 就把 local 永久留在 iso 状态"的那条风险。
  # 专用存储与它的目录**有意保留**（下一批 VM 直接复用；要撤见 --help 的说明）。
  log "== 销毁完成。当前 qm list："
  [ "$DRY_RUN" -eq 0 ] && qm list
  exit 0
fi

memory_plan
ensure_ssh_key
ensure_cloud_image
ensure_seed_storage

VM_IPS=()
for i in "${!VMIDS[@]}"; do
  vmid="${VMIDS[$i]}"
  host="$NAME_PREFIX$vmid"

  if qm status "$vmid" >/dev/null 2>&1; then
    # 判据①：**重跑不产生第二台 VM**。已存在 ⇒ 走"确保在跑"这条路。
    log "== VM $vmid 已存在（幂等重跑：不新建）"
    if ! qm status "$vmid" | grep -q running; then
      log "   → 它没在跑，启动它"
      run qm start "$vmid"
    fi
  else
    run qm create "$vmid" --name "$host" --ostype l26
    seed="$SEED_DIR/$host-seed.iso"
    build_seed_iso "$vmid" "$host" "$seed"
    create_vm "$vmid" "$host" "$seed"
    # **新建的机器 ⇒ host key 必然与同名旧机不同**（Task 16 / concern 3）：必须在本机开始
    # 连它**之前**把旧条目删掉。第一台的时候 ssh 还没见过它，但**第二台起**、
    # 以及"清机后再建"的循环里，旧条目已经在 $KNOWN_HOSTS 里了 —— 而 `accept-new`
    # 只接受新主机、**不接受变更后的主机** ⇒ 不清就会以 `Host key verification failed.` 收场
    # （那条错误与"私钥不对 / 机器不可达"同形）。幂等重跑（VM 已存在）不清。
    forget_host_key "$host"
    log "== 启动 VM $vmid"
    run qm start "$vmid"
  fi

  # 取客人 IP（判据：guest agent 说了才算；说不出来就**响亮失败**，绝不猜）
  # ⚠️ guest_ip 回的是 `<网卡名>\t<IP>` 两格，**不能**直接把它的整段输出当 IP 用。
  # 注意 `ip="$(guest_ip …)"` 那种写法会把函数跑在**子 shell**里 —— 网卡名就传不出来，
  # 故这里一次取回两格、在当前 shell 里切开。
  ip=""
  iface_used=""
  if [ "$DRY_RUN" -eq 0 ]; then
    if wait_guest_agent "$vmid" "$GUEST_AGENT_WAIT_S"; then
      ipinfo="$(guest_ip "$vmid" "$GUEST_IFACE_ACCEPT" || true)"
      iface_used="${ipinfo%%$'\t'*}"
      ip="${ipinfo#*$'\t'}"
      # 没有制表符 ⇒ 前后两格相等 ⇒ guest_ip 其实没给出结果
      if [ "$iface_used" = "$ip" ]; then iface_used=""; ip=""; fi
    fi
    if [ -z "$ip" ]; then
      warn "VM $vmid 的 guest agent 没能报出网卡（$GUEST_IFACE_ACCEPT）的 IPv4 ——"
      warn "  可能的因：cloud-init 还没收敛、镜像里没有 qemu-guest-agent、或网络没起来。"
      warn "  诊断：qm guest cmd $vmid network-get-interfaces；qm terminal $vmid（Ctrl-O 退出）"
      warn "  处置：确认 IP 后手工导出 EDGEEXP_VM_SSH_HOST=<ip> 再跑跑批前检查。"
      die "取不到 VM $vmid 的客人 IP（本脚本**不猜**取数地址：猜错会让 /etc/hosts 与后续取数锁到别的机器上）"
    fi
    log "   客人 IP：$ip（$iface_used@$NET_BRIDGE；期望网卡名 $GUEST_IFACE_ACCEPT）"
    VM_IPS[$i]="$ip"
  else
    printf '  [dry-run] qm guest cmd %s network-get-interfaces（取 %s 的 IPv4）\n' "$vmid" "$GUEST_IFACE_ACCEPT"
  fi

  # 等 SSH（**按 IP 连**：此刻 /etc/hosts 还没写）
  if [ "$DRY_RUN" -eq 0 ]; then
    if wait_ssh "$ip"; then
      log "   SSH 就绪：$SSH_USER@$ip"
    else
      die "等 SSH 超时（${SSH_WAIT_S}s）：$SSH_USER@$ip —— 诊断：qm terminal $vmid 看客人控制台"
    fi
    # 取数权限自检（Task 16 Step 2 的判据之一）：**在跑批之前**证明这台 VM 的取数
    # 与 CT 基质的 `pct exec`（天生 root）等价。拿不到就**响亮失败**（这里 exit 1），
    # 绝不把一台"只能以 asc 取数"的 VM 交给跑批 —— 那会让 B 与 −30 一起被带偏。
    log "   取数权限自检（root 等价）："
    guest_root_equivalence "$ip"
  fi
done

write_hosts_block
write_local_env

if [ "$DRY_RUN" -eq 0 ]; then
  log
  log "== 客人侧指标（这就是"环境是否完整"的判据）"
  for i in "${!VMIDS[@]}"; do
    vmid="${VMIDS[$i]}"
    log "-- $NAME_PREFIX$vmid（VMID $vmid）"
    guest_side_metrics "$NAME_PREFIX$vmid" || warn "取指标失败（$NAME_PREFIX$vmid）"
  done
  log
  log "== 建机完成。当前 qm list："
  qm list
  log
  log "下一步（跑批前）："
  log "  source $LOCAL_ENV"
  log "  bash lunwen/clab-lab/scripts/edge_prebatch_check.sh   # 前置门禁；rc 直接判（**不要**用管道）"
fi

# ============================================================================
# 跑批前怎么确认用的是 VM 基质（一句话口径，与 edge_prebatch_check.sh 对齐）
# ============================================================================
# **基质的唯一凭据是记录里的 `meta.observation_target` 带 `substrate=qemu`**；
# 跑批前用这两条把它钉住（两条都要，缺一条都可能跑成别的基质）：
#   1. `qi=1; qm list | awk 'NR>1 && $1 ~ /^[0-9]+$/ {c++} END {print c+0}'` 得 N，
#      且这 N 个 VMID 都 ≥ 910、名字都带 `$NAME_PREFIX` —— 环境**实际**是 VM 基质；
#   2. 每一台的取数地址在环境里显式可达：`EDGEEXP_VM_SSH_HOST`（或逐台
#      `EDGEEXP_VM_SSH_HOST_<vmid>`）与 `EDGEEXP_VM_SSH_KEY` 都指向真东西，
#      且 `edge_matrix.sh` 给每台的 `-target` 是 `qemu:<vmid>` ——
#      于是 `edgescen` 一定会走 `scp`+`ssh`，记录里一定带 `substrate=qemu`。
# 反过来，**任何** `substrate=pve` / `substrate=lxd` / 裸名字的记录都**不是** VM 基质的数据：
# 两套基质的数据**禁止混算**（基线活跃集随基质变，见设计文档）。
# ============================================================================
