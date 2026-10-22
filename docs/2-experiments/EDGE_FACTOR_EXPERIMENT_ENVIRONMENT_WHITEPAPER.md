# ASSCOR 实验环境白皮书：PVE 单机实验基质

> **文档性质**：可交付的**环境画像**。目的是让**没有参与过本项目**的读者，
> 仅凭本文 + 仓库内可跟踪的脚本，就能判断"这套实验是在什么机器上、以什么口径跑出来的"，
> 以及"这套环境够不够格承载本项目的实验"。
>
> **文档版本**：**v1.1（2026-10-16）** —— v1.1 把 **VM（QEMU/KVM）基质**从"已定案、待落地"改成**实测落地**（§4.1 / §5.3 / §5.4.1 / §3.7），并按 Task 16 的实测**更正了「−30」的口径**。
> **取证方式**：**全部条目均在实机上只读取证**，文末给出**每一条的复核命令**。
> 凡本文未实测的，一律标注「未实测」而**不填猜测值**。
> **基线提交**：`ASSCOR-Research-Core` @ `4c1ab06`。
> **数据锚点（两个提交，别混）**：本批 VM 数据的**采集提交**是 `8ae3c4b`（Task 17，跑批用的二进制盖着
> `vcs.revision=8ae3c4bb8961`）；**消费侧**（离线 V/G/C 合成）的修复是 `4c1ab06`（Task 18，
> 记录本体与 `legacy` 列逐位不变 ⇒ **不需要重采**）。

---

## 0. 脱敏口径（**先读这一节**）

本仓库是公开可交付的，本文因此**不含**内部实验环境的可寻址标识。占位符与真实值的对应关系如下：

| 占位符 | 含义 | 为什么用它 |
|---|---|---|
| `<pve-host>` | 承载本实验的 PVE 宿主机的主机名 | 主机名是团队自有实验机型号，不构成外部可寻址信息，但按脱敏铁律不写入公开文档 |
| `<mgmt-vlan-cidr>` | 管理 VLAN 的网段（本文中所有 `192.168.30.x` 的原始含义） | RFC1918 私有网段；**该 VLAN 与外网不互通**（见 §3.4 实测） |
| `<pve-host-ip>` | 宿主在管理 VLAN 上的地址（供 CT 访问 C2 用） | 同上 |
| `<mgmt-gw>` | 管理 VLAN 的路由器/网关地址 | 同上，且它是踩坑注释里的**关键事实**（见 §3.4） |
| `<lab-tag>` | 实验代号（记录文件名与 `meta.env` 里用的那个） | 与主机名同源 |
| `<ilo-host>` | 服务器的带外管理控制器 | **硬边界：绝对不许访问**（见 §5.1）。此地址**从未写入本仓库**（含历史提交，已核） |
| `<c2-key>` | C2（Caldera）API 口令 | **未跟踪的本地配置**提供；见 §4.5 |
| `<caldera-python>` | Caldera 进程的 Python 解释器路径 | 省略具体绝对路径，取法见 §4.4 |

**本仓库内既有内容的口径**：早期实验脚本与设计文档为了保留"踩坑注释的可读性"
（例如"容器的默认网关是路由器、不是宿主"这类必须带具体地址才能理解的教训），
**未做整体替换**，而是按"内部实验环境标识"的口径处理。凡在新文档里出现，
一律使用上表占位符。

> **本文的三条硬纪律（继承自项目既有裁定）**：
> 1. **带外管理控制器绝对不许访问** —— 不登录、不探测、不扫描、不改配置、不重启。
> 2. **上游交换机不直连** —— 需要交换机侧信息时，由环境所有者导出后提供。
> 3. **别动别人的客机** —— 备份存储、ISO/LXC 模板存储、以及不属于本实验的 VM/CT 一律不动。

---

## 1. 硬件与固件

### 1.1 整机

| 项 | 实测值 | 备注 |
|---|---|---|
| 厂商 / 型号 | HP **ProLiant DL360 Gen9** | 1U 机架服务器 |
| BIOS 序列号字段 | **空** | `dmidecode -t 1` 的 `Serial Number` 为空 ⇒ 本文不承担序列号脱敏义务 |
| UUID | `Not Settable` | 同上 |

### 1.2 CPU

| 项 | 实测值 |
|---|---|
| 型号 | **Intel(R) Xeon(R) CPU E5-2695 v4 @ 2.10GHz**（Broadwell-EP） |
| 插槽 | **1**（另一路空） |
| 每插槽核心 / 线程 | **18 核 / 36 线程** |
| 主频范围 | 1.20 GHz – 3.30 GHz |
| 实测主频（采样时） | 标称的 88% |

> **判据**：`lscpu | grep -E 'Model name|Socket|Core|Thread|CPU\(s\)'`

**含义**：36 个逻辑核对本实验的负载（2–3 个 LXC 客机 + 1 个 C2 进程）**非常充裕**。
CPU 不是这套环境的瓶颈。

### 1.3 内存（**已知短板，且是最硬的一条**）

| 项 | 实测值 |
|---|---|
| 可见总量 | **7.6 GiB** |
| 当前占用（采样时） | 已用 2.4 GiB / 可用 5.2 GiB |
| 主板最大容量 | **1536 GB**（`Maximum Capacity`，12 槽 × 2 路） |
| **已插内存条** | **1 条 8 GB**（`PROC 1 DIMM …`，其余槽位 `No Module Installed`） |
| Swap | 7.6 GiB |

> **判据**：`free -h`；`dmidecode -t 16 | grep 'Maximum Capacity'`；
> `dmidecode -t 17 | grep -B2 -A2 'Size: 8 GB'`

**为什么这是短板**：这台机器**只插了一条 8 GB 内存条**，而主板可以插到 1.5 TB。
⇒ 任何"给靶机多分几个核、多分几 G 内存"的想法都会**立刻撞到内存墙**。
⇒ **这是选择基质的决定性约束**（见 §5.2）：CT（LXC）的每实例开销是**进程级**的，
一台 CT 分 1 GiB 就够；而 VM（QEMU/KVM）要为每台客机预留完整内核 + 设备模型的内存，
在中重型拓扑下**必然爆**。

### 1.4 NVMe 固态盘（**已知的 x1 链路约束**）

| 项 | 实测值 |
|---|---|
| 型号 | **SAMSUNG MZVLB256HAHQ-000L7**（PM981 系列，256 GB） |
| 控制器 | Samsung NVMe SSD Controller SM981/PM981/PM983（`144d:a808`） |
| 固件 | `1L2QEXD7` |
| 链路能力（LnkCap） | 8 GT/s（PCIe 3.0），**x4** |
| **链路实际（LnkSta）** | 8 GT/s，**x1 —— `(downgraded)`** |

> **判据**：`lspci -vv -s <nvme-bdf> | grep -E 'LnkCap|LnkSta'`；
> `cat /sys/class/nvme/nvme0/device/current_link_width`（= **1**）、
> `.../max_link_width`（= **4**）

**含义与后果**：
- 盘的**能力**是 PCIe 3.0 x4（理论约 3.9 GB/s），但**实际只跑在 x1 上**（理论约 985 MB/s）。
  ⇒ 吞吐约为能力的 **1/4**，随机 IOPS 的差距更大。
- **根因未在本任务中定位**：`(downgraded)` 说明是链路协商结果与插槽能力不符。
  DL360 Gen9 的 PCIe 插槽在装入**第二颗 CPU** 或**特定 Riser 配置**时才有多条 x16 通道；
  单 CPU + 默认 Riser 下，部分槽位只能给到 x1/x4。**具体是插槽物理限制还是 Riser 型号限制，
  本文不做断言**（需要开箱/进 BIOS 才能确定，超出只读取证范围）。
- **对本实验的影响：可忽略**。实验负载是"每次采集几 KB～几 MB 的 JSON/JSONL"，
  不是大数据吞吐；瓶颈永远在**攻击观察窗的墙上时间**与**网络往返**上，不在盘的顺序带宽上。
- **对 VM 基质的影响：需要考虑**。同一块 NVMe 上还要放 VM 的虚拟磁盘；
  x1 链路下**多台 VM 同时启动**（QEMU 镜像 + 内核解压）会明显变慢，
  而开局慢会被误读成"环境不可靠"。

### 1.5 其它磁盘

| 设备 | 型号 | 容量 | 介质 | 挂载/用途 |
|---|---|---|---|---|
| `sda` | WDC WD10EZEX-08M2NA0 | 1.00 TB | **7200 rpm 机械** | ZFS 镜像的一半 |
| `sdb` | WDC WD10EZEX-00WN4A0 | 1.00 TB | **7200 rpm 机械** | ZFS 镜像的另一半 |
| `sdc` | MICROFLASH SATA3.0 128GB | 128 GB | **SATA SSD（无标称品牌）** | PVE 系统盘（`pve-root` 39.7 G + `pve-swap` 7.6 G + `local-lvm` 54.2 G） |
| `sdd` | WDC WD3200AAJS-00L7A0 | 320 GB | 7200 rpm 机械（老旧型号） | 备份专用（`Backup-320G`） |
| `nvme0n1` | SAMSUNG MZVLB256HAHQ-000L7 | 256 GB | NVMe | `NVMe-256G` 存储池（含靶机 CT 的根盘） |

> **判据**：`lsblk -o NAME,SIZE,TYPE,MODEL,MOUNTPOINT,ROTA`

### 1.6 SMART 健康状况（2026-10-15 采样）

**五块盘全部 `PASSED`**：

| 设备 | SMART overall-health |
|---|---|
| `sda` | **PASSED** |
| `sdb` | **PASSED** |
| `sdc` | **PASSED** |
| `sdd` | **PASSED** |
| `nvme0` | **PASSED** |

> **判据**：`for d in /dev/sd? /dev/nvme0; do echo "== $d"; smartctl -H "$d" \| grep 'SMART overall'; done`
>
> **本节省略序列号**：`smartctl -i` 会输出每块盘的 `Serial Number`。
> 序列号与型号的**对应关系**属于"设备指纹"，本文**不复述**；需要时由环境所有者就地查看。

---

## 2. 存储

### 2.1 存储配置（`/etc/pve/storage.cfg` 逐条实录）

```text
dir: local
        path /var/lib/vz
        content import,vztmpl,backup
        shared 0

lvmthin: local-lvm
        thinpool data
        vgname pve
        content rootdir,images

zfspool: RAID-Mirror
        pool RAID-Mirror
        content rootdir,images
        mountpoint /RAID-Mirror
        nodes pve

dir: ZFS-ISO
        path /RAID-Mirror/iso
        content iso
        prune-backups keep-all=1
        shared 0

dir: Backup-320G
        path /mnt/pve/Backup-320G
        content backup
        is_mountpoint 1
        nodes pve
        shared 0

dir: ZFS-LXD
        path /RAID-Mirror/lxd
        content vztmpl
        prune-backups keep-all=1
        shared 0

lvmthin: NVMe-256G
        thinpool NVMe-256G
        vgname NVMe-256G
        content rootdir,images
        nodes pve

dir: asscor-vmseed
        path /RAID-Mirror/asscor-vmseed
        content iso
```

> **最后一条 `asscor-vmseed` 是 Task 16 新增的**（本实验**唯一**一处持久的宿主存储改动，
> **additive**）：VM 基质的 **NoCloud seed ISO** 必须落在一条**带 `iso` 内容**的存储里
> （PVE 9 起 `qm set --ide2` 不再接受裸绝对路径），而既有三条带 `iso`/不许动的存储
> （`ZFS-ISO` / `Backup-320G` / `ZFS-LXD`）一律不许动 ⇒ **自建一条**是唯一不翻转全局状态的做法。
> 写法**参照 `ZFS-ISO`**。**本实验刻意保留它**（下批直接复用；删了就要再建一次）。
> **撤销命令**：`pvesm remove asscor-vmseed && rm -rf /RAID-Mirror/asscor-vmseed`。
>
> ⚠️ **`local` 的 `content` 顺序会变，语义不变**：起点是 `backup,import,vztmpl`，
> 现在可能显示成 `backup,vztmpl,import` —— 那是 **PVE 在 `pvesm add` 时重写 `storage.cfg`
> 的规范化行为**，不是本实验改的（Task 15 那套"临时给 `local` 补 `iso` 再写回"的代码
> **已被整段删除**）。⇒ **本条的正确判据是「逐项相同」，不是「逐字相同」**。

> **判据**：`cat /etc/pve/storage.cfg`

### 2.2 逐存储的形态与用法规则

| 存储 | 形态 | `content` | 用法规则（**逐条都是既有裁定**） |
|---|---|---|---|
| `RAID-Mirror` | **ZFS 镜像池**（2 × 1 TB 机械，`mirror-0`） | `rootdir,images` | 需要**容错**的东西放这里。池 `ONLINE`、容量 928 G / 已用 39.8 G（4%）、无已知数据错误；最近一次 scrub 2026-10-11 00:28，修复 0 B |
| `NVMe-256G` | **LVM thin**（NVMe 上的 `NVMe-256G` VG） | `rootdir,images` | **性能敏感**的客机根盘放这里（本实验的靶机 CT 就在这）。thin 池，注意**过度分配**风险 |
| `local-lvm` | **LVM thin**（系统 SSD 上的 `pve` VG，`data` 池 54.2 G） | `rootdir,images` | PVE 默认盘。容量小（54 G），**不要**用来放实验客机 |
| `local` | `dir`（`/var/lib/vz`） | `import,vztmpl,backup` | PVE 默认目录存储，只收导入/模板/备份 |
| `ZFS-ISO` | `dir`，路径 `/RAID-Mirror/iso` | **仅 `iso`** | **只收 ISO 镜像**。**新存储的写法参照它**：`dir:` + `path /RAID-Mirror/<名>`（既有约定） |
| `ZFS-LXD` | `dir`，路径 `/RAID-Mirror/lxd` | **仅 `vztmpl`** | **只收 LXC 模板**（`prune-backups keep-all=1`） |
| `Backup-320G` | `dir`，路径 `/mnt/pve/Backup-320G`（`is_mountpoint 1`） | **仅 `backup`** | **只收备份**。**不得**改它的 `content`、**不得**把客机磁盘放进去 |
| **`asscor-vmseed`** | `dir`，路径 `/RAID-Mirror/asscor-vmseed` | **仅 `iso`** | **本实验自建**（Task 16）：只放 **VM 的 NoCloud seed ISO**。⚠️ `dir` 存储的 ISO **不在 `<path>/iso/`，而在 `<path>/template/iso/`** —— 放错目录的症状是 `volume 'asscor-vmseed:iso/<名>' does not exist`（看着像"文件没了"，其实 ISO 已经生成好了）。见 §5.3 |

> **判据**：`zpool list && zpool status RAID-Mirror`；`df -hT`；`pvesm status`

### 2.3 存储层的一条硬判据

`Backup-320G` 是一块 **320 GB 的 2008 年前后型号机械盘**（`WDC WD3200AAJS`），
`is_mountpoint 1` 表示 PVE 会**在挂载点未挂载时拒绝**把备份写进空目录（防"备份写到根盘上"）。
它的**唯一**职责是**收备份**；把它当实验资源池用会同时违反"只收 backup"与它的容量/寿命假设。

---

## 3. 网络

### 3.1 拓扑（宿主侧实测）

```text
[上游交换机] ── GE/xxx ── nic0 ─┐
                                 ├── vmbr0  静态 <pve-host-ip>/24   ← 管理 VLAN（无网关）
[上游交换机] ── GE/xxx ── nic3 ─┐
                                 ├── vmbr1  DHCP  192.168.1.242/24  ← 默认路由出口
[带外管理控制器] ── (交换机管理口) ← 硬边界，本实验一概不碰
```

实测：

| 接口 | 状态 | 地址 |
|---|---|---|
| `lo` | UNKNOWN | `127.0.0.1/8`, `::1/128` |
| `nic0` | UP | （无 IP，`vmbr0` 的桥接口） |
| `nic1` | UP | **IPv6 全球地址** `2409:…:fe56:8721/64` + link-local |
| `nic2` | UP | **IPv6 全球地址** `2409:…:fe56:8722/64` + link-local |
| `nic3` | UP | （无 IP，`vmbr1` 的桥接口） |
| `vmbr0` | UP | **`<pve-host-ip>/24`** + link-local |
| `vmbr1` | UP | **`192.168.1.242/24`**（DHCP）+ link-local |
| `veth904i0@if2` | UP | （CT 904 的 veth 对） |

路由表（**关键**）：

```text
default via 192.168.1.2 dev vmbr1
192.168.1.0/24 dev vmbr1 proto kernel scope link src 192.168.1.242
<mgmt-vlan-cidr> dev vmbr0 proto kernel scope link src <pve-host-ip>
```

> **判据**：`ip -br a`；`ip route`；`cat /etc/network/interfaces`

### 3.2 双宿（dual-homed）的含义

宿主同时挂在**两个互不相通的网**上：

- **`vmbr1`**（`192.168.1.0/24`）：**唯一**带默认路由的出口 ⇒ 宿主自己装包、拉镜像、
  走 Go module 代理都靠它。这个网段的地址是 **DHCP** 拿的（采样时 `.242`），**会变**。
- **`vmbr0`**（管理 VLAN）：**静态**地址 `<pve-host-ip>/24`，**没有网关**
  （`/etc/network/interfaces` 里 `#gateway` 那行是被**注释掉**的）。
  所有**实验流量**（C2 ↔ 靶机 ↔ CT）都走这里。

⇒ **这条是整套环境设计的核心**：实验流量被**物理隔离**在一个没有默认路由的网桥上，
**不可能**泄露到外网，也**不可能**因为宿主装了什么东西而改变实验口径。

### 3.3 C2 的绑定地址

C2（Caldera）**显式绑在 `<pve-host-ip>`**（管理 VLAN 上的宿主地址），不是 `0.0.0.0`：

```text
host: <pve-host-ip>
port: 8888
```

实测监听（`ss -lntp`，只列与本实验相关的行）：

| 监听地址 | 端口 | 进程 |
|---|---|---|
| `<pve-host-ip>` | **8888** | Caldera（HTTP API） |
| `<pve-host-ip>` | 8022 | Caldera（SSH contact） |
| `<pve-host-ip>` | 7010 / 7012 | Caldera（内部服务） |
| `0.0.0.0` | 2222 | Caldera（FTP contact） |
| `0.0.0.0` | 22 | sshd |
| `127.0.0.1` | 85 | pvedaemon |
| `*` | 3128 / 8006 | spiceproxy / pveproxy |

> **判据**：`ss -lntp`；`grep -E 'host|port' /opt/caldera/conf/default.yml`

**为什么绑具体地址而不是 `0.0.0.0`**（**这是踩坑注释里那条教训的物理依据**）：
CT 里的容器拿到的默认网关**不是宿主**，而是**管理 VLAN 里的路由器**（`<mgmt-gw>`）。
若 URL 用默认网关拼，容器会向**路由器**发 C2 请求 ⇒ 拿到 `000` ⇒ 整轮在
"容器内问不到 C2"处失败。所以靶机 CT 里**必须显式**用 `<pve-host-ip>` 访问 C2。

### 3.4 管理 VLAN 的性质（**实测：与外网不互通**）

| 实测 | 结果 |
|---|---|
| 管理 VLAN 内 ping 公网地址（如 `8.8.8.8`） | **不通** |
| 管理 VLAN 内 ping 上游内网地址 | **不通** |
| 管理 VLAN 内 DNS 解析 | **失败** |
| 上游交换机在管理 VLAN 与出口网段之间做三层转发 | **是**（存在，但本实验不用它出网） |

⇒ **判据结论**：管理 VLAN 是**隔离段**。这既是**安全属性**（实验流量出不去），
也是**约束**（CT 内装包必须靠宿主做代理或预置镜像，见 §5.4）。

### 3.5 靶机的取址方式

靶机 CT 走 **`vmbr0` + DHCP**，而不是静态地址：

```text
net0: name=eth0,bridge=vmbr0,hwaddr=<mac>,ip=dhcp,type=veth
```

采样时容器内实测得 `192.168.30.65/24`（**注意：该地址会随 DHCP 变**）。

> **口径**：任何脚本、文档、命令**都不得**把 CT 的 IP 写死。
> 需要地址时**在容器内取**（容器自己的 `ip -br a`），需要宿主地址时用共享的
> `ct_reachable_host_addr()` 一类帮助函数取。**这条是既有踩坑的结论**。

### 3.6 管理 VLAN 的地址分布（脱敏表述）

| 角色 | 在管理 VLAN 上的位置 | 是否写入本仓库 |
|---|---|---|
| 路由器/网关 | `<mgmt-gw>`（网段第 1 个可用地址） | **是**（踩坑注释里必需；见 §0） |
| PVE 宿主（= C2 宿主） | `<pve-host-ip>`（网段第 2 个可用地址） | **是**（同上） |
| 靶机 CT | DHCP（采样 `.65`） | **否** |
| 带外管理控制器 | `<ilo-host>`（网段内的一台带外控制器） | **从未写入**（含历史提交，已核） |

**`192.168.30.0/24` 与主机名为什么不做整体替换**：
它们是 **RFC1918 私有网段 + 团队自有实验机型号**，且散布在大量**必须带具体地址才能读懂**的
踩坑注释里（"容器的默认网关是路由器 `<mgmt-gw>`、宿主是 `<pve-host-ip>`"）。
整体替换会**直接摧毁注释的可读性**，而它本身在仓库外不可达（§3.4 已实测隔离）。
⇒ 既有处理方式是：**既有文档/脚本保留** + **新文档使用占位符** + **加一句口径说明**。

### 3.7 VM 靶机的网络通路（**v1.1 新增，实测**）

这一节回答"VM 靶机怎么走到 C2"。**它和 CT 不是同一条路**，而这是 VM 基质能不能跑批的前提。

**（甲）网卡实名是 `ens18`，不是 `eth0`** —— PVE 的 virtio 网卡在客人里按 PCI 槽位取**可预测名**。
`edge_vm_provision.sh` 的客人侧指标因此写死 `eth0` 过一次的错，现在走
`EDGEEXP_VM_GUEST_IFACE`（默认 `ens18`）+ `eth0` 兜底；**仍以名字精确匹配优先**（多网卡时不锁到不通的那条）。

**（乙）VM 挂 `vmbr1` 时到不了 C2 —— 缺的是一条路由，不是一个端口**：

```text
VM 侧实测（客人内）：
default via 192.168.1.1 dev ens18 proto dhcp src 192.168.1.3 metric 100
192.168.1.0/24 dev ens18 proto kernel scope link src 192.168.1.3
宿主侧实测（宿主上）：
default via 192.168.1.2 dev vmbr1
```

⚠️ **两条默认路由的网关不是同一个（`.1` vs `.2`）** —— 两边都是 **DHCP** 拿的。
⇒ **"默认网关"这个值在这套环境里不得被任何脚本写死**（它连同一个网段的两台机器上都不一样）。
C2 只绑在宿主的 `vmbr0` 地址（`<pve-host-ip>`）上 ⇒ VM 发往 C2 的报文被默认网关拿走后就没了
（实测探针 `probe_rc=124`，8 秒超时）。

**修法（客人侧一条 `/32` 主机路由；实测立即生效）**：

```text
ip route replace <pve-host-ip>/32 via 192.168.1.242 dev ens18
```

- 下一跳 = **宿主自己在客人网段内的地址**（由 `guest_host_addr <iface>` **动态取**，不写死 ——
  它在 §3.1 里是 DHCP 的）；
- **为什么加 `/32` 而不是整段 `192.168.30.0/24`**：`/32` 恰好覆盖"取数要去的那台机器"，
  不替操作者做"那个网段整体该怎么走"的决定（网络设备是纪律边界，不碰）；
- **幂等必须用 `replace`**：`ip route add` 第二次会报 `File exists`，而那条错会以
  **"复位失败"**的形态出现；
- 对照实验（Task 15 实测）：把路由删掉，同一条探针**又变回不通** ⇒ 差异确实由这条路由造成。

**（丙）为什么宿主 `ip_forward=0` 也不影响**（实测 `sysctl -n net.ipv4.ip_forward` = **`0`**）：

> 报文的目的地 **`<pve-host-ip>` 就是宿主自己的地址** ⇒ 到宿主是**本机投递（local delivery）**，
> **不需要**转发。⚠️ 若将来要经宿主去到 `192.168.30.x` 的**别的**主机，`ip_forward=0`
> 就会**真的**成为阻塞（这条是纠错：任务书曾写"宿主已开 `ip_forward`"，**与实测不符**）。

**（丁）VM 挂 `vmbr0` 时不需要任何路由** —— 直连同网段（Task 15 实测：热插一块 `vmbr0` 网卡 +
客人侧 `192.168.30.201/24` ⇒ `ping` 3/3 收、`HTTP/1.0 401 Unauthorized`）。本批**没有**用这种方式
（VM 只挂 `vmbr1` + 一条 `/32` 主机路由）。

**（戊）"通"的判据是「客人内问到 HTTP 响应」，不是 ping、也不是 TCP**：

| 端点 | 结论 |
|---|---|
| 客人内 `curl -H "KEY: <c2-key>" <C2>/api/v2/abilities` → **200** | 真通（`edge_target_prepare.sh` 的自证判据） |
| 客人内不带 KEY → `401 Unauthorized` | 也**算通**（HTTP 层答了）；TCP 通不等于服务对 |
| **宿主**侧不带 KEY → **200**、`/health` → **200** | ⚠️ **与 CT/客人侧不是一回事** —— 别把宿主上的 200 当成"靶机也通"的证据 |

**（己）一处对 Task 13 的订正**：Task 13 §2.6 曾报「连 CT 904（本就在 `vmbr0` 同网段）也到不了 C2:8888」。
Task 15 用**TCP + 原始 HTTP** 复测 CT 904 → C2:8888，得到 **`HTTP/1.0 401 Unauthorized`** ⇒ **CT 是通的**。
那条结论是**探针形态**造成的（`/dev/tcp` 依赖 bash 特性），不是网络事实。
**VM 到 C2 不通是真的**（缺路由），**CT 到 C2 不通是假的** —— 两件事在 Task 13 里被写成了同一件。

> **判据**：宿主 `ip route`；客人内 `ip -br a; ip route`；客人内
> `curl -o /dev/null -w '%{http_code}' -H "KEY: <c2-key>" <C2>/api/v2/abilities`。

---

## 4. 基质与 C2

### 4.1 基质（substrate）是什么

本项目的实验把"被攻目标"抽象成一层**基质**：同一套管线（复位 → 攻击 → 采集 → 门禁 → 离线重算）
可以跑在**不同的虚拟化环境**上，由 `EDGEEXP_SUBSTRATE` 选择。

已实现的基质驱动：

| 基质名 | 后端 | 观测原语 | 入口 |
|---|---|---|---|
| `docker` | Containerlab 容器 | `docker exec` | 开发机（WSL2） |
| `lxd` | LXD 实例 | `lxc exec` / `lxc file push` | **（已退场）原远程 A-1**：驱动保留、**无可用宿主** —— 2026-10-19 退为备份端、数据归档 dl360gen9 的 `/RAID-Mirror/from-a1/`、即将重置。⚠️ **不要照这一行去跑 lxd 批次** |
| `clab` | Containerlab 拓扑 | `docker exec`（拓扑级） | 开发机 |
| **`pve`** | **PVE CT（LXC 容器）** | **`pct exec` / `pct push`** | **本文档描述的这台机** |
| **`qemu`** | **PVE VM（QEMU/KVM）** | **`ssh`（目标内执行） + `scp`（送文件）** | **本文档描述的这台机（v1.1 起已落地）** |

**`pve` 驱动的四条硬行为**（都是踩坑后的判据，逐条有夹具钉住）：

1. **只认解析后的 VMID**：`asc-tgt-c2` ⇒ `pve:904`。名字**一个字节都不会**进参数位。
2. **`pct push` 的参数顺序与 `lxc file push` 相反**：
   `pct push <vmid> <本地> <目标> --perms 755`。
3. **绝不静默回落**：`pve` 路径上**只**起 `pct`；`docker`/`lxc`/`clab` 一次都不调用。
4. **`lab_up`/`lab_down` 在 `pve` 下响亮失败**（`rc=2` + 说明原因）——
   拓扑生命周期属于"谁建的谁管"，管线不得偷偷建/删 CT。

> **判据**：`bash lunwen/clab-lab/tests/test-edge-lab.sh`（H 段 25 格专测 `pve` 分支、I 段专测 `qemu` 分支）；
> 驱动实现在 `lunwen/clab-lab/scripts/edge_lab.sh`。

**`qemu` 驱动的五条硬行为**（`docker`/`lxd`/`pve` 的"一个二进制、两级调用"关系在它这里**不成立**，逐条与代码一致）：

1. **两级 CLI 不是同一个二进制**：`lab_topology_bin = qm`（**实例视图**）、`lab_target_bin = ssh`（**目标内执行**）、
   另有 `lab_scp_bin = scp`（**送文件**）⇒ qemu 下 `bins=(…)` **三项都查**（缺哪一项的症状互不相干）。
2. **`qm` 只认数字 vmid**：`qm status asc-vm910` 报 `vmid: type check ('integer') failed`（rc=255），
   而 `qm status 910` → `status: running`。⇒ 名字 → vmid 的解析收在**唯一一处** `lab_qemu_vmid <node>`
   （判据与 pve 侧 `lab_node_vmid` 逐条同源；**`qm list` 的名字在第 2 格**，与 `pct list` 的"最后一格"**相反**）。
   **但与 `cmd/edgescen` 的 `-target qemu:<vmid|名字>` 不同**：那里**两种标识都收** ——
   数字按默认规则推 `asc-vm<vmid>`，非数字则**原样当主机名**（`nodecollect.go` 的 `qemuSSHHost`）
   且**刻意不去猜它对应哪个 vmid**（猜错就是"采到另一台机器的数据、而记录里的节点名照常"）。
3. **`ssh` 不保留 argv 的格边界**（**结构性差别，不是实现缺陷**）：`ssh <主机> <argv…>` 会把
   `-- <主机>` 之后的**所有格用空格拼成一个字符串**，交给**客人侧的登录 shell** 再分词。
   前三种基质都有"把 argv 原样交给客人"的 CLI（`docker exec <容器> <argv…>` / `lxc exec -- …` /
   `pct exec <vmid> -- …`），**`ssh` 没有**。
   ⇒ `lab_target_exec` 在 qemu 下用 `printf '%q '` **逐格引用**后拼成**一格**再交给客人侧 `bash -c`。
   ⚠️ **忘了这一步会得到一个 rc=0 的哑炮**（`bash -c bash -c rm -f /tmp/x` 的真实执行体是**无参 `bash`**，
   读 stdin 然后 EOF 退出 ⇒ 命令一次也没跑、**rc 还是 0**）。实测原文见操作手册 §6.12。
4. **取数手段是 `scp` + `ssh`**：`scp -O`（强制 legacy SCP 协议，免得依赖客人侧 `sftp-server`）+
   紧随的 `ssh … chmod 0755`（`scp` 保留权限位而**不**保证可执行）。
   **`-o User=<用户>`，绝不能用 `-l <用户>`** —— `ssh -l` 是登录名，而 **`scp -l` 是带宽上限**（要数字）。
5. **`lab_up`/`lab_down` 照旧 `rc=2`**（与 `lxd`/`pve` 同形），理由多一条：VM 是**要建**的（与 CT 不同），
   而建机/清机有**单一来源** `edge_vm_provision.sh`。两个入口对"哪些 VMID 属于本任务"的判据一旦分叉，
   一次 `lab_down` 就能拆掉别人的 VM。

> ⚠️ **一条实测教训（关于"注释里的推断"）**：上面第 3 条曾被 Task 13 的注释与 Task 16 的
> "实测澄清"**都**写成"客人侧收到的命令串逐字是 `bash -c bash -c rm -f /tmp/x`、**语义正确**"。
> Task 17 在真机上**推翻**了它 —— 而那正是"离线夹具与代码共享同一个错模型"的典型：
> 夹具的假 `ssh` 把 argv **逐格转交**（那是 `docker`/`lxc`/`pct` 的语义，**不是 ssh 的**）。
> ⇒ **qemu 分支的判据必须是行为判据**（假 `ssh` 照实模拟真 ssh 的拼格，判"副作用真的发生了"）。

### 4.2 C2（Caldera）

| 项 | 实测值 |
|---|---|
| 安装路径 | `/opt/caldera` |
| 版本（源码 HEAD） | `cb8d6a81`（2026-08-27） |
| 进程 | `python server.py --insecure -P sandcat,stockpile,atomic` |
| 已运行时长（采样时） | 5 天 15 小时 |
| 绑定 | `host: <pve-host-ip>`，`port: 8888` |
| API 口令口径 | 见 §4.5 |
| 插件集 | `-P` **必须显式给**：`sandcat`（agent）、`stockpile`（能力库）、`atomic`（Atomic Red Team） |

> **判据**：`ls -d /opt/caldera`；`git -C /opt/caldera log -1 --format='%h %ad' --date=short`；
> `ps -eo pid,etime,cmd | grep server.py`；`grep -E 'host|port' /opt/caldera/conf/default.yml`

**重要口径**：C2 **已经在跑，且不得重启、不得重装**。
`--insecure` 意味着 API 走 HTTP（不是 HTTPS），因此**必须**绑在内网地址上（§3.3）。
`-P` 不显式给会导致插件缺失 ⇒ C2 自证通过但能力/agent 不可用（"看起来起来了、其实不能用"）。

**残留 agent 问题**：C2 里会积累历史 agent 记录（实验反复起停靶机留下）。
采集器的"就绪判据"与"agent 归属判据"必须能区分**本次新起**的 agent 与**上一轮的残留**，
否则会把陈旧 agent 当成"目标已沦陷"的证据。既有夹具里有专门的钉子。

### 4.3 三件 TTP 实体（`targeted_ttp` 口径的必需输入）

`targeted_ttp` 场景要有**明确的成败标签**，就必须知道"哪条 link 算目标"。
这由**三件实体**（+1 个可选）声明：

| 环境变量 | 必需性 | 值（本实验在用的一套） | 含义 |
|---|---|---|---|
| `EDGEEXP_TTP_TARGET_ABILITY` | **必需** | `a5c0ffee-0000-4000-8000-0000000003b1` | **目标 TTP**：链里出现它的 link 才算"目标达成" |
| `EDGEEXP_TTP_TARGET_ABILITY_NAME` | 可选 | `T4D Step 3B: read /etc/shadow (AppArmor target TTP)` | 只用于核对 ID 没被换掉 |
| `EDGEEXP_TTP_CONTROL_ABILITY` | 可选 | `a5c0ffee-0000-4000-8000-0000000003c1` | **对照 TTP**：只用于归类与报告，不参与成败判定 |
| `EDGEEXP_TTP_PLAYBOOK_ID` | **必需** | `a5c0ffee-0000-4000-8000-0000000003c2` | 剧本 ID |
| `EDGEEXP_TTP_PLAYBOOK_NAME` | **必需** | `T4D Step 3B pair (control + target TTP)` | **剧本漂移守卫**：缺了会在**攻击步**被拒 |

> **判据**：`bash lunwen/clab-lab/scripts/edge_ttp_provision.sh --dry-run`（幂等 provisioning 入口）；
> 这三件实体由该脚本在 C2 里幂等创建，**ID 是写死的确定性 UUID**（`a5c0ffee-…` 前缀），
> 因此**跨环境可复现**、**可记档**。

**为什么剧本名必须显式给**（实测踩到的坑）：`edge_attack.sh` 的剧本名有默认值，
缺名字时 **25 个场景干跑照样 `rc=0`** ⇒ "干跑绿 ≠ 能跑"。
故矩阵层与 `TARGET_ABILITY`/`PLAYBOOK_ID` **同一处**加了显式门禁。

**为什么这三个 ID 可以写进公开文档**：它们是**自己造的确定性 UUID**（不是 C2 生成的随机 ID），
不含凭据、不含设备信息；写出来是为了让第二个人能在**另一个** C2 上**复现同一套标签口径**。

### 4.4 provisioning 入口

| 脚本 | 职责 |
|---|---|
| `lunwen/clab-lab/scripts/edge_ttp_provision.sh` | 在 C2 里**幂等**创建/校验三件 TTP 实体（含 ID 记档） |
| `lunwen/clab-lab/scripts/edge_target_prepare.sh` | **靶机侧**的幂等准备（装包、装 agent、声明基线、C2 自证）。**v1.1 起含 `qemu` 分支**：客人侧助手 + root 等价 + 真 AppArmor 策略 + agent 以 root 拉起 + 到 C2 的主机路由（§3.7） |
| **`lunwen/clab-lab/scripts/edge_vm_provision.sh`** | **VM 靶机的建机/清机唯一入口**（v1.1 起）。拉 Ubuntu cloud image → `qemu-img convert` → `qm importdisk` → `genisoimage` 造 **NoCloud seed**（卷标 `cidata`）→ `qm create/start` → 等 guest agent 取 IP → 写 `/etc/hosts` 托管区块 → 等 SSH → 客人侧依赖 → **取数权限自检** → 打印指标。⚠️ **清机必须走 `--destroy`** |
| **`lunwen/clab-lab/scripts/edge_vm_guest.sh`** | **客人侧助手**（v1.1 起）。qemu 的"目标内执行"由 `ssh` 承担，而 **`ssh` 不保留 argv 的格边界** ⇒ 多 token 的脚本**不能**靠 argv 送进去；处置是**落文件 → `lab_push` → 按路径执行**。子命令：`policy-status/apply/remove/probe`、`agent-install/start/stop`、`route-add/route-del`、`net-report`、`c2-probe` |
| `lunwen/clab-lab/scripts/edge_prebatch_check.sh` | **跑批前置的唯一入口**：把"能不能开跑"收成一道门（见 §5.4） |

> **判据**：`head -60 lunwen/clab-lab/scripts/edge_prebatch_check.sh`

### 4.5 C2 凭据的口径

C2 的 API 口令**不写入本仓库**。仓库里此前的落点是脚本默认值
（形如 `CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-<c2-key>}"`），属"真凭据的明文默认值"，
**已按脱敏铁律处置**（详见审计归档中的"脱敏处置台账"）。现行口径：

1. 口令由**未跟踪的本地配置**（环境变量或本地 env 文件）提供，变量名 `EDGEEXP_CALDERA_KEY`；
2. **跑批前置门禁会在缺 key 时响亮失败** —— 绝不允许回落成"没 key 也继续"；
3. dl360gen9 上的 C2 口令以 **argon2id 哈希**形式存在 `conf/default.yml`
   （`api_key_red` / `api_key_blue` 两条），**哈希本身不是明文**，但**不要**把它拷进仓库。
4. ⚠️ **实测补充（Task 14，2026-10-16）**：第 3 条那句"不要拷进仓库"**当时已经被违反了** ——
   `lunwen/clab-lab/scripts/exp_caldera_key2.sh`（及其在 `lunwen/attachment/scripts/` 的副本）
   里**内联着 `api_key_red` 的哈希原文**，而同一文件的候选口令表里还有那个默认口令的明文
   ⇒ 等于"靶子 + 答案"一起提交。Task 14 已把它改成**就地**从 `conf/default.yml` 读，
   哈希与候选明文均不再进仓库。
   判据：`git grep -nE '\$argon2id\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{16,}' -- lunwen`
   **零命中**（要匹配到**完整** PHC 串才算命中，故这条判据自身的文本不会命中它）。

> **判据**：`grep -c 'api_key' /opt/caldera/conf/default.yml`（应得 2 条，值为 `$argon2id$…`）；
> 仓库侧：`git grep -I -n -e '<明文>'` 与上一条哈希片段**均零命中**（Task 14 报告 §Step 1）。

---

## 5. 基质的定位与选择判据（**本白皮书的结论**）

### 5.1 两条硬边界（不可协商）

| 边界 | 内容 | 理由 |
|---|---|---|
| **带外管理控制器** | **绝对不许访问**：不登录、不探测、不扫描、不改配置、不重启 | 它是这台机器的"最后一条远程生命线"。实验**永远不需要**它，而任何误操作都可能让机器失联 |
| **上游交换机** | **不直连**：需要交换机侧信息时由环境所有者导出后提供 | 交换机是共享网络设备，它的配置变更会同时影响**别的使用者** |

### 5.2 基质分工原则（**2026-10-15 定案**）

> **项目口径**：CT 仅用于**快速验证与轻量模拟**，只作**临时短期任务**的选择；
> 长线任务、中重型拓扑模拟与要进论文的重要任务，交给拥有完整环境的 VM，
> 以保证数据的准确性与环境的可靠性。若 CT 用起来受限太多，直接改用 VM。

**判据表**：

| 维度 | **CT（LXC 容器）** | **VM（QEMU/KVM）** |
|---|---|---|
| **定位** | **快速验证 / 轻量模拟 / 临时短期任务** | **长线任务 / 中重型拓扑模拟 / 要进论文的重要任务** |
| 环境完整度 | **共享宿主内核** ⇒ 内核面、内核参数、可加载模块、部分 LSM/审计路径**与真机不同** | **独立内核 + 完整设备模型** ⇒ 与真机同形 |
| 数据准确性 | 受限于"内核面不可观测"（见 §5.4.1） | **高**（且取数权限对齐后**可复核**，见 §5.3） |
| 环境可靠性 | 受宿主与邻居影响；CT 的 cgroup/网络/存储都与宿主耦合 | **隔离边界清晰** |
| 每实例开销 | **进程级**（本机 8 GB 内存下可行） | **整机级**（本机 8 GB 内存下**很快撞墙**） |
| 起停速度 | 秒级 | 数秒～数十秒（NVMe x1 链路下更慢，见 §1.4） |
| 适用 | 冒烟、参数敏感性、逻辑回归、脚本与夹具 | 全量批次、拓扑规模实验、论文级证据 |

**三条推论（都是硬规则）**：

1. **全量批次在 VM 上跑**，不在 CT 上跑。
2. **两套基质的数据不可混用**：记录里的 `meta.observation_target` 会写出基质类型
   （`node:<vmid> (substrate=pve, hostname=<name>)`），跨基质合并统计**没有意义** ——
   同一场景在两套基质上的基线活跃集、可观测面、甚至 `compromised` 判定都可能不同。
3. **"CT 用起来难受"是一个合法且被鼓励的换基质理由**。这不是"妥协"，而是**把任务放到它能被可靠完成的地方**。

### 5.3 VM 基质（QEMU/KVM）：**v1.1 起已落地，以下是实测形态**

> **v1.0 的这一节写的是"已裁定、待落地"** —— 本节按落地后的实际情况**整节重写**。
> 所有数值都是真机实测（Task 13 / 15 / 16 / 17），不是推算。

**（甲）建机路线（`edge_vm_provision.sh`，唯一入口）**：

```text
Ubuntu cloud image（校验和核对）→ qemu-img convert 成 raw → qm importdisk
→ genisoimage 造 NoCloud seed ISO（**卷标 `cidata`**）→ 挂 CD-ROM（存到 `asscor-vmseed`）
→ qm set（逐条读回配置确认落盘）→ qm start
→ 等 guest agent 报 IP（上限 EDGEEXP_VM_GUEST_AGENT_WAIT_S，默认 **600 s**）
→ 写 /etc/hosts 托管区块（`asc-vm<vmid>`）→ 等 SSH → 客人侧依赖 → **取数权限自检** → 打印指标
```

- **VMID 从 910 起连续分配**；`MIN_VMID=910` 是**写死的硬下限**，`--first-vmid` 改小一律**拒绝执行**
  （避开 CT 904 与 PVE 自用的低位区间）。
- **为什么走 NoCloud ISO 而不是 PVE 原生 cloud-init**（`ciuser`/`sshkeys`+`cicustom`）：
  原生路线要把 `snippets` 加进某存储的 `content` —— 那是一次**宿主存储配置变更**（全局状态）；
  而 `qm set --sshkeys` 是**交互式**的（读 stdin 追加），进脚本必须写成 `cat | qm set` 那种形状，
  那正是**最容易把"追加失败"读成"设置成功"**的地方。代价是 `qm cloudinit dump` 看不到本项目的
  user-data —— **有意的取舍**，脚本自己写自己销毁，唯一真源在脚本里。
- **`--destroy` 是清机的唯一正确姿势**（走别的路会留下半清状态）。护栏：只拆"名字带前缀 + VMID ≥ 910"的。
- ⚠️ **首次冷启动要给足时间**：cloud-init 首启要 apt 装 `qemu-guest-agent`/`apparmor-utils`/`auditd`，
  **实测超过 240 s** ⇒ 写死的 240 s 在冷启动时**必定**超时（已改成环境变量，默认 600 s）。

**（乙）内存账（**这是"能跑几台"的唯一依据**）**：

| 项 | 值（实测/推算） |
|---|---|
| 宿主 `MemTotal` | **7795 MiB**（`free -m`） |
| CT 904 占用 | **1024 MiB**（`pct config 904` 的 `memory: 1024`） |
| PVE 自身 + 页缓存 | ~0.6–1.5 GiB |
| **可分配给 VM 的实际上限** | **≈ 5.5–5.9 GiB** |
| 本批单台 VM | `memory=2048` + `balloon=512` |

⇒ **稳跑 2 台 4 GiB**（余量安全）；**3 台**（6 GiB）已进入"要靠 balloon 与内核回收挤出来"的区间；
**4 台**（8 GiB）**必然**触发宿主 OOM 与换页 —— 而宿主一旦换页，**CT 904 与所有 VM 的测量都会被拖慢**，
"数据准确性"这条前提直接失效。**全量批次只起 1 台 VM**，`available` 全程 ≥ 4.0 GiB。

**为什么用 balloon（动态）而不是固定分配**：`memory=` 是**上限**、`balloon=`（默认 512 MiB）是**下限**，
两边都显式写死（不存在"PVE 默认值随版本漂移"）。靶机在被攻击/装包时要用内存，而**空转时不需要**，
空转恰是 VM 在整轮跑批里占比最大的状态（等 SSH、等 Caldera、等下一场景）。
⚠️ **约束（写死为约束而不是建议）**：balloon 会让**内存相关测量**多一个变量。方向② 现无内存类检查项
⇒ 不进任何因子的读数；**若将来加了内存类检查，必须改固定分配**。

**（丙）取数权限自检（**建机脚本每次都会实测并打印**）**：

```text
   取数权限自检（root 等价）：
      asc
      login-uid=1000
      sudo-uid=0
   ✅ **root 等价成立**（登录用户是 asc，取数走 sudo -n ⇒ uid 0）——
      与 CT 基质的 `pct exec`（天生 root）**等价**，两套基质的 B 可比。
```

**拿不到就 `die`（整轮建机失败）**，绝不把一台"只能以 `asc` 取数"的 VM 交给跑批。
这条不是卫生习惯，而是**测量语义的前提**（见 §5.4.1）：不对齐权限时 80 条检查里 **10 条会翻转**，
而**决定基线活跃集的那两条恰在其中**。**日志里没有这一行就不要往下走**。

**（丁）VM 基质的基线活跃集 `B` = `{EF-NO-IDS}`（**实测，且与 CT 不同**）**：

| 检查 | VM（root 等价取数） | 推出的因子 |
|---|---|---|
| `RS-006`（HIDS/NIDS 部署） | **失败**（`suricata.service=failed`、`aide` 无常驻服务、`ps` 无 IDS 进程） | ⇒ **`EF-NO-IDS` 在链上** |
| `RS-007`（入侵告警配置） | **通过** —— `edge_target_prepare.sh` 把**真实的告警面**写进 `/etc/aide/aide.conf` | ⇒ `EF-NO-SIEM` **不在**链上 |
| `OT-005` / `KS-012` | **通过**（root 等价取数下 AppArmor 真的在 enforcing，`aa-status` rc=0） | ⇒ `EF-SELINUX`/`EF-APPARMOR` **不在**链上 |

⇒ **`B = {EF-NO-IDS}`**（判据：真机记录的 `meta.expected_baseline_factors`）。

> ⚠️ **两个 B 值都是对的，但不可互换**（**这一节最容易读错的地方**）：
>
> | 基质 / 口径 | `B` | 成因 |
> |---|---|---|
> | **CT（LXC，`pct exec` 天生 root）** | `{EF-SELINUX, EF-APPARMOR}` | `OT-005` 在 LXC 里**结构性不可观测**（§5.4.1） |
> | **VM + 非 root 取数（`asc`）** | `{EF-SELINUX, EF-APPARMOR}` | **数值与 CT 相同、成因完全不同** —— 这是**权限伪影** |
> | **VM + root 等价取数（正确口径）** | **`{EF-NO-IDS}`** | 真实状态：AppArmor 真的在 enforcing，而 `prepare` 装齐六个控制 ⇒ `RS-007` 通过 |
>
> **一个中间态（Task 16 的裸 VM 上取的 `{EF-NO-IDS, EF-NO-SIEM}`）也出现过**：那时 `RS-007` 失败，
> 因为那次**没跑 `edge_target_prepare.sh`**。**一次真实跑批会先跑它** ⇒ `RS-007` 通过。
> ⇒ **`B` 必须由实测给出**（S0 基线探针），**不许写死**；而"声明一个不在链上的因子"会被门禁
> **如实拒掉**（不是"放宽一下就过了"）。

**（戊）建机 → 清机的判据（`--destroy` 之后逐条核对）**：

```
qm list                                  → 空（0 台）
pct list                                 → 只有 904 running asc-tgt-c2（**不许动**）
/etc/hosts 的托管区块                     → 0 行残留
local 的 content                          → 与起点**逐项**相同（顺序可能被 PVE 规范化，见 §2.1）
local-lvm 上的 vm-910-disk-0              → 已随 --purge 释放（lvs 只剩 data/root/swap）
asscor-vmseed / 它的目录                  → **刻意保留**（见 §2.1 与审计归档的处置条目）
```

**（己）"这批数据采自哪种基质"的唯一判据**：记录里的 **`meta.observation_target`**，形如
`node:<vmid> (substrate=qemu, hostname=<name>)`。**任何 `substrate=pve`/`substrate=lxd`/裸名字的记录
都 `不是` VM 基质的数据。**

**（庚）落地的提交锚点**：`541c504`（Task 13 接线 + 设计文档 10.4B）→ `5ae2a96`（Task 15：五个真机缺陷）
→ `de34ee0`（Task 16：权限对齐 + 专用 ISO 存储）→ `8ae3c4b`（Task 17：复位接线 + **本批数据的采集提交**）
→ `4c1ab06`（Task 18：链重复的消费侧修复）。
**逐条判据与原始输出**在仓库里体现为：驱动代码（`edge_lab.sh` / `edge_vm_provision.sh` /
`edge_vm_guest.sh` / `edge_target_prepare.sh`）、离线夹具（`test-edge-lab.sh` 的 I 段）、
数据集（`lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl`）。

### 5.4 已知约束与风险（逐条可复核）

| # | 约束 / 风险 | 后果 | 复核命令 |
|---|---|---|---|
| 1 | **内存只有 7.6 GiB（单条 8 GB）** | 中重型 VM 拓扑**必然爆**；CT 拓扑也只能轻量 | `free -h`；`dmidecode -t 17` |
| 2 | **NVMe 链路降级为 x1** | 多台 VM 同时启动慢；顺序带宽约为能力的 1/4 | `cat /sys/class/nvme/nvme0/device/current_link_width` |
| 3 | **管理 VLAN 无网关、与外网不互通** | CT 内 `apt`/`pip`/`go` 装包**必须**经宿主代理或预置镜像 | `ip route`；容器内 `getent hosts example.com` 应失败 |
| 4 | **`vmbr1` 的宿主地址是 DHCP 的** | 宿主的"出口地址"会变 ⇒ 任何写死它的脚本都会在某天失效 | `ip -br a show vmbr1` |
| 5 | **`192.168.30.0/24` 是隔离段** | 不能用它做任何"连到外部服务"的假设 | §3.4 的实测 |
| 6 | **CT 的路由器 ≠ 宿主** | 拼 C2 URL 时必须用 `<pve-host-ip>`；用容器默认网关会拿到 `000` | 容器内 `ip route` 的 `default via` |
| 7 | **测量的读数取决于「在哪读」×「谁在读」** | 不对齐取数权限 ⇒ 80 条检查里 **10 条翻转（双向）**，而**决定基线活跃集的那两条恰在其中**（见下） | 见下 |
| 8 | **残留 agent** | C2 里的历史 agent 会被误判成"本轮已沦陷" | `edge_agent_preflight.sh` 的就绪/归属判据 |
| 9 | **`GOPROXY` 需指镜像** | 默认 `https://proxy.golang.org` 在隔离网段内**拉不动** ⇒ 构建失败 | `go env GOPROXY`；见下 |
| 10 | **"生效二进制 == HEAD 构建"必须显式确认** | 工作区里的 `build/*` 可能是**很久以前**构建的（本机实测：某个跑批工作区的源码 HEAD 恒停在早期提交，历轮只同步了脚本 ⇒ 在那里 `go build` 出来的二进制**不支持 `pve:` 前缀**，会在采集步整轮失败） | `bash lunwen/clab-lab/scripts/edge_prebatch_check.sh`（它会把"HEAD 构建"这件事收成一道门） |
| 11 | **拟合与选模（计划 Task 6 / 本仓 Task 24）不消耗任何基质** | 它只吃**已入库的 JSONL** + `build/edgecompare`（`-fit` / `-candidate`）⇒ **不需要起 VM/CT、不需要 Caldera、不碰网络**；换基质只会换数据，不换工具 | `bash lunwen/clab-lab/data/edgefactors/` 下的产物 + 操作手册 **§5.5** 的复跑命令 |

> **本白皮书不承载的两条论文口径禁令**（取材时**必须**去别处核对，别从这里推）：
> ① "每个因子恰好出现两次"是**这批矩阵上的观测**、不是不变量（design §10.2 的禁令条；
> 实测 33 条里 3 条含 `n_i = 1`）；
> ② **两臂的链读数与分数逐项相同、只差标签** —— 这条 limitation **不许撤**
> （`test-arm-limitation.sh` 守着；它也是 Task 24「四候选在决策层无区分力」的结构性根因，
> 见 design §9.1）。

#### 5.4.1 第 7 条详述：**「−30」是「取数权限 × 基质」耦合出来的伪影**

> **这一节的措辞在 v1.1 被整节改写过**。v1.0 写的是「`OT-005` 在 PVE CT 里不可观测
> ⇒ 那个 −30 是 **LXC 基质的**测量伪影」。**那个说法是错的**（或者说：只对了一半）。
> 下面每一句都有真机实测支撑，三组证据分属三个任务，**不要把它们混成一条**。

**（甲）三组实测，摆在一起才看得见全貌**：

| 组 | 在哪读 / 谁在读 | 读数 | 来源 |
|---|---|---|---|
| ① | **CT 904，`pct exec`（天生 root）** | `aa-status` → `Failed to get profiles: 2`；采集器读到 **0 条** profile ⇒ `OT-005`/`KS-012` **恒失败**（−15 + −15 = **−30**） | Task 9（真机记录） |
| ② | **VM 910，手工 `sudo`（root）** | `aa-status` **rc=0 / 117 profiles / 23 enforce**；自写 AppArmor profile **真的能 enforce** 并拦住受限进程读 `/etc/shadow`（rc=1 + `Permission denied`，而读 `/etc/passwd` rc=0 ⇒ 排除假阳性）⇒ `OT-005`/`KS-012` **都通过** | Task 13（手工探针） |
| ③ | **VM 910，真机采集器**（`-target qemu:910`，**登录用户 `asc`**） | `OT-005`/`KS-012` **都失败**、各 −15 ⇒ **−30 原样复现**，而且 `B` 与 CT **逐项相同** | Task 15（端到端） |

**决定性实验（Task 16）：同一份二进制、同一台 VM，只换「取数用户」**：

```text
$ ssh … asc-vm910 sudo -n env PROBE_NONCE=probe-root /tmp/ascor-probe-edgescen -emit-checks   → 80 条
$ ssh … asc-vm910        env PROBE_NONCE=probe-asc  /tmp/ascor-probe-edgescen -emit-checks   → 80 条

差异条数 = 10 / 总条数 80
  OT-005   asc=False root=True | asc: SELinux和AppArmor均未检测到      | root: AppArmor 已加载策略
  KS-012   asc=False root=True | asc: LSM已加载(…)但无enforcing模块     | root: 活跃LSM: AppArmor(1 profiles)
  KS-010   asc=False root=True | asc: 无法执行dmesg…                     | root: Secure Boot 已启用
  AC-002   asc=True  root=False | asc: skipped — requires root privileges | root: 未发现远程备份配置
  AS-004   asc=True  root=False | asc: iptables 不可用: permission denied  | root: INPUT链默认策略非DROP
  AS-012   asc=True  root=False | asc: skipped — requires root privileges | root: 发现 3 个可疑幽灵账户
  BC-006   asc=True  root=False | asc: skipped — requires root privileges | root: 未发现异地备份配置
  OT-004   asc=True  root=False | asc: npm配置需 root 权限检查             | root: 未检测到pip/npm hash校验配置
  OT-008   asc=True  root=False | asc: skipped — requires root privileges | root: 审计规则仅覆盖 0 个
  OT-020   asc=True  root=False | asc: skipped — requires root privileges | root: auditd仅覆盖 0 个
```

⇒ **两个方向都有**：6 条在 `asc` 下被**跳过并算通过**、4 条（含 `OT-005`/`KS-012`/`KS-010`）
在 `asc` 下**假失败**。**这不是"少算了"的单调偏差，而是双向失真。**

**（乙）口径（**这才是正确的表述**）**：

> **`pct exec`（CT 基质）在容器里天生以 root 执行，而 VM 基质 `ssh` 登录的是 cloud-init 建的 `asc`。**
> ⇒ **那个常量 −30 是「取数权限」与「基质」耦合出来的伪影**：
> 在 CT 上它因"天生 root"而**看不见**（真正的成因是 LXC 的内核面不可观测），
> 在 VM 上它因"默认登录用户非 root"而**原样复现**（成因是权限）。
> **对齐取数权限之后（root 等价）**：`OT-005` 与 `KS-012` **都通过**、**−30 消失**（那一对 `−15 + −15` 不再产生）。

**⇒ 由此产生的硬口径（不是建议）**：

1. **取数必须 root 等价**（`ssh … sudo -n env <nonce> /tmp/asscor-edgescen -emit-checks`）；
2. **拿不到就响亮失败、绝不降级**（`sudo -n` 的 `-n` 让"拿不到权限"**当场失败**，而不是挂在口令提示上
   —— 挂在提示上最糟：ssh 的 `BatchMode` 会把它变成一句语焉不详的 rc=1）；
3. **不许用改判据语义的方式"修"它**（例如让 `internal/checks` 把"跳过"当成通过）——
   那会把测量问题变成判据问题。**已知的口径缺陷（"跳过的检查算通过"）登记在册、不改**（见审计归档）。

**（丙）由此产生的措辞禁令（**两条，都违过**）**：

1. **不得**把"控制项显式拒绝而环境未报出该因子"描述成 **"系统被削弱了 30%"**（或任何等价的减法表述）。
   那是**测量伪影**，不是安全态势的变化；把它当成态势变化，会让论文的核心结论退化成
   **"因为观测不到所以更安全"** —— **方法论错误**。
2. **不得再写"VM 基质上不存在 −30"** —— 那句话把**权限**与**基质**混在了一起，
   而 Task 15 已经实测它在**现行 qemu 基质上原样复现**。
   正确表述是：**「−30 由取数权限产生，在 CT 上被基质形态掩盖」**。

**（丁）Task 13 里仍然成立的部分（**与权限无关**，一个字节都没删）**：

- AppArmor **真能 enforce**（自写 profile 加载进内核表、`aa-status` 可见、`aa-exec … cat /etc/shadow` 被拦 rc=1）；
- 装包**直接 `apt-get install` 就行**（`suricata` / `aide` / 三个 PAM 包全 rc=0），
  CT 上那套"宿主下载闭包 + 送进去 + `dpkg --configure -a`"的绕法在 VM 上**完全不需要**；
- `systemctl` / `auditd` **正常**（`systemctl is-system-running` = `running`；`auditctl -s` → `enabled 1`）；
- SELinux **不可用**（Ubuntu 默认不装）——**与基质无关**，与 CT 处境相同。

**（戊）机器证据（**可复核**）**：

| 证据 | 位置 |
|---|---|
| CT 侧的声明理由（逐字） | `lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl` 的 `meta.expected_baseline_factors_source` |
| VM 侧的实测声明 | `lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl` 的 `meta.expected_baseline_factors` = `['EF-NO-IDS']` |
| 取数权限的**建机期自检** | `edge_vm_provision.sh` 的 `guest_root_equivalence()`（每次建机实测 `login-uid` / `sudo-uid`，打不出那一行就是 NO-GO） |
| 客人侧 argv 恰好 `[-emit-checks]` | `edge_vm_guest.sh` 的传输纪律 + `cmd/edgescen` 的 `rejectEmitChecksArgs`（nonce 若进参数位会被**拒绝**） |

⚠️ **一条必须继承下去的边界**：**`OT-005`/`KS-012` 的 `passed` 值依赖取数权限**
⇒ **同一个场景在两套基质上、或在不同取数权限下的"失败检查条数"不可直接比较**，
而**基线活跃集必须按（基质 × 取数权限）这一对如实声明**。

#### 5.4.2 第 9 条详述：`GOPROXY` 与模块镜像

管理 VLAN **与外网不互通**（§3.4），因此宿主上的 Go 工具链**不能**直连
`proxy.golang.org`。本机实测的 `go env GOPROXY` 仍是**默认值**：

```text
GOPROXY=https://proxy.golang.org,direct
GOSUMDB=sum.golang.org
go1.27.1
```

⇒ **后果**：在宿主上**直接** `go build` 依赖外部 module 的目标会卡在拉取上。
**可行做法**（三者之一）：
① 让宿主的 **`vmbr1`** 出口生效（宿主有默认路由，只有容器没有）；
② 设 `GOPROXY` 指向可达的镜像（如内网/自建 Go module proxy）；
③ **预先在一个能出网的地方 `go mod download`，把 module cache 拷到宿主**
（`GOMODCACHE`），再离线构建。

> **判据**：`go env GOPROXY GOSUMDB GOVERSION`；`go build ./cmd/edgescen`（观察是否卡在拉取）

⚠️ **注意**：`go env` 里改 `GOPROXY` 是**宿主配置变更**，属环境所有者职责。
**本白皮书只记录事实与可行做法，不改动任何环境配置。**

#### 5.4.3 第 10 条详述：跑批前必须确认"生效二进制 == HEAD 构建"

这是**本项目历史上真实踩过、且会造成整轮失败**的坑。具体的危险形态：

- 跑批使用的是一个**固定的工作区目录**，那里的源码 HEAD **很久没动**，
  而历轮只把**脚本**同步进去了 ⇒ 脚本是新的、**二进制是旧的**；
- 表现：`collect` 步整轮失败，报 `target "pve:904" 的基质前缀 "pve" 未知`；
- **为什么"只核 HEAD 的二进制能落三键"不够**：那只证明"HEAD 能行"，
  **不证明"操作者实际跑的那个二进制是 HEAD 构建的"**。

⇒ **判据**：跑批前用 `edge_prebatch_check.sh`（唯一入口），它会在
**一个显式指定的干净 HEAD 检出**里重新构建，并与生效二进制比对。
**"显式指定"是必须的**，因为它的默认路径会陈旧 —— 见技术文档的"跑批前置"与"常见坑"节。

---

## 6. 本文每一条的复核命令（汇总）

```bash
# ---- §1 硬件 ----
lscpu | grep -E 'Model name|Socket|Core|Thread|CPU\(s\)'
free -h
dmidecode -t 1  | grep -E 'Manufacturer|Product|Serial'
dmidecode -t 16 | grep 'Maximum Capacity'
dmidecode -t 17 | grep -E 'Size|Locator'
nvme list
lspci -vv -s <nvme-bdf> | grep -E 'LnkCap|LnkSta'
cat /sys/class/nvme/nvme0/device/current_link_width
lsblk -o NAME,SIZE,TYPE,MODEL,MOUNTPOINT,ROTA
for d in /dev/sd? /dev/nvme0; do echo "== $d"; smartctl -H "$d" | grep 'SMART overall'; done

# ---- §2 存储 ----
cat /etc/pve/storage.cfg
zpool list && zpool status RAID-Mirror
df -hT
pvesm status

# ---- §3 网络 ----
ip -br a
ip route
cat /etc/network/interfaces
ss -lntp
grep -E 'host|port' /opt/caldera/conf/default.yml
grep -c 'api_key' /opt/caldera/conf/default.yml

# ---- §4 基质与 C2 ----
pct list
qm list
ls -d /opt/caldera
git -C /opt/caldera log -1 --format='%h %ad %s' --date=short
ps -eo pid,etime,cmd | grep server.py
pct config 904
pct exec 904 -- ip -br a
bash lunwen/clab-lab/tests/test-edge-lab.sh      # H 段专测 pve 分支、I 段专测 qemu 分支

# ---- §5.3 VM 基质（v1.1 新增；建机/清机走唯一入口，不要手工 qm create/destroy）----
bash lunwen/clab-lab/scripts/edge_vm_provision.sh              # 建机（幂等）
bash lunwen/clab-lab/scripts/edge_vm_provision.sh --dry-run    # 只打印将要做什么
bash lunwen/clab-lab/scripts/edge_vm_provision.sh --destroy    # ⚠️ 清机**必须**用它
qm config 910                                    # 逐条读回配置（qm set 可能只落前几条）
qm guest cmd 910 network-get-interfaces          # 客人 IP（网卡名是 ens18，不是 eth0）
ssh -i /root/.ssh/asc-vm_ed25519 -l asc asc-vm910 'id -un; sudo -n id -u'   # 取数权限自检（期望 1000 / 0）
ssh -i /root/.ssh/asc-vm_ed25519 -l asc asc-vm910 'ip -br a; ip route'      # 客人侧网络（默认网关**不得写死**）
free -m                                          # 内存账（宿主 7795 MiB / CT 904 占 1024 MiB）
grep -A2 'dir: asscor-vmseed' /etc/pve/storage.cfg
pvesm list asscor-vmseed
ssh-keygen -F asc-vm910 -f /root/.ssh/asscor-edge-vm_known_hosts  # 同名重建前查旧 host key

# ---- §5 约束 ----
go env GOPROXY GOSUMDB GOVERSION
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh      # 需先按技术文档 §"跑批前置" 设好 env
```

> **上述命令全部是只读的**，唯一例外是 `edge_prebatch_check.sh`（它会在临时目录里构建，不写仓库）。

---

## 7. 术语表

| 术语 | 含义 |
|---|---|
| **基质**（substrate） | 承载"被攻目标"的虚拟化环境抽象层：`docker` / `lxd` / `clab` / `pve`（CT）/ **`qemu`（VM，v1.1 起已落地）** |
| **CT** | PVE 里的 LXC 容器（`pct` 管理）。**`pct exec` 天生以 root 执行** |
| **VM** | PVE 里的 QEMU/KVM 虚拟机（`qm` 管理）。取数经 `ssh` + 客人侧 `sudo -n` ⇒ **root 等价** |
| **C2** | 命令与控制服务端（本项目用 Caldera） |
| **TTP** | 战术/技术与过程；在本项目里指"链上的一条具体能力执行" |
| **link** | 边缘因子链条目（`edge_factor_chain` 的元素） |
| **基线活跃集** | 在**当前基质 × 当前取数权限**下事实活跃的边缘因子集合（**按实况如实声明**，**不许写死**） |
| **声明面** | 基线活跃集 ∪ 注入集（协作闭包：与已声明因子**共用触发检查**的因子也要纳入） |
| **取数权限等价**（root 等价） | "读的人"与 `pct exec` 同为 uid 0。**拿不到就响亮失败、绝不降级** |
| **臂**（arm） | targeted 场景的两种策略状态：`POLICY_ON=0`（策略**不在**）与 `=1`（策略**在**） |
| **重复轴** | 同一实例号在不同 `EDGEEXP_RUN_INDEX` 下的多次运行（用于检验可重复性） |
| **三道门禁** | 门禁⓪（重复因子，只报不拦）、门禁①（离线重算对比）、门禁②（往返 round-trip）；另有记录条数与因子集相等断言 |

---

## 附录 A：本白皮书**刻意不写**的内容（及原因）

| 不写 | 原因 |
|---|---|
| 带外管理控制器的地址/主机名 | 硬边界（§5.1）；且它**从未**进过本仓库 |
| C2 的明文 API 口令 | 真凭据（§4.5） |
| 各磁盘/整机的序列号 | 设备指纹，无技术必要性 |
| MAC 地址 | 同上（且从容器/客机视角每次重建都可能变） |
| 管理 VLAN 内的具体地址（除网关与宿主） | 无技术必要性（§3.6） |

> **v1.1 删掉的一行**：v1.0 的这张表里有「VM 基质的实测性能值 —— **尚未落地**，写了就是编造（§5.3）」。
> VM 基质已经落地，实测值在 §5.3 里 —— 那一条**不再成立**，故删除。
