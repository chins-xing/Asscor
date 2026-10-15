# ASSCOR 实验环境白皮书：PVE 单机实验基质

> **文档性质**：可交付的**环境画像**。目的是让**没有参与过本项目**的读者，
> 仅凭本文 + 仓库内可跟踪的脚本，就能判断"这套实验是在什么机器上、以什么口径跑出来的"，
> 以及"这套环境够不够格承载我的实验"。
>
> **文档版本**：v1.0（2026-10-15）
> **取证方式**：**全部条目均在实机上只读取证**，文末给出**每一条的复核命令**。
> 凡本文未实测的，一律标注「未实测」而**不填猜测值**。
> **基线提交**：`ASSCOR-Research-Core` @ `5eaedec`。

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
```

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

---

## 4. 基质与 C2

### 4.1 基质（substrate）是什么

本项目的实验把"被攻目标"抽象成一层**基质**：同一套管线（复位 → 攻击 → 采集 → 门禁 → 离线重算）
可以跑在**不同的虚拟化环境**上，由 `EDGEEXP_SUBSTRATE` 选择。

已实现的基质驱动：

| 基质名 | 后端 | 观测原语 | 入口 |
|---|---|---|---|
| `docker` | Containerlab 容器 | `docker exec` | 开发机（WSL2） |
| `lxd` | LXD 实例 | `lxc exec` / `lxc file push` | 远程 A-1 服务器 |
| `clab` | Containerlab 拓扑 | `docker exec`（拓扑级） | 开发机 |
| **`pve`** | **PVE CT（LXC 容器）** | **`pct exec` / `pct push`** | **本文档描述的这台机** |

**`pve` 驱动的四条硬行为**（都是踩坑后的判据，逐条有夹具钉住）：

1. **只认解析后的 VMID**：`asc-tgt-c2` ⇒ `pve:904`。名字**一个字节都不会**进参数位。
2. **`pct push` 的参数顺序与 `lxc file push` 相反**：
   `pct push <vmid> <本地> <目标> --perms 755`。
3. **绝不静默回落**：`pve` 路径上**只**起 `pct`；`docker`/`lxc`/`clab` 一次都不调用。
4. **`lab_up`/`lab_down` 在 `pve` 下响亮失败**（`rc=2` + 说明原因）——
   拓扑生命周期属于"谁建的谁管"，管线不得偷偷建/删 CT。

> **判据**：`bash lunwen/clab-lab/tests/test-edge-lab.sh`（H 段 25 格专测 `pve` 分支）；
> 驱动实现在 `lunwen/clab-lab/scripts/edge_lab.sh`。

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
| `lunwen/clab-lab/scripts/edge_target_prepare.sh` | **靶机侧**的幂等准备（装包、装 agent、声明基线、C2 自证） |
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

> **判据**：`grep -c 'api_key' /opt/caldera/conf/default.yml`（应得 2 条，值为 `$argon2id$…`）

---

## 5. 基质的定位与选择判据（**本白皮书的结论**）

### 5.1 两条硬边界（不可协商）

| 边界 | 内容 | 理由 |
|---|---|---|
| **带外管理控制器** | **绝对不许访问**：不登录、不探测、不扫描、不改配置、不重启 | 它是这台机器的"最后一条远程生命线"。实验**永远不需要**它，而任何误操作都可能让机器失联 |
| **上游交换机** | **不直连**：需要交换机侧信息时由环境所有者导出后提供 | 交换机是共享网络设备，它的配置变更会同时影响**别的使用者** |

### 5.2 基质分工原则（**2026-10-15 裁定**）

> **原话要点**：「CT 的作用本来就是快速验证和轻量模拟，应该作为临时短期任务的选择。
> 长线和中重型拓扑模拟和重要任务本来就应该交给拥有完整环境的 VM 来保证数据的准确性和环境和可靠性。」
> 以及此前：「如果 CT 用起来难受或者受限太多直接用 VM，不然我为啥会选择 PVE 作为系统。」

**判据表**：

| 维度 | **CT（LXC 容器）** | **VM（QEMU/KVM）** |
|---|---|---|
| **定位** | **快速验证 / 轻量模拟 / 临时短期任务** | **长线任务 / 中重型拓扑模拟 / 要进论文的重要任务** |
| 环境完整度 | **共享宿主内核** ⇒ 内核面、内核参数、可加载模块、部分 LSM/审计路径**与真机不同** | **独立内核 + 完整设备模型** ⇒ 与真机同形 |
| 数据准确性 | 受限于"内核面不可观测"（见 §5.3） | **高** |
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

### 5.3 VM 基质的现状（**已裁定、待落地**）

> **本文不填任何 VM 基质的实测值** —— 本文写作时**VM 基质尚未落地**。

已确定的事实（可复核）：

| 项 | 现状 | 判据 |
|---|---|---|
| 已运行客机 | **只有 1 台 CT**：VMID **904**、名称 `asc-tgt-c2`、`status=running` | `pct list` |
| VM 数量 | **0** | `qm list`（空） |
| VM 存储 | `RAID-Mirror`（`images`）与 `NVMe-256G`（`images`）**都已支持 VM 磁盘** | `cat /etc/pve/storage.cfg` |
| 驱动实现 | `cmd/edgescen` 的基质前缀目前只认 `docker:` / `lxd:` / `pve:<vmid>`；**`qemu`/`vm` 前缀尚未实现** | `grep -rn 'pve:' cmd/edgescen/*.go` |
| 落地任务 | 已单独立项（"Task 13：VM 生产基质"），范围：SSH 取数、基线随基质重声明、provisioning 按多机设计 | 仓库内任务目录 |

⇒ **对本文读者的意思**：§5.2 的表是**已经生效的选择判据**，
但"VM 基质的实测性能与口径"**要等 Task 13 落地后另行发布**，届时本节应被替换为实测版。

### 5.4 已知约束与风险（逐条可复核）

| # | 约束 / 风险 | 后果 | 复核命令 |
|---|---|---|---|
| 1 | **内存只有 7.6 GiB（单条 8 GB）** | 中重型 VM 拓扑**必然爆**；CT 拓扑也只能轻量 | `free -h`；`dmidecode -t 17` |
| 2 | **NVMe 链路降级为 x1** | 多台 VM 同时启动慢；顺序带宽约为能力的 1/4 | `cat /sys/class/nvme/nvme0/device/current_link_width` |
| 3 | **管理 VLAN 无网关、与外网不互通** | CT 内 `apt`/`pip`/`go` 装包**必须**经宿主代理或预置镜像 | `ip route`；容器内 `getent hosts example.com` 应失败 |
| 4 | **`vmbr1` 的宿主地址是 DHCP 的** | 宿主的"出口地址"会变 ⇒ 任何写死它的脚本都会在某天失效 | `ip -br a show vmbr1` |
| 5 | **`192.168.30.0/24` 是隔离段** | 不能用它做任何"连到外部服务"的假设 | §3.4 的实测 |
| 6 | **CT 的路由器 ≠ 宿主** | 拼 C2 URL 时必须用 `<pve-host-ip>`；用容器默认网关会拿到 `000` | 容器内 `ip route` 的 `default via` |
| 7 | **`OT-005` 在 PVE CT 里不可观测** | 基线活跃集在本基质上**只能是** `{EF-SELINUX, EF-APPARMOR}`（见下） | 见下 |
| 8 | **残留 agent** | C2 里的历史 agent 会被误判成"本轮已沦陷" | `edge_agent_preflight.sh` 的就绪/归属判据 |
| 9 | **`GOPROXY` 需指镜像** | 默认 `https://proxy.golang.org` 在隔离网段内**拉不动** ⇒ 构建失败 | `go env GOPROXY`；见下 |
| 10 | **"生效二进制 == HEAD 构建"必须显式确认** | 工作区里的 `build/*` 可能是**很久以前**构建的（本机实测：某个跑批工作区的源码 HEAD 恒停在早期提交，历轮只同步了脚本 ⇒ 在那里 `go build` 出来的二进制**不支持 `pve:` 前缀**，会在采集步整轮失败） | `bash lunwen/clab-lab/scripts/edge_prebatch_check.sh`（它会把"HEAD 构建"这件事收成一道门） |

#### 5.4.1 第 7 条详述：`OT-005` 不可观测 ⇒ 基线活跃集与「−30」伪影

**实测事实**：PVE CT 是 LXC 容器，**共享宿主内核**且使用**缩减的 `/proc` 视图**。
在本机实测到的具体现象：

- 容器内 `aa-status` 报 `Failed to get profiles: 2` ⇒ **AppArmor profile 视图不可用**，
  采集器读到 **0 条**；
- 靶机 CT 的 `pct config` 里既有
  `lxc.apparmor.raw: audit deny /etc/shadow r,`（**为实验刻意加的一条 LSM 拒止规则**），
  而这类 LXC 级规则**不**出现在容器内的 profile 列表里。

**后果**：`OT-005`（以及同类"内核面"检查项）在 CT 基质上**恒为不可观测**。

**由此产生的口径（既有裁定）**：**基线活跃集必须按基质如实声明**，
即在本基质上声明 `EDGEEXP_BASELINE_FACTORS={EF-SELINUX, EF-APPARMOR}`。
**"本来就没测到"不是"不存在"** —— 声明面的语义是"这套环境上事实活跃的因子"，
不是"理论上应该活跃的因子"。

**由此产生的措辞禁令**：**不得**把"控制项显式拒绝而环境未报出该因子"描述成
**"系统被削弱了 30%"**（或任何等价的减法表述）。
那是一个**测量伪影**（观测面缺失），**不是**一个安全态势的变化。
把它当成态势变化，会让论文的核心结论变成"因为观测不到所以更安全"——
那是**方法论错误**。

**机器证据**：`lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl` 里
`meta.expected_baseline_factors_source` 字段逐字记录了这条理由。

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
  **不证明"你现在跑的那个二进制是 HEAD 构建的"**。

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
bash lunwen/clab-lab/tests/test-edge-lab.sh      # H 段专测 pve 分支

# ---- §5 约束 ----
go env GOPROXY GOSUMDB GOVERSION
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh      # 需先按技术文档 §"跑批前置" 设好 env
```

> **上述命令全部是只读的**，唯一例外是 `edge_prebatch_check.sh`（它会在临时目录里构建，不写仓库）。

---

## 7. 术语表

| 术语 | 含义 |
|---|---|
| **基质**（substrate） | 承载"被攻目标"的虚拟化环境抽象层（`docker` / `lxd` / `clab` / `pve`；规划中 `qemu`） |
| **CT** | PVE 里的 LXC 容器（`pct` 管理） |
| **VM** | PVE 里的 QEMU/KVM 虚拟机（`qm` 管理） |
| **C2** | 命令与控制服务端（本项目用 Caldera） |
| **TTP** | 战术/技术与过程；在本项目里指"链上的一条具体能力执行" |
| **link** | 边缘因子链条目（`edge_factor_chain` 的元素） |
| **基线活跃集** | 在**当前基质**上事实活跃的边缘因子集合（**按基质如实声明**） |
| **声明面** | 基线活跃集 ∪ 注入因子 |
| **臂**（arm） | targeted 场景的两种策略状态：`POLICY_ON=0`（策略在）与 `=1`（策略在且生效） |
| **重复轴** | 同一实例号在不同 `EDGEEXP_RUN_INDEX` 下的多次运行（用于检验可重复性） |
| **三道门禁** | gate1（离线重算对比）、gate2（往返 round-trip）、gate3/记录条数与集合一致性 |

---

## 附录 A：本白皮书**刻意不写**的内容（及原因）

| 不写 | 原因 |
|---|---|
| 带外管理控制器的地址/主机名 | 硬边界（§5.1）；且它**从未**进过本仓库 |
| C2 的明文 API 口令 | 真凭据（§4.5） |
| 各磁盘/整机的序列号 | 设备指纹，无技术必要性 |
| MAC 地址 | 同上（且从容器/客机视角每次重建都可能变） |
| VM 基质的实测性能值 | **尚未落地**，写了就是编造（§5.3） |
| 管理 VLAN 内的具体地址（除网关与宿主） | 无技术必要性（§3.6） |
