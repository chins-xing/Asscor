# ASSCOR 边缘因子实验：技术文档与操作手册

> **面向读者**：**下一个人**。读完这一份 + 环境白皮书，你应该能在这台机器上
> **自己跑一遍**边缘因子实验，并**正确读出**记录里的每一个字段。
>
> **版本**：**v1.1（2026-10-16）** ｜ **基线提交**：`ASSCOR-Research-Core` @ `4c1ab06`
> （本批 VM 数据的**采集提交**是 `8ae3c4b`；消费侧修复是 `4c1ab06`）
> **配套文档**：环境画像见《PVE 单机实验基质白皮书》；裁定依据见《边缘因子实验审计归档》。
>
> **v1.1 新增/改写**：§2.1（`qemu` 基质的语法与陷阱）、§2.2（VM 前置变量）、
> **§2.5（从零到一条 VM 记录的完整命令序列）**、§4.6（**这份数据集怎么读**）、
> §5.3（基线活跃集：**基质 × 取数权限**）、§6.12–§6.18（**七个真机实测的坑**）、§8（环境变量全表）。
>
> **脱敏口径**：本文不含内部实验环境的可寻址标识；占位符表见白皮书 §0。
> 本文出现的 `<pve-host-ip>` / `<mgmt-gw>` / `<ilo-host>` / `<c2-key>` 均按同一口径替换。

---

## 目录

1. [30 秒速览](#1-30-秒速览)
2. [怎么跑：环境变量与跑批前置](#2-怎么跑环境变量与跑批前置)
3. [矩阵的实例模型（三个维度）](#3-矩阵的实例模型三个维度)
4. [怎么读记录](#4-怎么读记录)
5. [三道门禁与"基线活跃集"口径](#5-三道门禁与基线活跃集口径)
   （含 **5.5 拟合与选模怎么复跑**，Task 24）
6. [常见坑（**逐条都是实测踩出来的**）](#6-常见坑逐条都是实测踩出来的)
7. [已知问题与未修清单](#7-已知问题与未修清单)
8. [附录：环境变量全表](#8-附录环境变量全表)

> **只想跑一遍的人**：直接跳 **§2.5「从零到一条 VM 记录」** —— 那是一段可以在宿主上照抄执行的
> 完整序列（含建机、前置门禁、**实测 `B`**、跑一条 targeted 实例、清机）。

---

## 1. 30 秒速览

```bash
# 0) 在你的跑批工作区里，先把"生效二进制 == HEAD 构建"这件事做掉
#    （**必须先显式设** EDGEEXP_HEAD_CHECKOUT，见 §2.3）
export EDGEEXP_HEAD_CHECKOUT=<一个真的等于 HEAD 的干净检出>
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh --install

# 1) 跑批前置：任何一项不满足就 NO-GO，不要绕过
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh          # 期望：rc=0（GO）

# 2) 跑
set -a; . ./edgeexp-env.sh; set +a        # 你的 env 文件（见 §2.2）
bash lunwen/clab-lab/scripts/edge_matrix.sh S1-apparmor     # 单场景
bash lunwen/clab-lab/scripts/edge_matrix.sh                  # 全量 25 场景
```

**管线**：每个场景固定三步，**顺序即依赖，任一失败即整轮失败，绝不"跳过继续"**：

```text
edge_reset.sh   →  干净环境（复位目标 CT + 确认 C2 + 就绪 agent）
edge_attack.sh  →  相位推进 + 固定剧本 + 客观结果（harness 产物）
edge_collect.sh →  用**同一份采集配置**采集一条记录（候选差异交给离线比较）
```

**产物落点**：`$EDGEEXP_DATA_DIR`（默认 `<仓库>/lunwen/clab-lab/data/edgefactors/`）

```text
run.json                      本次运行汇总（拓扑/剧本/配置哈希、权重口径、逐实例耗时、
                              门禁⓪ 重复因子计数、注入-采集时钟核对、记录条数、因子集相等断言…）
run-<run-id>.json             同一份内容的不可变副本（历史留档）
run.d/{reset,attack,collect,gate}-*.json   逐实例碎片
run.d/rejected-<实例>.jsonl   被断言拒掉、已从数据集回滚的记录（留档）
records-<env>-<date>.jsonl    记录本体
```

---

## 2. 怎么跑：环境变量与跑批前置

### 2.1 第一件必须搞清的事：**你跑在哪种基质上**

```bash
export EDGEEXP_SUBSTRATE=pve      # docker | lxd | clab | pve | qemu
```

| 取值 | 含义 | 目标节点名（`EDGEEXP_TARGET`）的形式 |
|---|---|---|
| `clab`（默认） | Containerlab 拓扑 | `asc-asscor-host1` |
| `docker` | 单容器 | 容器名 |
| `lxd` | LXD 实例 | `probe-ot005` |
| **`pve`** | **PVE CT** | **CT 的名字**，如 `asc-tgt-c2`（脚本会解析成 `pve:904`） |
| **`qemu`** | **PVE VM（QEMU/KVM）** | **VM 的 hostname**，如 `asc-vm910`（**不是** vmid —— Caldera 的 `host` 字段就是 hostname） |

> **为什么必须显式给**：`edge_prebatch_check.sh` 会在**不转发**基质时退回默认的 `clab`（docker），
> 于是它去问一个**不存在的容器**，把"看错了地方"报成 **"目标上没有活着的 agent"**。
> 这条已写进前置入口的注释，并作为硬要求执行。

**基质决定 `edgescen -target` 的语法**（唯一解析点：`edge_lab.sh` 的 `lab_target_spec`）：

```text
-target docker:<容器>   -target lxd:<实例>   -target pve:<vmid>   -target qemu:<vmid|名字>
```

> ⚠️ **`qemu` 与 `pve` 在"名字"这一格上刻意不同**：`pct` 只认**数字 vmid**（`pct` 的名字要在基质层
> 解析成 vmid），而 `-target qemu:` **既收 vmid 也收名字** —— 数字按默认规则推 `asc-vm<vmid>`，
> 非数字则**原样当主机名**，且**不去猜它对应哪个 vmid**（猜错就是"采到另一台机器的数据、
> 而记录里的节点名照常"）。
>
> ⚠️ **但 `qm` 的子命令只认数字**：`qm status asc-vm910` → `vmid: type check ('integer') failed`（rc=255），
> `qm status 910` → `status: running`。基质层里"名字 → vmid"的解析因此收在**唯一一处**
> `lab_qemu_vmid`（`qm list` 的名字在**第 2 格**，与 `pct list` 的**最后一格相反**）。

### 2.2 一份可以照抄的 env 文件（**脱敏版**）

> ⚠️ **适用范围**：这一份是 **`pve`（PVE CT）快速验证**用的 —— `EDGEEXP_SUBSTRATE=pve`，且
> `EDGEEXP_TARGET` 是**靶机 CT 的名字**（例 `asc-tgt-c2`）。**VM 批次不能照抄这一份**：
> 现行生产基质是 `qemu`，`EDGEEXP_TARGET` 要写成 **VM 的 hostname**（例 `asc-vm910`），取数是
> `EDGEEXP_VM_SSH_SUDO='sudo -n'` 的 **root 等价**，并需补上本节下半段那几格 VM 专用变量
> （`EDGEEXP_VM_SSH_KEY` / `EDGEEXP_VM_SSH_USER` / `EDGEEXP_VM_GUEST_IFACE` 等）。**VM 批次的完整序列见 §2.5。**
> 基质抄错的症状不是报错，而是前置门禁以"目标上没有活着的 agent"把整轮拒掉（见 §2.1 的注）。

```bash
# ---- 基质与标识 ----
export EDGEEXP_SUBSTRATE=pve
export EDGEEXP_ENV=<lab-tag>                     # 进记录文件名与 meta.env；REPEAT>1 时**必须**显式给
export EDGEEXP_DATA_DIR=<仓库>/lunwen/clab-lab/data/edgefactors
export EDGEEXP_TARGET=<靶机 CT 的名字>            # 例：asc-tgt-c2

# ---- C2 ----
export EDGEEXP_CALDERA_URL=http://<pve-host-ip>:8888   # **必须**是宿主地址，不是容器默认网关
export EDGEEXP_CALDERA_KEY=<c2-key>              # **绝不写进仓库**；由未跟踪的本地配置提供

# ---- TTP 三件实体（targeted_ttp 口径必需）----
export EDGEEXP_TTP_TARGET_ABILITY=a5c0ffee-0000-4000-8000-0000000003b1
export EDGEEXP_TTP_TARGET_ABILITY_NAME='T4D Step 3B: read /etc/shadow (AppArmor target TTP)'
export EDGEEXP_TTP_CONTROL_ABILITY=a5c0ffee-0000-4000-8000-0000000003c1
export EDGEEXP_TTP_PLAYBOOK_ID=a5c0ffee-0000-4000-8000-0000000003c2
export EDGEEXP_TTP_PLAYBOOK_NAME='T4D Step 3B pair (control + target TTP)'

# ---- 配置与二进制 ----
export EDGEEXP_CONFIG=<仓库>/configs/edgeexp/m0-baseline.ini
export EDGEEXP_EDGESCEN=<仓库>/build/edgescen
export EDGEEXP_TOPOLOGY=<仓库>/lunwen/clab-lab/asscor.clab.yml

# ---- 跑批前置 ----
export EDGEEXP_HEAD_CHECKOUT=<一个真的等于 HEAD 的干净检出>    # **没有默认值**，必须显式给（见 §2.3.1）
export EDGEEXP_CALDERA_KEY=<c2-key>              # 前置入口会读它；**没有默认值**，缺了必须 GO 失败
#   （也可以把 KEY 与 URL 一起写进未跟踪的本地配置 ~/.config/asscor/edgeexp.local.env；
#     文件名已在根 .gitignore 里。唯一取值点见 lunwen/clab-lab/scripts/edge_c2_key.sh）

# ---- 三个维度：臂 / 重复 ----
export EDGEEXP_POLICY_ON_ARM=1    # 1 = 每个 targeted 场景两条臂（默认）；0 = 与旧行为逐字节相同
export EDGEEXP_RUN_INDEX=1        # 重复号（repetition）；>1 时才进记录的 meta.repeat
```

**`qemu` 基质额外要设的几格**（**没有它们跑不起来**；逐格的默认值与守卫见 §8.1）：

```bash
# ---- VM 基质的取数前置（Task 16 起）----
export EDGEEXP_VM_SSH_KEY=/root/.ssh/asc-vm_ed25519     # 私钥**路径**（内容进不了 argv/记录/仓库）
export EDGEEXP_VM_SSH_USER=asc                          # 客人里的登录用户（cloud-init 建的）
export EDGEEXP_VM_KNOWN_HOSTS=/root/.ssh/asscor-edge-vm_known_hosts   # 专用 known_hosts（见 §6.16）
export EDGEEXP_VM_SSH_SUDO='sudo -n'                    # **取数必须 root 等价**；拿不到就响亮失败、绝不降级
#   ⚠️ 这一格是**拼进客人侧 shell 的命令**（会被拆成格）⇒ **不要**用 printf '%q' 那种带反斜杠的写法，
#      也**不要**给它加引号内容。含空白/分号/反引号/$ 一律**响亮失败**（不做"清洗后继续"）。
export EDGEEXP_VM_GUEST_IFACE=ens18                     # 客人网卡实名（**不是 eth0**）；见 §6.13
# export EDGEEXP_VM_SSH_HOST='asc-vm%s'                 # 默认按 vmid 推 asc-vm<vmid>；含 %s 时按节点标识展开（多机靠这条）

# ---- 跑批身份（VM 批次用过的取值，逐条可核）----
export EDGEEXP_TARGET=asc-vm910                         # = VM 的 hostname（Caldera 的 host 字段）
export EDGEEXP_ENV=<lab-tag>-qemu
export EDGEEXP_TTP_GROUP=<本机独占的投送组>              # ★ **必须本机独占**，见 §6.17
```

### 2.3 跑批前置（**唯一入口，不许绕过**）

```bash
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh [--install] [--strict-agents]
```

**为什么要有这个入口**：全量扫描是 **36 个场景实例 × 3 个重复 ≈ 13 小时**（**本批实际放的是
22 场景 / 33 实例**，差 R 组那 3 个 —— 理由见 §3.1）。
历史上"开局就错"的**三次都发生在跑批之前的最后三十秒里**：

| 事故 | 形态 | 代价 |
|---|---|---|
| 缺 `build/edgecompare` | 门禁①/② **静默 skipped**，报告照常打印 | 整轮数据作废（事后才发现） |
| 跑批工作区源码陈旧 | 采集器**不认识 `pve:` 前缀**，第 1 个场景就整轮失败 | 13 小时白等 |
| 残留 agent | operation 打到**已经死掉**的那只 agent | 整轮产物被污染 |

**四项前置判据**：

| # | 项 | 判据 |
|---|---|---|
| 1 | **生效的二进制 == HEAD 构建** | 从**干净 HEAD 检出**用 `-trimpath -tags` 构建 `edgescen`/`edgecompare` 到临时目录，与跑批工作区里那两个**比 sha256** |
| 2 | **残留 agent 复核** | 转调 `edge_agent_preflight.sh`：`host` + `trusted` + `pid ∈ 容器内当前活 sandcat` + `last_seen ≤ EDGEEXP_AGENT_FRESH_S`（默认 180）。`rc=1`（无活 agent）⇒ **NO-GO**；`rc=10`（有残留）⇒ 响亮警告（`--strict-agents` 时升级为 NO-GO） |
| 3 | **TTP 三件实体** | 转调 `edge_ttp_provision.sh`（幂等：已存在则**核对关键字段**，不一致**响亮失败**）。`rc≠0` ⇒ NO-GO |
| 4 | **门禁①/② 的前提** | `build/edgecompare` **在位且可执行**（第 1 项比过 sha256，这里单独确认执行位与位置） |

**退出码**：`0` = GO（可以开跑）；非零 = **NO-GO**（哪一项没满足就修哪一项，**别绕过**）。

#### 2.3.1 `EDGEEXP_HEAD_CHECKOUT` 必须显式设置（**没有默认值了**）

> **来源**：Task 12 把这条登记为"本项目最容易中的一枪"（当年只能靠"跑批前显式设该变量"绕过）；
> **Task 14（`6e11fa0`）已把根因修掉**，本节按**修好之后**的实际行为重写。

`edge_prebatch_check.sh` 里这个变量**没有默认值**：缺省 ⇒ 该项直接判红并给出示例路径。
必须显式设的理由不是"默认值陈旧"，而是"**只有跑批的人知道这一次该用哪份检出**"。

```bash
export EDGEEXP_HEAD_CHECKOUT=/root/t6/t14/head     # 例：本次跑批要用的那份干净检出
```

**判据（Task 14 之后）**，三条走的是**同一套** git 命令，与 `.git` 是文件还是目录**无关**：

```bash
git -C "$EDGEEXP_HEAD_CHECKOUT" rev-parse --git-dir     # 必须是 git 仓库（**worktree 也算**）
git -C "$EDGEEXP_HEAD_CHECKOUT" rev-parse HEAD          # 必须 == 你要跑的 HEAD
git -C "$EDGEEXP_HEAD_CHECKOUT" status --porcelain      # 必须为空（脏 ⇒ 直接判红）
```

**为什么当年会误报**：旧判据是 `[ -d "$HEADCO/.git" ]`，而 **git worktree 的 `.git` 是一个
46~50 字节的文本文件**（内容 `gitdir: …/.git/worktrees/<名>`）⇒ 对一份**完全正常**的检出判
"不是 git 仓库"（控制侧 2026-10-15 实测 rc=1；且当时 rc 是从管道里读的 ⇒ 更不可信）。
复现与对照的**原始输出**见 Task 14 报告 §Step 2。前置入口现在还会多打一行**检出形态**
（`**git worktree**` / 主检出），让这一类问题一眼可见。

> **口径**：前置入口**同时**要求检出干净且等于 HEAD。**"脏检出"会被直接判红而不是静默放行**，
> 因为脏检出构出的二进制里盖着 `…+dirty` 的 `vcs.revision`，此时**"比 sha256"比的是一个没人能复现的东西**。

### 2.4 干跑（dry run）与真跑

```bash
export EDGEEXP_DRY_RUN=1     # 只打印将要做什么，不执行
```

**干跑能抓到什么**：参数缺失、门禁配置缺项、矩阵分类错误、环境变量拼写。
**干跑抓不到什么**（**实测教训**）：

- **缺 `…_PLAYBOOK_NAME` 时 25 个场景干跑照样 `rc=0`** —— 剧本名默认值存在，
  干跑看不出它会漂移；**真跑会在攻击步被拒**。故矩阵层把剧本名与
  `TARGET_ABILITY`/`PLAYBOOK_ID` 放在**同一处**加了显式门禁。
- **"干跑绿 ≠ 能跑"**：干跑不碰 C2、不碰网络、不碰二进制。

---

## 2.5 从零到一条 VM 记录（`qemu` 基质，**完整命令序列**）

> **这一段是 Task 17 的真机序列，对着当前代码核过**。以下命令**都在宿主**上执行，
> 工作区 = 一份**等于 HEAD 的干净检出**（本文用 `/root/t6/t17-head`，本批数据的采集提交 `8ae3c4b`）。
> **所有 `rc` 一律直接取 `$?`，不许用管道**（§6.6）。

### 步骤 0：把代码送上宿主（三种手法，任选一种）

```bash
# (a) git bundle：自包含、**逐字节同 SHA**（Task 15 用过；80 MB）
git bundle create /tmp/arc.bundle ASSCOR-Research-Core     # 本机
scp -C /tmp/arc.bundle root@<pve-host>:/root/t6/           # 传输
ssh root@<pve-host> 'cd /root/t6 && rm -rf t19-head && git clone -q --branch ASSCOR-Research-Core arc.bundle t19-head'

# (b) git format-patch + git am：多轮迭代时更省（补丁合计 ~120 KB）
#   本机： git format-patch <起点>..HEAD -o build/t19 --no-signature
#   宿主： git clone -q /root/t6/<上一轮检出> /root/t6/t19-head
#          cd /root/t6/t19-head
#          git config user.name '<你的名字>'; git config user.email '<你的邮箱>'
#          git am --committer-date-is-author-date /root/t6/t19-patches/000{1..N}.patch
#          git rev-parse HEAD     # 必须**逐字等于**本地 HEAD
```

> ⚠️ **`git am` 的两个前置（实测踩到）**：不带 `--committer-date-is-author-date` 与仓库级
> `user.name`/`user.email` 时，`git am` 会把 **committer** 写成 `root <root@pve.…>`、时间取当下
> ⇒ **SHA 与本地不同**（实测 `ad5c8f0` vs 本地 `5f24718`）＝ **"宿主检出 = 本地 HEAD"这句话不成立**。
> `git bundle` 没有这个问题（对象是搬过去的，不是重建的）。

### 步骤 1：建 VM（**幂等；建机/清机只有一个入口**）

```bash
cd /root/t6/t19-head
bash lunwen/clab-lab/scripts/edge_vm_provision.sh
echo "PROVISION_RC=$?"        # 期望 0
```

**必须在这段日志里看到的三样东西**（没有就不要往下走）：

```text
内存账：宿主 MemTotal=7795 MiB；本批 1 台 × 2048 MiB = 2048 MiB（balloon 下限 512 MiB/台）
   客人 IP：192.168.1.3（ens18@vmbr1；期望网卡名 ens18,eth0）
   取数权限自检（root 等价）：asc / login-uid=1000 / sudo-uid=0
   ✅ **root 等价成立**（登录用户是 asc，取数走 sudo -n ⇒ uid 0）—— 与 CT 基质的 `pct exec` 等价
```

- **冷启动要给足时间**：客人首启要 apt 装 `qemu-guest-agent`/`apparmor-utils`/`auditd`，
  **实测超过 240 s** ⇒ `EDGEEXP_VM_GUEST_AGENT_WAIT_S` 默认 **600 s**。
- ⚠️ **同名重建（销毁后又用同一个 vmid/名字建）必须先清 host key**，且**清 IP 不只是清名字**
  （`wait_ssh` 那一刻是按 **IP** 连的）—— 见 §6.16。

### 步骤 2：构建二进制（**从 HEAD 检出构建**）

```bash
export GOPROXY=https://goproxy.cn,direct
go build -tags expr,engine,checks -trimpath -o build/edgescen    ./cmd/edgescen    ; echo "rc=$?"
go build -tags edgeexp            -trimpath -o build/edgecompare ./cmd/edgecompare ; echo "rc=$?"
go version -m build/edgescen | head -4      # 应看到 vcs.revision == 当前 HEAD
```

### 步骤 3：跑批环境（**未跟踪**；可变的两格写进本地 env）

```bash
source /root/.config/asscor/edgeexp.local.env   # C2 的 KEY/URL + VM 的 SSH 几格（**不进仓库**）
source /root/t6/t19-env.sh                      # 跑批身份：SUBSTRATE/TARGET/ENV/DATA_DIR/RECORDS/
                                                # HEAD_CHECKOUT/TTP 五件/投送组/BASELINE_FACTORS…
```

> ⚠️ **投送组必须本机独占**（宿主上还有 CT 904 的遗留 agent，同组会让标签串味）——见 §6.17。

### 步骤 4：前置门禁（**唯一入口，不许绕过**）

```bash
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh --install
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh ; echo "PREBATCH_RC=$?"   # 期望 GO / rc=0
```

> ⚠️ **HEAD 一变就要重新 `--install`**：二进制里盖着构建时的 `vcs.revision`（`-trimpath` 也会盖）
> ⇒ **即使 Go 源码没动，哈希也会变**，前置门禁会以「与 HEAD 构建**逐字节不同**」报红。

### 步骤 5：★ **先实测 `B`**（不实测就没法写对声明面）

```bash
cd /root/t6/t19-head/lunwen/clab-lab && source /root/t6/t19-env.sh
unset EDGEEXP_TARGET_ABILITY EDGEEXP_TARGET_ABILITY_NAME EDGEEXP_CONTROL_ABILITY \
      EDGEEXP_PLAYBOOK_ID EDGEEXP_PLAYBOOK_NAME            # 走 recon 口径的探针
export EDGEEXP_BASIS=recon_playbook EDGEEXP_POLICY_ON=0 EDGEEXP_ATTACK_TIMEOUT_S=120
EDGEEXP_POLICY_ON=0 bash ./scripts/edge_reset.sh S1-apparmor       # 保证 VM 已备好 + agent 在跳
bash ./scripts/edge_attack.sh S0-baseline /root/t6/t19-data/probe/attack-S0-baseline.json
cd /root/t6/t19-head
./build/edgescen --scenario S0-baseline --config configs/edgeexp/m0-baseline.ini \
  --attack-out /root/t6/t19-data/probe/attack-S0-baseline.json \
  --out /root/t6/t19-data/probe/probe-B.jsonl --run 1 --env t19-baseline-probe --target qemu:asc-vm910
echo "rc=$?"
python3 -c "import json;print(json.load(open('/root/t6/t19-data/probe/probe-B.jsonl'))['factors'])"
#   ⇒ 本机实测 = ['EF-NO-IDS']；把它与**来源**写进 EDGEEXP_BASELINE_FACTORS[_SOURCE]
```

> **为什么必须实测**：`B` 取决于**这台靶机的实际配置**（装没装控制、LSM 在不在 enforcing），
> 而"声明一个不在链上的因子"会被门禁**如实拒掉**（不是放宽一下就过）。见 §5.3。

### 步骤 6：跑一条 targeted 实例（**两条臂**；reset → attack → collect + 门禁①/②）

```bash
cd /root/t6/t19-head/lunwen/clab-lab && source /root/t6/t19-env.sh
bash ./scripts/edge_matrix.sh S1-apparmor ; echo "MATRIX_RC=$?"     # 期望 0
```

期望看到的判据行（本批的实测形态）：

```text
edge_matrix: 记录条数 本次写入 2/2｜文件总行数 2｜record_counts_ok=True
edge_matrix: 因子集相等断言 all_ok=True
edge_matrix: 门禁⓪ 观察到重复条目：S1-apparmor→{'EF-APPARMOR': 2, 'EF-NO-IDS': 2, 'EF-SELINUX': 2}
edge_matrix: 注入-采集时钟核对 all_ok=True
edge_matrix: 门禁① exit=0（all-records，2 条）；门禁② 最大偏差 0（2 条）
```

### 步骤 7：收工（**清机必须走 `--destroy`**）

```bash
bash lunwen/clab-lab/scripts/edge_vm_provision.sh --destroy ; echo "DESTROY_RC=$?"
qm list ; pct list ; grep -c 'asc-vm' /etc/hosts
```

| 判据 | 期望 |
|---|---|
| `qm list` | **空**（0 台） |
| `pct list` | 只有 `904 running asc-tgt-c2`（**别人的 CT，不许动**） |
| `/etc/hosts` | 托管区块 **0 行**残留 |
| `local` 的 `content` | 与起点**逐项**相同（顺序可能被 PVE 规范化） |
| `lvs` | `vm-910-disk-0` 已释放（只剩 `data`/`root`/`swap`） |
| `asscor-vmseed` | **刻意保留**（见白皮书 §2.1） |

---

## 3. 矩阵的实例模型（三个维度）

**一句话**：**场景** × **臂** × **重复** = 实例。三个维度落在**三个不同的地方**，
互不覆盖，且都能从记录里查回来。

| 维度 | 由什么控制 | 落在记录的哪里 | 取值 |
|---|---|---|---|
| **场景** | 矩阵的参数（`edge_matrix.sh <场景名>…`，或缺省全跑） | `scenario_id` 的**前缀** | 25 个场景：S0–S5 共 22 + R 组 3 |
| **臂** | `EDGEEXP_POLICY_ON_ARM`（**只对 targeted 场景生效**） | `meta.policy_on` | `0` = 策略**不在**（卸掉策略以对齐"该控制缺失"的声明）；`1` = 策略**在**（默认） |
| **重复** | `EDGEEXP_RUN_INDEX`（`REPEAT`） | `meta.repeat`（**仅 `>1` 时存在**） | 1, 2, 3, … |

### 3.1 实例数怎么算

```text
NARMS = 2   若该场景是 targeted 且 EDGEEXP_POLICY_ON_ARM=1
      = 1   否则（recon/R 组本来就是 1；targeted 关掉臂也是 1）

实例号 NN = (REPEAT - 1) * NARMS + 臂序号 + 1       臂序号：0 = 策略不在，1 = 策略在
记录的 scenario_id 尾号 = NN（形如 S1-apparmor-03）
实例键（碎片/产物文件名） = <场景> [ + -pon ] [ + -r<REPEAT> ]     REPEAT>1 才加 -r<REPEAT>
```

**已知的规模数**（`EDGEEXP_POLICY_ON_ARM=1`、`REPEAT=1`）：

```text
targeted_ttp      ：11 个场景 × 2 条臂 = 22 实例
recon_playbook    ：14 个场景 × 1 条臂 = 14 实例
                 ────────────────────────────────
矩阵合计          ：36 实例
```

> ⚠️ **但本实验实际放的是 33 实例，不是 36** —— 差的就是 R 组那 3 个（`R-no-2fa`/`R-no-ids`/`R-no-siem`）。
> **理由（三条缺一不可，逐条已实测）**：
>
> | R 场景 | 需要的"真实缺失" | 装齐六个控制的靶机上 | 结论 |
> |---|---|---|---|
> | `R-no-ids` | `RS-006`（IDS/NIDS 不运行） | suricata `failed`、无 IDS 进程 ⇒ **确实缺** | ✅ **可跑**（已单独跑通，**不占批次**） |
> | `R-no-siem` | `RS-007`（无告警面） | `prepare` 写了 `alert_notification=email` ⇒ **在位** | ❌ **结构性不满足** |
> | `R-no-2fa` | `EF-001`（PAM 无第二因素） | `prepare` 装了包并写了 `pam.d/sshd` ⇒ **在位** | ❌ **结构性不满足** |
>
> 1. 其中两条**不可能产出记录**（R 组硬闸门在**建 operation 之前**整轮失败："不得用注入失败顶上"）；
> 2. 它们若入批次，**门禁①/② 都拿不到**（`REPEAT=1` 的条数门禁**必然为红**，见 §6.18）；
> 3. **不是新引入的**：Task 13 的"结论六"早已记着「R 组三场景**结构性不可达**」，
>    Task 9 的全量实验也只跑了 **11 个 targeted 场景**。
>
> ⇒ 取 **"33 实例 + 当轮门禁①/② 可绿"**，而不是"36 实例 + 门禁必然红"。
> **这是如实收口，不是跳过**：R 组的三条证据（1 条跑通 + 2 条闸门原文）已留档。
>
> ⚠️ **已知规模数不是"通用可跑数"**：本批的实测判据是
> **22 场景 / 33 实例**（11 targeted × 2 臂 + 11 非 targeted）。

> **判据**：`EDGEEXP_DRY_RUN=1 bash lunwen/clab-lab/scripts/edge_matrix.sh <场景>`，
> 输出里的 `实例数`/`实例键` 行；
> 全量台账在 `run.json` 的 `conditions.<实例>.instances` 与 `condition_summary`。

### 3.2 两条关键的不变式（**有夹具钉住**）

| 不变式 | 含义 | 为什么重要 |
|---|---|---|
| **`POLICY_ON_ARM=0` 是恒等变换** | 关掉臂时矩阵**逐字节回到旧行为**（实例 == 场景、尾号 == `-01`） | 保证"新旧批次可比"，也保证历史数据不被静默改写 |
| **`REPEAT>1` 时实例号与第 1 遍不重叠** | `NN = (REPEAT-1)*NARMS + …`，且实例键带 `-r<REPEAT>` | 重复样本**不覆盖**第 1 遍的碎片与产物；同一份记录文件承载 1..REPEAT 各一遍 |

> **`REPEAT>1` 时 `EDGEEXP_ENV` 必须显式给**（否则重复样本会被打上默认标签**混进主数据集**）——
> 矩阵层硬门禁，`exit 2`。

### 3.3 期望行数的算法（供写门禁/校验用）

```text
期望**文件行数** = 实例数 × 重复号
records_missing_for_selected = max(0, 实例数 × 重复号 - 文件行数)
records_extra_in_file        = max(0, 文件行数 - 实例数 × 重复号)
record_counts_ok             = (文件行数 == 实例数 × 重复号)
```

### 3.4 重复轴（`REPEAT>1`）怎么跑：驱动 `edge_repeat.sh` 与**口径定案**

**一句话**：重复轴由 `lunwen/clab-lab/scripts/edge_repeat.sh` 驱动；**同一段批次的 N 遍写进
同一份记录文件**（§3.3 的 `record_counts_ok` 就是按这个形态定义的），逐轮只隔离
`meta.env`（`<base>-r<k>`）与逐轮的 `run-<id>.json`。

#### 3.4.1 命令（**两段批次各一份记录文件**）

```bash
DATA=/path/to/data/edgefactors      # 或 EDGEEXP_DATA_DIR

# ① 先做 1 场景 × 2 轮冒烟（判据见 3.4.2；别跳过它直接开 19 h 长跑）
EDGEEXP_REPEATS=2 EDGEEXP_RUN_TAG=smoke \
EDGEEXP_RECORDS="$DATA/records-<env>-rpt-smoke.jsonl" \
  bash lunwen/clab-lab/scripts/edge_repeat.sh S1-selinux

# ② 真跑 · 第 1 段：targeted（11 场景 × 2 臂 × 3 轮 = 66 条，约 3 h）
EDGEEXP_REPEATS=3 EDGEEXP_RUN_TAG=targeted \
EDGEEXP_RECORDS="$DATA/records-<env>-rpt-targeted.jsonl" \
  bash lunwen/clab-lab/scripts/edge_repeat.sh \
  S1-apparmor S1-selinux S2-2fa-selinux S2-apparmor-no-ids S2-selinux-apparmor \
  S2-selinux-no-ids S2-selinux-no-siem S3-3fa-selinux-apparmor S3-selinux-apparmor-2fa \
  S3-selinux-no-siem-no-ids S4-all

# ③ 真跑 · 第 2 段：非 targeted（11 场景 × 1 臂 × 3 轮 = 33 条，约 15 h）
#    必须**在 ② 结束之后**再起（同一台 VM、同一 agent 组）；记录文件另给一份
EDGEEXP_REPEATS=3 EDGEEXP_RUN_TAG=nontargeted \
EDGEEXP_RECORDS="$DATA/records-<env>-rpt-nontargeted.jsonl" \
  bash lunwen/clab-lab/scripts/edge_repeat.sh \
  S0-baseline S1-2fa S1-no-ids S1-no-siem S1-syn-cookie S2-no-siem-no-ids \
  S2-syn-cookie-no-ids S2-syn-cookie-no-siem S3-syn-cookie-no-siem-no-ids S5-2fa-only S5-cascade-3fa
```

| 变量 | 缺省 | 作用 |
|---|---|---|
| `EDGEEXP_REPEATS` | `3` | 轮数（= 每场景的重复次数） |
| `EDGEEXP_RECORDS` | `records-<env>-<date>.jsonl` | **段级**记录文件；两段各一份，**不许**把两段塞进同一份（门禁按段算） |
| `EDGEEXP_RUN_TAG` | 空 | 段标识，进 `run-<id>.json`（`<date>[-<tag>]-r<k>`）⇒ 不同段/不同次重跑不会同名覆盖 |
| `EDGEEXP_RESUME` | `1` | 中断后重跑同一轮时跳过"文件里已有该实例记录"的实例 |
| `EDGEEXP_DRY_RUN` | `0` | `1` = **只看计划**（不碰实验室、不写记录、不写 `run.json`）；此时条数口径记 `skip(...)` |

#### 3.4.2 ⚠️ 口径定案（Task 21 实测，2026-10-17）：**一份记录文件承载 1..REPEAT**

这一条以前在代码里是**两套互相矛盾**的机制，2026-10-17 用 **1 场景 × 2 轮冒烟**定案到
"路 B"，并把驱动改成与 §3.2/§3.3 一致：

| 机制 | 它以为的形态 | 结果（实测） |
|---|---|---|
| 修前的 `edge_repeat.sh` | **逐轮一个**记录文件 `records-…-r<k>.jsonl` | 第 1 轮 `record_counts_ok=True`；**第 2 轮 `record_counts_ok=False`**（文件 2 行、门禁要 `2×2=4` 行，`records_missing_for_selected=2`），而**退出码仍是 0**、驱动还打印"全部 2 轮完成" ⇒ **不吭声的假红** |
| `edge_matrix.sh` 的 `record_counts_ok` / §3.3 | **一份文件承载 1..REPEAT** | 与 §3.2 的原话一致（"同一份记录文件承载 1..REPEAT 各一遍"） |

- **为什么"逐轮一个文件"的理由不成立**：`edge_repeat.sh` 原先写着"`edge_collect.sh` 的幂等守卫
  按**场景名前缀**匹配，三轮同文件会被判重复而拒写"。守卫现在比的是**完整实例 id**
  `<场景>-<实例号>`（`edge_collect.sh:167`），而实例号 `NN=(REPEAT−1)×NARMS+臂+1` **逐轮不重叠**
  ⇒ 第 2 轮写同一份文件**不会**被判重复（冒烟实测：`-01/-02` 与 `-03/-04` 四行同在一份文件里）。
- **为什么不动矩阵的门禁**：`record_counts_ok` 只有"文件行数 == 实例数 × 重复号"这一种语义；
  给它加"这份文件是逐轮独立的"分支 = 同一字段两种语义，且必然**放松判据**。
- **判据（冒烟必须达成）**：**两轮的 `record_counts_ok` 都是 `true`、驱动的 `rc=0`**，
  且同一份文件里同时出现 `-01/-02`（第 1 轮）与 `-03/-04`（第 2 轮）。

驱动另有两条护栏（都是实测踩出来的）：

1. **`record_counts_ok=false` 也算这一轮失败**：驱动逐轮**读 `run-<id>.json`**（不 grep 猜），
   `rc=0` 但 `record_counts_ok=false` 的那一轮记成失败（`overall_rc=1`）。
2. **陈旧 `run.json` 护栏**：`RUN_ID` 缺省是 `<date>-r<k>` ⇒ 同一天重跑同名时，
   驱动会读到**上一次**的 `record_counts_ok`（实测：一次什么都没做的干跑读到了前一次冒烟的 `true`）。
   判据取 `run.json` 自己记的 `records_file`：与本次要写的不同 ⇒ 视为"没有本轮判据"。

> **不许做的事**：把第 2 轮写进**另一份**记录文件（门禁会报"缺 N 条"）；
> 把两段（targeted / 非 targeted）塞进同一份（门禁按段算，且 `run.json` 会混两段的条件台账）；
> 用 `EDGEEXP_POLICY_ON_ARM=0` 冒充"控制重复"（那是**臂**，不是重复）。

#### 3.4.3 中断与续跑（停在干净边界）

- 默认 `EDGEEXP_RESUME=1`：矩阵逐实例跳过"文件里已有该实例记录"的那些，并把它记进
  `run.json` 的 `scenarios_skipped_resume`（`record_counts_ok` 的第二个合取项会把它算作已完成）。
- `REPEAT>1` 时矩阵的**硬门禁**是"**本轮每个实例 id 在文件里恰好一条**"（不是"文件行数 == 实例数"），
  所以中断后重跑同一轮不会因为"文件里已有前几遍的行"而红。
- 重跑 = **同一条命令**（记录文件、`RUN_TAG`、`REPEATS` 都不变）；换了记录文件就等于换了一批样本。

#### 3.4.4 方差分析（Step 2/3）

```bash
python3 lunwen/clab-lab/scripts/edge_variance.py \
  --records lunwen/clab-lab/data/edgefactors/records-<env>-rpt-targeted.jsonl \
  --records lunwen/clab-lab/data/edgefactors/records-<env>-rpt-nontargeted.jsonl \
  --baseline lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl \
  --preamble docs/experiments/variance-report-preamble.md \
  --json docs/experiments/variance.json --md docs/experiments/variance-report.md
```

> ⚠️ **两段的输入指纹判据必须「按段做」**（Task 22 纠正的一条假警报）：两份记录文件是**两个段**，
> 而它们在**设计上就用不同剧本** —— `targeted` 段用 TTP pair 剧本（`playbook_hash = e585b846…`）、
> 非 targeted 段用固定 Discovery 侦察剧本（`b112ca3c…`）。把 `meta.playbook_hash` 当"**全批**唯一"
> 去数取值个数，合并后必然得到 **2 个取值**并喊出"重复之间换了条件" —— 那是**假警报**。
> 现行判据：**每个段内部**每种指纹只有一种取值（§0.1 的「段内唯一项」表），
> 跨段取值只作可读性、**不参与判据**；报告还会给「逐段小计」把两个段的跨批结论分开报
> （合并后的总数**不得**写成"22/22"这类口径）。

> **报告落在 `docs/experiments/variance-report.md`**（计划里的 `variance-report.md` 就是它）：
> 数据目录 `data/edgefactors/` 的 `.gitignore` 白名单只放行 `records-*.jsonl` 与
> `run-<8 位日期>-<pid>.json`（Task 20 的口径），故**报告不进数据目录**，
> 与手册/审计归档放在一起（同样的可发现性，且不需要 `git add -f` 绕过白名单）。
> `--preamble` 是**手写结论块**（`docs/experiments/variance-report-preamble.md`），插在 §0；
> 它与脚本算出来的数冲突时**以脚本为准**，并回来修那一节。
> 「零方差」的**用途边界**写在报告开头：它测的是**基质稳定性与评分确定性**，**不是模型噪声**。

- **数值层**：`final_score`、五个域分、每条被观测因子的 `effective_factor`（键按
  `因子#出现序号`，同 ID 多条不合并）的**极差**与**样本标准差（n−1）**；
- **判定层**：`observed.acceptable` 是否翻转；**标签层**：`ground_truth.compromised` 是否翻转；
- **门禁层**：链因子集是否 N 次相同（形状变了 = **环境敏感**）。
- **判据**：**判定翻转的场景×臂必须单独列出并标注"环境敏感"，不隐去、不取平均掩盖**；
  与 `REPEAT=1` 主批逐次对照（有没有哪一次与主批结论相反）。
- **口径**：**重复样本不是独立样本**（同一宿主状态的重复，用来估方差/稳定性）⇒
  决策层 N 写成 `N=<条数>（<场景数> × <重复数>）`，**不得**当独立样本虚增；
  合并两段时还要把"每场景几条臂"写准（本批 = 11 个两臂组 + 11 个单臂组，
  **不是**"22 场景 × 2 臂"）。
- **跑批侧的门禁怎么读这两段**：非 targeted 段里**一条 `targeted_ttp` 都没有** ⇒
  门禁①/② 在这个段上**不适用**（`not_applicable: true`，不是失败，`MATRIX_RC` 不受影响），
  见 **§5.1.1**。

---

## 4. 怎么读记录

记录是 **JSONL**（一行一条），契约实现在 `internal/edgeexp/record.go`（**生产者与消费者共用**）。

### 4.1 顶层结构

```jsonc
{
  "scenario_id": "S1-apparmor-01",     // 场景 + 实例号
  "factors":     ["EF-SELINUX", "…"],  // **链上实际**出现的因子集（去重）
                                       //   == meta.expected_baseline_factors ∪ meta.expected_chain_factors
  "injection":   "…",                  // 注入描述
  "observed":    { … },                // 采集到的观测面
  "ground_truth":{ … },                // 客观标签（**决策层指标只吃这里**）
  "meta":        { … }                 // 溯源 / 口径 / 环境标识
}
```

### 4.2 `meta` 里的字段（**逐实例枚举自真机记录**）

| 字段 | 类型 | 含义 | 进不进评分 |
|---|---|---|---|
| `meta.env` | string | 环境标识（与 `EDGEEXP_ENV` 同源，形如 `<lab-tag>`） | ❌ 标识 |
| `meta.run` | string | 运行序号 | ❌ 标识 |
| `meta.repeat` | int（**可选**） | **重复号**（= `EDGEEXP_RUN_INDEX`）。**仅在 >1 时存在**；缺席 = 第 1 遍 | ❌ 标识（但**是重复轴分析的唯一依据**） |
| `meta.policy_on` | **string**（`"0"`/`"1"`） | **臂**：`"0"` = 策略**不在**（卸掉策略以对齐"该控制缺失"的声明）；`"1"` = 策略**在**。**缺席 = 采集产物没写**（历史记录/手写夹具），与"显式声明过 `"0"`"是两件事 | ❌ 条件标识 |
| `meta.observation_target` | string | **观测主体**，形如 `node:<vmid> (substrate=qemu, hostname=<name>)` —— **"这批数据采自哪种基质"的唯一判据**（§5.4） | ❌ 但**决定"这台机器的数据"是谁的** |
| `meta.timestamp` | RFC3339 | 该记录的时刻 | ❌ |
| `meta.config_hash` | string | 采集所用配置的指纹（**权重的锚点**） | ❌ 溯源 |
| `meta.expected_baseline_factors` | []string | **基线活跃集**（按「基质 × 取数权限」如实声明，见 §5.3） | ❌ 声明面 |
| `meta.expected_baseline_factors_source` | string | **为什么**是这个基线集（逐字理由） | ❌ 声明面证据 |
| `meta.expected_chain_factors` | []string | ⚠️ **只装「注入集 E」**（含级联展开），**不是**完整声明面。**完整声明面 = `expected_baseline_factors` ∪ 本字段** | ❌ 声明面 |
| `meta.playbook_hash` | string | 剧本字节的 sha256（漂移守卫） | ❌ 溯源 |
| `meta.weight_source` | string | **权重口径**：`observed.effective_weights` 从哪来，以 `config_hash` 为锚点 | ❌ 溯源（**离线重算必需**） |
| `meta.ts_source` | string | **链条目 `ts` 的基准**（独立字段） | ❌ 溯源 |
| `meta.skipped_checks` | []{id,reason} | 由采集器写的**被跳过检查项**及其原因 | ❌ **不参与任何指标**（见 §4.4） |

### 4.3 决策层的两类关键字段

**（甲）`ground_truth.basis`** —— 说明"这条标签从哪来"：

| 取值 | 含义 | 谁消费 |
|---|---|---|
| `targeted_ttp` | 该场景的**目标 TTP** 成败 | **决策层指标只吃这一类** |
| `recon_playbook` | 侦察剧本口径（**没有**目标 ability） | **不进决策层指标**（统计恒为空） |

> **口径**：`ground_truth.basis` 是 **additive、可选**字段。**缺依据**不能猜 ——
> 缺依据的三条出路：① 用带 `basis` 的采集产物**重采**；② 显式声明口径；
> ③ 该条**不进**决策层统计。**不容许**的是"用 `recon_playbook` 的数据冒充 `targeted_ttp`"。

**（乙）`observed` 里的必填项**（缺了会**静默**把判定抬高到最宽松的一档，故读取层 fail-fast）：

| 字段 | 为什么必填 |
|---|---|
| `threshold` | 缺了复现不出部署判定线 |
| `acceptable` | 部署判定结果 |
| `spc_score`（E） | 总分公式 `round2(0.5·base + 30·E + 20·T)` 的 E 项 |
| `threat_coeff`（T） | 同上 T 项 |
| `effective_weights`（**读取层可选、生产者必写**） | 离线重算必须知道"哪些域参与聚合、各占多少权重"；**配置权重 ≠ 生效权重**（引擎用动态权重，0 权重域会被填默认值并归一化） |

> **区别"零值"与"没写"**：`spc_score`/`threat_coeff`/`threshold`/`compromised` 用过**指针解码**，
> 因为 JSON 的零值与缺失在 Go 结构体里同形；缺失会被静默读成 0，
> 再被公式的 `<= 0 ⇒ 1.0` 兜底成"无暴露"，**报告照常打印但判定全部失真**。

### 4.4 **哪些不进评分**（把这条记牢，能省掉一整类误读）

| 字段/概念 | 为什么不进评分 |
|---|---|
| `meta.skipped_checks` | 它是"采集器**没测**的东西"，是**观测缺口**的记录，不是安全态势 |
| `meta.*` 的身份/溯源字段（`env`/`run`/`repeat`/`policy_on`/`observation_target`/`config_hash`/`playbook_hash`/`weight_source`/`ts_source`） | 标识与溯源 |
| `ground_truth.basis = recon_playbook` 的记录 | **不进决策层指标**（只进侦察口径的统计） |
| `meta.expected_baseline_factors` / `expected_chain_factors` | **声明面**，用于**集合相等断言**，不参与分数 |

**唯一进评分的**：`observed`（域分、与 E/T、权重、阈值、链）+
`ground_truth.compromised`（`basis=targeted_ttp` 时）。

### 4.5 `OT-005` / `KS-012` 与"基线活跃集"

见 §5.3。**一句话（v1.1 更正）**：这两条的 `passed` 值取决于**在哪读（基质）× 谁在读（取数权限）** ——
在 CT 上因 LXC 内核面不可观测、在 VM 上若用非 root 登录用户取数也会**假失败**，
于是**那个常量 −30 是「取数权限 × 基质」耦合出来的伪影**。
**同一场景的"失败检查条数"在两套基质/两种权限之间不可直接比较。**

### 4.6 ★ **这份数据集怎么读**（VM 批次 33 条；v1.1 新增）

**数据集本体（已在仓库内）**：

| 文件 | 内容 |
|---|---|
| `lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl` | **33 条记录**（sha256 `82d37eade414327ba3bdaee8d96d419e84eba64eba80264947f1807531f5b468`） |
| `lunwen/clab-lab/data/edgefactors/run-20261015-3482605.json` | 本次运行的汇总元数据（拓扑/配置哈希/权重口径/逐实例耗时/门禁⓪/注入-采集时钟核对/记录条数/因子集相等断言） |
| `lunwen/clab-lab/data/edgefactors/run.d-qemu-20261016/**` | 逐实例碎片：`reset-*.json`、`collect-*.json`、`gate-inputs.json`、`gate-gate1.json`、`gate-gate2.json`、`rejected-S1-apparmor.jsonl`（**被断言拒掉并已回滚**的那条记录）、`.state.json` |
| （对照）`records-dl360-pve-20261013.jsonl` | **CT（LXC）基质**的 11 条 —— **另一套基质的数据，不可混算** |

> **只入数据与 run 元数据**：宿主 `run.d/` 里另有 44 个 `.edgescen-*.out/.err`、`.gate*.out/.err`
> （合计 116 KB 过程日志）**刻意不入库**；日志里提炼出来的结论在本文与白皮书里。
> 宿主的 33 份 harness 产物（`attack-*.json`）也**不入库**：它们与 CT 批次的产物**同名**，
> 平铺进同一个目录会**静默覆盖 CT 的证据**，而读这批数据所需的声明面记录本体已经全有。

**33 条 = 22 + 11（逐条实测）**：

| 组 | 条数 | 构成 | `meta.policy_on` | 边界 |
|---|---|---|---|---|
| `ground_truth.basis = targeted_ttp` | **22** | 11 个 targeted 场景 × **2 条臂** | `"0"` × 11 / `"1"` × 11 | ✅ **只有这一组进决策层指标** |
| `ground_truth.basis = recon_playbook` | **11** | 11 个非 targeted 场景 × 1 | **全部 `"1"`** | ❌ **不得进决策层指标** |

```
basis: {'targeted_ttp': 22, 'recon_playbook': 11}
policy_on: {'0': 11, '1': 22}
targeted score range: 51.55 55.73
recon compromised set: Counter({True: 11})        ← **旧口径**
recon block_effective set: Counter({False: 11})
```

**六条读法（每条都能让一次误读变成一次结论）**：

1. **`recon` 那 11 条的 `compromised` 是「旧口径（任意 link 成功）」** —— 11/11 都是
   `compromised=true`，因为它报的是"侦察剧本的 link 跑成功了"，**不是**"目标 TTP 达成了"。
   拿它当标签用会把恒真的结果喂进决策层 ⇒ 统计恒为空。**判据是 `ground_truth.basis`。**
2. **`compromised` / `block_effective` 在 `ground_truth` 下，不在 `observed` 下。**
   （`observed` 的键是 `acceptable / checks / domain_scores / edge_factor_chain /
   effective_weights / final_score / spc_score / threat_coeff / threshold`。）
3. **`observed.checks[]` 只装「未通过」的检查**（键 `id / domain / passed / delta / confidence / ts`）
   ⇒ **"某条检查不在记录里"不能读成"它通过了"**。要完整观测面就得看**客人侧完整信封**
   （`edgescen -emit-checks` 的 80 条）。
4. **`meta.expected_chain_factors` 只装「注入集 E」**；**完整声明面 = `meta.expected_baseline_factors`
   ∪ 前者**。本批的基线是 `['EF-NO-IDS']` —— **只拿注入集与链比对会误判一大批"不等"**。
5. **`meta.policy_on` 是字符串**（`"0"`/`"1"`），不是布尔。
6. **`meta.ts_source`** 逐字说明了链条目 `ts` 的取法（本批：全部取评估时刻）。

**两条论文级口径（**必须写对，别写反**）**：

```text
# 两臂逐项比较（忽略 ts，比 chain / checks / domain_scores / final_score + ground truth 标签）
S1-apparmor   chain=True score=True checks=True dom=True label_diff=True
…（11 个 targeted 场景全部同形）
ALL-IDENTICAL-EXCEPT-LABEL: 11 / 11
```

- ① **两臂的链读数与分数逐项相同、只有 ground truth 标签不同**（11/11）。
  ⇒ **这条 limitation 不许撤**：分数侧与链侧**都区分不开两条臂**，能区分的只有标签。
  **★ 机器判据（Task 20 钉住）**：`lunwen/clab-lab/tests/test-arm-limitation.sh` —— 直接读本节的这个数据集（33 条），
  9 条断言（3 条硬判据 + 3 条加固 + 3 条计数/源指纹），已接进 `run-all.sh`（第 7 组，期望 `PASS=9`）。
  **它变红 = 提示去更新文档**（limitation 不再成立、论点要重写），**不是**叫你把断言放松。
- ② `n_i`（每个因子在链上出现几次）**不是常数 2**。实测的 `n_i` 多重集分布：
  `(2,)×2 / (2,2)×6 / (2,2,2)×12 / (2,2,2,2)×8 / (2,2,2,2,2,2)×2 / (1,1,2,2,2)×2 / (1,2,2)×1`
  ⇒ **「每个因子恰好出现两次」只是这批矩阵的观测、不是不变量**（33 条里 **3 条**含 `n_i = 1`）。

**★ 只靠仓库就能自证的三件事**（不需要宿主机、不需要 `.superpowers/`，
判据全在 `run.d-qemu-20261016/` 的碎片里 —— **这就是为什么 harness 产物不入库也不影响复核**）：

| 要自证什么 | 看哪个字段 | 本批实测 |
|---|---|---|
| **探针与观测在同一台机器上**（"这次真的是在 VM 里跑的"） | `collect-*.json` 的 `observation_subject`：`target_declared` / `record_observation_target` / `harness_probe_targets` / `ok` | **30/31** 个碎片的 `harness_probe_targets == ["asc-vm910"]` 且 `ok=true`（第 31 个是 `S0-baseline`，它的 `probes_expected=false` ⇒ 探针列表本来就该是空的） |
| **每条记录都通过了进程内往返自检**（记录与复算一致） | `collect-*.json` 的 `gate2_round_trip.delta` | **31/31** 全部 `delta == 0`（容差 0.005） |
| **当轮门禁①/② 是绿的**（不是 `null`/`skipped`） | `gate-gate1.json` / `gate-gate2.json` 的 `exit_code` | 两条**都是 `0`**，`records: 33`，`dataset: all-records` |

**离线复算（分钟级，不需要 VM/CT/Caldera）**：

```bash
build/edgecompare -records lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl \
  -candidate legacy=configs/edgeexp/m0-baseline.ini -candidate vector=configs/edgeexp/vector.ini \
  -candidate graph=configs/edgeexp/graph.ini        -candidate chain=configs/edgeexp/chain.ini \
  -factors EF-002FA=0.70,EF-SYNCOOKIE=0.75,EF-SELINUX=0.80,EF-APPARMOR=0.82,\
EF-NO-SIEM=0.90,EF-NO-IDS=0.88,EF-3FA=0.82 \
  -weights attack_surface=35,business_continuity=25,operation_trust=25,resilience=15,kernel_security=10
echo "rc=$?"
```

> ⚠️ **`-factors` 的取值必须以「链上用到的每个因子」为准**（含 `EF-3FA=0.82`）。
> ⚠️ **本批上"链上同一因子有两个条目"是配置的真实形态**（`[edge_factors]` 内置 7 条 + `[edge_factors.custom]` 另 7 条，
> 解析后同名）⇒ **链上会出现重复条目**。这在**合成层**曾经让主效应 ×2、耦合项 ×4
> （`L_d` 被污染）；**Task 18（`4c1ab06`）已把折叠点放在「条目 → 因子」的换算层**
> （`internal/edgefactor.CollapseToFactors`，取**最强观测惩罚**）。判据：**`legacy` 列逐位不变**
> （链上的重复对 legacy 是**载荷**，`ConfigToEdgeFactors` 不许去重），**只有 V/G/C 逐条数值上升**。

### 4.7 ★ **数据集怎么入库**（`.gitignore` 白名单；Task 20 规范化）

**规则在哪**：根 `.gitignore` 的 `lunwen/clab-lab/data/*` 块里，紧跟在
`!lunwen/clab-lab/data/experiments-final/` 之后。

**它放行两类"证据本体"**（其余在这个目录里仍然忽略）：

| 放行 | 是什么 |
|---|---|
| `lunwen/clab-lab/data/edgefactors/records-*.jsonl` | 每批实验的**记录集本体**（论文数据点，逐条可复核） |
| `lunwen/clab-lab/data/edgefactors/run-<8 位日期>-<pid>.json` | 那一批的 **run 元数据**（口径/参数/门禁/耗时/条数断言） |

**新增一批数据时的正确姿势**：

```bash
cp <新数据集> lunwen/clab-lab/data/edgefactors/records-dl360-<基质>-<YYYYMMDD>.jsonl
git status --porcelain          # 必须**看得见**这两条 `??`（看不见就是被规则吃掉了，停下来查规则）
git add lunwen/clab-lab/data/edgefactors/records-<…>.jsonl \
        lunwen/clab-lab/data/edgefactors/run-<YYYYMMDD>-<pid>.json
```

> ✅ **不再需要 `git add -f`。** Task 19（`fa48ed8`）那 69 个文件是**规则化之前**的做法，
> 保留在历史上不动；从 Task 20 起，数据集靠**规则**入库。

**为什么要把惯例写进规则（而不是继续靠 `-f`）**：这两条曾经**同时成立** ——
ignore 规则说"不该入库"，而 146 个已跟踪文件说"该入库"。实测代价就在这个目录里：

```bash
git ls-files lunwen/clab-lab/data | wc -l                    # 146（进了库的）
git status --ignored --porcelain lunwen/clab-lab/data | wc -l #  33（在场却没进库的）
```

那 33 个里有 **19 个是"同类兄弟已经入库、这几个没入"的半跟踪态**：3 个 `attack-*.json`
（另有 12 个已入库）、3 份 `records-wsl-clab-14-20260912-smoke*.jsonl`、13 个
`run.d/` 碎片（同类碎片在 `run.d-qemu-20261016/` 里已入库）。
⇒ **"要不要入库"取决于当班执行者记不记得加 `-f`** —— 证据的可得性不能取决于人的记性。

**刻意保持忽略的**（都不构成"论文数据点"，见 `.gitignore` 里的逐条理由）：
`attack-*.json`（harness 原始产物，**与旧批次同名**，平铺即静默覆盖）、`run.d*/`（现场碎片，
每轮被 `edge_matrix.sh` 清掉）、`run.json` / `run-smoke1.json`（无批次号的临时件）、
`records-wsl-clab-14-20260912-smoke*.jsonl`（一次性 WSL 试跑，一份还是 0 字节占位）。

**三层复核（改完/新增后各跑一次，逐条可判真假）**：

```bash
git ls-files | wc -l                                      # 不得减少（白名单被误杀的第一个信号）
git status --porcelain                                    # 新数据集必须是 `??`，不是"看不见"
git check-ignore -q lunwen/clab-lab/data/edgefactors/records-<新>.jsonl   # rc=1 ⇒ 没被忽略
```

> ⚠️ **历史事故形态**：本项目曾因 `lunwen*/` 这类**整目录**排除规则把白名单**整体杀死**
> （`!` 无法穿透被排除的父目录）⇒ 新文件**静默不被跟踪**。所以规则里的顺序是硬要求：
> **先** negate `edgefactors/` 目录本身，**再** negate 目录里的文件（见 `.gitignore` 里的注释）。

**驱动层汇总（`repeats.json`）放哪儿**（Task 22 明确）：它**不在**数据目录 ——
白名单只放行 `records-*.jsonl` 与 `run-<8 位日期>-<pid>.json`，`repeats.json` 会被规则忽略
（`git check-ignore -q` **rc=0**）。按"报告与手册放一起"的既有口径，它落在
**`docs/experiments/repeats-<环境>-<tag>.json`**（本批：`docs/experiments/repeats-t21-qemu-rpt.json`），
与 `variance-report.md` / `variance.json` 相邻。判据：`git check-ignore -q docs/experiments/repeats-*.json`
**rc=1**（会被跟踪）。

> `repeats.json` 里的 `exit_code` 是**驱动当时**读到的矩阵 rc —— 本批非 targeted 段那三轮的
> `exit_code: 1` 是"门禁① 把不适用误报成失败"的**历史证据**，**原样保留**、不得手改
> （纠正后的口径见 §5.1.1；重跑同一段现在会得到 `MATRIX_RC=0` + `not_applicable: true`）。
> **Task 23 起该文件带三个显式标注**（`segment` / `pre_fix_record: true` / `pre_fix_note`）——
> 加标注**不算**改历史：`runs[]` 的 `exit_code`/`elapsed_s`/`record_counts_ok` 一个字没动，
> 标注只写明"这份是修复前产物、能用来证明什么、不能用来证明什么"。
> targeted 段的驱动汇总另有一份：`docs/experiments/repeats-t21-qemu-rpt-targeted.json`
> （**重建件**，来源逐条写在它的 `reconstruction` 里 —— 驱动把汇总固定写到 `$DATA_DIR/repeats.json`，
> 那段被随后非 targeted 段原地覆盖了）。

---

## 5. 三道门禁与"基线活跃集"口径

### 5.1 门禁清单

| 门禁 | 键（在 `run.json` 里） | 查什么 | 失败后果 |
|---|---|---|---|
| **门禁⓪** | `gate0_duplicate_factors` | 逐场景统计链里的**重复因子 ID**（`trim + upper` 归一后），区分"真实重复"与"折叠形态" | 只报不拦（**记录事实**，因为重复是出厂部署的真实形态） |
| **门禁①** | `gate1_offline_compare` | 用 `edgecompare` 对**同一数据集**离线重算，**exit_code 必须为 0**；**`not_applicable: true` 是第三态**（见 §5.1.1：本段没有任何 `targeted_ttp` ⇒ 决策层指标无输入，不算失败） | **静默 skipped 是最危险形态**（报告照常打印 ⇒ 整轮作废）；**不适用 ≠ 失败**，但也不许静默：它必须带原因串落盘 |
| **门禁②** | `gate2_round_trip` / `gate2_offline_compare` | 记录**往返**（load → marshal → load）后**逐字节一致**；离线那半边的 `not_applicable` 与门禁① 同口径 | 契约漂移 |
| **记录条数/集合** | `record_counts_ok`、`chain_factor_set_equality`、`records_file_agreement` | 文件行数 == 实例数 × 重复号；链因子集合 == 声明面；碎片与记录一致 | 少一条 = 有实例没采成 ⇒ 硬失败 |

### 5.1.1 门禁① 的**第三态**：不适用 ≠ 失败（`targeted_ttp` 缺失的段）

**形态（本里程碑实测）**：非 targeted 段 = 11 个侦察口径场景 × 3 轮 = **33 条**记录，
其中**一条 `targeted_ttp` 都没有**（它们的标签口径是 `recon_playbook`，是**背景测量**）。
决策层指标按裁定只覆盖 `targeted_ttp` ⇒ 过滤后 `N == 0` ⇒ **这个段上决策层指标本来就不存在**。

**旧行为的错**：`edgecompare` 把它与"数据坏"归成同一个 `exit=1`，矩阵照着写
`FAIL_REASON="门禁① 离线比较失败"` 并 `exit 1` ⇒ 整轮 `MATRIX_RC=1`。
这不是数据坏，是**分类错了**（把"不适用"报成"失败"）。

**现行口径（三态）**：

| 形态 | `edgecompare` 退出码 | `gate-gate1.json` | `MATRIX_RC` |
|---|---|---|---|
| 通过 | `0` | `exit_code: 0`, `not_applicable: false` | `0` |
| **不适用**（本段无 `targeted_ttp`） | **`3`** | **`exit_code: null`, `not_applicable: true`, `not_applicable_reason: <工具 stderr 原文>`** | **`0`**（不算失败） |
| 失败（数据坏：缺依据/读不出来/因子未覆盖/缺加权域分/权重表无正权重） | `1` | `exit_code: 1`, `not_applicable: false` | 非零 |

> **⚠️ 门禁① 的能力边界（引用这张表前必读 —— 第一次审计 Minor-4）**：
> 上面这三个码判的是 **fail-fast 的可用性**：记录能不能读、依据能不能判、因子有没有覆盖、
> 域分够不够、生效权重表可不可用。**它不是逐条复算门。** 实测（Task 23 报告 §1.8）：
> 把一条记录的 `observed.final_score` 改 `+5`、或把 `acceptable` 改反，
> `edgecompare` **仍然 `exit=0` 且报告逐字不变**；改一个域分只会让报告里的指标**悄悄漂移**。
> 逐条"记录 ↔ 复算"一致由 `edgescen` 收集时的**进程内自检**（`gate2_round_trip`，不通过即
> 拒绝写出该条记录）承担 —— **不在**门禁① 的退出码里。
> ⇒ **「门禁① 绿」只等于「这份输入可用」，不能当作「这批数据好」的证据**；
> 论文/台账里只写"门禁① 在该段上**无失败/不适用**"，**不许**写"该段数据通过了门禁复核"。
>
> **「不适用」的边界（Task 23 收紧）**：逐条输入校验（域覆盖 + 生效权重表可用）**排在依据守卫
> 之前、对全部输入记录跑** ⇒ `exit=3` 严格等于"输入完好、只是没有决策层标签"。
> 修复前这两条校验只对**进决策层**的记录跑，于是"全侦察口径段 + 打分输入被破坏"会被记成
> 不适用而**变绿**（第一次审计 Important-1 实测：删一条 `domain_scores.resilience` ⇒ MATRIX_RC 由 1 变 0）。

**红线（不许做的事）**：**不许把"不适用"改成 `exit=0`** —— 那是静默放行，不是第三态。
第三态必须**带原因串落盘**、并在日志与 `run.json` 汇总行**显著打印**：
```
edge_matrix: 门禁① **不适用**（not_applicable：33 条记录里没有 targeted_ttp ⇒ 决策层指标无输入；exit_code=null）
  原因：edgecompare: 过滤后没有任何记录进入决策层指标（过滤前 33 条；**跳过 recon_playbook=33**）……
```
同一口径覆盖三个消费者：门禁①、**门禁② 的离线那半边**（它的实质是逐条复算，由 `edgescen`
进程内自检承担）、以及**阈值敏感性行**（`sensitivity.json` 里该阈值记 `not_applicable: true` +
`exit_code: null`，并仍写一份标注"不适用"的产物）。

**判据没有放宽**（三条可直接复核的验收；harness **尚未入库** —— 它在未跟踪的
`.superpowers/sdd/2026-09-12-edge-factor-coupling-milestone-b/t22-gate-test.sh`，
依赖宿主的绝对路径与三份真实记录文件；手工等价操作 = `EDGEEXP_RESUME=1` +
`EDGEEXP_RUN_INDEX=3` + 对应段的场景清单，让它只跑"记录条数门禁 → 门禁①② → run.json"这一段）：

```bash
# ① 非 targeted 段（33 条）⇒ 门禁① 报"不适用"、MATRIX_RC=0
bash t22-gate-test.sh nt
# ② targeted 段（66 条）⇒ 门禁① 仍 exit=0、MATRIX_RC=0（回归）
bash t22-gate-test.sh tg
# ③ 故意造一个真失败（删一条记录的 ground_truth.basis）⇒ 门禁① 仍非零、MATRIX_RC 非零（还有牙）
bash t22-gate-test.sh bad
```

> 注意 ③ 用的是"缺依据"而**不是**"改一条分数"：门禁① 判的是"工具能不能读**全量**记录、
> 有无 fail-fast"，改分数**不会**让它变红（逐条复算的权威证据在门禁② 的进程内自检里）。
> 拿"改分数"当"真失败"会造出一条假证据。


### 5.2 三道门禁的历史事故（**为什么它们现在是硬的**）

| 事故 | 形态 | 现行判据 |
|---|---|---|
| 门禁①/② **静默 skipped** | `build/edgecompare` 不在位 ⇒ 门禁不跑、报告照常打印 | 前置入口第 4 项单独确认它在位可执行；现在改成**硬门禁** |
| 缺采集器/比较器**静默降级** | 缺口被当成"没问题" | 前置入口 + 矩阵层硬门禁 |
| 记录条数不齐 | 续跑 / 崩溃导致少条 | `record_counts_ok` 硬断言，`records_missing_for_selected` 如实报出 |

### 5.3 基线活跃集：**按「基质 × 取数权限」如实声明**（v1.1 改写）

#### 5.3.1 两个基质的 `B` 实测值（**两套都留档，都不许写死**）

| 基质 / 取数口径 | `B` | 成因 | 证据 |
|---|---|---|---|
| **CT（LXC，`pct exec` 天生 root）** | `{EF-SELINUX, EF-APPARMOR}` | `OT-005` 类**内核面**检查项在 LXC 里**结构性不可观测** | `records-dl360-pve-20261013.jsonl` |
| **VM + 非 root 取数（`asc`）** | `{EF-SELINUX, EF-APPARMOR}` | **数值与 CT 相同、成因完全不同** —— 这是**权限伪影**（`OT-005`/`KS-012` 假失败） | Task 15 端到端 |
| **VM + root 等价取数（正确口径）** | **`{EF-NO-IDS}`** | 真实状态：AppArmor 真的在 enforcing；`prepare` 装齐六个控制 ⇒ `RS-007` **通过** | `records-dl360-qemu-20261016.jsonl` 的 `meta.expected_baseline_factors` |

**CT 侧的实测事实**（真机记录的 `meta.expected_baseline_factors_source` 逐字记录了这条理由）：

- PVE CT 是 **LXC 容器**：共享宿主内核 + 缩减的 `/proc` 视图；
- 容器内 `aa-status` 报 **`Failed to get profiles: 2`** ⇒ **AppArmor profile 视图不可用**，
  采集器读到 **0 条**；
- 靶机 CT 的 `pct config` 里既有 `lxc.apparmor.raw: audit deny /etc/shadow r,`
  （**为实验刻意加的一条 LSM 拒止规则**），而这类 LXC 级规则**不**出现在容器内的 profile 列表里。

**VM 侧的实测事实**（`RS-006` 失败 ⇒ `EF-NO-IDS`；`RS-007` 通过 ⇒ `EF-NO-SIEM` 不在链上）：

```text
$ ssh … asc-vm910 'systemctl is-active suricata; systemctl is-active aide;
                   grep -ciE "email|alert|notification" /etc/aide/aide.conf;
                   ps -eo comm --no-headers | grep -cE "^(suricata|snort|snort3|zeek|aide)$"'
suricata: failed
aide: inactive
aide.conf 告警面: 2
ps 里有无 IDS 进程: 0
```

⇒ **`RS-006` 失败**（真没有 IDS 在跑）而 **`RS-007` 通过**（`edge_target_prepare.sh` 把**真实的告警面**
写进了 `aide.conf`）⇒ **`B = {EF-NO-IDS}`**。

> ⚠️ **一个中间态也必须留档**：Task 16 在**没跑 `edge_target_prepare.sh`** 的裸 VM 上取到的是
> `{EF-NO-IDS, EF-NO-SIEM}`（那时 `RS-007` 失败）。**一次真实跑批会先跑 `prepare`** ⇒ 变成 `{EF-NO-IDS}`。
> ⇒ **`B` 只能由实测给出（§2.5 步骤 5），不许写死、也不许从别的批次抄。**

#### 5.3.2 口径四条

| # | 口径 | 含义 |
|---|---|---|
| 1 | **按「基质 × 取数权限」如实声明** | 基线活跃集 = **这套环境上事实活跃的因子**，不是"理论上应该活跃的因子"。"本来就没测到" **≠** "不存在" |
| 2 | **声明面 = 基线活跃集 ∪ 注入集** | `meta.expected_chain_factors`；门禁做**集合相等**断言。⚠️ **注入集要按「触发检查的耦合闭包」补全**：`trigger.EF-SELINUX = trigger.EF-APPARMOR = OT-005` ⇒ 一次注入 `OT-005` 会**同时**激活两个因子 |
| 3 | **`−30` 是「取数权限 × 基质」耦合出来的伪影，不是态势变化** | **措辞禁令**（见下） |
| 4 | **取数必须 root 等价（`sudo -n`）；拿不到就响亮失败、绝不降级** | 这是**测量语义的前提**，不是卫生习惯：不对齐权限时 80 条检查里 **10 条会翻转（双向：6 条假通过 + 4 条假失败）**，而**决定 `B` 的那两条恰在其中**。**不许**用"改判据语义"（例如把"跳过"当成通过）去掩盖它 |

#### 5.3.3 ⚠️ 措辞禁令（**两条，违反即方法论错误**）

1. **禁止**把"某个控制项本应拒止、而环境未报出该因子"描述成
   **"系统被削弱了 30%"**（或任何等价的减法/百分比表述）。
   **为什么**：那是**测量伪影**，**不是**安全态势的变化。把它当成态势变化，等于让论文的核心结论退化成
   **"因为观测不到，所以更安全"** —— 这是**自证式的伪结论**。
2. **禁止**再写 **"VM 基质上不存在 −30"** —— 那句把**权限**与**基质**混在了一起，
   而真机实测表明它在**现行 qemu 基质（非 root 取数）上原样复现**。

**正确表述（照抄这一段）**：

> **「−30 由取数权限产生，在 CT 上被基质形态掩盖。」**
> `pct exec`（CT 基质）在容器里**天生以 root 执行**，而 VM 基质 `ssh` 登录的是 cloud-init 建的 `asc`。
> ⇒ 在 CT 上它因"天生 root"而看不见（真正的成因是 LXC 内核面不可观测），
> 在 VM 上它因"默认登录用户非 root"而原样复现（成因是权限）。
> **对齐取数权限（root 等价）之后，`OT-005` 与 `KS-012` 都通过、−30 消失。**

**Task 13 里仍然成立的部分（**与权限无关**）**：VM 上 AppArmor **真能 enforce**、
装包**直接 `apt-get install` 就行**、`systemctl`/`auditd` **正常**、SELinux 不可用（与基质无关）。

### 5.4 两套基质的数据**不可混用**

`meta.observation_target` 会写出基质类型。同一场景在**不同基质**上的
基线活跃集、可观测面、甚至 `compromised` 判定都可能不同 ⇒
**跨基质合并统计没有意义**。全量批次统一在**一种**基质上跑（按裁定：**VM**）。

**唯一的判据**（照抄）：

```text
meta.observation_target = "node:<vmid> (substrate=qemu, hostname=<name>)"     ← VM 基质
meta.observation_target = "node:<vmid> (substrate=pve,  hostname=<name>)"     ← CT 基质
```

⇒ **任何 `substrate=pve` / `substrate=lxd` / 裸名字的记录都不是 VM 基质的数据。**

⚠️ **同一条边界还有第二个维度**（v1.1 新增）：**"采自哪种基质"只说了半件事，另一半是"谁在读"**
（取数权限）。同一台 VM、同一份二进制，`asc` 与 `root` 两种取数下的**失败检查条数**与**基线活跃集**
都可能不同 ⇒ 比较"失败条数"这类量之前，**先确认两边的取数权限相同**。

**落地状态**：全量批次（22 场景 / 33 实例）已在 **VM 基质**上跑完，数据入库见 §4.6；
CT 基质的 11 条记录**保留在仓库里作为历史证据**（它们同时是"链重复与基质无关"的对照证据）。

---

### 5.5 拟合与选模怎么复跑（Task 24 = 计划 Task 6）

> **只用离线数据 + `build/edgecompare`，不起 VM、不碰 Caldera**（本任务全程在仓内数据上完成）。

```bash
# 0) 先建二进制（与门禁①用的是同一个）
GOPROXY=https://goproxy.cn,direct go build -tags edgeexp -o build/edgecompare ./cmd/edgecompare

FACTORS='EF-002FA=0.70,EF-SYNCOOKIE=0.75,EF-SELINUX=0.80,EF-APPARMOR=0.82,EF-NO-SIEM=0.90,EF-NO-IDS=0.88,EF-3FA=0.82'
EDGES='EF-SELINUX|EF-APPARMOR,EF-NO-SIEM|EF-NO-IDS,EF-002FA|EF-3FA,EF-SELINUX|EF-002FA,EF-SYNCOOKIE|EF-NO-IDS'
DATA=lunwen/clab-lab/data/edgefactors

# 1) 四候选对比（主判据 = 决策层：漏判率 → 误阻断率 → AUC → 字典序）
./build/edgecompare -records $DATA/records-dl360-qemu-20261016.jsonl \
  -candidate legacy=configs/edgeexp/m0-baseline.ini -candidate vector=configs/edgeexp/vector.ini \
  -candidate graph=configs/edgeexp/graph.ini  -candidate chain=configs/edgeexp/chain.ini \
  -factors "$FACTORS" -weights attack_surface=35,business_continuity=25,operation_trust=25,resilience=15,kernel_security=10 \
  -out $DATA/compare-20261021.md

# 2) 拟合（**权威口径：按实例重抽**）
./build/edgecompare -records $DATA/records-dl360-qemu-20261016.jsonl -fit \
  -config configs/edgeexp/graph.ini -factors "$FACTORS" -edges "$EDGES" \
  -seed 20261021 -folds 3 -group-by scenario -out $DATA/fit-20261021.md
```

- **`-group-by scenario` 不是可选项**：矩阵的两臂（`policy_on=1/0`）读数与分数**逐项相同、只差标签**
  （§5.4 的 limitation）。按**行**切折时同一实例的两臂会同时进训练与验证 ⇒ 泛化误差被系统性**估低**
  （实测同一批数据：逐行 CVErr **3.491897** vs 按实例 **0.693147**，后者正是常数预测器的 `ln 2`）。
  缺省（不给 `-group-by`）仍是逐行口径，**报告头会写明"逐行"**——读到那一行就该知道这不是权威口径。
- **产物三件套**（参数可复现性 = 三件齐出，spec §5.2）：
  `fit-<date>.md`（拟合报告 + `[edge_factors.model]` 段）、`params-<date>.ini`（该段单独成文件）、
  `params-<date>-factors.ini`（`[edge_factors]` 段 —— **离线工具不读它**，不归档就复现不出来）。
  另有 `fit-<date>-rowlevel.md`（逐行对照）与 `fit-<date>-diagnostics.md`（共线性/秩/VIF 的独立复算）。
- **两条拟合纪律（违反即结论作废）**：
  1. `-l1` **默认关闭**，且**不得**用它"解释边强度"：本设计上点估计已是 0（设计矩阵秩亏），
     罚项无从再推高任何系数；而在共线夹具上**中等 L1 反而把耦合系数推高**（0.453→0.664→0.918）⇒
     "`L1 > 0 ⇒ 耦合更小`"是**假命题**。
  2. **不得为迁就实现而放宽偏置阈值**（`TestFitCouplingIsUnbiasedAcrossSeeds` 的 `0.08`、
     `fitDefaultL2 = 0.01`）。要动就动默认值本身并重新论证，**不是**调阈值让绿灯回来。
- **怎么读 NULL**：本次四候选三层判据逐位相同（一致率 0.500 / 漏判 0 / 误阻断 0.500 / AUC 0.500）
  ⇒ **不选模**。原因不是"模型太像"，而是**设计矩阵秩亏**（22 条 → 5 个不同设计行、13 个参数）。
  此时正确的写法是「决策层无法区分四候选」+ 降级选择原则（design §9.1 第 5 条），
  **不许**硬选一个再编故事，也**不许**把它写成"耦合很弱"。
- **`-fit` 也会拒坏输入**（Task 24 Step 0 起）：记录缺了"被加权的域分"或"拟合特征域（`DefaultDomains ∩ λ`）"
  的观测分 ⇒ `exit=1`，与对比路径同口径同措辞；不会再被记成"没有可用的标签"。

---

## 6. 常见坑（**逐条都是实测踩出来的**）

### 6.1 缺采集器/缺比较器会**静默降级**（现已是硬门禁）

`build/edgecompare` 不在位时，门禁①/② **静默 skipped**，而报告**照常打印**。
⇒ 现在的判据：前置入口第 4 项**单独**确认它在位且可执行。

### 6.2 残留 agent

C2 里会积累历史 agent 记录。判据必须能区分**本次新起**与**上一轮残留**：

```text
host + trusted + (pid ∈ 容器内当前活 sandcat) + (last_seen ≤ EDGEEXP_AGENT_FRESH_S)
```

残留**不会**让 operation 打错人（新鲜度判据会滤掉死 paw），
但它会**污染每份产物里的 link 统计** ⇒ 前置入口把它列为**必须看见**的一项。

### 6.3 ⚠️ Go 文件名里的 `_<GOOS>` / `_<GOARCH>` 后缀 = **隐式构建约束**

**这是本项目踩过的、最隐蔽的一枪**：

- 把测试文件命名成 `policy_arm_test.go` ⇒ `_arm` 被 Go 解析成 **GOARCH=arm**
  ⇒ 在 **amd64 上整个测试文件被静默忽略、不报错**；
- 表现是 **"用例写了但根本没跑"** —— 测试全绿，但那个文件一行都没执行。
- **规则**：凡文件名以 `_arm` / `_386` / `_amd64` / `_arm64` / `_linux` / `_windows` /
  `_darwin` 等**已知 GOOS/GOARCH 名**结尾的都要改名（本例改成 `policy_arm_meta_test.go`）。
- **判据**：`go test -v` 的输出里**能看见用例名**。看不见 = 没跑。

### 6.4 ⚠️ `pct exec` 传多行 `sh -c` 会**静默无输出**

⇒ 要执行的脚本**推进容器再执行**，不要用 `pct exec` 灌多行。
相关的第二条：`dpkg-query -f='${Status}'` 经 `pct exec` 时要写成 `\${Status}`
（宿主侧的单引号会把它吃掉，导致轮询**永不退出**）。

### 6.5 ⚠️ CT 里的"容器默认网关"是**路由器**，不是宿主

实测：容器内 `ip route` 的 `default via` 指向 **`<mgmt-gw>`（路由器）**，
而宿主是 **`<pve-host-ip>`**。
⇒ 用网关拼 C2 的 URL 会让"C2 自证"回 **`000`**，整轮在**"容器内问不到 C2"**处失败。
⇒ **必须**用共享的 `ct_reachable_host_addr()` 一类帮助函数取宿主地址。

### 6.6 ⚠️ 判 `rc` 时 `cmd | tail` 读的是**管道的 rc**

```bash
bash foo.sh | tail -20 ; echo $?      # ← 这是 **tail** 的退出码，不是 foo.sh 的
bash foo.sh > out 2>&1 ; rc=$?        # ✅ 正确
bash foo.sh | tail -20 ; echo "${PIPESTATUS[0]}"   # ✅ 也可以
```

**为什么记这一条**：它会让"NO-GO"被读成"GO"，是**最廉价也最致命**的一类误判。

### 6.7 ⚠️ `go` 构建在隔离网段里拉不动 module

本机实测 `go env GOPROXY` 是默认的 `https://proxy.golang.org,direct`
⇒ 在管理 VLAN（**与外网不互通**）上**拉不动**。
`edge_prebatch_check.sh` 自己会把 `GOPROXY` 置为 **`https://goproxy.cn,direct`**（可被环境覆盖）。
若你的环境连镜像也不可达 ⇒ 预先 `go mod download` 把 module cache 带进来（见白皮书 §5.4.2）。

### 6.8 ⚠️ 跑批前必须确认"生效二进制 == HEAD 构建"

见白皮书 §5.4.3。**判据**：前置入口第 1 项。**不要**只看"HEAD 的二进制能落三键"。

### 6.9 干跑 ≠ 能跑

见 §2.4。典型形态：**缺剧本名时 25 个场景干跑 `rc=0`，真跑在攻击步被拒**。

### 6.10 历史脚本的"路径算错一层"问题

入口脚本按**自身位置**解析仓库根（`$SCRIPT_DIR/../../..`）。
**曾经写成两层** ⇒ 落成 `<repo>/lunwen` ⇒ 四项前置**全部**指向不存在的路径，
一运行就"全红"。**这类"入口自己算错位置"的错只有真跑一遍才会现形**。

同类形态还有一处**死变量**：`edge_agent_preflight.sh` 里有个 `REPO_ROOT`
**同样少算一层**，因为**无人使用**所以从未现形（见 §7）。

### 6.11 夹具在 Windows/Git Bash 下的环境性失败（**不是回归**）

六组离线夹具是 **Linux bash** 夹具。在 Windows + Git Bash 下会因环境差异红掉，**与代码无关**：

| 组 | Windows 下的表现 | 根因 |
|---|---|---|
| `lab-diff` | `rc=2`，通过数 0 | 需要 `unshare -rm`（私有 `/tmp`）；Windows 上不可用，夹具**自己**报"本机不可用" |
| `test-chain-derivation` | 通过数 2（期望 8） | `python3` 不在 Git Bash 的 PATH 上 |
| `test-matrix-classification` | 通过数 0（期望 12） | 同上（判据用 `python3` 解析 JSON） |
| `test-edge-lab` | 通过数低于期望 | 唯一那一格 diff 到的是 `python3: command not found` 的**路径文本差异**，不是断言差异（**另**：本机 Git Bash 的 `POSIXLY_CORRECT` 会让 `grep -E` 退回 BRE，`+`/`?` 变成字面量 —— 见 §6.18） |

⇒ **判据结论**：夹具的**权威执行环境是 Linux**（在跑批工作区或等价 Linux 环境里跑）。
Windows 下跑出来的红**不能**当成回归，也**不能**当成"绿灯"。
**权威的期望值是 Linux 上的那一组**（见 §7 第 5 条）。

---

### 6.12 ⚠️ `ssh` 会把命令**拼格**（qemu 基质里最隐蔽的一枪）

`ssh <主机> <argv…>` **不保留 argv 的格边界**：它把 `-- <主机>` 之后的**所有格用空格拼成一个字符串**，
交给**客人侧的登录 shell** 再分词。而 `docker exec` / `lxc exec --` / `pct exec --` 都是**原样转交**的。

**症状（实测原文，同一台 VM、同一份二进制，只差这一层写法）**：

```text
$ ssh … -- asc-vm910 sudo -n bash /tmp/asscor-edge-vm-guest.sh net-report ens18
iface=ens18 cidr=192.168.1.3/24
default=default via 192.168.1.1 dev ens18 proto dhcp src 192.168.1.3 metric 100
A rc=0                                     ← 正常形态

$ ssh … -- asc-vm910 bash -c "sudo -n bash /tmp/asscor-edge-vm-guest.sh net-report ens18"
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user] …
B rc=1                                     ← 原实现发出的形态：sudo 收到的 argv 是空的
```

**真因**：那对引号**在传输中不存在**。客人侧登录 shell 拿到裸的
`bash -c bash -c rm -f /tmp/x` 并重新分词 ⇒ `bash` 的 `-c` 脚本只有**一个词** `bash`，
其余全成位置参数 ⇒ **真实执行的是无参 `bash`（读 stdin），命令一次也没跑，而 rc 还是 0**。

**修法**：用 `printf '%q '` 把 argv **逐格引用**后拼成**一格**交给 ssh（在 `lab_target_exec` 的 qemu 分支里）。
`lab_target_exec_detached` 同因同修（否则起的是一个**没有命令的后台 shell**，症状与"agent 起不来"完全同形）。

**为什么这条活了三个任务才被发现**（**值得记住的元教训**）：
这条路径**从来没跑到过**（`edge_reset.sh` 当时没有 qemu 分支），而**离线夹具也放过了它** ——
I 段的假 `ssh` 只记账、I-F 段的假 `ssh` 把 argv **逐格转交**（那是 `docker`/`lxc`/`pct` 的语义，
**不是 `ssh` 的**）⇒ **夹具与代码共享同一个错模型**。
⇒ **修夹具与修代码同等重要**：现在有一条 **I-E 行为判据** —— 假 `ssh` **照实模拟真 ssh**（拼格后交给本地 shell），
判据是"**副作用真的发生了**"，它在旧实现下**必红**。

### 6.13 ⚠️ 客人网卡实名是 `ens18`，**不是 `eth0`**

PVE 的 virtio 网卡在客人里按 PCI 槽位取**可预测名**。写死 `eth0` 的症状**极具误导性**：

```text
edge_vm_provision: VM 910 的 guest agent 没能报出 eth0 的 IPv4 ——
edge_vm_provision: 取不到 VM 910 的客人 IP
（而 agent 是好的、IP 就在那儿：qm guest cmd 910 network-get-interfaces → ens18=['192.168.1.3', …]）
```

**报错文案把根因指到了 agent 身上**，真因是"网卡名不对 ⇒ 过滤条件恒真 ⇒ 永远取不到 IP"。
⇒ 走 `EDGEEXP_VM_GUEST_IFACE`（默认 `ens18`）+ `eth0` 兜底，**仍以名字精确匹配优先**
（多网卡时不锁到管理 VLAN 那条不通的路）；名字全不匹配才回退用唯一非环回 IPv4，
且把"回退到了哪个网卡"打到 **stderr**（**回退必须看得见**）。

### 6.14 ⚠️ `scp -l <用户>` 是**带宽上限**，不是登录名（**端到端从来没跑通的直接原因**）

`ssh -l <用户>` = 登录名；**`scp -l <值>` = 带宽上限**（要数字）。
而这两个命令**共用**同一组连接参数（`qemuSSHConnArgs` / `lab_ssh_conn_args`）。
用 PATH 上的壳逐格抓到过真实 argv：

```text
scp … -l asc … → usage: scp [-346ABCOpqRrsTv] …     （失败）
scp … -o User=asc … → rc=0，文件落到客人 /tmp，权限 0755   （成功）
```

⇒ **统一用 `-o User=<用户>`**（对 `ssh` 与 `scp` 语义唯一，故这一格共用是安全的），
并在用例里**钉死**这一格（改回 `-l` 必须让用例红）。
⚠️ **bash 层与 Go 层是两份实现**（一侧 bash、一侧 Go，没有共享代码的手段）⇒ 曾经只改了一侧。

### 6.15 ⚠️ `qm set` 在单个 SSH 会话里被中断时**只有前几条落盘**

实测：把 8 条 `qm set` 串在一个 SSH 会话里，会话超时被中断 ⇒ **只有前几条落盘** ⇒
VM 用 `-m 512`、**没有网卡**、**没有 agent** 起来了（`ps` 里能看到 `-m 512`、`-smp 1`）。
**症状是"SSH 一直连不上"，而真正的原因是"配置压根没写进去"。**
⇒ `edge_vm_provision.sh` 里**每一步都读回配置再继续**；排查时用 `qm config <vmid>` 逐条核对。

同族第二枪：**`--ide2` 必须走受管存储**。PVE 9 起 `qm set --ide2 <裸绝对路径>,media=cdrom` 报
`unable to associate path … to any storage`；`readonly=1`/`ro=1` 都**不是** ide2 的合法属性
（`property is not defined in schema`）。而 `dir` 存储的 ISO **不在 `<path>/iso/` 而在 `<path>/template/iso/`** ——
放错目录的症状是 `volume 'asscor-vmseed:iso/<名>' does not exist`（看着像"文件没了"，其实 ISO 已经生成好了）。

### 6.16 ⚠️ 同名重建：清 host key 要清 **IP**，不只是清名字

`--destroy` 后再用同一 vmid/名字重建，**客人 host key 会变**，而 `StrictHostKeyChecking=accept-new`
**只接受新主机、不接受变更后的主机** ⇒ 两边都炸：

```text
@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@
Host key for asc-vm910 has changed and you have requested strict checking.
Host key verification failed.
```

- **`wait_ssh` 是按 IP 连的**（那一刻 `/etc/hosts` 还没写），而 PVE 通常把**同一个 IP** 再分给新 VM
  ⇒ **只清名字不够，必须一并清 IP**（实测：不清就死等满 300 s 超时）；
- 处置**不削弱检查**：新增 `EDGEEXP_VM_KNOWN_HOSTS`（默认 `/root/.ssh/asscor-edge-vm_known_hosts`），
  建机侧在**新建 VM 之后、开始连它之前** `ssh-keygen -R <主机/ IP> -f <我们那一份>`
  （**只清这一个主机、只清我们那一份文件**，不动 `~/.ssh/known_hosts` 里别人的）；
  **取数侧（Go）与基质层（bash）都显式 `-o UserKnownHostsFile=<同一份>`**。
- **为什么不改成 `StrictHostKeyChecking=no`**：那会把**真的**中间人也一起放过。

### 6.17 ⚠️ 投送组必须**本机独占**，否则标签串味

宿主上长期有 CT 904 的遗留 agent（`asc-tgt-c2`）。若 VM 靶机与它**同组**（且心跳新鲜），
operation 会**同时**打在两台机器上，而 `compromised` 只看"目标 ability 的 link 里有没有 `status==0`"、
**不看 paw 属于哪台机器** ⇒ 一条"CT 上成功"的 link 会把 VM 臂的标签写成 `compromised=true`
（**策略在的那条臂也会**），**两臂读数相同**、而记录看起来完全正常。
⇒ 给**本轮的靶机**单独分组（`EDGEEXP_TTP_GROUP`/`EDGEEXP_ATTACK_GROUP` = 一个**只有这台 VM 用**的组名）。

**同族的两个坑**：

- **投送范围闸门②曾经是死代码**：它的判据基于一个**已经按目标主机过滤过**的列表 ⇒ 恒为空集、
  **永远不会红**。修后的判据是"该组里有没有**别的机器上 trusted + 心跳新鲜**的 agent"。
- **活 agent 判据不含投送组** ⇒ 换组名后 `prepare` 会静默沿用旧组、走幂等路径不重拉，
  随后攻击侧以「投送组 X 里没有一只活 agent」失败，而那句提示让操作者"先跑 `edge_reset.sh`"——
  **重跑复位什么也不会做**。修法：活 agent 判据补上投送组这一条（空串 = 不过滤 ⇒ 旧行为逐字不变）。

### 6.18 ⚠️ 批次必须**一次调用跑完**（`REPEAT=1` 的记录条数门禁）

`edge_matrix.sh` 的记录条数门禁在 `REPEAT=1` 时比的是 **"整个记录文件的行数 == 本次实例数"**，
而 `EDGEEXP_RESUME=1` 只影响**逐实例循环**、**不影响**这条门禁
⇒ **拆成多次调用时，第 2 次起文件里已经有前一次的记录 ⇒ 门禁永远红**。
**要分批就必须分批换记录文件**（或用 `REPEAT>1`）。

> **`REPEAT>1` 走 `edge_repeat.sh`**（§3.4）：它把同一段的 N 遍写进**同一份**记录文件，
> 于是这条门禁按 "文件行数 == 实例数 × 重复号" 自然成立；
> 但"一份文件只装一段"仍是硬要求 —— 两段（targeted / 非 targeted）各给一份 `EDGEEXP_RECORDS`。

**同族的第三条（R 组结构性不满足）**：`R-no-siem` / `R-no-2fa` 的语义是"目标机上**真的没有**这个防护"，
而 `edge_attack.sh` 对 R 组有一条硬闸门：**真实缺失必须成立**（"不得用注入失败顶上"）。
`edge_target_prepare.sh` 按设计**装齐六个控制**并写告警面 ⇒ 这两个场景在**装齐控制的靶机上
结构性不满足**，闸门会在**建 operation 之前**整轮失败。⇒ **不入批次，理由是"不可能产出记录"**，
而不是"跑起来太难"：把它们塞进批次会让 `REPEAT=1` 的条数门禁**必然为红**，
连门禁①/② 都拿不到。`R-no-ids` **相反**：真实缺失**成立**（suricata failed、无 IDS 进程）⇒ 可以跑。

**同族的第四条（环境相关）**：本机 Git Bash 设了 `POSIXLY_CORRECT` ⇒ **`grep -E` 退回 BRE 语义**，
`+` / `?` 变成**字面量**（实测：`grep -E 'ssh (-o [^ ]+ )+-- …'` 对**完全匹配**的行报 NOMATCH）。
**Linux（宿主/CI）没有这个变量 ⇒ 同一份夹具在两边行为不同。**

### 6.19 ⚠️ 别把 C2 地址指到一台「什么请求都回 200」的假服务

本项目历史上真的出现过这一幕：为了做**脱敏回归判据**（"未设 key 时脚本必须 `rc=2` 且 C2 收到 **0** 个请求"），
现场起过一台**伪 C2**（一个只回 `200` + `[]` 的小脚本），而它**比真 C2 先起来**
⇒ 后来有人改 **env** 或手工导出时把 `EDGEEXP_CALDERA_URL` **指到了它**。

**它不会让跑批静默跑错**（agent 表恒为**空** ⇒ `edge_attack.sh` 会在"Caldera 里一条 agent 都没有"处**响亮失败**），
但它会让**复位步骤的 `ensure_caldera` 通过**这件事变成**假绿** —— 而那一格正是"环境对不对"的自证。

**三个判据（任一条命中就要怀疑地址给错了）**：

```bash
# ① 带不带 KEY 都 200 ⇒ 它根本不是真 C2（真 C2 不带 KEY 在 CT/客人侧回 401）
curl -s -o /dev/null -w '%{http_code}\n' -H "KEY: $EDGEEXP_CALDERA_KEY" "$EDGEEXP_CALDERA_URL/api/v2/abilities"
curl -s -o /dev/null -w '%{http_code}\n' "$EDGEEXP_CALDERA_URL/api/v2/abilities"
# ② agent 表恒空（连历史残留都没有）
curl -s -H "KEY: $EDGEEXP_CALDERA_KEY" "$EDGEEXP_CALDERA_URL/api/v2/agents"
# ③ 监听地址对不对（真 C2 绑在**宿主**的管理 VLAN 地址上，不是 127.0.0.1）
ss -ltnp | grep ':8888'
```

**处置**：把地址改回**真 C2**（`edge_c2_key.sh` 是取值的唯一入口），
并**把假服务停掉** —— 留着它只会让"下一次有人改错"这件事继续可能发生
（脚本本身可以留在磁盘上，重建是一条命令）。

---

## 7. 已知问题与未修清单

| # | 问题 | 影响 | 现状 |
|---|---|---|---|
| 1 | **`cmd/edgescen` 的一处 flaky 测试**：`TestCollectChecksForTargetDefaultsToLocalHostChecks` 断言 `ot001()` 的 `Detail` 串**逐字相同**，而 `internal/checks/linux/checks.go`（约 707 行）**遍历 map** ⇒ 顺序随机 | 起点树上 20 次跑 **7 红 13 绿**（`4fc5859` 干净工作树上也曾 4 次红 3 次）。**不止是测试问题**：该 `Detail` 会进落盘记录的 `checks[].detail` ⇒ 同一状态两次采集**写出的字节不同**，"数据可复现"失效 | ✅ **已修（Task 14 / `cb14060`）**：map → **有序切片**（输出格式逐字不变），同类点 `as012()`/`as010()` 各补一条 `sort.Strings`；新增 `determinism_test.go`（连调 50 次逐字相同 + 声明次序）。实测：起点树新判据 5/5 红、修好后 20/20 绿 |
| 2 | `edge_agent_preflight.sh` 里的**死变量 `REPO_ROOT`** | 变量**无人使用** ⇒ 无实际影响；但它"少算一层"（`../..` 只到 `<repo>/lunwen`） | ✅ **已清（Task 14 / `2dac30d`）**：**删除**（不是改对 —— 改对等于凭空造一个"看起来可用"的仓库根），原处留一行注释说明 |
| 3 | `edge_prebatch_check.sh` 的 `EDGEEXP_HEAD_CHECKOUT` **默认值陈旧**（`/root/t6/t8/head`）与**判据认不出 worktree** | 对一份**完全正常**的 worktree 误报 NO-GO（控制侧实测 rc=1） | ✅ **已修（Task 14 / `6e11fa0`）**：判据改 `git -C … rev-parse --git-dir`（认 worktree）；**删掉默认值**（缺 ⇒ 响亮失败并给示例）；"脏检出判红"保留。见 §2.3.1 |
| 4 | `lunwen/clab-lab/scripts/` 里若干历史脚本的**默认值仍有内部标识**（网段/主机名/C2 默认口令） | 口令类已清零；网段/主机名按审计归档 §E.2 的口径**保留**（是"必须带地址才读得懂"的踩坑注释） | C2 口令：✅ **已处置完（Task 14 / `e282f19`）** —— 18 个文件，判据 `git grep -I -n -e '<明文>'` = 0；网段/主机名：**保留项**（见审计归档 §E.2 + Part F 的 F1/F2） |
| 5 | 六组夹具在 Windows 下不可全绿（§6.11） | 只影响开发机；不影响 Linux 上的权威执行 | ✅ **已在 Linux 上验证**：干净检出上 **`6/83/20/31/8/12` 全绿、`run-all.sh` rc=0**（Task 14/16/17 逐步更新期望值：`test-edge-lab` 51 → 73 → 78 → **83**，每次改动都给了理由与原始输出） |
| 6 | `gofmt -l` 在**起点上**就不是空的：**15 个既有**文件（`prism-lib/*` 9 个、`ssam-lib/*` 5 个、`lunwen/attachment/scripts/exprunner-main.go` 1 个） | 与各次改动无关；属**既有**失败 | ⏳ **未修**（**另开任务**）：判据是"`gofmt -l` 的**差集**必须为空"—— Task 18 在起点 `8ae3c4b` 与 HEAD `4c1ab06` 上各跑一次，**都是 15 行、差集为空** |
| 7 | **"跳过的检查算通过"这条口径本身**（非 root 取数时 6 条检查 `detail = "skipped — requires root privileges"` 却算 `passed=true`） | **双向失真**：非 root 取数下既**假失败 4 条**、又**假通过 6 条** | ⏳ **已登记、不改**：改动属**判据语义变更** ⇒ 会让所有既有数据的口径失效（要整体重采）。**现行处置是"取数必须 root 等价"**（§5.3.2 第 4 条），从**测量侧**消除它 |
| 8 | **门禁⓪ 只报不判死** | 链上的重复条目会被如实报出但不拦；**若收紧就是判据变更** | ⏳ **维持现状**：Task 18 已把"重复为什么会出现、对 `L_d` 有什么后果"查清并修复（折叠点在**消费侧**，链与配置**不动**）；收紧门禁需**先裁定** |
| 9 | **Task 10 的拟合系数**（离线 `-fit` 的产物） | Task 18 顺带统一了 `fit.go:design()` 的**静默 last-wins 折叠**（真机取到 custom 的 `0.85` → 现在用**文档化的 0.70**）⇒ **旧系数是在"未文档化的 0.85"上算的** | ⏳ **只登记、不重跑**：论文若要引用**拟合出的耦合系数**，**必须重跑 `-fit`**（重跑成本 = 分钟级，但会改结论数值） |
| 10 | **重复轴第 2/3 遍**（`EDGEEXP_RUN_INDEX=2,3`） | 本批最初只放了第 1 遍（`run=1`） | ✅ **已跑（Task 21，数据 Task 22 入库）**：两段各 3 遍 —— targeted 段 66 条、非 targeted 段 33 条，均 `record_counts_ok=true`、门禁② 偏差 0（非 targeted 段的门禁① 属"不适用"，见 §5.1.1）。**第 4 遍起仍未跑**（另一次长批次） |
| 11 | **`--count N` 多机拓扑** | 接口已留（`EDGEEXP_VM_SSH_HOST` 含 `%s` 按 vmid 展开），**真机上未验** | ⏳ **未实测**：本批只起 1 台 VM（内存账见白皮书 §5.3 乙）；"中重型拓扑"是后续里程碑 |
| 12 | **`edge_probe.sh` 在 qemu 上不是 root 等价** | 探针经 `lab_target_exec`（登录用户 `asc`）执行，而**取数是 root 等价** ⇒ `condition_probes[].condition_holds` 与 `checks[]` 在 VM 上**可能不一致**（例：`EF-APPARMOR` 的探针走 `aa-status`，`asc` 下 rc=4） | ⏳ **未改**：改它要动 `edge_probe.sh` 与它的 20 条离线判据（**判据语义变更**）。对 S 组不阻断，但它**不是**一致证据 |
| 13 | **`run.d/` 的清理会毁掉上一轮的碎片证据** | `edge_matrix.sh` **每轮开始时清 `run.d/`** ⇒ 小批验证的 `collect-*.json` 在随后启动的全量批次里被清掉 | ⏳ **未改**：**记录本体不受影响**（那是权威产物）。建议把证据目录与运行目录分开（或按 run_id 归档） |

> **注意**：第 1、2、3、4 条原本是**代码/脚本缺陷**，Task 12（文档任务）只登记不改；
> **Task 14 受命修掉了它们**（第 4 条的网段/主机名部分仍是保留项）。第 6 条是 Task 14 新登记
> 的**既有**失败。

---

## 8. 附录：环境变量全表

### 8.1 基质与标识

| 变量 | 默认 | 必需性 | 含义 |
|---|---|---|---|
| `EDGEEXP_SUBSTRATE` | `clab` | **强烈建议显式** | `docker`/`lxd`/`clab`/`pve`/**`qemu`** |
| `EDGEEXP_ENV` | 由脚本推 | `REPEAT>1` 时**必需** | 环境标签（进文件名与 `meta.env`） |
| `EDGEEXP_TARGET` | `asc-asscor-host1` | 建议显式 | **被攻节点名**（基质层的名字）。`qemu` 下 = **VM 的 hostname**（Caldera 的 `host` 字段就是它） |
| `EDGEEXP_DATA_DIR` | `<仓库>/lunwen/clab-lab/data/edgefactors` | 可选 | 产物落点 |
| `EDGEEXP_RUN_ID` | `<date>-<pid>` | 可选 | 运行标识 |
| `EDGEEXP_RESUME` | 未设 | 可选 | `1` = 续跑（跳过已有记录的场景） |

### 8.2 C2 与 TTP

| 变量 | 默认 | 必需性 |
|---|---|---|
| `EDGEEXP_CALDERA_URL` | 脚本默认（脱敏） | 建议显式 |
| `EDGEEXP_CALDERA_KEY` | **无默认值**（Task 14 已把明文默认值移除） | **必需**（缺 ⇒ 脚本 `exit 2`；前置门禁记 NO-GO） |
| `EDGEEXP_TTP_TARGET_ABILITY` | 空 | **必需**（`targeted_ttp`） |
| `EDGEEXP_TTP_TARGET_ABILITY_NAME` | 空 | 可选（核对 ID 没被换掉） |
| `EDGEEXP_TTP_CONTROL_ABILITY` | 空 | 可选（只用于归类与报告） |
| `EDGEEXP_TTP_PLAYBOOK_ID` | 空 | **必需** |
| `EDGEEXP_TTP_PLAYBOOK_NAME` | 空（有脚本内默认，**会导致漂移**） | **必需**（见 §6.9） |

### 8.3 三维度与条件

| 变量 | 默认 | 含义 |
|---|---|---|
| `EDGEEXP_POLICY_ON_ARM` | `1` | `1` = 每个 targeted 场景两条臂；`0` = 与旧行为逐字节相同 |
| `EDGEEXP_RUN_INDEX` | `1` | **重复号**；`>1` 时进 `meta.repeat`，实例键加 `-r<N>` |
| `EDGEEXP_POLICY_ON` | — | 单实例的**策略开关**（arm 由矩阵设置，一般不要手改） |
| `EDGEEXP_BASIS` | — | `targeted_ttp` / `recon_playbook`（由矩阵按场景声明**成对设置**） |
| `EDGEEXP_TTP_FACTORS` | `EF-SELINUX,EF-APPARMOR` | 判定"该场景是否 targeted"的因子集 |
| `EDGEEXP_BASELINE_FACTORS` | — | **基线活跃集**（按基质如实声明，见 §5.3） |
| `EDGEEXP_ATTACK_GROUP` | — | 场景的 ATT&CK 组 |

### 8.4 路径与二进制

| 变量 | 默认 | 含义 |
|---|---|---|
| `EDGEEXP_CONFIG` | — | 采集配置（如 `configs/edgeexp/m0-baseline.ini`） |
| `EDGEEXP_EDGESCEN` | — | **生效的** `edgescen` 二进制路径 |
| `EDGEEXP_TOPOLOGY` | — | Containerlab 拓扑文件 |
| `EDGEEXP_REPO` | 由脚本自身位置推 | 跑批工作区（前置入口用） |
| `EDGEEXP_HEAD_CHECKOUT` | **无默认值**（Task 14 已删；缺 ⇒ 响亮失败并给示例） | 干净 HEAD 检出（见 §2.3.1） |
| `GOPROXY` | `https://goproxy.cn,direct`（脚本内置） | 构建时用 |

### 8.5 前置入口专用

| 变量 | 默认 | 含义 |
|---|---|---|
| `EDGEEXP_AGENT_FRESH_S` | `180` | agent 心跳新鲜度（秒） |
| `--install` | — | 先用规范配方（`-trimpath` + 干净检出）重建并安装两个二进制 |
| `--strict-agents` | — | 有残留 agent 也算 NO-GO |

### 8.6 调试

| 变量 | 含义 |
|---|---|
| `EDGEEXP_DRY_RUN=1` | 只打印将要做什么（见 §2.4 的能力边界） |
| `EDGEEXP_DOCKER_BIN` | 覆盖目标级 `docker` 二进制（两个可分辨的假 docker 可测抽象是否生效） |
| `EDGEEXP_QM_BIN` / `EDGEEXP_SSH_BIN` / `EDGEEXP_SCP_BIN` | **`qemu` 基质**下覆盖三个 CLI（离线夹具靠它们做假 CLI） |
| `EDGEEXP_PRINT_EXPECTED=1` | **只打印**每个场景的 `expected_chain_factors`（不碰 Caldera/拓扑）—— 操作者自查入口 |

### 8.7 `qemu` 基质专用（v1.1 新增；**逐格都有守卫**）

| 变量 | 默认 | 必需性 | 含义与守卫 |
|---|---|---|---|
| `EDGEEXP_CALDERA_KEY` | **无默认值** | **必需** | 缺 ⇒ 脚本 `exit 2`；前置门禁记 NO-GO（§2.3） |
| `EDGEEXP_CALDERA_URL` | 脚本默认（脱敏） | 建议显式 | **必须是宿主地址**，不是客人默认网关（§6.5 / 白皮书 §3.7） |
| `EDGEEXP_C2_HOST` | 由 URL 推 | 仅当 URL 是域名时必需 | 加主机路由要用 **IPv4 字面量**；不是字面量 ⇒ **不猜**、响亮失败 |
| `EDGEEXP_HEAD_CHECKOUT` | **无默认值** | **必需** | 干净 HEAD 检出（§2.3.1） |
| `EDGEEXP_VM_SSH_KEY` | 空 | **必需** | 私钥**路径**（内容从不进 argv/记录/仓库） |
| `EDGEEXP_VM_SSH_USER` | `asc` | 建议显式 | 客人里的登录用户 |
| `EDGEEXP_VM_SSH_HOST` | 按 vmid 推 `asc-vm<vmid>` | 可选 | 含 `%s` 时按节点标识展开 ⇒ **多机靠这条**；**刻意不做 `-o` 选项串**（那种变量会被当成 `-o` 的值，于是 `ProxyCommand` 能在操作者看不见的地方把**取数目标**改到别处） |
| `EDGEEXP_VM_SSH_PORT` | `22` | 可选 | SSH 端口 |
| `EDGEEXP_VM_KNOWN_HOSTS` | `/root/.ssh/asscor-edge-vm_known_hosts` | 建议显式 | 专用 known_hosts（§6.16）。目录不可用 ⇒ **响亮失败** |
| `EDGEEXP_VM_SSH_SUDO` | `sudo -n` | **必需** | 取数**必须 root 等价**。每一格只收 `A-Za-z0-9_./:+-`；含空白/分号/反引号/`$` ⇒ **响亮失败**（不做"清洗后继续"） |
| `EDGEEXP_VM_GUEST_IFACE` | `ens18`（`eth0` 兜底） | 建议显式 | 客人网卡名（§6.13） |
| `EDGEEXP_VM_GUEST_AGENT_WAIT_S` | `600` | 可选 | 等 guest agent 报 IP 的上限（冷启动**实测超过 240 s**，不要改小） |
| `EDGEEXP_VM_IMAGE_URL` | Ubuntu cloud image | 可选 | 建机用的镜像（已缓存在宿主 `/var/lib/vz/import/`） |
| `EDGEEXP_ATTACK_GROUP` / `EDGEEXP_TTP_GROUP` | 空 | **强烈建议显式** | **投送组必须本机独占**（§6.17） |
| `EDGEEXP_AGENT_GROUP_FOR_JUDGE` | 空（= 不过滤） | 由 qemu 路径自动传 | 活 agent 判据的第五条（§6.17） |
