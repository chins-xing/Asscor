# ASSCOR 边缘因子实验：技术文档与操作手册

> **面向读者**：**下一个人**。读完这一份 + 环境白皮书，你应该能在这台机器上
> **自己跑一遍**边缘因子实验，并**正确读出**记录里的每一个字段。
>
> **版本**：v1.0（2026-10-15） ｜ **基线提交**：`ASSCOR-Research-Core` @ `5eaedec`
> **配套文档**：环境画像见《PVE 单机实验基质白皮书》；裁定依据见《边缘因子实验审计归档》。
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
6. [常见坑（**逐条都是实测踩出来的**）](#6-常见坑逐条都是实测踩出来的)
7. [已知问题与未修清单](#7-已知问题与未修清单)
8. [附录：环境变量全表](#8-附录环境变量全表)

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
export EDGEEXP_SUBSTRATE=pve      # docker | lxd | clab | pve
```

| 取值 | 含义 | 目标节点名（`EDGEEXP_TARGET`）的形式 |
|---|---|---|
| `clab`（默认） | Containerlab 拓扑 | `asc-asscor-host1` |
| `docker` | 单容器 | 容器名 |
| `lxd` | LXD 实例 | `probe-ot005` |
| **`pve`** | **PVE CT** | **CT 的名字**，如 `asc-tgt-c2`（脚本会解析成 `pve:904`） |

> **为什么必须显式给**：`edge_prebatch_check.sh` 会在**不转发**基质时退回默认的 `clab`（docker），
> 于是它去问一个**不存在的容器**，把"看错了地方"报成 **"目标上没有活着的 agent"**。
> 这条已写进前置入口的注释，并作为硬要求执行。

**基质决定 `edgescen -target` 的语法**（唯一解析点：`edge_lab.sh` 的 `lab_target_spec`）：

```text
-target docker:<容器>   -target lxd:<实例>   -target pve:<vmid>
```

### 2.2 一份可以照抄的 env 文件（**脱敏版**）

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
export EDGEEXP_HEAD_CHECKOUT=<一个真的等于 HEAD 的干净检出>    # **不要依赖默认值**，见 §2.3
export EDGEEXP_CALDERA_KEY=<c2-key>              # 前置入口会读它；缺了必须 GO 失败

# ---- 三个维度：臂 / 重复 ----
export EDGEEXP_POLICY_ON_ARM=1    # 1 = 每个 targeted 场景两条臂（默认）；0 = 与旧行为逐字节相同
export EDGEEXP_RUN_INDEX=1        # 重复号（repetition）；>1 时才进记录的 meta.repeat
```

### 2.3 跑批前置（**唯一入口，不许绕过**）

```bash
bash lunwen/clab-lab/scripts/edge_prebatch_check.sh [--install] [--strict-agents]
```

**为什么要有这个入口**：全量扫描是 **36 个场景实例 × 3 个重复 ≈ 13 小时**。
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

#### 2.3.1 ⚠️ `EDGEEXP_HEAD_CHECKOUT` 必须显式设置（**本项目最容易中的一枪**）

`edge_prebatch_check.sh` 的默认值是 `/root/t6/t8/head`，**这个默认值已经陈旧**。
实测（2026-10-16 只读复核）：

```text
$ ls -la /root/t6/t8/head
.git  →  **一个 46 字节的文本文件**，内容：gitdir: /root/t6/t8/fresh/.git/worktrees/head

$ git -C /root/t6/t8/head rev-parse --short HEAD
042c3fe
$ git -C /root/t6/t8/head status --porcelain | wc -l
14                                   # 带未提交改动
```

而前置入口用的是 `[ -d "$HEADCO/.git" ]` —— 它把一个 **worktree 的 `.git` 文件**判成
**"不是 git 仓库"** ⇒ 直接报红。

**正确做法**（在跑批工作区里，每次跑批前）：

```bash
export EDGEEXP_HEAD_CHECKOUT=<一个 .git 是**真目录**、且 HEAD 真的 == 你当前 HEAD、且工作树干净的检出>
# 复核三件事：
[ -d "$EDGEEXP_HEAD_CHECKOUT/.git" ]                    || echo "❌ .git 不是目录（可能是 worktree，前置会判否）"
git -C "$EDGEEXP_HEAD_CHECKOUT" rev-parse HEAD          # 必须 == 你要跑的 HEAD
git -C "$EDGEEXP_HEAD_CHECKOUT" status --porcelain      # 必须为空
```

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
合计              ：36 实例
```

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

---

## 4. 怎么读记录

记录是 **JSONL**（一行一条），契约实现在 `internal/edgeexp/record.go`（**生产者与消费者共用**）。

### 4.1 顶层结构

```jsonc
{
  "scenario_id": "S1-apparmor-01",     // 场景 + 实例号
  "factors":     ["EF-SELINUX", "…"],  // 本场景**注入**的因子
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
| `meta.policy_on` | bool | **臂**：策略是否在（`false` = 卸掉策略的臂） | ❌ 条件标识 |
| `meta.observation_target` | string | **观测主体**，形如 `node:<vmid> (substrate=pve, hostname=<name>)` | ❌ 但**决定"这台机器的数据"是谁的** |
| `meta.timestamp` | RFC3339 | 该记录的时刻 | ❌ |
| `meta.config_hash` | string | 采集所用配置的指纹（**权重的锚点**） | ❌ 溯源 |
| `meta.expected_baseline_factors` | []string | **基线活跃集**（按基质如实声明，见 §5.3） | ❌ 声明面 |
| `meta.expected_baseline_factors_source` | string | **为什么**是这个基线集（逐字理由） | ❌ 声明面证据 |
| `meta.expected_chain_factors` | []string | **声明面** = 基线活跃集 ∪ 注入因子 | ❌ 声明面 |
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

见 §5.3。**一句话**：在 PVE CT 基质上，`OT-005` 一类**内核面**检查项**不可观测**，
所以基线活跃集**只能是** `{EF-SELINUX, EF-APPARMOR}`，**必须按基质如实声明**。

---

## 5. 三道门禁与"基线活跃集"口径

### 5.1 门禁清单

| 门禁 | 键（在 `run.json` 里） | 查什么 | 失败后果 |
|---|---|---|---|
| **门禁⓪** | `gate0_duplicate_factors` | 逐场景统计链里的**重复因子 ID**（`trim + upper` 归一后），区分"真实重复"与"折叠形态" | 只报不拦（**记录事实**，因为重复是出厂部署的真实形态） |
| **门禁①** | `gate1_offline_compare` | 用 `edgecompare` 对**同一数据集**离线重算，**exit_code 必须为 0** | **静默 skipped 是最危险形态**（报告照常打印 ⇒ 整轮作废） |
| **门禁②** | `gate2_round_trip` / `gate2_offline_compare` | 记录**往返**（load → marshal → load）后**逐字节一致** | 契约漂移 |
| **记录条数/集合** | `record_counts_ok`、`chain_factor_set_equality`、`records_file_agreement` | 文件行数 == 实例数 × 重复号；链因子集合 == 声明面；碎片与记录一致 | 少一条 = 有实例没采成 ⇒ 硬失败 |

### 5.2 三道门禁的历史事故（**为什么它们现在是硬的**）

| 事故 | 形态 | 现行判据 |
|---|---|---|
| 门禁①/② **静默 skipped** | `build/edgecompare` 不在位 ⇒ 门禁不跑、报告照常打印 | 前置入口第 4 项单独确认它在位可执行；现在改成**硬门禁** |
| 缺采集器/比较器**静默降级** | 缺口被当成"没问题" | 前置入口 + 矩阵层硬门禁 |
| 记录条数不齐 | 续跑 / 崩溃导致少条 | `record_counts_ok` 硬断言，`records_missing_for_selected` 如实报出 |

### 5.3 基线活跃集：**按基质如实声明**

#### 5.3.1 为什么在本基质上是 `{EF-SELINUX, EF-APPARMOR}`

**实测事实**（真机记录的 `meta.expected_baseline_factors_source` 逐字记录了这条理由）：

- PVE CT 是 **LXC 容器**：共享宿主内核 + 缩减的 `/proc` 视图；
- 容器内 `aa-status` 报 **`Failed to get profiles: 2`** ⇒ **AppArmor profile 视图不可用**，
  采集器读到 **0 条**；
- 靶机 CT 的 `pct config` 里既有 `lxc.apparmor.raw: audit deny /etc/shadow r,`
  （**为实验刻意加的一条 LSM 拒止规则**），而这类 LXC 级规则**不**出现在容器内的 profile 列表里。

⇒ **结论**：`OT-005` 一类**内核面**检查项在 CT 基质上**恒为不可观测**。

#### 5.3.2 口径三条

| # | 口径 | 含义 |
|---|---|---|
| 1 | **按基质如实声明** | 基线活跃集 = **这套环境上事实活跃的因子**，不是"理论上应该活跃的因子"。"本来就没测到" **≠** "不存在" |
| 2 | **声明面 = 基线活跃集 ∪ 注入因子** | `meta.expected_chain_factors`；门禁做**集合相等**断言 |
| 3 | **`−30` 是测量伪影，不是态势变化** | **措辞禁令**（见下） |

#### 5.3.3 ⚠️ 措辞禁令（**违反即方法论错误**）

**禁止**把"某个控制项本应拒止、而环境未报出该因子"描述成
**"系统被削弱了 30%"**（或任何等价的减法/百分比表述）。

**为什么**：那是**观测面的缺失**（测量伪影），**不是**安全态势的变化。
把它当成态势变化，等于让论文的核心结论退化成
**"因为观测不到，所以更安全"** —— 这是**自证式的伪结论**。

**正确表述**：**"该因子在本基质上不可观测 ⇒ 基线活跃集按其实际情况声明为
`{EF-SELINUX, EF-APPARMOR}` ⇒ 声明面与注入集做集合相等断言。"**

### 5.4 两套基质的数据**不可混用**

`meta.observation_target` 会写出基质类型。同一场景在**不同基质**上的
基线活跃集、可观测面、甚至 `compromised` 判定都可能不同 ⇒
**跨基质合并统计没有意义**。全量批次统一在**一种**基质上跑（按裁定：**VM**）。

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
| `test-edge-lab` | **50**（期望 51） | 唯一那一格 diff 到的是 `python3: command not found` 的**路径文本差异**，不是断言差异 |

⇒ **判据结论**：夹具的**权威执行环境是 Linux**（在跑批工作区或等价 Linux 环境里跑）。
Windows 下跑出来的红**不能**当成回归，也**不能**当成"绿灯"。

---

## 7. 已知问题与未修清单

| # | 问题 | 影响 | 现状 |
|---|---|---|---|
| 1 | **`cmd/edgescen` 的一处 flaky 测试**：`TestCollectChecksForTargetDefaultsToLocalHostChecks` 断言 `ot001()` 的 `Detail` 串**逐字相同**，而 `internal/checks/linux/checks.go`（约 707 行）**遍历 map** ⇒ 顺序随机 | 约 **2/3 ~ 3/4** 的概率红（`4fc5859` 干净工作树上跑 4 次红 3 次）；该 `Detail` **不进数据集**，不影响任何实验结论 | **未修**。修法方向：断言改为**集合比较**或对 `Detail` 排序。属代码改动，本任务不动 |
| 2 | `edge_agent_preflight.sh` 里的**死变量 `REPO_ROOT`** | 变量**无人使用** ⇒ 目前无实际影响；但"少算一层"是与 §6.10 同型的隐患 | **未清**。属代码改动，本任务不动 |
| 3 | `edge_prebatch_check.sh` 的 `EDGEEXP_HEAD_CHECKOUT` **默认值陈旧**（`/root/t6/t8/head`） | 不改它就会**误报 NO-GO**（见 §2.3.1） | **未改**（改默认值 = 碰脚本，本任务不动）。**现行处置：跑批前显式设该变量** |
| 4 | `lunwen/clab-lab/scripts/` 里若干历史脚本的**默认值仍有内部标识**（网段/主机名/C2 默认口令） | 不影响脚本可运行性；见审计归档的"脱敏处置台账" | **待裁定**（见审计归档 §待裁定项） |
| 5 | 六组夹具在 Windows 下不可全绿（§6.11） | 只影响开发机；不影响 Linux 上的权威执行 | **已知、不修**（环境差异，非缺陷） |

> **注意**：第 1、2 条是**代码缺陷**，本任务（文档任务）**按纪律不改代码**，
> 只登记在此。要修请另开任务。

---

## 8. 附录：环境变量全表

### 8.1 基质与标识

| 变量 | 默认 | 必需性 | 含义 |
|---|---|---|---|
| `EDGEEXP_SUBSTRATE` | `clab` | **强烈建议显式** | `docker`/`lxd`/`clab`/`pve` |
| `EDGEEXP_ENV` | 由脚本推 | `REPEAT>1` 时**必需** | 环境标签（进文件名与 `meta.env`） |
| `EDGEEXP_TARGET` | `asc-asscor-host1` | 建议显式 | **被攻节点名**（基质层的名字） |
| `EDGEEXP_DATA_DIR` | `<仓库>/lunwen/clab-lab/data/edgefactors` | 可选 | 产物落点 |
| `EDGEEXP_RUN_ID` | `<date>-<pid>` | 可选 | 运行标识 |
| `EDGEEXP_RESUME` | 未设 | 可选 | `1` = 续跑（跳过已有记录的场景） |

### 8.2 C2 与 TTP

| 变量 | 默认 | 必需性 |
|---|---|---|
| `EDGEEXP_CALDERA_URL` | 脚本默认（脱敏） | 建议显式 |
| `EDGEEXP_CALDERA_KEY` | 脚本默认（**已脱敏，见审计归档**） | **必需**（前置门禁会拦） |
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
| `EDGEEXP_HEAD_CHECKOUT` | `/root/t6/t8/head`（**陈旧，必须显式覆盖**） | 干净 HEAD 检出（见 §2.3.1） |
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
