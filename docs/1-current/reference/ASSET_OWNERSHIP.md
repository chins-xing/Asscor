# ASSCOR 资产归属表（`main` vs `ASSCOR-Research-Core`）

> **快照（2026-10-15 重取）**：`main` = `aef84de`、`ASSCOR-Research-Core`(ARC) = `5eaedec`
> **规模实测**：main **662** 文件 / ARC **1098** 文件；**ARC 独有 436 个**、**main 独有 0 个**
> ⇒ 两分支的文件集是**包含关系**（main ⊂ ARC），差异只有"ARC 独有"与"共有但内容不同"两种。
> **分叉点**（merge-base）= `df8342e`；此后 main **605** 提交、ARC **706** 提交。
> **本表的依据**：用户 2026-09-13 的四条分支规则（下 §0）+ 可复跑判据（§4）。
>
> ⚠️ **本节数字是快照，会随提交漂移**。要拿当前值请照 §4 的**重取命令**现算，
> **不要**把这里的数字当成现状引用。
> 📌 **上一条快照**（2026-09-13 分叉后）：`main` = `fdb116e` / ARC = `028cfd5`；
> main 661 / ARC 1014 文件、ARC 独有 353 个。两版之间 ARC 增加 **84** 个文件
> （里程碑 B 的采集器、离线工具、离线夹具与实验数据）。

---

## 0. 四条规则（本表的判据来源）

| # | 规则 |
|---|---|
| ① | `main` 与 ARC **正式分叉、永不整体同步**；只按用户**点名**"哪些改动/模块可以上 main"才单独推（cherry-pick/移植）。 |
| ② | **历史债务清偿 / 漏洞修复 / 审计修复**三类 → **第一时间进 main**。 |
| ③ | 两分支的 **ASSCOR 底座**（产品能被构建／发布／被使用者信任所必需的部分）保持一致：**有意差异清单之外必须逐字节相同**。 |
| ④ | **被研究线改动过的底座文件**（研究接线）**留在 ARC**，逐条登记为**有意差异**。 |

---

## 1. ARC 特有资产（main **不**持有，**436** 个文件）

> 文件数为 **2026-10-15 快照**（`git ls-tree -r --name-only` 双侧比对的结果，见 §4 重取命令）。

| 路径 | 文件数 | 内容 | 为什么只留 ARC |
|---|---|---|---|
| `lunwen/clab-lab/` | **293** | 实验基质：拓扑 `asscor.clab.yml`、`scripts/edge_*.sh`（矩阵/复位/攻击/采集/探针/基质层/目标准备/跑批前置）、`data/edgefactors/` 数据集与 `run.json`、`kernel-config.ini`、`experiments-final/`、`tests/`（六组离线夹具） | 研究线实验资产（含真实攻防数据） |
| `lunwen/attachment/` | 68 | 评审/送审附件包（含 `bin/` 已忽略） | 论文送审材料 |
| `lunwen/paper/` | 18 | MDPI preprint 版 + article 版 tex/PDF、论文 md、模板 | 论文（未发表） |
| `lunwen/research-core/` | 11 | 研究核心素材（设计白皮书、攻击者模型等） | 研究过程材料 |
| `cmd/edgecompare/` | 14 | 离线重算/对比/拟合工具（**全部**带 `//go:build edgeexp`） | 研究线工具（消费实验记录） |
| `cmd/edgescen/` | **13** | 实验采集器（tag `expr,engine,checks`） | 研究线工具（产出实验记录） |
| `configs/edgeexp/` | 4 | 四候选实验模板（`m0-baseline`/`vector`/`graph`/`chain`） | 研究线配置 |
| `docs/2-experiments/clab-lab/` | 3 | 实验室文档 | 研究 |
| `docs/4-archive/plans/2026-09-08-edge-factor-coupling.md`<br>`…/2026-09-08-entropy-pack.md`<br>`…/2026-09-12-edge-factor-coupling-milestone-b.md` | 3 | 方向② 里程碑 A/B 计划、方向③ 熵包计划 | 研究线过程文档（同目录的 `2026-08-21-secure-mode.md` 属**产品线**，两侧都有） |
| `docs/1-current/reference/ASSCOR-Research-Core.md` | 1 | 研究线总览 | 研究 |
| `docs/1-current/design/ENTROPY_EXTENSION_DESIGN_2026-09-08.md` | 1 | 方向③ 熵扩展包设计（已归档、未实现） | 研究（归档） |
| `docs/1-current/reference/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md` | 1 | 拓扑蓝图 | 用户裁定撤出。**撤出时暴露的悬空引用已修**：`internal/kernel/topo_types.go` 与 `internal/topology/topology.go` 的注释原本指向该文档 ⇒ 已在**两分支同步**改为不引用（`f9d96d1`），因此这两处**不产生新的有意差异**（两侧仍逐字节相同） |
| `internal/edgeexp/` | 2 | 共享 JSONL 契约（`Record`/`Validate`/`MarshalRecord`） | 研究线契约（`cmd/edgescen`+`cmd/edgecompare` 共用） |
| `internal/engine/assessor_chain_test.go`<br>`internal/engine/ssam/edgefactor_chain_test.go`<br>`internal/kernel/persistence_types_test.go`<br>`internal/model/edgefactor_chain_test.go` | 4 | 观测链在 legacy/插件/落盘/契约四处的**研究线新测试** | 研究接线的测试（被测代码差异见 §3） |
| `docs/2-experiments/` | 3 | 本方向的**三份标准文档**：环境画像白皮书、实验技术文档与操作手册、审计归档与裁定台账 | 研究线的可交付文档（此前只散落在记忆与会话产物里 ⇒ 外人看不到） |

---

## 2. 两分支共有：产品线 / 底座（main **持有**，且与 ARC 一致）

| 路径 | 说明 |
|---|---|
| `internal/**`（350 文件，**不含** §1 的 6 个） | 全部产品内核/引擎/检查/配置/安全模块；**含** `internal/edgefactor/`（7 文件，方向② 的**核心装配层**——它已在 main 且是 `engine` tag 线的硬依赖，两侧逐字节相同） |
| `cmd/kernel/`、`cmd/agent/`、`cmd/asscor/` | 产品三个可执行入口 |
| `cmd/exprunner/`、`cmd/decoyd/`、`cmd/tracecheck/` | **ACL 实验线**（用户裁定**留在 main**，两侧同构） |
| `api/`、`pluginsdk/`、`optional/`、`deploy/`、`scripts/`（2） | 接口、插件 SDK、可选扩展、部署、构建脚本 |
| `configs/config.*.ini`（8）、`config.ini`、`agent.ini` | 出厂配置模板与默认配置（`scoring_engine` 修复已在两侧生效） |
| `go.mod`/`go.sum`、`Dockerfile`、`.dockerignore` | 构建 |
| `.github/workflows/` | CI（**内容有意不同**，见 §3） |
| `.gitattributes`（`*.sh text eol=lf`）、`.gitignore` | 行尾与忽略规则（`.gitignore` **内容必然不同**，见 §3） |
| `ssam-lib/`、`prism-lib/` | 两个内嵌独立仓库**的产品侧文件**（外层只跟踪快照；内仓各自维护） |
| `LICENSE`、`CONTRIBUTING.md` | 许可与贡献指南 |
| `docs/3-audits/`（82）、`docs/1-current/design/`（2）、`docs/4-archive/plans/2026-08-21-secure-mode.md`、`docs/1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md`、`docs/1-current/reference/asscor-architecture-review/` 与 `-zh` | 审计/债务记录、产品特性设计、架构评审（用户裁定**留 main**） |
| ~~`README.md`、`README_EN.md`~~ | **2026-09-13 起改为按分支表述** ⇒ 移入 §3.1 有意差异（原本两侧同一份文本，但通篇按研究线口径写，在 main 上是错的） |

---

## 3. 有意差异清单（两分支**共有但内容不同**，逐条登记）

### 3.1 底座路径内（进 `main-base-drift-manifest.txt`，共 16 条 = 以下 12 条 + §1 里那 4 个新测试）

| 路径 | 差异内容 | 引入提交 |
|---|---|---|
| `README.md` | 仅**横幅与结构树**按分支表述：ARC 列研究线资产（`cmd/edgescen/`、`cmd/edgecompare/`、`configs/edgeexp/`、`lunwen/`、`internal/edgeexp/`），main 列产品线并说明研究内容不在本分支；其余内容（四条目分支规则、"论文"中性措辞、社区模式段）**逐字相同** | `0affc73`(ARC) + `5efdf49`(main) |
| `README_EN.md` | 同上（英文版） | 同上 |
| `internal/model/model.go` | 新增 `EdgeFactorObservation` 类型 + `AssessmentResult.EdgeFactorChain`（`omitempty`） | `304bbd6` |
| `internal/engine/assessor.go` | legacy 评分路径 `evaluateEdgeFactorChain` 回填观测链 | `304bbd6` |
| `internal/engine/ssam/adapter_engine.go` | 插件路径在与溯源戳**同处、同判据**回填观测链 | `304bbd6` |
| `internal/kernel/persistence_types.go` | `AssessmentRecord` 增 additive 字段 `EdgeFactorChain` | `304bbd6` |
| `internal/persistence/persistence.go`（+ `_test.go`） | 落盘时透出观测链 + 往返测试 | `304bbd6` |
| `internal/config/configs_templates_test.go` | ARC 版多 4 条读研究线契约（`configs/edgeexp/`、`lunwen/`）的用例 ⇒ **main 侧只有 3 条纯产品断言** | `c22fd9c` + `7f111ea` + `22f4d33` |
| `scripts/build.sh` | ARC 的 `BINARIES` 多 `cmd/edgescen` 交叉编译目标 ⇒ main 侧同一行已去掉该命令 | `e842a3c` |
| `.github/workflows/ci.yml` | ARC 的 `MODULE_TAGS` 含 `edgeexp` 且含 `cmd/edgecompare`/`edgescen` 的构建与测试步骤 ⇒ main 侧已去掉 | `e842a3c` |
| `.gitignore` | ARC 用 `lunwen/*` **白名单**（可跟踪 `lunwen/paper`、`lunwen/clab-lab` 等）；main 必须保留 `lunwen/` + `lunwen*/` **整目录忽略** ⇒ **永不一致** | `ef3f52a`（ARC 侧）/ `5071441`（main 侧） |

### 3.2 文档层（**不在**底座检查范围内，但同样是有意差异）

| 路径 | 差异内容 | 处理 |
|---|---|---|
| `docs/1-current/design/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md` | ARC 版多出里程碑 B 的实测章节（§5.4 手册、§10.3 实测纠正等） | 登记为有意差异；随方向② 收口、用户点名后再决定是否上 main |
| `docs/3-audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md` | ARC 版有 §七「里程碑 B 实测发现与债务」（C1、B-1…B-6、"不得夸大"口径） | **用户裁定不上 main**（`54adcce`）：它是**研究实测记录**、且引用两个已从 main 撤出的文件 ⇒ 上了会造成"研究内容进主线 + 悬空引用" |

> **教训（记档）**：把 `54adcce` 判成"该上 main 的债务修复"是**只按路径（`docs/3-audits/`）判的**；
> **分类必须看内容**。该提交已改为登记为有意差异。

---

## 4. 复跑判据（每次要动 main 之前跑一次）

> ✅ **判据的产物已在仓内**（2026-10-15 起）：
> `scripts/check-main-base-consistency.sh`（检查脚本）+ `scripts/main-base-drift-manifest.txt`（有意差异清单）。
> 此前这两个文件只存在于**会话产物目录**（未跟踪）⇒ **clone 者照做必然失败**，判据等于没有披露。

```bash
# 在工作区（ARC 检出）里执行：
MANIFEST=scripts/main-base-drift-manifest.txt BASE_REF=main \
  bash scripts/check-main-base-consistency.sh
```

### 4.1 快照数字的重取命令（**不要引用本文的快照值**）

```bash
# 两分支的头与分叉点
git merge-base main ASSCOR-Research-Core
git rev-parse main ASSCOR-Research-Core
git rev-list --count main ; git rev-list --count ASSCOR-Research-Core

# 文件集规模与包含关系（ARC 独有 / main 独有）
git ls-tree -r --name-only main | wc -l
git ls-tree -r --name-only ASSCOR-Research-Core | wc -l
comm -13 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) | wc -l    # ARC 独有
comm -23 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) | wc -l    # main 独有

# 逐目录的 ARC 独有文件数（本文 §1 那张表就是这么来的）
comm -13 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) \
  | cut -d/ -f1-2 | sort | uniq -c | sort -rn

# 底座漂移面（不提供清单时的原始输出）
bash scripts/check-main-base-consistency.sh        # 不加 MANIFEST ⇒ 只报漂移面
```

### 4.2 清单的格式与语义

清单是**双侧登记**（v3 起）：

```
<登记 blob sha(ARC 侧 HEAD)>  <登记 blob sha(main 侧 BASE_REF) | ABSENT>  <路径>  # 理由
```

- 两侧都有的文件记 **main 侧** blob sha；只在 ARC 有的文件（本表 §1 那 4 个研究线新测试）记字面量 **`ABSENT`**。
- **任一侧与登记不符都报红**（`ABSENT` 变成"确实存在"也算不符）⇒ 这样"**main 侧被改写**"这种 v2 发现不了的形态也能被抓住。已用**变异测试**验证：改写 `internal/model/model.go` 的 main 侧 + 让 `internal/model/edgefactor_chain_test.go` 在 main 上凭空出现 ⇒ **两处都被判红**（v2 对这两种形态只会报"黄"）。

| 输出 | 含义 | 处置 |
|---|---|---|
| **绿 exit=0** | 底座路径两侧**逐字节相同**（清单为空或全部已同步） | 可以继续 |
| **黄 exit=3** | 清单外逐字节一致；清单内 16 条有意差异，**两侧均与登记一致** | **裁定「乙」的合格终态** |
| **红 exit=1** | ①出现**清单之外**的漂移 ②ARC 侧与登记不符 ③**main 侧与登记不符**（被改写 / 凭空出现）④清单行缺 main 侧登记 | 要么**消除**漂移（按规则② 上 main），要么**登记**（按规则④ 写理由与引入提交） |

**当前实测状态（2026-10-15）**：`清单条目=16 active=16 stale=0`、`登记失效 ARC 侧=0 / main 侧=0`、**清单外未解释 = 0** ⇒ **黄 exit=3**。
（2026-09-13 分叉后首次测得的是同一形态，当时对照分支是 `fdb116e`；本次对照 `aef84de`，结论未变。）
（对照分叉前的 `df8342e` 会报 22 个漂移、其中 8 个未解释 ⇒ 红；那 8 个正是已按规则② 上 main 的 A 类产品侧修复。）

---

## 5. 已知边界与前瞻

- **`docs/` 不在底座检查范围内**：§3.2 的两个文档差异不会被该检查发现 ⇒ 依赖本表逐条登记。
- **`README.md`/`README_EN.md` 自 2026-09-13 起按分支表述**（§3.1 已登记）：两份文件的差异被刻意压到最小——只有**横幅**与**结构树**不同，其余段落两分支逐字相同；将来若还要改 README，请**两侧同改**（除横幅/结构树），改完更新清单里那两个 sha。
- **其他未覆盖**：`optional/adversary/packages/acl/README.md`、`scripts/acl-pack.sh` 目前两侧相同；若将来因分叉需要各自改写，会**新增**有意差异条目，按同一口径登记。
- **不要做的事**：不要用 `git merge ASSCOR-Research-Core`（会把 ARC 特有的 353 个文件一次性带回 main，`.gitignore` 挡不住）；要按点名 **cherry-pick/移植**。
