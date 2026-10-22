# ASSCOR 资产归属表（`main` vs `ASSCOR-Research-Core`）

> **快照（2026-10-22 Task 39 重取）**：`main` = `81c27bb`（**本地就绪、尚未 push**）、
> `ASSCOR-Research-Core`(ARC) = `4998dec`
> **规模实测**：main **669** 文件 / ARC **1287** 文件；**ARC 独有 775 个**、**main 独有 157 个**
> ⇒ 两分支的文件集**不是包含关系**（`main ⊄ ARC` 且 `ARC ⊄ main`），差异有三种：
> "ARC 独有"、"main 独有"、"共有但内容不同"。
> main 独有的 157 个几乎全在 `docs/`：`docs/audits/…`（82）+ 两份架构评审（20+20）+ `docs/en/…`（5）
> + `docs/superpowers/…`（3）+ 27 个扁平文档 —— 即 main 仍是**扁平 docs 布局**，
> ARC 已迁到 `docs/1-current`…`4-archive` 的分代布局。
> **分叉点**（merge-base）= `df8342e`；此后 main **10** 提交、ARC **210** 提交
> （提交总数 main 608 / ARC 808）。
> 取数命令见 §4.1（上面每个数字都能现算，均可复现）。
> **本表的依据**：用户 2026-09-13 的四条分支规则（下 §0）+ 可复跑判据（§4）。
>
> ⚠️ **本节数字是快照，会随提交漂移**。要拿当前值请照 §4 的**重取命令**现算，
> **不要**把这里的数字当成现状引用。
> 📌 **历史快照（勿引用）**：2026-09-13 分叉后 main `fdb116e` / ARC `028cfd5`、661/1014 文件、
> ARC 独有 353；2026-10-15 版 main `aef84de` / ARC `5eaedec`、662/1098、ARC 独有 436，
> 并**错误地**断言"main 独有 0 / 两分支文件集是包含关系"——该断言已被 Task 35a 实测
> 与 Task 39 复核推翻（实测 main 独有 **157**，`git ls-tree` 双向 `comm` 取数，见 §4.1）。

---

## 0. 四条规则（本表的判据来源）

| # | 规则 |
|---|---|
| ① | `main` 与 ARC **正式分叉、永不整体同步**；只按用户**点名**"哪些改动/模块可以上 main"才单独推（cherry-pick/移植）。 |
| ② | **历史债务清偿 / 漏洞修复 / 审计修复**三类 → **第一时间进 main**。 |
| ③ | 两分支的 **ASSCOR 底座**（产品能被构建／发布／被使用者信任所必需的部分）保持一致：**有意差异清单之外必须逐字节相同**。 |
| ④ | **被研究线改动过的底座文件**（研究接线）**留在 ARC**，逐条登记为**有意差异**。 |

---

## 1. ARC 特有资产（main **不**持有，**775** 个文件）

> 文件数为 **2026-10-22（Task 39）实测**（`comm -13 <(git ls-tree -r --name-only main | sort) <(git ls-tree -r --name-only HEAD | sort)`，见 §4 重取命令）。

| 路径 | 文件数 | 内容 | 为什么只留 ARC |
|---|---|---|---|
| `lunwen/clab-lab/` | **456** | 实验基质：拓扑 `asscor.clab.yml`、`scripts/edge_*.sh`（矩阵/复位/攻击/采集/探针/基质层/目标准备/跑批前置）、`data/edgefactors/` 数据集与 `run.json`、`kernel-config.ini`、`experiments-final/`、`tests/`（六组离线夹具） | 研究线实验资产（含真实攻防数据） |
| `lunwen/attachment/` | 68 | 评审/送审附件包（含 `bin/` 已忽略） | 论文送审材料 |
| `lunwen/paper/` | 18 | MDPI preprint 版 + article 版 tex/PDF、论文 md、模板 | 论文（未发表） |
| `lunwen/research-core/` | 11 | 研究核心素材（设计白皮书、攻击者模型等） | 研究过程材料 |
| `cmd/edgecompare/` | **15** | 离线重算/对比/拟合工具（**全部**带 `//go:build edgeexp`） | 研究线工具（消费实验记录） |
| `cmd/edgescen/` | **14** | 实验采集器（tag `expr,engine,checks`） | 研究线工具（产出实验记录） |
| `configs/edgeexp/` | 4 | 四候选实验模板（`m0-baseline`/`vector`/`graph`/`chain`） | 研究线配置 |
| `docs/2-experiments/clab-lab/` | 3 | 实验室文档 | 研究 |
| `docs/4-archive/plans/2026-09-08-edge-factor-coupling.md`<br>`…/2026-09-08-entropy-pack.md`<br>`…/2026-09-12-edge-factor-coupling-milestone-b.md` | 3 | 方向② 里程碑 A/B 计划、方向③ 熵包计划 | 研究线过程文档（同目录的 `2026-08-21-secure-mode.md` 属**产品线**，两侧都有） |
| `docs/1-current/reference/ASSCOR-Research-Core.md` | 1 | 研究线总览 | 研究 |
| `docs/1-current/design/ENTROPY_EXTENSION_DESIGN_2026-09-08.md` | 1 | 方向③ 熵扩展包设计（已归档、未实现） | 研究（归档） |
| `docs/1-current/reference/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md` | 1 | 拓扑蓝图 | 用户裁定撤出。**撤出时暴露的悬空引用已修**：`internal/kernel/topo_types.go` 与 `internal/topology/topology.go` 的注释原本指向该文档 ⇒ 已在**两分支同步**改为不引用（`f9d96d1`），因此这两处**不产生新的有意差异**（两侧仍逐字节相同） |
| `internal/edgeexp/` | 2 | 共享 JSONL 契约（`Record`/`Validate`/`MarshalRecord`） | 研究线契约（`cmd/edgescen`+`cmd/edgecompare` 共用） |
| `internal/engine/assessor_chain_test.go`<br>`internal/engine/ssam/edgefactor_chain_test.go`<br>`internal/kernel/persistence_types_test.go`<br>`internal/model/edgefactor_chain_test.go` | 4 | 观测链在 legacy/插件/落盘/契约四处的**研究线新测试** | 研究接线的测试（被测代码差异见 §3） |
| `docs/2-experiments/` | 3 | 本方向的**三份标准文档**：环境画像白皮书、实验技术文档与操作手册、审计归档与裁定台账 | 研究线的可交付文档（此前只散落在记忆与会话产物里 ⇒ 外人看不到） |

> 上表是**分类明细、不是穷举**：ARC 独有的 775 个文件里还有按目录整体迁移的部分
> （`docs/1-current/` 65、`docs/3-audits/` 82、`docs/4-archive/` 11、`docs/en/` 6 等），
> 它们与 main 的同名文档是**布局不同**（见 §2 与 §3），故没有逐份列进上表。

---

## 2. 两分支共有：产品线 / 底座（main **持有**，且与 ARC 一致）

| 路径 | 说明 |
|---|---|
| `internal/**`（366 文件，**不含** §1 的 6 个） | 全部产品内核/引擎/检查/配置/安全模块；**含** `internal/edgefactor/`（9 文件，方向② 的**核心装配层**——它已在 main 且是 `engine` tag 线的硬依赖，两侧逐字节相同） |
| `cmd/kernel/`、`cmd/agent/`、`cmd/asscor/` | 产品三个可执行入口 |
| `cmd/exprunner/`、`cmd/decoyd/`、`cmd/tracecheck/` | **ACL 实验线**（用户裁定**留在 main**，两侧同构） |
| `api/`、`pluginsdk/`、`optional/`、`deploy/`、`scripts/`（2） | 接口、插件 SDK、可选扩展、部署、构建脚本 |
| `configs/config.*.ini`（8）、`config.ini`、`agent.ini` | 出厂配置模板与默认配置（`scoring_engine` 修复已在两侧生效） |
| `go.mod`/`go.sum`、`Dockerfile`、`.dockerignore` | 构建 |
| `.github/workflows/` | CI（**内容有意不同**，见 §3） |
| `.gitattributes`（`*.sh text eol=lf`）、`.gitignore` | 行尾与忽略规则（`.gitignore` **内容必然不同**，见 §3） |
| `ssam-lib/`、`prism-lib/` | 两个内嵌独立仓库**的产品侧文件**（外层只跟踪快照；内仓各自维护） |
| `LICENSE`、`CONTRIBUTING.md` | 许可与贡献指南 |
| `docs/3-audits/`（82）、`docs/1-current/design/`（2）、`docs/4-archive/plans/2026-08-21-secure-mode.md`、`docs/1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md`、`docs/1-current/reference/asscor-architecture-review/` 与 `-zh` | 审计/债务记录、产品特性设计、架构评审（用户裁定**留 main**）。⚠️ 这一组在 main 上是**扁平路径**（`docs/audits/…`、`docs/` 根下、`docs/asscor-architecture-review*`）⇒ 内容同一批、**路径不同**（属布局差异，不产生内容分叉；这也是 main 独有 157 个文件的主要来源） |
| ~~`README.md`、`README_EN.md`~~ | **2026-09-13 起改为按分支表述** ⇒ 移入 §3.1 有意差异（原本两侧同一份文本，但通篇按研究线口径写，在 main 上是错的） |

---

## 3. 有意差异清单（两分支**共有但内容不同**，逐条登记）

### 3.1 底座路径内（进 `main-base-drift-manifest.txt`，**共 26 条**）

> 26 = **下表 13 条**（12 行，`internal/persistence/persistence.go` 行含 `_test.go`；含 `internal/engine/ssam/edgefactor.go`）
> + **§1 里那 5 个研究线新测试** + **§3.3 里 Task 39 新登记的 8 条**。
> 实测（2026-10-22 Task 39）：`清单条目=26 active=26 stale=0`、登记失效 ARC 侧 0 / main 侧 0、
> 清单外未解释 **0** ⇒ **黄 exit=3**。取数命令见 §4。

| 路径 | 差异内容 | 引入提交 |
|---|---|---|
| `README.md` | 仅**横幅与结构树**按分支表述：ARC 列研究线资产（`cmd/edgescen/`、`cmd/edgecompare/`、`configs/edgeexp/`、`lunwen/`、`internal/edgeexp/`），main 列产品线并说明研究内容不在本分支；其余内容（四条目分支规则、"论文"中性措辞、社区模式段）**逐字相同** | `0affc73`(ARC) + `5efdf49`(main) |
| `README_EN.md` | 同上（英文版） | 同上 |
| `internal/model/model.go` | 新增 `EdgeFactorObservation` 类型 + `AssessmentResult.EdgeFactorChain`（`omitempty`） | `304bbd6` |
| `internal/engine/assessor.go` | legacy 评分路径 `evaluateEdgeFactorChain` 回填观测链 | `304bbd6` |
| `internal/engine/ssam/adapter_engine.go` | 插件路径在与溯源戳**同处、同判据**回填观测链（main 侧已随 Task 39 带入 `SetAcceptByLowerBound`，ARC 版只多观测链） | `304bbd6` |
| `internal/engine/ssam/edgefactor.go` | `activationsFromResults` 返回前调 `edgefactor.CollapseToFactors`（Task 18 合成层双条目折叠）；研究线 V/G/C 装配钩子，main 的产品路径不装载 V/G/C ⇒ 不移植 | Task 18 |
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

### 3.3 Task 39 新登记的 8 条（2026-10-22）

> 背景：方向①（置信度审计修复）的 15 个提交已 cherry-pick 到 main（`0a0e346` → `81c27bb`，
> **本地就绪、未 push**）。同步后重跑检查，未解释漂移从 36 降到 8，本表把剩下的 8 条逐条登记。
> 判据：`git cat-file`/`git rev-parse` 取两侧 blob（§4.1），理由逐条写在 `main-base-drift-manifest.txt`。

| 路径 | 差异内容 | 为何不同步到 main |
|---|---|---|
| `CONTRIBUTING.md` | 审计报告目录写作 `docs/3-audits/`（main 为 `docs/audits/…`）；同处分叉还含首行 BOM 去除 | ARC 的 docs 分代布局在 main 上不成立；属纯文档面 |
| `config.ini` | 仅 `[confidence]` 段上方注释里的设计文档路径（`docs/1-current/design/…` vs `docs/…`） | 键与值两侧一致，只有引用路径属布局差异 |
| `internal/config/config.go` | 仅 `adapterSecretEnv` 注释里的文档引用路径 | 同上（无行为差异） |
| `internal/srdwrapper/srd_wrapper.go` | 仅模块 tag 依赖矩阵的注释引用（`docs/4-archive/plans/…` vs `docs/…`） | 同上（无行为差异） |
| `scripts/check-doc-refs.sh` | ARC-only 工具：检查 `docs/1-current/**` 引用完整性（含 `--selftest`） | main 没有 `docs/1-current` 布局，脚本无从运行；登记为 ARC-only 而不是改成"缺目录就跳过"（那会让门禁在 main 上静默通过） |
| `ssam-lib/SSAM-README.md` | `8e968d4` 的文档收口：新增 Confidence/Sigma/CI 字段表 | Task 39 只把方向① 的**代码/注释 hunk** 同步到 main，文档面留在 ARC |
| `ssam-lib/SSAM-Theory.md` | 同上（理论章节 §2.4） | 同上 |
| `prism-lib/types.go` | 仅 `ScoreFloor` 注释 `0.40` → `0.15`（`70c65cc`，与 `config.go` 实际值一致） | 该提交 95% 是白皮书，唯一代码改动是这一行注释、不在方向① 的 15 个提交里；待控制侧裁定是否单独上 main |

> ⚠️ 其中 `prism-lib/types.go` 是**已知的 main 侧注释瑕疵**（main 的注释仍写 0.40，而代码是 0.15），
> 不是"有意如此"；保留为登记只是为了把方向① 之外的改动挡在本次同步之外。

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
mb=$(git merge-base main ASSCOR-Research-Core)
git rev-list --count "$mb..main" ; git rev-list --count "$mb..ASSCOR-Research-Core"

# 文件集规模与包含关系（ARC 独有 / main 独有 / 共有）
git ls-tree -r --name-only main | wc -l
git ls-tree -r --name-only ASSCOR-Research-Core | wc -l
comm -13 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) | wc -l    # ARC 独有
comm -23 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) | wc -l    # main 独有
comm -12 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) | wc -l    # 共有

# 逐目录的 ARC 独有 / main 独有文件数（本文 §1、§2 的数字就是这么来的）
comm -13 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) \
  | cut -d/ -f1-2 | sort | uniq -c | sort -rn
comm -23 <(git ls-tree -r --name-only main | sort) \
         <(git ls-tree -r --name-only ASSCOR-Research-Core | sort) \
  | cut -d/ -f1-2 | sort | uniq -c | sort -rn

# 单目录文件数（例：internal/edgefactor、lunwen/clab-lab、cmd/edgescen …）
git ls-tree -r --name-only ASSCOR-Research-Core -- internal/edgefactor | wc -l
git ls-tree -r --name-only ASSCOR-Research-Core -- internal | wc -l

# 底座漂移面（不提供清单时的原始输出）
bash scripts/check-main-base-consistency.sh        # 不加 MANIFEST ⇒ 只报漂移面
```

> **2026-10-22 实测值**（Task 39，main=`81c27bb` 本地未 push / ARC=`4998dec`）：
> merge-base `df8342e`；提交数 main 608 / ARC 808（分叉后 main 10 / ARC 210）；
> 文件数 main 669 / ARC 1287；ARC 独有 775 / main 独有 **157** / 共有 512；
> `internal` 366、`internal/edgefactor` 9、`lunwen/clab-lab` 456、`cmd/edgecompare` 15、`cmd/edgescen` 14。

### 4.2 清单的格式与语义

清单是**双侧登记**（v3 起）：

```
<登记 blob sha(ARC 侧 HEAD)>  <登记 blob sha(main 侧 BASE_REF) | ABSENT>  <路径>  # 理由
```

- 两侧都有的文件记 **main 侧** blob sha；只在 ARC 有的文件（本表 §1 的 5 个研究线新测试 + `scripts/check-doc-refs.sh`）记字面量 **`ABSENT`**。
- **任一侧与登记不符都报红**（`ABSENT` 变成"确实存在"也算不符）⇒ 这样"**main 侧被改写**"这种 v2 发现不了的形态也能被抓住。已用**变异测试**验证：改写 `internal/model/model.go` 的 main 侧 + 让 `internal/model/edgefactor_chain_test.go` 在 main 上凭空出现 ⇒ **两处都被判红**（v2 对这两种形态只会报"黄"）。

| 输出 | 含义 | 处置 |
|---|---|---|
| **绿 exit=0** | 底座路径两侧**逐字节相同**（清单为空或全部已同步） | 可以继续 |
| **黄 exit=3** | 清单外逐字节一致；清单内 **26** 条有意差异，**两侧均与登记一致** | **裁定「乙」的合格终态** |
| **红 exit=1** | ①出现**清单之外**的漂移 ②ARC 侧与登记不符 ③**main 侧与登记不符**（被改写 / 凭空出现）④清单行缺 main 侧登记 | 要么**消除**漂移（按规则② 上 main），要么**登记**（按规则④ 写理由与引入提交） |

**当前实测状态（2026-10-22 Task 39 收口）**：`清单条目=26 active=26 stale=0`、
登记失效 ARC 侧=`0` / main 侧=`0`、缺 main 侧登记=`0`、**清单外未解释 = 0** ⇒ **黄 exit=3**。
（取数：`MANIFEST=scripts/main-base-drift-manifest.txt BASE_REF=main bash scripts/check-main-base-consistency.sh`；
**判 rc 不要走管道**，否则拿到的是管道末端的 rc。）
（对照：Task 35a 在 main `0a0e346` 时实测为红 —— 18 条、active 11、ARC 侧登记失效 7、未解释 **36**；
Task 39 把方向① 修复同步到 main `81c27bb` 后复测为本行的黄。）
（更早：2026-09-13 分叉后首次测得同一黄形态，对照分支是 `fdb116e`；对照分叉前的 `df8342e`
会报 22 个漂移、其中 8 个未解释 ⇒ 红，那 8 个正是已按规则② 上 main 的 A 类产品侧修复。）

---

## 5. 已知边界与前瞻

- **`docs/` 不在底座检查范围内**：§3.2 的两个文档差异不会被该检查发现 ⇒ 依赖本表逐条登记。
- **`README.md`/`README_EN.md` 自 2026-09-13 起按分支表述**（§3.1 已登记）：两份文件的差异被刻意压到最小——只有**横幅**与**结构树**不同，其余段落两分支逐字相同；将来若还要改 README，请**两侧同改**（除横幅/结构树），改完更新清单里那两个 sha。
- **其他未覆盖**：`optional/adversary/packages/acl/README.md`、`scripts/acl-pack.sh` 目前两侧相同；若将来因分叉需要各自改写，会**新增**有意差异条目，按同一口径登记。
- **不要做的事**：不要用 `git merge ASSCOR-Research-Core`（会把 ARC 特有的 **775** 个文件一次性带回 main，`.gitignore` 挡不住）；要按点名 **cherry-pick/移植**。同理禁止 `git push . ASSCOR-Research-Core:main` 这类**整体快进**（已于 Task 39 之前被裁定撤销）。
