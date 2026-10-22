# 情报可信度原生变量 — 设计文档（SSAM/SRD 算法层）

> 状态：**已实现；两轮审计修复已落地（B-1/B-2 + I-1…I-12）；`标定` 仍后置**（2026-10-22 复核；
> 设计定稿 2026-09-08；实现 2026-09；修复 `34b89c6`…`ac1bd29`）｜分支：ASSCOR-Research-Core｜关联：研究方向 ①
> 作者决策：贝叶斯置信区间语义 + config 内可替换规则引擎（用户 2026-09-08 确认）
> 配套方向 ②（边缘因子向量图变量化）另行设计，本设计只保证 ① 覆盖到边缘因子触发链；
> `c` 的归一**已统一**为一份（`ssam-lib.NormalizeConfidence`），插件 / legacy / SRD 共用同一规则。
>
> **可以按「已实现」对外，但仍不得按「已标定 / 已验证」对外**。债务清单那一行读作
> 「**已完成（审计 14 项已修）+ 标定后置**」。逐条修复、提交号与验证方式见 **§7.7**；
> 独立复审结论见 `.superpowers/sdd/2026-09-12-edge-factor-coupling-milestone-b/audit-3-direction1-verdict.md`
> 的后续复审。§7.5 保留的是**修复前**首次审计的问题清单，仅作历史背景。

---

## 1. 问题陈述

ASSCOR 的评分链（agent 检查 → SSAM 域分 → Prism/SRD 风险动态）把每条情报当作
**确定事实**处理：`passed=false` 即按 `delta` 全额扣分，债务按失败时间全额累积。
现实中情报来源的可信度差异巨大：

- 本地直接读取（文件/proc/sysctl）≈ 高可信
- 用户自定义检查 / 脚本检查 ≈ 中高
- 外部扫描器（Nuclei/Trivy/Lynis/OpenSCAP/…）≈ 中（工具误报、版本漂移）
- CTI/ATT&CK 匹配 / SPC 推断 ≈ 低-中（推断、时效）

把这些来源一律当作硬事实，导致：(a) 单条误报即可大幅拉低分数并驱动阻断；
(b) 模型无法表达"我们对这个分数有多确定"；(c) SRD 债务/传播把噪声当真实攻击证据。

**目标**：可信度 `confidence ∈ [0,1]` 作为 **SSAM/SRD 算法层原生变量**（非展示层
标注），从每条情报入口贯穿到公式内部，并输出**带置信区间的分数**。

## 2. 语义（贝叶斯观测模型）

把每条检查/情报视为对主机真实安全状态的一个**带噪观测**：

```
真实状态 θ_d ∈ [0,1]   （域 d 的"安全度"，score_d = 100·θ_d）
观测 i: (passed_i, delta_i)  观测噪声由 confidence_i 描述
  confidence_i = 1  → 无噪声直接观测（现状语义）
  confidence_i → 0 → 观测接近随机（不提供证据）
```

域分的点估计维持"证据期望扣分"，方差来自低置信观测 → 输出后验近似
`N(score_d, σ_d²)`。这是高斯近似的证据加权（Beta 先验的工程化近似），
理由：(a) 与现有 delta 多级幅度体系直接兼容；(b) `confidence=1` 时解析等价于
现状公式（**向后兼容可证**）；(c) 公式透明可解释，适合论文叙述。

### 2.1 点估计（证据期望扣分）

域 d 的失败观测集合 `F_d = {i | !passed_i, delta_i < 0}`：

```
E_d = Σ_{i∈F_d} |delta_i| · confidence_i        # 期望扣分（证据加权）
score_d = max(0, 100 − E_d)
```

`confidence=1` 全部时 `score_d = max(0, 100 − Σ|delta_i|)` = 现状。✅

### 2.2 方差 / 置信区间

每条低置信观测贡献不确定度（把"该扣分是否成立"视为伯努利(p=c)，幅度 s=|delta|）：

```
U_d = Σ_{i∈F_d} s_i² · c_i · (1 − c_i)
σ_d = sqrt(U_d)                                  # 域分标准差
```

- `c=1` 每项方差 0 → `σ_d=0`（区间坍缩为点，现状语义）✅
- `c=0.5`、s=10 → 方差 25 → σ=5 → 95% 区间约 ±9.8（该失败证据高度不确定）

域级输出（新增，模型原生字段）：
```
score_d                     # 后验期望（点估计，即现有 score）
sigma_d                     # 后验标准差
conf_d = E_d>0 ? Σ(s_i·c_i)/Σs_i : 1    # 域证据平均可信度（展示/下游用）
```

### 2.3 最终分与区间传播

最终分沿用 **SSAM V2.0 三层加权聚合**（`SSAMV20Formula`，`ssam-lib/formulas_v2.go:66-72`），
域分只进入 intrinsic 层；exposure / threat 是配置系数，没有采样方差：

```
score_d       = max(0, 100 − E_d)                             # 2.1
sigma_d       = sqrt(U_d)                                     # 2.2
Total         = 0.5·(Σ w_d·score_d / Σ w_d) + 0.3·100·E + 0.2·100·T
                # E = exposure(SPC)，T = threat；0.5/0.3/0.2 是三层权重
sigma_final   = 0.5 · sqrt( Σ (w_d·sigma_d)² ) / Σ w_d         # 只有 intrinsic 层随机
区间          = [Total − 1.96·sigma_final, Total + 1.96·sigma_final]
                # **只把下界钳到 0，上界不夹**
```

- σ 只描述**域分（intrinsic 层）**的不确定度，必须按 `IntrinsicLayerWeight = 0.5`
  折算后才成为 `FinalSigma`；它**不是**对三层聚合分数的严格后验标准差。
- `Total` 本身不做上界钳位：当 `threat=1.4` 等配置使 `Total = 108` 时，区间以 108 为中心，
  上界可以 > 100。因此**区间恒包含自己的点估计**；若夹上界会得到 `[100,100]` 这种
  连点估计都不含的“区间”（审计 S10 的历史缺陷，已修）。
- 该区间是**文档化的启发式**（domain RSS 折合 intrinsic 权重、以实际最终分为中心），
  不是经过覆盖率验证的有效后验区间。

**可接受性判定**：唯一实现是 `ssam-lib.AcceptanceDecision`（`ssam-lib/confidence.go:231-242`）：
默认 `Total ≥ threshold`；config 开 `accept_by_lower_bound=true` 时用 `Lower95 ≥ threshold`
做保守判定。插件、ssam-lib v1/v2、legacy 两处与 kernel `applyCTIOnly` **全部**消费这同一函数
（审计 B-2）。

### 2.4 边缘因子触发链（① 覆盖边缘因子）

边缘因子由失败检查触发，把触发强度按触发检查的可信度衰减：

```
effective_factor = 1 − (1 − factor) · c_trigger
```

- `c_trigger=1` → `effective_factor = factor`（现状）✅
- `c_trigger=0.5`, factor=0.75 → effective = 0.875（惩罚减半：低可信触发只轻微放大）

同时 `EdgeFactorResult` 输出携带触发可信度（溯源字段，模型原生）。

### 2.5 Prism / SRD 债务与传播

Prism `computeDebtRaw` 每项失败债务按可信度加权：

```
effective_delta = |delta| · c_i
debt += effective_delta · elapsedDays^α
```

- `c=1` 与现状一致 ✅
- 低可信失败不累积高债务，避免"噪声驱动塌缩判定"

节点级：`NodeState.Confidence` 由 SSAM 域可信度聚合（`ssam.AggregateNodeConfidence`）。
**当前唯一的算法消费点**是 Prism 推断层：`PredictFuture` 把模型置信与输入可信度取
`min` 作为**推断置信度**（`prism-lib/inference.go:302-351`，审计 I-7）；传播风险、
债务与塌缩判定的**数值不变**（它们只由 per-failure `CheckFailure.Confidence` 驱动）。
SRD `ExternalCheckResult` 增加 `Confidence`，`pipeline` 装配 `CheckFailure` 时按 tool id 走同一
`ConfidenceConfig.Resolve`（工具自带 > 来源表 > default；审计 I-8）；`adapter` 只做字段搬运。

## 3. 可信度规则引擎（config 内可配置）

初始可信度**不硬编码单一值**：由 `[confidence]` 段按**规则表**计算。**规则表这一层已实现**
（5 层优先级 + 精确/正则/来源/域/default）。**聚合算法替换未实现**：设计初稿曾规划
“算法注册表 + config 引用”，实际只有 `weighted_evidence` 一种聚合（见 §3.3）。

### 3.1 config.ini 语法（实现现状）

> **实现与本节早期的设计稿有两处收敛**（审计 I-10）：
> 1. `[confidence.algorithm]` 段**完全不解析**；`floor` / `prior_strength` 只有写在
>    `[confidence]` 下才生效。独立段已删除。
> 2. `algorithm` / `prior_strength` 标为 **reserved（无消费）**：唯一实现的聚合是
>    `weighted_evidence`；写其它 `algorithm` 值在**加载时即报错**（不再静默同分）。
>    字段级 DSL（`[confidence.check.<ID>]`）**不存在**，仅为“未实现（保留设计）”。

```ini
[confidence]
enabled = false                        ; 默认禁用 → 与历史评分逐位一致
algorithm = weighted_evidence          ; reserved；仅接受这一个值，其它值加载失败
accept_by_lower_bound = false          ; true=可接受性按 95% 区间下界判定
default = 1.0                          ; 规则未匹配时的兜底可信度
floor = 0.05                           ; 可信度下限（必须 < 1；0 视为未指定）
; prior_strength = 2.0                 ; reserved（无消费）：beta_bayes 未实现

; ---- 规则优先级: 精确检查ID > 正则 > 来源 > 域 > default ----
[confidence.check]                     ; 精确 check_id（小写；Resolve 用小写比对）
as-001 = 0.99
; 字段级 DSL（[confidence.check.AS-001]）未实现，保留设计。

[confidence.checkrx]                   ; 正则，按 key 字节字典序首个命中
^rs- = 0.92

[confidence.source]                    ; 来源级
builtin = 1.0
user = 0.90
root = 1.0
extension = 0.70
adapter = 0.80
scan_external = 0.65
cti = 0.50
spc = 0.60
check_module = 0.75
unknown = 0.50

[confidence.domain]                    ; 域级兜底（未匹配检查时）
attack_surface = 0.95
business_continuity = 0.98
operation_trust = 0.95
resilience = 0.97
```

> 上表的数值是**设计示例 / 先验**，出厂只内置 `user=0.90`、`adapter=0.80`（见 §3.4），
> 且**全部未经实验标定**。

### 3.2 规则匹配顺序

对每条检查/情报按 `(source, check_id/rule_id, domain)` 解析，**5 层**（与
`config.ini` 和 `ConfidenceConfig.Resolve` 一致）：

1. `[confidence.check]` 精确 `check_id` 命中 → 用之
2. `[confidence.checkrx]` 正则命中 → 用之；**重叠正则按 key 的字节字典序**取首个命中
   （`sort.Strings`，与声明顺序无关；审计 I-5）
3. `[confidence.source]` 来源命中 → 用之
4. `[confidence.domain]` 域命中 → 用之
5. `default`

外部工具 finding 的 source 由 adapter 归一化：`NormalizedFinding.Source` 经
`ToCheckResult` **原样搬进** `CheckResult.Source`（审计 B-1），`ResolveChecks` 把空
Source 映射为 `builtin`。因此 `[confidence.source] nuclei = 0.7` 可以对第三方扫描器生效；
工具自带 `Confidence > 0` 时优先于来源表。

### 3.3 规则 DSL 与“算法写进 config”（未实现，保留设计）

用户曾诉求“更精细规则 + 算法直接写在 config 内供用户自行替换”。
**截至 2026-10-22，以下两项均未实现**（审计 I-10），本节只保留设计意图：

- **规则 DSL**（`[confidence.rules]`）**不存在**：没有 `severity:` / `age_days:` 选择器，
  没有 `&` 组合，也没有表达式求值器。实际能力只有 §3.2 的 5 层查表 + 正则。
- **算法替换不存在**：没有 `RegisterAlgorithm` / `Aggregator` 注册表，`beta_bayes`
  没有实现（Go 代码 0 命中）。唯一聚合是 `weighted_evidence`（§2.1–§2.3 公式）；
  `algorithm` / `prior_strength` 是 **reserved**，未知 `algorithm` 在加载时 fail-fast。

> 因此**不得**对外声称“两种聚合器可替换”或“规则 DSL 可配置”。
> 若未来实现，入口仍是 `[confidence] algorithm = <id>` + 库注册点，但当前两者都不存在。

### 3.4 默认值策略（已落地先验表；仍未标定）

**已落地**（审计 I-2，`e9d12ff` / `4e5db9c`）：出厂 `DefaultConfidenceConfig()` 带一张
**来源先验表** ——

| 来源键 | 先验值 | 说明 |
|---|---|---|
| `user` | **0.90** | 配置自定义检查 |
| `adapter` | **0.80** | 仅对「来源记为 `adapter`」的**通用类**调用方生效；仓库内生产适配器填具体 tool id（`trivy`/`ansible`/`netbox`…），**不会命中此键**（复审 N-4） |
| `builtin` | **1.0**（**不建显式 source 键**） | 设计 §3.1 的 `builtin = 1.0` 是**身份值**，由 `default = 1.0` 表达 |

`builtin` 刻意不写成 `[confidence.source]` 键：`source` 层先于 `domain` 层求值，一旦为
内置检查写死 source 规则，`[confidence.domain]` 对**最大检查群体**（builtin）就永远不可达。
需要固定全可信的部署方可显式写 `[confidence.source] builtin = 1.0`。

**默认仍禁用**（`enabled = false`）：`Resolve` 对每条检查恒回 1.0，评分与历史逐位一致。
开启 `enabled=true` 且不手写规则时，因出厂先验表存在，已**不是**纯 no-op（`user`/`adapter`
两类会降到 0.90/0.80），其余来源仍落到 `default=1.0` + 域级兜底。

> **`adapter=0.80` 的适用范围（复审 N-4）**：它只对「**真的把 `Source` 记为 `adapter`**」的调用方生效。
> 仓库内的生产适配器（`trivy`/`ansible`/`netbox` 等）产出的 `NormalizedFinding.Source` 是具体
> tool id，B-1 又把它原样搬进 `CheckResult.Source`，因此这些 finding **不会命中 `adapter` 键**，
> 而会落到 `default=1.0`。要让它们降权，必须按 tool id 显式写 `[confidence.source] trivy = …`
> 之类的规则。**不要**为了「让先验命中」去改适配器的 `Source` —— 那会改行为。

**⚠️ 标定未做**：`user=0.90` / `adapter=0.80` 是**先验**，不是从真实数据拟合出来的参数。
设计原文“实现期用实验标定并记录”**仍未兑现**；已有的是先验敏感性表
（`docs/2-experiments/CONFIDENCE_SENSITIVITY_2026-10-22.md`，扫 `c ∈ [0.5,1.0]`），
**不是标定**、也不是 CI 覆盖率验证。对外与论文口径不得声称“已标定 / 已验证”。

## 4. 数据流与覆盖矩阵（15 行；状态 = 修复后）

| 层 | 结构 | 改动 | 状态 |
|---|---|---|---|
| model | `CheckResult.Confidence` | 加字段（json `confidence,omitempty`）；`ResolveChecks` 按规则表填充 | ✅ |
| model | `CheckResult.Source` | 已有（builtin/user）→ 扩展为规则键；外部 adapter 也填（B-1） | ✅ |
| adapter | `NormalizedFinding` → `ToCheckResult` | 搬 `Source` + `Confidence`（`internal/adapter/adapter.go:86-105`） | ✅ **B-1** |
| ssam-lib | `CheckInput.Confidence` | 加字段；`NormalizeConfidence` 归一化 0→default、floor、≤1 | ✅ |
| ssam-lib | `DomainScore.Sigma / Confidence` | 输出带后验标准差 / 域证据可信度 | ✅ |
| ssam-lib | `EdgeFactorResult` | 触发强度按 `c_trigger` 衰减；携带触发可信度 | ✅ |
| ssam-lib | ScoringConfig | 注入 `ConfidencePolicy`（floor/default/enabled） | ✅ |
| ssam-lib | `AssessmentOutput` | `FinalSigma` + 区间 + `EvidenceConfidence` | ✅ |
| engine/ssam adapter | `CheckResultsToInputs` | 透传 Confidence | ✅ |
| engine/assessor | `computeDynamicFinalScore`/`computeDynamicDomainScores` | legacy 域分**调用** `ComputeDomainScoresBayes`（唯一实现）+ 写 σ/CI/证据置信度；`evaluateEdgeFactorChain` 接触发衰减 | ✅（I-1/I-4） |
| prism-lib | `CheckFailure.Confidence` | 加字段；`computeDebtRaw` 加权、塌缩计数加权 | ✅ |
| prism-lib | `NodeState.Confidence` | 加字段；**仅影响推断置信度**（`min(模型置信, node)`），风险数值不变 | ✅（I-7） |
| engine/srd | `ExternalCheckResult.Confidence` | 加字段；`pipeline` 按 tool id 走同一 `Resolve`（工具自带优先）；`adapter` 只搬运字段 | ✅（I-8） |
| config | `[confidence]` | 5 层规则解析；坏值 fail-fast；checkrx 字节字典序；algorithm reserved | ✅（I-5/I-9/I-10） |
| 输出 | `AssessmentResult` | `FinalSigma/Lower95/Upper95/EvidenceConfidence`（additive，旧字段不变） | ✅ |

**向后兼容原则（additive）**：`confidence=1` 且 `[confidence] enabled=false` 时，**既有字段**的
语义与取值逐位不变；输出是 **additive** 的 —— `domain_scores[].confidence`、
`score_lower95`/`score_upper95`、`evidence_confidence` 是**新增字段**（默认配置下 σ=0、
区间退化为 `[score, score]`、`evidence_confidence=1.0`，仍会随非零值出现在 JSON 中）。
因此**不能说“输出与改造前完全一致”**，只能说“**既有字段逐位一致 + 新增字段**”。
**唯一的既有字段行为变更（有意）**：`passed=false` 且 `Delta >= 0` 的检查
在修复前 legacy 会累加正 delta、插件会跳过；现在两边统一**跳过**（`DomainBayes` 只处理
`Delta < 0`，legacy 复用同一实现，`cee657f`）。

## 5. 验证计划（完成度，2026-10-22）

| # | 计划项 | 实际完成度 | 证据 |
|---|---|---|---|
| 1 | ssam-lib：conf=1 逐位一致；conf<1 单调；floor/clamp | ✅ | `TestConfidenceDisabledMatchesLegacy`、`TestNormalizeConfidenceClamps`、`TestEdgeFactorTriggerConfidenceAttenuation` |
| 2 | 方差传播：单域手工可算；多域 RSS | ✅ | `TestFinalBayesStats`、`TestFinalSigmaIntrinsicLayerWeight` |
| 3 | engine 集成：真实 config.ini 全默认与主分支逐位一致 | ⚠️ 有**位模式对照**，不是自动化门禁 | 修复前后 5 组默认配置夹具的域分/`FinalScore` IEEE-754 位模式完全相同、主批 33 条四候选指标逐行相同（控制侧独立复跑） |
| 4 | 边缘因子：c=1 与现状一致；c=0.5 半强度 | ✅ | `TestEdgeFactorTriggerConfidenceAttenuation`；legacy `TestChainRecords...` |
| 5 | Prism：债务加权；节点置信注入 | ✅ | `TestDebtConfidenceWeighted`、`TestNodeConfidenceCapsInferenceConfidence`（I-7 后仅推断置信度取 min，风险数值不变） |
| 6 | SRD：外部报告 confidence 归一化；缺省走来源表 | ✅ | `TestExternalToolIDConfidencePrecedence`、`TestExternalReportConfidenceToCheckFailure` |
| 7 | 论文素材：可信度 0.5–1.0 扫描敏感性表 | ⚠️ **有产物、非标定** | `docs/2-experiments/CONFIDENCE_SENSITIVITY_2026-10-22.md`（先验敏感性；明确不构成标定/覆盖率验证） |

> 第 7 项按设计 §5.7 的**表格形态**交付了，但**没有**用真实数据标定、也没有验证 CI 覆盖率：
> 它只回答“把先验 `c` 从 0.5 扫到 1.0 时分数/区间怎么变”。

## 6. 阶段拆分（实现顺序）

- P0 设计（本文档）
- P1 ssam-lib：字段 + weighted_evidence 域分/区间 + 边缘因子衰减 + 单测
- P2 prism-lib：CheckFailure.Confidence + 债务加权 + 节点置信
- P3 model/config：字段 + 规则引擎 DSL + 解析 + 默认表
- P4 engine 接入（主评分 + 边缘因子链）+ 集成测试
- P5 srd 管道 + adapter 来源映射
- P6 全量回归 + conf=1 基线验证 + 提交（中文说明）

---

## 7. 实现落点核对与遗留（2026-10-22；首次审计 → 两轮修复 → 复核）

> 本节的三层结构：**§7.1–§7.4 是修复后的现状**；**§7.5 是首次审计的问题清单（修复前，
> 只作历史背景）**；**§7.6 是曾经写错的地方（留痕）**；**§7.7 是逐条修复清单与复审状态**。
>
> 历史背景：首次独立审计判 **「不通过」**（2 Blocker + 12 Important + 12 Minor），依据
> `.superpowers/sdd/2026-09-12-edge-factor-coupling-milestone-b/audit-3-direction1-verdict.md`。
> 随后两轮修复把 **B-1/B-2 + I-1…I-12 共 14 项**全部落地，提交链见 §7.7。
> 因此债务清单应读作「**已完成（审计 14 项已修）+ 标定后置**」，而**不是**“已标定/已验证”。

### 7.1 §4 覆盖矩阵：逐行现状（15 行，全部已接上）

§4 共 **15 行**（原 14 行 + 为 B-1 补的 `ToCheckResult` 行）。下表逐行给落点与**修复后**状态：

| §4 的层 | 落点（文件:符号） | 状态 |
|---|---|---|
| `model.CheckResult.Confidence` | `internal/model/model.go:196-201`；`config.ResolveChecks` 填充 | ✅ |
| `model.CheckResult.Source` | `internal/model/model.go:192-195`；外部 adapter 也填（B-1） | ✅ |
| `NormalizedFinding` → `ToCheckResult` | `internal/adapter/adapter.go:86-105` 搬 `Source`+`Confidence` | ✅ **B-1**（`34b89c6`） |
| `ssam-lib.CheckInput.Confidence` | `ssam-lib/types.go:26-37` + `NormalizeConfidence`（`confidence.go:53-76`） | ✅ |
| `DomainScore.Sigma / Confidence` | `ssam-lib/types.go:3-13` | ✅ |
| `EdgeFactorResult` 触发衰减 + 触发可信度 | `TriggerConfidence` 在 `types.go:20-23`，**衰减在 `ssam-lib/ssam.go:225-298`**（`ast.go` 0 命中，此前写错） | ✅ |
| `ScoringConfig.ConfidencePolicy` | `ssam-lib/types.go:36,91`（此前写 35,88，行号漂移） | ✅ |
| `AssessmentOutput`：`FinalSigma` + 区间 | `ssam-lib/types.go:60-66`；插件 `engine.go:142-145`，legacy `assessor.go:978-988` | ✅（插件 + legacy；I-1 已修） |
| adapter `CheckResultsToInputs` 透传 | `internal/engine/ssam/adapter.go:104`（`Confidence: c.Confidence`；此前写 103，行号漂移） | ✅ |
| engine/assessor 域分与后验 | `internal/engine/assessor.go:524-533` **调用** `ComputeDomainScoresBayes`（唯一实现）；`978-988` 写 σ/CI/证据置信度 | ✅（I-1/I-4） |
| `prism-lib.CheckFailure.Confidence` + `computeDebtRaw` 加权 | `prism-lib/core.go:98-141`（`failureConfidence` → `abs(delta)·c`；塌缩计数同样加权） | ✅ |
| `prism-lib NodeState.Confidence` | `prism-lib/core.go:221` 回显；**唯一算法消费**在 `inference.go:328-334`：推断置信度取 `min(模型置信, node)`，风险数值不变 | ✅（I-7；`7b307f2`） |
| `engine/srd ExternalCheckResult.Confidence` | `internal/engine/srd/pipeline.go:201-203` 按 tool id 走同一 `ConfidenceConfig.Resolve`（工具自带优先）；`adapter.go:124-140` 只搬运字段 | ✅（I-8；`36a5b2c`） |
| config `[confidence]` | `internal/config/confidence.go`：5 层解析 + 坏值 fail-fast + `checkrx` 字节字典序 + `algorithm` reserved | ✅（I-5/I-9/I-10） |
| 输出 `AssessmentResult` | `internal/model/model.go:376-382`（additive 后验字段，旧字段不变） | ✅ |

§4 未单列、但 §7.1 初版曾作为独立行的两个落点：

| 落点 | 说明 | 状态 |
|---|---|---|
| `internal/engine/ssam/engine.go:93` | 装配路径调同一 `ComputeDomainScoresBayes`；接受性判定在 `:149-150` | ✅ |
| `internal/engine/assessor.go` `evaluateEdgeFactorChain` | 边缘因子触发衰减 | ✅ |

### 7.2 两条路径对 `c` 的归一：**已统一**（修复前是三类不一致）

修复后**只有一份**归一与累积：`ssam-lib.NormalizeConfidence` / `DomainBayes`。插件
（`internal/engine/ssam/engine.go:93`）、legacy（`internal/engine/assessor.go:524-533`）、
库入口（`ssam-lib/ssam.go:152-165`）全部调用 `ComputeDomainScoresBayes`，因此两条评分路径
不再可能漂移。**修复前**（首次审计时）有三类不一致，仅作历史背景保留：

1. **`0 < conf < floor`**：插件抬到 floor（`0.01 → 0.05`，域分 98），legacy 用 raw（`0.01`，域分 99.6）
   ⇒ 修复后两边都经 `NormalizeConfidence` 抬到 floor。
2. **`policy.Enabled = false` + 显式正置信**：legacy 内联完全不看 `policy.Enabled`，显式
   `0.5` 仍扣一半；插件恒回 `1.0` ⇒ 修复后 `NormalizeConfidence` 对两条路径都恒回 1.0。
3. **failed 且 `Delta > 0`**：插件跳过，legacy 内联仍累加（域分 93 vs 90）⇒ 修复后
   `DomainBayes` 只处理 `Delta < 0`，**两边统一跳过**。这是**唯一有意的行为变更**：
   旧 legacy 会累加正 delta；`enabled=false` 下该输入不再与修复前逐位一致（`old=93/new=90`）。

> 验证：`TestLegacyAndPluginHalfConfidenceParity`、
> `TestFailedCheckWithPositiveDeltaSkippedOnBothPaths`、
> `TestLegacyDefaultConfigIgnoresExplicitConfidence`（`cee657f`）。

### 7.3 ⚠️ 未兑现：实验标定（保留）；但默认表已落地、敏感性表已有

- **默认来源表已落地**（先验，`e9d12ff` / `4e5db9c`）：`user=0.90`、`adapter=0.80`；
  `builtin` 用 `default=1.0` 身份值表达（保留域级可达性）；默认仍**禁用**。见 §3.4。
  开启 `enabled=true` 且不手写规则时**不再是纯 no-op**（`user`/`adapter` 会降权），
  其余来源仍落到 `default` / 域级兜底。
- **敏感性表已有**（`docs/2-experiments/CONFIDENCE_SENSITIVITY_2026-10-22.md`，`ac1bd29`）：
  它扫的是**先验** `c ∈ [0.5,1.0]`，明确标注“不是标定、不是 CI 覆盖率验证”。
- **实验标定仍未做**：仓内没有标定产物（`git ls-files | grep -i calib` 为空），
  §3.4 的「实现期用实验标定并记录」**未兑现**。
⇒ 默认置信表是**先验**，**对外与论文口径不得声称"已标定/已验证"**。

### 7.4 `PP-01` 与 σ 边界（修复后）

- `Total` 无上界钳位 ⇒ 总分可 >100（`threat=1.4` 时 108）。
- 区间 `ConfidenceInterval` **只钳下界 0、不夹上界**，并以**实际** `Total` 为中心
  ⇒ `Total=108` 时区间仍包含 108（审计 M-1 修复）。
- 修复前是 `clamp95` 同时夹两端：`Total=108` 得 `[100,100]`，**点估计不在自己的区间内**
  （审计 S10）。该缺陷已修，上文保留作背景。
- `FinalBayesStats` 的 σ 已按 V2.0 intrinsic 权重乘 `0.5`（`IntrinsicLayerWeight`），
  但它仍是「域分不确定度折合 intrinsic 层」的**启发式**，不是对三层总分（含 0.3/0.2
  确定性层）的有效后验标准差 ⇒ 不得称「最终分的 95% 后验区间」（I-12）。

### 7.5 首次审计的问题清单（**修复前**摘要，仅作历史背景）

> 下表记录的是**修复前**的状态，**不是现状**；逐条修复状态见 §7.7。

| 级别 | 编号 | 问题 |
|---|---|---|
| **Blocker** | B-1 | 外部 adapter `ToCheckResult` 丢弃 `Source`/`Confidence` ⇒ `[confidence.source] nuclei=0.65` **永不命中**（方向① 的主要动机失效） |
| **Blocker** | B-2 | `accept_by_lower_bound` **只解析、从未被消费** ⇒ 打开后无任何行为变化 |
| Important | I-1 | legacy `runLegacyScoring` 完全不写 σ/CI/`EvidenceConfidence` |
| Important | I-2 | 出厂无来源默认表 ⇒ `enabled=true` 是纯 no-op（与 §3.4 冲突） |
| Important | I-3 | 标定未兑现（见 §7.3） |
| Important | I-4 | 两条路径归一不一致的三类（见 §7.2） |
| Important | I-5 | `[confidence.checkrx]` 首个命中**顺序不确定**（同一 INI 300 次 parse 出现两种结果） |
| Important | I-6 | 关键测试**没有牙**：调换规则优先级、删掉 legacy `*conf` 均全绿 |
| Important | I-7 | `NodeState.Confidence` 未用于传播/塌缩/推断（见 §7.1） |
| Important | I-8 | SRD 侧只透传、不查来源表（见 §7.1） |
| Important | I-9 | 坏数值**静默**（只有坏正则 fail-fast） |
| Important | I-10 | `algorithm` / `prior_strength` / `beta_bayes` 是**死配置**（Go 代码 `beta_bayes` 0 命中）；`[confidence.algorithm]` 段不解析 |
| Important | I-11 | 本节初版「11/11」误导 + `ast.go` 引用错误（已按 7.1 纠正） |
| Important | I-12 | σ 传播与 `SSAMV20Formula` 三层聚合不一致（见 §7.4） |

### 7.6 曾经写错的地方（留痕，防复发）

1. 「§4 覆盖矩阵 11/11 有落点」→ 实为**选择性核对**：§4 当时有 14 行（现 15 行），省略行里含 `NodeState.Confidence` 子项（当时未实现）。
2. 「分歧只在 `0<conf<floor`」→ 实为**三类**（其中「disabled 下 legacy 仍按显式 c 扣分」最严重）。
3. 「`ast.go` 的 `c_trigger` 衰减」→ 实际在 `ssam-lib/ssam.go:225-298`，`ast.go` 0 命中。
4. 「engine/assessor 主评分接贝叶斯域分」→ 实际是**内联 `delta*conf`**，不是同一份实现。

**教训**：核对落点时「字段存在」≠「接上了」≠「生效了」。这三层必须分开判。
（以上四处在两轮修复后都不再成立；§7.1 / §7.2 是修复后的现状，§7.7 给出提交与验证。）

### 7.7 修复清单与复审状态（2026-10-22）

> 逐条：问题 → 提交 → 实现落点 → 验证方式 → 状态。**本清单只反映实现侧**；
> 独立复审结论见 `audit-3-direction1-verdict.md` 的后续复审，二者不可互相替代。

| 编号 | 修复内容 | 提交 | 实现落点 | 验证（用例 / 命令） | 状态 |
|---|---|---|---|---|---|
| **B-1** | `ToCheckResult` 搬 `Source`/`Confidence`，来源表对第三方扫描器生效 | `34b89c6` | `internal/adapter/adapter.go:86-105` | `TestNormalizedFindingToCheckResultCarriesSource`、`...CarriesToolConfidence`、`TestExternalFindingDomainDeductionUsesSourceConfidence` | ✅ |
| **B-2** | 唯一判定 `AcceptanceDecision`，插件/库/legacy/kernel 全部消费 `accept_by_lower_bound` | `929b454` | `ssam-lib/confidence.go:231-242`；`engine.go:149`、`assessor.go:973-976`、`internal/assessor/assessor.go:655` | `TestAcceptanceDecisionUsesLowerBound`、`TestAcceptByLowerBoundPluginPath`、`TestAcceptByLowerBoundLegacyPath`、`TestApplyCTIOnlyAcceptsByLowerBound` | ✅ |
| **I-1** | legacy 也写 σ/CI/`EvidenceConfidence` | `cee657f` | `internal/engine/assessor.go:949-988` | `TestLegacyScoringEmitsPosteriorStats` | ✅ |
| **I-2** | 出厂来源先验表 `user=0.90`/`adapter=0.80`；`builtin` 用 `default=1.0` 表达；默认禁用 | `e9d12ff` / `4e5db9c` | `internal/config/confidence.go:90-123` | `TestDefaultConfidenceSourcePriors` | ✅（先验，未标定） |
| **I-3** | 先验敏感性表（明确非标定） | `ac1bd29` | `docs/2-experiments/CONFIDENCE_SENSITIVITY_2026-10-22.md` | 该表 §2 扫描结果 + §4 口径声明 | ⚠️ **有产物、仍非标定** |
| **I-4** | `c` 归一只有一份；`Delta>=0` 失败项两边都跳过（唯一有意行为变更） | `cee657f` | `ssam-lib/confidence.go:92-118`；`internal/engine/assessor.go:524-533` | `TestLegacyAndPluginHalfConfidenceParity`、`TestFailedCheckWithPositiveDeltaSkippedOnBothPaths` | ✅ |
| **I-5** | `[confidence.checkrx]` 按 key 字节字典序确定化 | `e10977d` | `internal/config/confidence.go:229-254` | `TestConfidenceCheckPatternsDeterministic`（300 次 parse） | ✅ |
| **I-6** | 关键测试装牙（优先级/legacy 域分/disabled 评分） | `cee657f` / `e10977d` | `internal/config/confidence_test.go`、`internal/engine/ssam/legacy_confidence_test.go` | `TestConfidenceResolveOverlappingCheckAndPattern`、`TestLegacyDefaultConfigIgnoresExplicitConfidence`、`TestPluginDefaultConfigIgnoresExplicitConfidence` | ✅ |
| **I-7** | `NodeState.Confidence` 只影响推断置信度（`min`），风险数值不变 | `7b307f2` | `prism-lib/inference.go:328-334`、`types.go:112-116` | `TestNodeConfidenceCapsInferenceConfidence`、`TestNodeConfidenceCarriedThrough` | ✅ |
| **I-8** | SRD 按 tool id 走同一 `Resolve`（工具自带 > 来源表 > default） | `36a5b2c` | `internal/engine/srd/pipeline.go:201-203`（`adapter.go:124-140` 只搬运字段） | `TestExternalToolIDConfidencePrecedence`、`TestExternalReportConfidenceToCheckFailure` | ✅ |
| **I-9** | `[confidence*]` 坏数值/坏布尔 fail-fast（带 section/key/value），`0` 是唯一哨兵 | `78c2a1d` | `internal/config/confidence.go:136-141,290-350` | `TestConfidenceBadValuesFailFast`、`TestConfidenceZeroSentinelClears` | ✅ |
| **I-10** | 未知 `algorithm` 加载即错；`algorithm`/`prior_strength` 标 reserved；只有 `weighted_evidence` | `9a3f348` | `internal/config/confidence.go:14-19,154-169` | `TestConfidenceUnknownAlgorithmFailsParse`、`TestConfidenceReservedPriorStrength` | ✅ |
| **I-11** | §7.1 改为 §4 逐行（15 行）、修正 `ast.go`/行号/prism 落点 | 本次文档收口（Task 31） | §7.1 | 本文 §7.1 与 `git show` 对照 | ✅ |
| **I-12** | `σ_final = 0.5·σ_domain`；区间只钳下界、上界不夹 | `1a54c67` | `ssam-lib/confidence.go:154-229` | `TestFinalSigmaIntrinsicLayerWeight`、`TestFinalBayesStats`、`TestEngineIntervalNotClampedTo100AndContainsPoint` | ✅ |

**默认行为对照**：修复前后 5 组默认配置夹具的域分 / `FinalScore` **IEEE-754 位模式完全相同**；
主批 33 条四候选指标**逐行相同**（控制侧独立复跑）。唯一例外是 I-4 的
`passed=false && Delta>=0` 输入（旧 legacy 累加正 delta，新实现两边跳过）。

**仍未兑现**：**实验标定 / CI 覆盖率验证**（I-3）。⇒ 对外口径：实现完成，
数值是**先验**，不得声称“已标定”。

### 7.8 内仓提交（两个算法库的历史补齐）

外层仓把 `ssam-lib/`、`prism-lib/` 作为**普通目录**跟踪（`git ls-tree` mode `040000`），
但两者**各自是独立 git 仓库**。本轮修复一度只体现在外层文件快照上、内仓工作树是脏的
（`ssam-lib` 7 文件 / `prism-lib` 5 文件未提交）—— 2026-10-23 已补齐内仓提交：

| 内仓 | 提交 | 内容 |
|---|---|---|
| `ssam-lib` | **`b2d0351`** | σ 折半传播（`IntrinsicLayerWeight=0.5`）、唯一区间 `ConfidenceInterval`（只钳下界）、唯一判定 `AcceptanceDecision`、先验表、测试加严 |
| `prism-lib` | **`e79c517`** | `SemanticRiskReport.InputConfidence` + `PredictFuture` 用 `min(模型置信, node.Confidence)`；风险数值不变 |

**用法**：外层读的是文件快照，所以**交付不受影响**；但引用库历史时以这两个内仓提交为准
（此前的 `d21efc0` / `cd2c60b` 是“可信度原生变量”的**初版**，本表两笔是其上的审计修复）。
