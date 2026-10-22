# 情报可信度原生变量 — 设计文档（SSAM/SRD 算法层）

> 状态：**主体已实现，但首次独立审计判「不通过」—— 2 个 Blocker 未修**（审计 2026-10-22；
> 设计定稿 2026-09-08；实现 2026-09）｜分支：ASSCOR-Research-Core｜关联：研究方向 ①
> 作者决策：贝叶斯置信区间语义 + config 内可替换规则引擎（用户 2026-09-08 确认）
> 配套方向 ②（边缘因子向量图变量化）另行设计，本设计只保证 ① 覆盖到边缘因子触发链。
>
> **⚠️ 不要按「✅ 完成」对外**。债务清单那一行应读作「主体实现 + 2 Blocker 未修 + 标定后置」。
> 详见 §7：**B-1** 外部 adapter 丢弃 `Source`/`Confidence`（`[confidence.source]` 对第三方扫描器
> 永不命中）· **B-2** `accept_by_lower_bound` 只解析不消费 · 标定未兑现 · 两条评分路径归一不一致 等。

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

加权期望不变；方差按权重 RSS 传播：

```
score_final = Σ w_d·score_d / Σw_d                      # 与现状一致
sigma_final = sqrt( Σ (w_d·σ_d)² ) / Σw_d               # 域独立假设
区间: [score_final − 1.96·sigma_final, score_final + 1.96·sigma_final] ∩ [0,100]
```

**可接受性判定**：默认仍用点估计 `score_final ≥ threshold`（与现状一致，避免全线
行为漂移）；config 可开 `confidence.accept_by_lower_bound=true` 时用区间下界做
保守判定（更安全，会显著提高阻断率——论文中作为选项讨论）。

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

节点级：`NodeState` 增加 `Confidence`（由 SSAM 域可信度聚合），传播/塌缩/推断
层将其作为观测噪声系数（推断置信度 = f(模型置信, 输入可信度)）。SRD
`ExternalCheckResult` 增加 `Confidence`，adapter 规范化时从工具源映射。

## 3. 可信度规则引擎（config 内可配置 / 可替换）

初始可信度**不硬编码单一值**：由 `[confidence]` 段按**规则表**计算，且**聚合算法
本身可配置/可替换**。用户可在 config.ini 内声明用哪个算法与全部参数；实现侧以
算法注册表支持替换（Go 注册点 + config 引用），默认 `weighted_evidence`。

### 3.1 config.ini 语法（设计）

```ini
[confidence]
enabled = true
algorithm = weighted_evidence          ; 可选: weighted_evidence | beta_bayes | <自定义注册id>
accept_by_lower_bound = false          ; true=可接受性按95%区间下界判定
default = 1.0                          ; 规则未匹配时的兜底可信度

; ---- 规则优先级: 精确检查ID > 来源 > 域 > default ----
[confidence.check]
AS-001 = 0.99                          ; 检查级微调
; 更细: [confidence.check.AS-001] 可给字段级? —— 见 3.3 规则 DSL

[confidence.source]
builtin = 1.0                          ; 本地内置
user = 0.90                            ; 用户自定义检查
root = 1.0                             ; root 特权检查(直接系统读取)
extension = 0.70                       ; 扩展检查
adapter = 0.80                         ; 适配器
scan_external = 0.65                   ; 外部扫描器(默认组)
cti = 0.50                             ; CTI/ATT&CK 情报
spc = 0.60                             ; SPC 漏洞关联
check_module = 0.75                    ; SRD 外部评估模块
unknown = 0.50

[confidence.domain]
attack_surface = 0.95                  ; 域级兜底(未匹配检查时)
business_continuity = 0.98
operation_trust = 0.95
resilience = 0.97

[confidence.algorithm]                 ; 算法参数(按 algorithm 名解释)
prior_strength = 2.0                   ; weighted_evidence: Beta先验等效样本(>0)
floor = 0.05                           ; 可信度下限(不允许0 → 完全随机观测)
```

### 3.2 规则匹配顺序

对每条检查/情报按 `(source, check_id/rule_id, domain)` 解析：

1. `[confidence.check]` 精确 `check_id` 命中 → 用之
2. `[confidence.source]` 来源命中 → 用之
3. `[confidence.domain]` 域命中 → 用之
4. `default`

外部工具 finding 的 source 由 SRD adapter 归一化为 `scan_external` 组内具体源
（nuclei/trivy/lynis/openscap/…可各自微调：`[confidence.source] nuclei = 0.7`）。

### 3.3 规则 DSL 与"算法写进 config"

用户诉求"更精细规则 + 算法直接写在 config 内供用户自行替换"。落地方案：

- **规则 DSL**（`[confidence.rules]`，每行一条）：
  ```
  ; 语义: <selector> -> <value|expr>
  check:AS-003 -> 0.98
  source:adapter & severity:critical -> min(1.0, 0.75 + 0.15)   ; 表达式(常量运算)
  domain:attack_surface & check:/^AS-/ -> 0.97                   ; 正则选择器
  ```
  选择器支持 `check:`、`source:`、`domain:`、`severity:`、`age_days:`，可 `&` 组合，
  值支持常量或简单算术表达式（`min/max/+/-/*/` 与常量）——由小型 DSL 解释器
  求值（白名单 token，无脚本逃逸面）。
- **算法替换**：`algorithm = <id>`；内置 `weighted_evidence`（2.1–2.3 公式）与
  `beta_bayes`（Beta 后验的严格形式）。外部/自定义算法经
  `confidencesrc.RegisterAlgorithm(id, func(cfg) Aggregator)` 注册，config 内
  直接引用即可——config 是用户替换算法的入口，注册是库扩展点。

### 3.4 默认值策略（用户确认）

按来源默认表 + config 可覆盖，且规则引擎允许**检查级/域级/正则级**的精细覆盖；
不提供"全 1.0 纯 opt-in"（机制会形同虚设），也不默认激进拉低（保持 conf=1 基线
可验证后，默认表的值让总分布在现状附近，具体数值在实现期用实验标定并记录）。

## 4. 数据流与覆盖矩阵

| 层 | 结构 | 改动 |
|---|---|---|
| model | `CheckResult.Confidence` | 加字段（json `confidence,omitempty`）；转换时从规则表填充 |
| model | `CheckResult.Source` | 已有（builtin/user）→ 扩展为规则键 |
| ssam-lib | `CheckInput.Confidence` | 加字段；`ComputeDomainScores` 归一化 0→default |
| ssam-lib | `DomainScore.Sigma / Conf` | 输出带后验标准差/域可信度 |
| ssam-lib | `EdgeFactorResult` | 触发强度按 `c_trigger` 衰减；携带触发可信度 |
| ssam-lib | ScoringConfig | 注入 `ConfidencePolicy`（floor/default） |
| ssam-lib | `AssessmentOutput` | `FinalSigma` + 区间字段 |
| engine/ssam adapter | `CheckResultsToInputs` | 透传 Confidence |
| engine/assessor | `computeDynamicFinalScore`/`computeDynamicDomainScores` | 主评分路径接贝叶斯域分（engine 库模式）；`evaluateEdgeFactorChain` 接触发衰减 |
| prism-lib | `CheckFailure.Confidence` | 加字段；`computeDebtRaw` 加权 |
| prism-lib | `NodeState.Confidence` | 加字段；传播/推断用 |
| engine/srd | `ExternalCheckResult.Confidence` | 加字段；adapter 归一化映射 |
| config | `[confidence]` | 规则引擎解析 |
| 输出 | `AssessmentResult` | `Confidence` 区间字段（json），保持旧字段不变 |

**向后兼容原则（每个阶段可验证）**：`confidence=1` 且 `[confidence] enabled=false`
时，所有路径输出与当前完全一致。实现顺序上先保证公式级兼容单测，再做接入。

## 5. 验证计划

1. ssam-lib 单测：conf=1 与旧 ComputeDomainScores 逐位一致；conf<1 时分数单调、
   区间随可信度下降而变宽；floor/clamp 边界。
2. 方差传播正确性：单域单失败手工可算；多域 RSS 对照。
3. engine 集成：真实 config.ini 全默认 → 与当前主分支评分逐位一致。
4. 边缘因子：c=1 与现状一致；c=0.5 半强度。
5. Prism：债务加权单测（c=1 兼容）；节点置信注入。
6. SRD：外部报告带 confidence 归一化；缺省走来源表。
7. 论文素材：敏感性表格（可信度扫描 0.5–1.0 的分数变化）供 E-系列分析。

## 6. 阶段拆分（实现顺序）

- P0 设计（本文档）
- P1 ssam-lib：字段 + weighted_evidence 域分/区间 + 边缘因子衰减 + 单测
- P2 prism-lib：CheckFailure.Confidence + 债务加权 + 节点置信
- P3 model/config：字段 + 规则引擎 DSL + 解析 + 默认表
- P4 engine 接入（主评分 + 边缘因子链）+ 集成测试
- P5 srd 管道 + adapter 来源映射
- P6 全量回归 + conf=1 基线验证 + 提交（中文说明）

---

## 7. 实现落点核对与遗留（2026-10-22；含**首次独立审计**结论）

> ⚠️ **本节在 2026-10-22 被审计推翻后重写**。本节的初版写过两处**乐观的错误结论**，均已作废并保留在
> §7.6 的「曾经写错的地方」里：
> ① 「§4 覆盖矩阵 11/11 有落点」——实际是**选择性核对**，且省略的一行里包含一条**未实现**的算法子项；
> ② 「两条路径的归一分歧只在 `0<conf<floor`」——实际有**三类**（见 §7.2）。
>
> **审计判决：不通过**（2 Blocker + 12 Important + 12 Minor）。依据：
> `.superpowers/sdd/2026-09-12-edge-factor-coupling-milestone-b/audit-3-direction1-verdict.md`。
> **债务清单「✅ 完成」因此言过其实**，应读作「**主体实现 + 2 个 Blocker 未修 + 标定后置**」。

### 7.1 §4 覆盖矩阵：逐行现状（含 4 行不是「已实现」）

§4 共 **14 行**（不是 11 行）。下表逐行给落点，并用状态区分「真接上了」与「字段/解析在但不生效」：

| §4 的层 | 落点（文件:符号） | 状态 |
|---|---|---|
| `model.CheckResult.Confidence` | `internal/model/model.go:201` | ✅ |
| `model.CheckResult.Source` | 字段在（`model.go`），但**外部 adapter 不填** ⇒ `[confidence.source]` 对第三方扫描器永不命中 | ❌ **B-1** |
| `ssam-lib.CheckInput.Confidence` | `ssam-lib/types.go` + `NormalizeConfidence` | ✅ |
| `DomainScore.Sigma / Conf` | `ssam-lib/types.go:9`（`Sigma`） | ✅ |
| `EdgeFactorResult` 触发衰减 + 触发可信度 | `TriggerConfidence` 定义在 `types.go:20-23`，**衰减实现在 `ssam-lib/ssam.go:225-298`**（`ast.go` 里 **0 命中**，此前写错） | ✅ |
| `ScoringConfig.ConfidencePolicy` | `ssam-lib/types.go:36,91`（此前写 35,88，行号漂移） | ✅ |
| `AssessmentOutput`：`FinalSigma` + 区间 | `ssam-lib/types.go:61-66` | ✅（插件路径）/ ❌ **legacy 路径不写，见 I-1** |
| adapter `CheckResultsToInputs` 透传 | `internal/engine/ssam/adapter.go:103` | ✅ |
| engine/assessor 主评分路径 | `internal/engine/assessor.go:486-504` —— 是**内联 `delta*conf`**，**不是**贝叶斯域分（此前描述不准确） | ⚠️ 实现但不是同一份代码 |
| engine/ssam 装配路径 | `internal/engine/ssam/engine.go:93` | ✅ |
| `evaluateEdgeFactorChain` | `internal/engine/assessor.go`（触发衰减） | ✅ |
| `prism-lib.CheckFailure.Confidence` + `computeDebtRaw` 加权 | `prism-lib/core.go:98-138`（`failureConfidence` → `|delta|·c`） | ✅ |
| `prism-lib NodeState.Confidence`「传播/推断用」 | `prism-lib/core.go:221` **只回显**；`nodeConfidence` 无其它调用点 ⇒ 不参与传播/塌缩/推断 | ❌ **I-7 未实现** |
| `engine/srd ExternalCheckResult.Confidence` | `internal/engine/srd/adapter.go:124-136` 只透传，**不查 `[confidence.source]`** | ⚠️ **I-8 接线不完整** |

### 7.2 两条路径对 `c` 的归一：**三类**不一致（不是一类）

1. **`0 < conf < floor`**：插件抬到 floor（`0.01 → 0.05`，域分 98），legacy 用 raw（`0.01`，域分 99.6）。
2. **`policy.Enabled = false` + 显式正置信**：`internal/engine/assessor.go:498-503` 的内联**完全不看
   `policy.Enabled`** ⇒ check 自带 `Confidence=0.5` 时 legacy 仍扣一半（score 90 / domain 80），
   而插件按 `NormalizeConfidence` 恒回 `1.0`（score 80 / domain 60）。
   ⇒ 这与 `ConfidencePolicy` 注释「disabled ⇒ every check treated as fully confident」**直接冲突**。
3. **failed 且 `Delta > 0`**：插件 `DomainBayes` 跳过（域分 90），legacy 内联仍累加（93）；
   改前快照对比 `old=93 / new=90` ⇒ **「`enabled=false` ⇒ 历史逐位一致」并非普遍成立**。

> 此前初版只写了第 1 类并断言「真正的分歧只在 `0<conf<floor`」——**错**。
> 归一/累积应当抽成**一份**共享实现，并由测试钉住；修法见审计报告 I-4。

### 7.3 ❌ 未兑现：实验标定（保留）

§3.4 原文：「…具体数值在**实现期用实验标定并记录**」。
**截至 2026-10-22，仓内没有任何标定产物**（`git ls-files | grep -i calib` 为空），§5.7 的
「可信度 0.5–1.0 扫描敏感性表」也未交付。另：**出厂 `config.ini` 没有来源默认表**
（`ByCheckID/BySource/ByDomain/CheckPatterns` 全空、`Default=1.0`）⇒ `enabled=true` 目前是**纯 no-op**，
与 §3.4「不提供全 1.0 纯 opt-in」直接冲突（I-2）。
⇒ 默认置信表是**先验**，**对外与论文口径不得声称"已标定/已验证"**。

### 7.4 `PP-01` 与 σ 边界（补审计实测）

`clamp95` 只夹 `Lower95`/`Upper95`（`ssam.go:146-147`），`Total` 无钳位 ⇒ 总分可达 >100。
审计实测出更难看的一面：`Total=108` 时 **`Lower95 = Upper95 = 100`** ⇒ **点估计不在区间内**
（区间被夹到 `[0,100]`，而点估计在区间外）。论文脚注需补这一句。
另：`FinalBayesStats` 的 σ 只是**域分 RSS**，没有按 V2.0 三层权重（0.5/0.3/0.2）传播
⇒ 把它叫作「最终分的 95% 后验区间」**不成立**（I-12）；要么改公式，要么改称「域分不确定度启发式」。

### 7.5 首次审计的问题清单（摘要，详见 verdict 文件）

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

1. 「§4 覆盖矩阵 11/11 有落点」→ 实为**选择性核对**：§4 有 14 行，省略行里含未实现的 `NodeState.Confidence` 子项。
2. 「分歧只在 `0<conf<floor`」→ 实为**三类**（其中「disabled 下 legacy 仍按显式 c 扣分」最严重）。
3. 「`ast.go` 的 `c_trigger` 衰减」→ 实际在 `ssam-lib/ssam.go:225-298`，`ast.go` 0 命中。
4. 「engine/assessor 主评分接贝叶斯域分」→ 实际是**内联 `delta*conf`**，不是同一份实现。

**教训**：核对落点时「字段存在」≠「接上了」≠「生效了」。这三层必须分开判。
