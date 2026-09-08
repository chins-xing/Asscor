# 情报可信度原生变量 — 设计文档（SSAM/SRD 算法层）

> 状态：设计定稿（2026-09-08）｜分支：ASSCOR-Research-Core｜关联：研究方向 ①
> 作者决策：贝叶斯置信区间语义 + config 内可替换规则引擎（用户 2026-09-08 确认）
> 配套方向 ②（边缘因子向量图变量化）另行设计，本设计只保证 ① 覆盖到边缘因子触发链。

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
