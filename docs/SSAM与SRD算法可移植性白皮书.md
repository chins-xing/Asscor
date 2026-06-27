# SSAM 与 SRD 算法可移植性白皮书

**版本**：v1.1
**日期**：2026-06-28
**状态**：发布
**配套文档**：SSAM 2.0 白皮书（第一篇章）、SRD 白皮书、工程实现白皮书（第三篇章）、ASSCOR 扩展体系白皮书

> 本文档为 SSAM (ssam-lib) 与 SRD/Prism (prism-lib) 两个纯函数式算法库的可移植性评估，分析其对外部平台的嵌入能力和跨语言移植路径。

---

## 摘要

SSAM 和 Prism 是 ASSCOR 项目中两个核心算法库，均采用"零外部依赖的纯函数式核心 + 适配层"架构设计。SSAM (ssam-lib) 提供系统安全可接受性评分引擎，Prism (prism-lib) 提供系统风险动力学计算引擎。两个库均可脱离 ASSCOR 框架独立部署，且仅依赖 Go 标准库（SSAM: 7 个包，Prism: 2 个包），具备向 Python、Rust、Java、C++、TypeScript 等语言的低门槛移植能力。SSAM 已具备完整的 JSON IR 中间表示和公式 DSL（AST），Prism 在这两方面仍有待完善。

---

## 目录

1. [架构概览](#一架构概览)
2. [SSAM 可移植性分析](#二ssam-ssam-lib-可移植性分析)
3. [SRD / Prism 可移植性分析](#三srd--prism-prism-lib-可移植性分析)
4. [两层架构对比分析](#四两层架构对比分析)
5. [可移植性评分卡](#五可移植性评分卡)
6. [改进建议](#六改进建议)
7. [统计汇总](#七统计汇总)

---

## 一、架构概览

```
┌──────────────────────────────────────────────────────────────┐
│                    ASSCOR Kernel (消费方)                      │
│                                                              │
│  ┌───────────────────────┐    ┌───────────────────────────┐  │
│  │  internal/ssam/       │    │  internal/prism/          │  │
│  │  (ASSCOR 适配层)       │    │  (线程安全包装 + 配置管理)   │  │
│  └───────────┬───────────┘    └─────────────┬──────────────┘  │
│              │                               │                 │
│  ===== 可移植边界 =====                                     │
│              ▼                               ▼                 │
│  ┌───────────────────────┐    ┌───────────────────────────┐  │
│  │  ssam-lib/            │    │  prism-lib/               │  │
│  │  ★ 纯函数式核心       │    │  ★ 纯函数式核心           │  │
│  │  ★ 零外部依赖         │    │  ★ 零外部依赖             │  │
│  │  ★ 独立 Go Module     │    │  ★ 独立 Go Module         │  │
│  └───────────────────────┘    └───────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 二、SSAM (ssam-lib) 可移植性分析

### 2.1 模块信息

| 属性 | 值 |
|------|-----|
| Module 路径 | `github.com/chins-xing/ssam` |
| Go 版本要求 | 1.26 |
| 源文件数 | 15 个 .go 文件 |
| 外部依赖 | **0** |
| 标准库依赖 | `math`, `sort`, `strconv`, `encoding/json`, `fmt`, `strings`, `time` |

### 2.2 文件功能清单

| 文件 | 职责 | 导出符号数 |
|------|------|:---:|
| `types.go` | 核心类型定义 (DomainScore, CheckInput, AssessmentInput/Output, WeightConfig, EdgeFactorConfig, ScoringConfig, ScoringFormula) | 8 类型 |
| `types_v2.go` | V2.0 三层语义类型 (RiskContext, RiskLayers, FinalScore, AssessmentInputV2/OutputV2, ScoringFormulaV2) | 8 类型 |
| `ssam.go` | 核心评分入口 (ComputeScore, ComputeDomainScores, ComputeWeightedSum, ApplyEdgeFactors, ApplyEdgeFactorsToChecks) | 5 函数 |
| `formulas.go` | V1.2 公式实现 (SSAMV12Formula, SimpleWeightedFormula, BuildWeightMap, RegisterBuiltinFormulas) | 4 函数 |
| `formulas_v2.go` | V2.0 公式实现 (SSAMV20Formula, ComputeScoreV2, RegisterBuiltinFormulasV2) | 4 函数 |
| `ast.go` | 公式 DSL (FormulaAST, EvalAST, ASTToFormula, 7 种操作符) | 3 函数 + 7 常量 |
| `ir.go` | 中间表示 (SSAMIR, NewIR, UnmarshalIR, Validate) | 1 类型 + 3 函数 |
| `defaults.go` | 默认权重/边缘因子/评分配置 | 3 变量 |
| `validation.go` | 输入/输出校验 | 2 函数 |
| `errors.go` | 错误类型 (SSAMError) | 1 类型 + 4 变量 |

### 2.3 依赖分析

```
ssam-lib 依赖树：
├── math          (标准库)  — 所有公式文件
├── sort          (标准库)  — ComputeDomainScores, ApplyEdgeFactorsToChecks
├── strconv       (标准库)  — validation.go, formulas_v2.go
├── encoding/json (标准库)  — ir.go (SSAMIR.MarshalJSON)
├── fmt           (标准库)  — ast.go (错误格式化)
├── strings       (标准库)  — ast.go (evalRef 前缀匹配)
└── time          (标准库)  — ir.go (时间戳)
```

**外部依赖：0 个。所有依赖均为 Go 标准库。**

### 2.4 耦合度分析

| 耦合维度 | 评级 | 说明 |
|---------|:---:|------|
| 与 ASSCOR Kernel 耦合 | **无耦合** | ssam-lib 完全独立，不 import 任何 ASSCOR 包 |
| 与 ASSCOR config 耦合 | **无耦合** | 配置通过 `ScoringConfig` 结构体传入，由 adapter 做转换 |
| 与 ASSCOR model 耦合 | **无耦合** | 使用独立类型 `CheckInput`/`AssessmentInput`，由 adapter 做映射 |
| 与数据库耦合 | **无** | 不涉及任何持久化 |
| 与网络耦合 | **无** | 无 HTTP/RPC 调用 |
| 与 goroutine 耦合 | **无** | 纯函数，无并发原语 |

### 2.5 跨语言移植路径

**方式一：JSON IR（推荐）**

通过 `SSAMIR` 中间表示实现跨语言消费：

```json
{
  "meta": {"version": "2.0", "formula_id": "ssam_v2.0", "timestamp": "2026-05-28T12:00:00Z"},
  "input": {"host_id": "server-01", "checks": [...], "risk_context": {...}},
  "output": {"final_score": 51.03, "acceptable": false, "domain_scores": [...], "risk_layers": {...}}
}
```

**方式二：公式重实现**

| 公式 | AST 结构 | 核心操作 |
|------|---------|---------|
| SSAM V1.2 | `multiply(multiply(multiply(weighted_sum, threat), exposure), product_chain)` | 加权平均 + 连乘 |
| SSAM V2.0 | `multiply(multiply(multiply(weighted_sum, product_chain), max(exposure, 0.60)), max(threat, 0.60))` | 加权平均 + 边缘因子连乘 + 三层乘积 |

### 2.6 跨语言实现难度

| 目标语言 | 难度 | 关键工作量 |
|---------|:---:|------|
| Python | **低** | 约 150 行 |
| Rust | **低** | 约 200 行 |
| Java | **低-中** | 约 250 行 |
| C++ | **中** | 约 250 行 |
| JavaScript/TypeScript | **低** | 约 120 行 |

### 2.7 可嵌入目标平台

| 平台 | 集成方式 |
|------|------|
| Kubernetes Admission Controller | Pod Security → SSAM Score → Accept/Reject |
| CI/CD Pipeline | Build → SSAM < 80 → Block deploy |
| SIEM / SOAR | Alert → SSAM re-evaluation → Prioritize |
| Cloud Security Platform | Cloud Asset → SSAM → Unified Risk Score |
| LLM Agent | IR JSON → LLM analysis → Recommendation |

---

## 三、SRD / Prism (prism-lib) 可移植性分析

### 3.1 模块信息

| 属性 | 值 |
|------|-----|
| Module 路径 | `github.com/chins-xing/prism` |
| Go 版本要求 | 1.21 |
| 源文件数 | 7 个 .go 文件（含测试 8 个） |
| 外部依赖 | **0** |
| 标准库依赖 | `math`, `sort` |

### 3.2 文件功能清单

| 文件 | 职责 | 导出符号数 |
|------|------|:---:|
| `types.go` | 数据模型 (NodeState, EdgeState, PrismConfig, AssetRiskResult, PathResult, CheckFailure) | 6 类型 |
| `config.go` | 默认配置 (DebtAlpha=1.2, PropCap=0.25, DebtCap=0.30, DebtNormDays=1500, PathDecay=0.80, MaxPathDepth=5, ScoreFloor=0.40) | 1 函数 |
| `core.go` | Core Layer — 确定性数值求值 (ComputeDynamicScore) | 1 函数 |
| `semantic.go` | Semantic Layer — 四态模糊隶属度映射 (ComputeStateMembership, trapezoidUp/Down, triangular) | 1 核心函数 |
| `inference.go` | Inference Layer — 马尔可夫链状态预测 (PredictFuture, MarkovDefaultTransition, matMulVec4, determineTrend) | 2 核心函数 |
| `paths.go` | 路径搜索 (FindPropagationPaths) | 1 函数 |
| `core_test.go` | 完整测试套件 (10+ 个测试用例) | 0 |

### 3.3 依赖分析

```
prism-lib 依赖树：
├── math  (标准库)  — core.go (Pow, Sqrt, Max, Min, Abs)
└── sort  (标准库)  — paths.go (路径排序)
```

**外部依赖：0 个。仅依赖 2 个 Go 标准库包。**

### 3.4 耦合度分析

prism-lib 完全独立于 ASSCOR，通过 `PrismConfig` 值类型接收配置，通过 `float64` 接收 SSAM 输出，无类型级别耦合。

### 3.5 关键设计特性

| 特性 | 说明 | 可移植性影响 |
|------|------|:---:|
| 正交性 | 传播惩罚仅依赖上游节点 SSAM，与当前节点独立 | 公式可独立验证 |
| 下界稳定 | `ScoreFloor=0.40` 防止永久塌缩 | 无状态依赖 |
| 天归一化 | 债务公式使用天而非秒，数值稳定 | 降低浮点误差 |
| 跳跃衰减 | γ^n 路径衰减，长路径不无限叠加 | 纯数学计算 |
| 无状态 | Prism 不管理 FailUnix、不记录历史 | 无迁移状态数据 |

### 3.6 核心公式

**外部风险**：E(v) = (100 − S_ssam(v)) / 100

**风险溢出**：spillover(u → v) = E(u) × λ_trans(e)

**传播风险**：R_prop(v) = min(1.0, √(Σ spillover(e)²))

**安全债务**（天归一化）：D(c, t) = |Δ(c)| × ((t − t_fail) / 86400)^α

**正交化动态评分**：S_prism(v, t) = max(S_ssam(v) × 0.40, S_ssam(v) × (1 − min(0.25, R_prop)) × (1 − min(0.30, ΣD/1500)))

### 3.7 跨语言实现难度

| 目标语言 | 难度 | 关键工作量 |
|---------|:---:|------|
| Python | **低** | 两个函数 + 一个 DFS，约 80 行 |
| Rust | **低** | 约 100 行 |
| Java | **低** | 约 120 行 |
| C++ | **低-中** | 约 150 行 |
| JavaScript/TypeScript | **低** | 约 70 行 |

### 3.8 实现状态

| 维度 | 状态 |
|------|------|
| Core Layer 计算函数 | ✅ 已实现 (core.go) |
| Semantic Layer 隶属度映射 | ✅ 已实现 (semantic.go) |
| Inference Layer 马尔可夫预测 | ✅ 已实现 (inference.go) |
| 路径搜索 | ✅ 已实现 (paths.go) |
| 单元测试覆盖 | ✅ 10+ 测试用例 |
| JSON IR | ❌ 未实现 |
| 跨语言验证套件 | ❌ 未实现 |

---

## 四、两层架构对比分析

两个算法库共享"纯函数核心 + 适配层"架构模式：

```
┌──────────────────────────────────────────────────────┐
│                  纯函数核心 (Pure Core)                │
│  ssam-lib / prism-lib                                │
│  ✅ 零外部依赖    ✅ 纯函数    ✅ 无副作用              │
│  ✅ 独立 Module   ✅ 可测试    ✅ 可独立发布            │
│  ===== 可移植边界 =====                               │
├──────────────────────────────────────────────────────┤
│                  适配层 (Adapter)                     │
│  internal/ssam / internal/prism                      │
│  ⚠️ 依赖 ASSCOR 类型    ⚠️ 添加线程安全                │
│  ⚠️ 添加 context.Context  ⚠️ 添加 Hook 机制           │
│  ===== ASSCOR 绑定边界 =====                          │
├──────────────────────────────────────────────────────┤
│                  ASSCOR Kernel                       │
└──────────────────────────────────────────────────────┘
```

### 4.1 适配层职责对比

| 职责 | SSAM 适配层 | Prism 适配层 |
|------|:---:|:---:|
| 类型转换 (config → lib) | adapter.go (152 行) | 无（直接透传） |
| 类型重导出 | re_exports.go (55 行) | 无 |
| 线程安全 | sync.RWMutex | sync.RWMutex |
| 生命周期 Hooks | 4 个 HookPhase | 无 |
| Context 支持 | 有 | 无 |
| 自定义公式 | 有 | 无 |
| 接口抽象 | Provider | 无 |

**关键发现**：Prism 适配层远比 SSAM 适配层轻薄（1 个文件 vs 4 个文件），原因是 Prism 的职责更单一（仅 2 个函数）。

### 4.2 适配层迁移开销

适配层属于 ASSCOR 特有的工程层，**不需要移植**。只有纯函数核心需要移植。目标平台需重新实现的能力：类型转换（必须）、线程安全（按需）、超时控制（按需）、Hooks（按需）。

---

## 五、可移植性评分卡

### 5.1 SSAM (ssam-lib)

| 维度 | 评分 | 权重 | 加权分 |
|------|:---:|:---:|:---:|
| 外部依赖数量 | ⭐⭐⭐⭐⭐ (0) | 30% | 1.50 |
| 代码耦合度 | ⭐⭐⭐⭐⭐ (无耦合) | 25% | 1.25 |
| 接口抽象度 | ⭐⭐⭐⭐⭐ (JSON IR + AST) | 20% | 1.00 |
| 跨语言消费 | ⭐⭐⭐⭐ (JSON IR 完整，但需 Go 运行时) | 15% | 0.60 |
| 文档完整性 | ⭐⭐⭐⭐⭐ (白皮书 + README) | 10% | 0.50 |
| **总分** | | | **4.85 / 5.00** |

### 5.2 SRD / Prism (prism-lib)

| 维度 | 评分 | 权重 | 加权分 |
|------|:---:|:---:|:---:|
| 外部依赖数量 | ⭐⭐⭐⭐⭐ (0) | 30% | 1.50 |
| 代码耦合度 | ⭐⭐⭐⭐⭐ (无耦合) | 25% | 1.25 |
| 接口抽象度 | ⭐⭐⭐⭐ (纯函数，但无 IR) | 20% | 0.80 |
| 跨语言消费 | ⭐⭐⭐ (无 JSON IR，需重实现) | 15% | 0.45 |
| 文档完整性 | ⭐⭐⭐⭐⭐ (白皮书 + 完整测试) | 10% | 0.50 |
| **总分** | | | **4.50 / 5.00** |

### 5.3 差距分析

SSAM 和 Prism 之间的最大差距在于**中间表示（IR）**：

| 特性 | SSAM | Prism |
|------|:---:|:---:|
| JSON IR | ✅ SSAMIR | ❌ |
| 公式 DSL (AST) | ✅ FormulaAST | ❌ |
| 版本化公式 ID | ✅ ssam_v1.2 / ssam_v2.0 | ❌ |
| 可追溯归因 | ✅ RiskLayers.Contributors | ⚠️ 部分 |

---

## 六、改进建议

### 6.1 高优先级：Prism JSON IR

为 Prism 添加类似 SSAM 的 JSON IR 机制，实现与 SSAM 同级别的跨语言消费能力。

### 6.2 中优先级：跨语言验证套件

为两个算法库提供跨语言参考实现和测试向量（已知输入 → 期望输出），降低第三方移植的验证成本。

### 6.3 中优先级：Prism 公式 AST 化

参考 SSAM 的 `FormulaAST`，将 Prism 的公式结构化，支持序列化和版本化。

### 6.4 低优先级：Go 版本降低与 WASM

将 ssam-lib 的 Go 版本从 1.26 降至 1.21（与 prism-lib 一致）；探索 WASM 编译目标，实现浏览器端直接调用。

---

## 七、统计汇总

| 指标 | SSAM (ssam-lib) | SRD / Prism (prism-lib) |
|------|:---:|:---:|
| 源文件数 | 15 | 7 |
| 外部依赖 | 0 | 0 |
| 标准库依赖 | 7 个包 | 2 个包 |
| 导出类型 | 16 | 6 |
| 导出函数 | 21 | 7 |
| 代码行数 (不含测试) | ~800 | ~350 |
| 测试用例数 | 多个 | 10+ |
| JSON IR | ✅ | ❌ |
| 公式 DSL/AST | ✅ | ❌ |
| 多版本公式 | ✅ (v1.2 + v2.0) | ❌ (单版本) |
| 语义层 (Semantic Layer) | ✅ (V2.0 三层模型) | ✅ (四态隶属度) |
| 推理层 (Inference Layer) | ❌ | ✅ (马尔可夫链预测) |
| 独立 Go Module | ✅ | ✅ |
| 可嵌入平台 | 6+ | 依赖 SSAM 输出 |

---

## 结论

SSAM 和 Prism 均具备优秀的可移植性，是 ASSCOR 项目中最容易独立部署和跨语言移植的两个模块。其核心设计模式——"零外部依赖的纯函数式核心 + 适配层"——为后续的任何平台迁移提供了坚实的基础。两者功能互补：SSAM 侧重安全性评分与 IR/AST 成熟度，Prism 侧重风险动力学状态推理。Prism 在三层架构（Core/Semantic/Inference）已全部实现，其 Semantic Layer（四态隶属度）和 Inference Layer（马尔可夫链预测）提供了 SSAM 所不具备的模糊语义与状态推理能力。两者的主要差距在于中间表示成熟度：SSAM 已具备完整的 JSON IR 和公式 DSL，Prism 在 JSON IR 方面仍有提升空间。补齐后两个算法库将具有完全等效的可移植性。