# Prism

**Propagation Risk Inference & Semantic Model** — 风险传播推断与语义模型引擎

## 定义

Prism 是一个三层风险分析引擎：

```
External Assessment Report
    → Core Layer: 动态风险评分 (ComputeDynamicScore)
    → Semantic Layer: 模糊语义状态归属 (ComputeSemanticState)
    → Inference Layer: Markov Chain 未来风险预测 (PredictFuture)
```

## 架构

```
┌──────────────────────────────────────────┐
│              Prism Engine                │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  │
│  │  Core    │  │ Semantic │  │Infer  │  │
│  │  Layer   │→ │  Layer   │→ │ Layer │  │
│  │  (PDAG)  │  │(Fuzzy 4) │  │(Markov)│  │
│  └──────────┘  └──────────┘  └───────┘  │
│       │              │            │      │
│       └──────────────┴────────────┘      │
│                      │                   │
│              ┌───────▼───────┐           │
│              │   Prism IR    │           │
│              │  (JSON/API)   │           │
│              └───────────────┘           │
└──────────────────────────────────────────┘
```

## 三层详解

### Core Layer (核心层)
- 输入: `NodeState` (SSAM分数 + 失败检查列表 + 时间戳)
- 传播: Partial Dependency Acyclic Graph (PDAG) 风险传播
- 输出: `AssetRiskResult` (PrismScore, ExternalRisk, PropagatedRisk, CollapseModifier)

### Semantic Layer (语义层)
- 四状态模糊隶属度: Stable, Degraded, Untrusted, Collapse
- 基于 PrismConfig 阈值映射
- 输出: `SemanticRiskReport`

### Inference Layer (推断层)
- Markov Chain 未来状态预测
- 可配置 horizon days
- 输出: `FutureRiskReport` (Trend, CollapseRisk, Confidence)

## 依赖

零外部依赖。仅使用 Go 标准库。

## 许可证

Apache 2.0
