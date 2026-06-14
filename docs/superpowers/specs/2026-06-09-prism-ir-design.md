# Prism IR（中间表示）设计

**版本**：v1.0  
**日期**：2026-06-09  
**状态**：已实现

---

## 1. 背景

Prism 是 SRD（Systemic Risk Dynamics）理论的工程实现，采用三层架构（Core → Semantic → Inference），输出风险动力学计算结果。当前 Prism 缺少标准化的 JSON 输出格式，下游 SIEM/SOC 消费困难。

SSAM 已有成熟的 SSAM IR 设计（`ssam-lib/ir.go`），采用 Meta/Input/Output 三段式自描述结构。Prism IR 应遵循相同的设计模式，确保两个模块的 IR 具有一致的消费体验。

## 2. 设计目标

- **自描述**：可独立于原始代码复现完整的风险动力学计算过程
- **三层全覆盖**：Core Layer 评分 + Semantic Layer 四态 + Inference Layer 预测
- **输入快照**：包含 SSAM 分数、失败检查项、传播边、配置参数，确保可复现
- **与 SSAM IR 一致**：同样的 Meta/Input/Output 三段式结构，同样的 `MarshalJSON()` / `UnmarshalIR()` / `Validate()` 接口
- **零外部依赖**：仅使用 Go 标准库 `encoding/json`、`time`

## 3. JSON Schema

### 3.1 完整结构

```json
{
  "prismir_version": "1.0",
  "meta": {
    "version": "1.0",
    "engine": "prism",
    "timestamp": "2026-06-09T14:30:00Z",
    "horizon_days": 30
  },
  "input": {
    "host_id": "prod-web-01",
    "ssam_score": 72.35,
    "failed_checks": [
      {"check_id": "L3-CE-23", "delta": -15.0, "fail_at": 1717948800},
      {"check_id": "IAM-010", "delta": -8.0, "fail_at": 1717862400}
    ],
    "propagation_edges": [
      {"source": "db-01", "target": "prod-web-01", "risk_transmission": 0.35}
    ],
    "config": {
      "debt_alpha": 1.2,
      "prop_cap": 0.25,
      "debt_cap": 0.30,
      "debt_norm_days": 1500,
      "score_floor": 0.40,
      "max_path_depth": 5
    }
  },
  "output": {
    "core": {
      "prism_score": 58.40,
      "external_risk": 0.2765,
      "propagated_risk": 0.35,
      "prop_penalty": 0.0933,
      "debt_raw": 345.0,
      "debt_penalty": 0.1867,
      "collapse_modifier": 0.0,
      "risk_velocity": -2.10
    },
    "semantic": {
      "state_vector": [0.15, 0.45, 0.30, 0.10],
      "dominant_state": "Degraded",
      "membership": {
        "stable": 0.15,
        "degraded": 0.45,
        "untrusted": 0.30,
        "collapse": 0.10
      }
    },
    "inference": {
      "horizon_days": 30,
      "future_vector": [0.08, 0.35, 0.38, 0.19],
      "confidence": 0.85,
      "trend": "collapsing",
      "collapse_risk": 0.57,
      "model": "MarkovChain"
    }
  }
}
```

### 3.2 Meta 段

| 字段 | 类型 | 说明 |
|:---|:---|:---|
| `version` | string | Prism 引擎版本号 |
| `engine` | string | 固定值 `"prism"` |
| `timestamp` | string | RFC3339 格式时间戳 |
| `horizon_days` | int | Inference Layer 预测时间窗口（天） |

### 3.3 Input 段

| 字段 | 来源 | 说明 |
|:---|:---|:---|
| `host_id` | `NodeState.HostID` | 节点标识 |
| `ssam_score` | `NodeState.SSAMScore` | 上游 SSAM 分数快照 |
| `failed_checks` | `NodeState.FailedChecks` | 失败检查项列表，含 delta 和时间戳 |
| `propagation_edges` | `[]EdgeState` | 入边传播关系，用于追溯风险来源 |
| `config` | `PrismConfig` 关键参数 | 确保可复现的关键配置 |

### 3.4 Output 段

**Core Layer**（确定性数值求值）：

| 字段 | 来源 | 说明 |
|:---|:---|:---|
| `prism_score` | `AssetRiskResult.PrismScore` | 正交化动态评分 [0,100] |
| `external_risk` | `AssetRiskResult.ExternalRisk` | E(v) = (100−SSAM)/100 |
| `propagated_risk` | `AssetRiskResult.PropagatedRisk` | 入边传播风险 R_prop |
| `prop_penalty` | `AssetRiskResult.PropPenalty` | 实际传播惩罚 |
| `debt_raw` | `AssetRiskResult.DebtRaw` | 未归一化安全债务 |
| `debt_penalty` | `AssetRiskResult.DebtPenalty` | 归一化后债务惩罚 |
| `collapse_modifier` | `AssetRiskResult.CollapseModifier` | 塌缩修正值（≥2 失败项时触发） |
| `risk_velocity` | `AssetRiskResult.RiskVelocity` | 评分变化速度（负值=恶化） |

**Semantic Layer**（模糊语义映射）：

| 字段 | 来源 | 说明 |
|:---|:---|:---|
| `state_vector` | `SemanticRiskReport.StateVector` | 归一化四态向量 [S,D,U,C] |
| `dominant_state` | `SemanticRiskReport.CurrentState` | 主导状态标签 |
| `membership.*` | 各隶属度字段 | 四态拆解 |

**Inference Layer**（状态推理预测）：

| 字段 | 来源 | 说明 |
|:---|:---|:---|
| `horizon_days` | 预测窗口 | 与 meta.horizon_days 一致 |
| `future_vector` | `FutureRiskReport` | N 天后预测状态分布 |
| `confidence` | `FutureRiskReport.Confidence` | 预测置信度 [0,1] |
| `trend` | `FutureRiskReport.Trend` | improving/stable/degrading/collapsing |
| `collapse_risk` | P(Untrusted)+P(Collapse) | 综合塌缩风险 |
| `model` | 推理模型标识 | 可插拔模型的可追溯性 |

## 4. Go 接口

```go
// NewIR 从 Prism 三层输出构造完整 IR
func NewIR(node NodeState, edges []EdgeState, cfg PrismConfig, core AssetRiskResult, sem SemanticRiskReport, inf FutureRiskReport) PrismIR

// MarshalJSON 序列化为格式化 JSON
func (ir PrismIR) MarshalJSON() ([]byte, error)

// UnmarshalIR 从 JSON 反序列化
func UnmarshalIR(data []byte) (PrismIR, error)

// Validate 校验 IR 完整性
func (ir PrismIR) Validate() error
```

## 5. 文件规划

| 文件 | 内容 |
|:---|:---|
| `prism-lib/prismir.go` | PrismIR 结构体定义 + NewIR + MarshalJSON + UnmarshalIR + Validate |
| `prism-lib/prismir_test.go` | 序列化/反序列化往返测试 + 校验测试 + 与 SSAM IR 一致性对比 |

## 6. 与 SSAM IR 的差异

| 维度 | SSAM IR | Prism IR |
|:---|:---|:---|
| 版本字段 | `meta.version` | `meta.version` + `prismir_version`（顶层） |
| 引擎标识 | 无（隐含） | `meta.engine: "prism"`（显式） |
| 输入 | Checks + Weights + RiskContext | SSAM Score + FailedChecks + Edges + Config |
| 输出 | 单层（FinalScore + Layers） | 三层（Core + Semantic + Inference） |
| 预测 | 无 | `inference.future_vector` + `trend` |