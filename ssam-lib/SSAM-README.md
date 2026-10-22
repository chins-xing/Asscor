# SSAM

**Security Scoring & Acceptability Model** — 安全风险求值语言运行时

## 一句话定义

> SSAM 不是安全工具，而是**风险语义求值器**：接收结构化检查断言，输出确定性风险评分与归因。

## 理论边界

| SSAM 不负责 | 原因 | 由谁负责 |
|-------------|------|----------|
| 检测（Detection） | 检测是数据采集层的职责 | ASSCOR / Falco / Wazuh |
| Telemetry | 遥测是平台基础设施 | Kubernetes / OpenTelemetry |
| IOC 匹配 | 威胁指标是 CTI 层的输出 | MISP / OpenCTI |
| EDR | 端点检测是数据源 | CrowdStrike / Elastic |
| SIEM | 安全信息聚合是数据总线 | Splunk / Elastic |
| AI 分析 | 上层推理是消费方 | LLM / 贝叶斯网络 |
| 威胁情报收集 | 情报是外部输入 | NVD / CISA KEV / EPSS |

**SSAM 只负责一件事：**

```
CheckInput[] → ComputeScore → AssessmentOutput
    ↑                              ↓
原子断言                      风险判定 + 完全归因
```

## 架构

```
┌──────────────────────────────────────────┐
│            SSAM Pure Functional Core      │
│                                           │
│  无 goroutine · 无锁 · 无 IO · 无 RPC     │
│  无 Plugin · 无 Event Bus · 无数据库      │
│                                           │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  │
│  │ Domain  │  │  Edge    │  │ Formula │  │
│  │ Scores  │  │ Factors  │  │ Engine  │  │
│  │   Σ     │  │    ∏     │  │  λ(Σ,∏) │  │
│  └─────────┘  └──────────┘  └─────────┘  │
│       │              │            │       │
│       └──────────────┴────────────┘       │
│                      │                    │
│              ┌───────▼───────┐            │
│              │  Final Score  │            │
│              │  + RiskLayers │            │
│              │  + IR Output  │            │
│              └───────────────┘            │
└──────────────────────────────────────────┘
```

## 公式

### SSAM V1.2

$$\text{FinalScore} = \frac{\sum(S_i \cdot W_i)}{\sum W_i} \cdot \mu \cdot P_{score} \cdot \prod M_j$$

| 符号 | 含义 |
|------|------|
| $S_i$ | 域分数（0-100） |
| $W_i$ | 域权重（总和 100） |
| $\mu$ | 威胁系数（默认 1.0） |
| $P_{score}$ | SPC 修正因子（∈ [0.60, 1.00]） |
| $M_j$ | 活跃边缘因子（∈ (0, 1)） |

### SSAM V2.0 — 三层语义

$$\text{FinalScore} = \text{Layer}_1 \cdot \text{Layer}_2 \cdot \text{Layer}_3 \cdot 100$$

| 层 | 语义 | 计算 |
|----|------|------|
| **Layer 1: Intrinsic** | 内生安全姿态 | `weighted_sum(domainScores)` × `∏ activeEdgeFactors` |
| **Layer 2: Exposure** | 环境暴露上下文 | 网络可达性 × 资产关键性 × CVE 影响 |
| **Layer 3: Threat** | 外部威胁压力 | APT 活跃度 × KEV 利用 × 情报系数 |

每层独立可追溯（Contributors），消除 V1.2 的 double penalization 问题。

### 情报可信度与后验区间（方向①）

每条检查/情报可带一个可信度 `c ∈ [0,1]`。它进入**算法层**而不只是展示层：

$$\text{score}_d=\max\left(0,\;100-\sum_{i\in F_d}|\delta_i|\,c_i\right),\qquad
\sigma_d=\sqrt{\sum_{i\in F_d}|\delta_i|^2\,c_i(1-c_i)}$$

$$\text{FinalSigma}=0.5\cdot\frac{\sqrt{\sum_d (w_d\,\sigma_d)^2}}{\sum_d w_d}$$

| 结构 | 字段 | 语义 |
|---|---|---|
| `CheckInput` | `Confidence` | 本条观测的可信度 ∈ [0,1]；0 = 未指定（由 `ConfidencePolicy.Default` 归一），低于 `Floor` 时抬到 `Floor` |
| `DomainScore` | `Sigma` | 域分后验标准差 |
| `DomainScore` | `Confidence` | 域证据平均可信度 `Σ(abs(δ)·c)/Σabs(δ)`（无失败证据时 1.0） |
| `AssessmentOutput` | `FinalSigma` | 域分 σ 的 RSS **乘 intrinsic 层权重 0.5** |
| `AssessmentOutput` | `Lower95` / `Upper95` | `FinalScore ± 1.96·FinalSigma`；**只钳下界 0，上界不夹**（`Total>100` 时区间仍含点估计） |
| `AssessmentOutput` | `EvidenceConfidence` | 域证据可信度的权重归一均值 ∈ [0,1] |

- **默认禁用**：`DefaultConfidencePolicy()` 下 `c` 恒为 1.0，`Sigma=0`、区间退化为
  `[FinalScore, FinalScore]`，与历史实现逐位一致。
- **区间是启发式**：只有 intrinsic（域分）层被视为随机量，exposure/threat 是配置系数；
  因此它不是三层总分的严格后验区间。
- **未标定**：出厂先验表（`user=0.90`/`adapter=0.80`）是 prior，没有实验标定；
  不得据此声称“已标定 / CI 覆盖率已验证”。

## 快速开始

```go
package main

import (
    "fmt"
    ssam "github.com/chins-xing/ssam"
)

func main() {
    config := ssam.DefaultScoringConfig
    input := ssam.AssessmentInput{
        HostID:      "server-01",
        Threshold:   80,
        ThreatCoeff: 1.0,
        SPCScore:    1.0,
        Checks: []ssam.CheckInput{
            {CheckID: "AS-001", Domain: "attack_surface",
             Name: "SSH Root Login", Passed: false, Delta: -15},
            {CheckID: "BC-001", Domain: "business_continuity",
             Name: "Backup Status", Passed: false, Delta: -10},
            {CheckID: "OT-001", Domain: "operation_trust",
             Name: "File Permissions", Passed: true, Delta: 0},
            {CheckID: "RS-001", Domain: "resilience",
             Name: "Fail2ban", Passed: false, Delta: -5},
        },
    }

    output, err := ssam.ComputeScore(config, input)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Score: %.2f\n", output.FinalScore)
    fmt.Printf("Acceptable: %v\n", output.Acceptable)

    for _, ds := range output.DomainScores {
        fmt.Printf("  %s: %.0f\n", ds.Domain, ds.Score)
    }
    for _, ef := range output.EdgeFactors {
        if ef.Active {
            fmt.Printf("  ×%s (%.2f)\n", ef.ID, ef.Factor)
        }
    }
}
```

## 可嵌入目标

| 平台 | 集成方式 |
|------|----------|
| Kubernetes Admission Controller | Pod Security → SSAM Score → Accept/Reject |
| CI/CD Pipeline | Build → SSAM < 80 → Block deploy |
| SIEM / SOAR | Alert → SSAM re-evaluation → Prioritize |
| Wazuh / Falco / OpenSCAP | Check Provider → SSAM → Risk Assessment |
| Cloud Security Platform | Cloud Asset → SSAM → Unified Risk Score |
| LLM Agent | IR JSON → LLM analysis → Recommendation |

## 核心概念

### 域（Domain）

安全风险的四个正交语义域：

| 域 | 权重 | 含义 |
|----|:--:|------|
| `attack_surface` | 35 | 攻击面暴露 |
| `business_continuity` | 25 | 业务连续性 |
| `operation_trust` | 25 | 操作可信度 |
| `resilience` | 15 | 系统韧性 |

### 边缘因子（Edge Factor）

非线性系统塌缩规则。不满足某防御条件时，整体分数乘以因子（∈ (0, 1)）：

| 因子 | 触发条件 | 乘数 |
|------|----------|:--:|
| EF-002FA | 双因素认证缺失 | ×0.85 |
| EF-SYNCOOKIE | SYN Cookie 禁用 | ×0.75 |
| EF-SELINUX | SELinux 禁用 | ×0.80 |
| EF-APPARMOR | AppArmor 禁用 | ×0.82 |
| EF-NO-SIEM | SIEM 未集成 | ×0.90 |
| EF-NO-IDS | IDS/IPS 缺失 | ×0.88 |
| EF-3FA | 三因素认证未满足 → 级联 EF-002FA | ×0.82 |

级联机制：EF-3FA 触发时，EF-002FA 被覆盖为 0.82（即使 2FA 已通过）。

### 检查项（Check）

原子断言。由外部 Check Provider 提交：

```go
type CheckInput struct {
    CheckID string  // 如 "AS-001"
    Domain  string  // 所属域
    Passed  bool    // 是否通过
    Delta   float64 // 未通过时的扣分值（负数）
}
```

SSAM 不与检查实现耦合。任何能产生 `[]CheckInput` 的系统都可以作为 Check Provider。

## SSAM IR（中间表示）

评分结果可序列化为标准 JSON IR，实现跨语言消费：

```json
{
  "meta": {
    "version": "2.0",
    "formula_id": "ssam_v2.0",
    "timestamp": "2026-05-28T12:00:00Z"
  },
  "input": {
    "host_id": "server-01",
    "checks": [...],
    "risk_context": {"intrinsic": 1.0, "exposure": 0.70, "threat": 0.90},
    "weights": [...]
  },
  "output": {
    "final_score": 51.03,
    "acceptable": false,
    "domain_scores": [...],
    "risk_layers": {
      "intrinsic":  {"coeff": 0.81, "contributors": ["domain_scores", "edge_factor:EF-002FA"]},
      "exposure":   {"coeff": 0.70, "contributors": ["exposure_coefficient"]},
      "threat":     {"coeff": 0.90, "contributors": ["threat_coefficient"]}
    }
  }
}
```

## Formula DSL

内置公式以 AST 形式定义，可被序列化、审计、版本化：

```go
ast := ssam.SSAMV20AST()
// multiply(multiply(multiply(weighted_sum, product_chain), exposure), threat)

score, _ := ssam.EvalAST(ast, ctx)          // 直接求值
compiled := ssam.ASTToFormula(ast)           // 编译为 Go 函数
score := compiled(domainScores, weights, ...) // 高性能执行
```

## 确定性

相同输入 → 相同输出。可重复、可验证、可审计。这是工业级安全评估的基础。

## 依赖

**零外部依赖**。仅使用 Go 标准库：

```
encoding/json  fmt  math  sort  strconv  strings  time
```

## 许可证

Apache 2.0

## 理论白皮书

参见 [SSAM-Theory.md](SSAM-Theory.md)
