# SSAM 理论白皮书

**Security Scoring & Acceptability Model — 风险语义求值语言运行时**

> 版本：2.0 | 日期：2026-05-28 | 状态：发布

---

## 摘要

SSAM 是一个**纯函数式风险语义求值器**。它不检测、不采集、不聚合、不推理。它只做一件事：接收结构化检查断言，返回确定性风险评分与完全归因。

SSAM 的理论创新在于：将安全评估从"专家系统打分"提升为"声明式风险求值"，并首次将线性风险累计（$$\sum$$）与非线性系统塌缩（$$\prod$$）统一在同一形式化框架中。

---

## 一、问题定义

### 1.1 安全评分的核心困境

传统安全评分系统面临三个根本问题：

**问题一：语义重叠（Semantic Overlap）**

威胁系数（Threat Coefficient）与资产暴露系数（SPC Score）在数学上等价于单系数乘积 $$\mu \cdot P$$。当评分异常时，无法归因到具体层——"为什么这台机器被扣这么多？" 无法回答。

**问题二：接口封闭（Interface Closure）**

评分函数以特定语言实现，外部系统无法跨语言消费。Kubernetes Admission Controller、CI/CD Pipeline、SIEM、Python 数据分析工具——各自需要重新实现评分逻辑。

**问题三：公式固化（Formula Rigidity）**

评分公式硬编码在源代码中，修改需重新编译。评分过程不可解释、不可审计、不可版本化。当 Formula V1.2 和 V2.0 产生不同结果时，无法追溯差异来源。

### 1.2 SSAM 的理论边界

SSAM 通过**严格定义"不做什么"**来确立自身边界：

| SSAM 不负责 | 原因 | 由谁负责 |
|-------------|------|----------|
| 检测（Detection） | 检测是数据采集层的职责 | ASSCOR / Falco / Wazuh |
| Telemetry | 遥测是平台基础设施 | Kubernetes / OpenTelemetry |
| IOC 匹配 | 威胁指标是 CTI 层的输出 | MISP / OpenCTI |
| EDR | 端点检测是数据源 | CrowdStrike / Elastic |
| SIEM | 安全信息聚合是数据总线 | Splunk / Elastic |
| AI 分析 | 上层推理是消费方 | LLM / 贝叶斯网络 |
| 威胁情报收集 | 情报是外部输入 | NVD / CISA KEV / EPSS |

**SSAM 只负责：**

> 风险语义求值（Risk Semantic Evaluation）

即：

```
CheckInput[] → ComputeScore → AssessmentOutput
    ↑                              ↓
原子断言                     风险判定 + 完全归因
```

### 1.3 为什么这个边界重要

安全工具市场的核心问题是**职责混乱**。每个产品都想成为"全栈安全平台"，导致：

- 评分引擎绑定特定检测实现
- 威胁情报与评分逻辑耦合
- 无法跨平台复用评估模型

SSAM 选择了一条相反的路：**极致的单一职责**。这让它能够被嵌入任何系统——Kubernetes、CI/CD、SIEM、Cloud Platform、甚至 LLM Agent——作为统一的风险求值内核。

---

## 二、数学模型

### 2.1 V1.2 公式

$$\text{FinalScore} = \frac{\sum_{i=1}^{n}(S_i \cdot W_i)}{\sum_{i=1}^{n}W_i} \cdot \mu \cdot P_{score} \cdot \prod_{j=1}^{m} M_j$$

其中：

| 符号 | 含义 | 约束 |
|------|------|------|
| $$S_i$$ | 第 $$i$$ 个域的百分制分数 | $$S_i \in [0, 100]$$ |
| $$W_i$$ | 第 $$i$$ 个域的权重 | $$\sum W_{core} = 100$$ |
| $$\mu$$ | 威胁态势系数 | $$\mu \in [0.60, 1.00]$$ |
| $$P_{score}$$ | SPC 态势修正因子 | $$P_{score} \in [0.60, 1.00]$$ |
| $$M_j$$ | 第 $$j$$ 个活跃边缘因子 | $$M_j \in (0, 1)$$ |

**问题诊断：** $$\mu \cdot P_{score}$$ 构成**语义冗余**。两者在数学上等价于单一环境风险系数 $$E = \mu \cdot P_{score}$$，但调用方需要提供两个独立参数，评分异常时无法归因到具体因素。

### 2.2 V2.0 三层语义模型

$$\text{FinalScore} = L_{intrinsic} \cdot L_{exposure} \cdot L_{threat} \cdot 100$$

其中每层独立定义：

**Layer 1: Intrinsic（内生安全）**

$$L_{intrinsic} = \frac{\sum_{i=1}^{n}(S_i \cdot W_i)}{\sum_{i=1}^{n}W_i} \cdot \prod_{j=1}^{m} M_j \mid_{M_j \in (0,1)}$$

描述系统自身的安全姿态：配置合规性 × 基线偏差 × 防御机制失效。该层回答："这台机器自身有多安全？"

**Layer 2: Exposure（环境暴露）**

$$L_{exposure} = f(\text{网络可达性}, \text{资产关键性}, \text{CVE影响})$$

描述系统在环境中的暴露程度。默认值 $$1.0$$（无额外暴露），取值范围 $$[0.60, 1.00]$$。

该层回答："这台机器暴露在什么样的风险环境中？"

**Layer 3: Threat（威胁压力）**

$$L_{threat} = f(\text{APT活跃度}, \text{KEV利用}, \text{威胁情报})$$

描述系统面临的外部攻击压力。默认值 $$1.0$$（无特别威胁），取值范围 $$[0.60, 1.00]$$。

该层回答："当前有哪些外部威胁在针对这类资产？"

### 2.3 混合风险模型

SSAM 的核心理论贡献在于统一了两种风险模型：

**线性累计层（$$\sum$$）** — 域评分

风险在单个域内按加法累计。这对应现实中的"合规偏差累积"——每多一个配置缺陷，安全姿态线性恶化。

**非线性塌缩层（$$\prod$$）** — 边缘因子

风险在系统级别按乘法塌缩。这对应现实中的"防御体系失能"——一旦某个关键防御机制（如认证、LSM、IDS）失效，整体安全性不是"减去 N 分"，而是"坍缩为原来的 K 倍"。

这种 $$\sum + \prod$$ 的混合结构在安全评估领域是**首次被明确形式化**。

---

## 三、边缘因子理论

### 3.1 什么是边缘因子

边缘因子不是"扣分项"，而是**系统性风险塌缩乘数**。

传统评分系统对"SELinux 被禁用"的处理是：

```
Score -= 15  （线性扣分）
```

SSAM 的处理是：

```
Score *= 0.80  （系统坍缩为原来的 80%）
```

这背后的理论洞察是：某些安全控制机制的失效不是"多加了一个缺陷"，而是"整个防御体系的根基受损"。

### 3.2 边缘因子 vs 域检查

| 维度 | 域检查 | 边缘因子 |
|------|--------|----------|
| 作用层级 | 域内 | 跨域系统级 |
| 数学模型 | $$\sum$$ | $$\prod$$ |
| 语义 | "这项配置不对" | "这个防御机制失效了" |
| 影响 | 局部扣分 | 全局衰减 |
| 失败后果 | 域分下降 | 整体分数按比例塌缩 |

### 3.3 级联防御（Cascade）

级联机制解决的是**防御层次依赖**问题。

**理论：** 高阶防御机制（如 3FA）的失效，会同时降低低阶防御机制（如 2FA）的有效性。

**实现：**

```
EF-3FA 触发 → CascadeTo: EF-002FA → Factor 从 0.85 降为 0.82
```

即：即使 2FA 本身已启用，3FA 的缺失也会使 2FA 的保护效果打折。

级联属性 `CascadeOnly: true` 确保 EF-3FA 自身不直接参与乘法修正，仅通过级联影响目标因子——避免了对同一防御缺陷的双重惩罚。

### 3.4 边缘因子配置

```go
{ID: "EF-002FA",    Factor: 0.85, TriggerCheck: "EF-001"},
{ID: "EF-SYNCOOKIE", Factor: 0.75, TriggerCheck: "RS-005"},
{ID: "EF-SELINUX",  Factor: 0.80, TriggerCheck: "OT-005"},
{ID: "EF-APPARMOR", Factor: 0.82, TriggerCheck: "OT-005"},
{ID: "EF-NO-SIEM",  Factor: 0.90, TriggerCheck: "RS-007"},
{ID: "EF-NO-IDS",   Factor: 0.88, TriggerCheck: "RS-006"},
{ID: "EF-3FA",      Factor: 0.82, TriggerCheck: "EF-002",
    CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true},
```

---

## 四、架构哲学

### 4.1 Pure Functional Core

SSAM 遵循 **Pure Functional Core / Imperative Shell** 架构模式：

```
┌────────────────────────────────┐
│     Pure Functional Core       │
│                                │
│  • 无 goroutine                │
│  • 无锁（sync）                │
│  • 无 IO                       │
│  • 无 RPC                      │
│  • 无 Plugin                   │
│  • 无 Event Bus                │
│  • 无数据库                    │
│  • 无全局可变状态               │
│                                │
│  Input → Compute → Output      │
└────────────────────────────────┘
          ↑              ↓
┌────────────────────────────────┐
│      Imperative Shell          │
│  (由宿主平台提供)               │
│                                │
│  • Check Provider              │
│  • Config Management           │
│  • Persistence                 │
│  • RPC Transport               │
│  • Scheduling                  │
└────────────────────────────────┘
```

### 4.2 为什么纯函数化

纯函数化的理论收益：

1. **确定性**：相同输入 → 相同输出。SOC 可以信任评分结果的唯一性和可重复性
2. **可嵌入性**：无副作用 = 可在任何上下文中调用，无需初始化基础设施
3. **可测试性**：100% 的代码路径可通过单元测试覆盖，无需 mock
4. **可组合性**：纯函数可以组合成更复杂的求值管道
5. **可审计性**：求值过程的每个步骤都可通过输入/输出的差分追踪

### 4.3 零外部依赖

SSAM 的依赖图：

```
SSAM
 ├── encoding/json  （仅用于 IR 序列化）
 ├── fmt            （仅用于错误格式化）
 ├── math           （Round/Max/Abs）
 ├── sort           （结果排序）
 ├── strconv        （仅用于错误消息构造）
 ├── strings        （AST Op 比较）
 └── time           （仅用于 IR 时间戳）
```

**无任何第三方库。** 这确保 SSAM 可以在任何 Go 编译环境下构建，包括受限的 CI/CD runner 和 air-gapped 环境。

---

## 五、SSAM IR（中间表示）

### 5.1 设计原则

SSAM IR 是 SSAM 的**平台无关接口**。它不是 Go 结构体的简单 JSON 映射，而是一个**自描述的求值记录**。

一个完整的 IR 文档包含：

- **输入快照**：所有的检查项、权重、边缘因子配置、风险上下文
- **输出快照**：最终分数、域分数、风险层、边缘因子状态
- **元信息**：版本号、公式 ID、时间戳

读取一份 IR 文档，无需原始代码即可**完全重现评分过程**。

### 5.2 IR 结构

```json
{
  "meta": {
    "version": "2.0",
    "formula_id": "ssam_v2.0",
    "timestamp": "2026-05-28T12:00:00Z"
  },
  "input": {
    "host_id": "server-01",
    "hostname": "web-prod-01",
    "threshold": 80,
    "risk_context": {
      "intrinsic": 1.0,
      "exposure": 0.70,
      "threat": 0.90
    },
    "checks": [
      {
        "check_id": "AS-001",
        "domain": "attack_surface",
        "passed": false,
        "delta": -15,
        "detail": "SSH root login enabled"
      }
    ],
    "weights": [
      {"domain": "attack_surface", "weight": 35}
    ],
    "edge_factors": [
      {"id": "EF-002FA", "factor": 0.85, "trigger_check": "EF-001"}
    ]
  },
  "output": {
    "final_score": 51.03,
    "acceptable": false,
    "threshold": 80,
    "domain_scores": [
      {"domain": "attack_surface", "score": 85},
      {"domain": "business_continuity", "score": 90}
    ],
    "risk_layers": {
      "intrinsic": {
        "coeff": 0.81,
        "contributors": ["domain_scores", "edge_factor:EF-002FA"]
      },
      "exposure": {
        "coeff": 0.70,
        "contributors": ["exposure_coefficient"]
      },
      "threat": {
        "coeff": 0.90,
        "contributors": ["threat_coefficient"]
      }
    },
    "edge_factors": [
      {"id": "EF-002FA", "factor": 0.85, "active": true}
    ]
  }
}
```

### 5.3 IR 的消费场景

| 场景 | 消费者 |
|------|--------|
| 合规审计 | 审计系统读取 IR，验证评分流程和依据 |
| 跨系统集成 | Python/JS 解析 IR JSON，无需 Go 运行时 |
| LLM 分析 | LLM 读取 IR → 生成修复建议 |
| 历史回溯 | 存储 IR 快照 → 对比不同时点的评分变化 |
| 公式回归测试 | 批量 IR → 公式升级后重新求值 → 差分对比 |

---

## 六、Formula DSL

### 6.1 设计动机

`ScoringFormula` 是 Go 函数类型，这带来了灵活性也带来了不可解释性。

**问题：**
- Go 函数无法序列化 → 无法审计
- 修改公式需要重新编译 → 无法热切换
- 公式结果不可解释 → "为什么是 72.5 分？"

**解决方案：** Formula AST

### 6.2 AST 结构

```go
type FormulaAST struct {
    Op    string      // 操作符
    Left  *FormulaAST // 左子树
    Right *FormulaAST // 右子树
    Ref   string      // 上下文引用
    Const float64     // 字面常量
}
```

支持的操作符：

| Op | 语义 | 数学表示 |
|----|------|----------|
| `weighted_sum` | 加权求和 | $$\frac{\sum(S_i \cdot W_i)}{\sum W_i}$$ |
| `multiply` | 乘法 | $$a \cdot b$$ |
| `divide` | 除法 | $$a / b$$ |
| `min` | 取下界 | $$\min(a, b)$$ |
| `max` | 取上界 | $$\max(a, b)$$ |
| `product_chain` | 因子连乘 | $$\prod_{active} f_j$$ |
| `ref` | 上下文引用 | 查表取值 |
| `const` | 字面常量 | $$c$$ |

### 6.3 ssam_v2.0 AST

```
multiply
├── multiply
│   ├── multiply
│   │   ├── weighted_sum          ← Σ(S_i·W_i)/ΣW_i
│   │   └── product_chain         ← ∏edgeFactors
│   └── max(ref:exposure, 0.60)   ← Layer 2
└── max(ref:threat, 0.60)         ← Layer 3
```

这个 AST 可以：
- 序列化为 JSON → 存储到数据库 → 审计
- 遍历节点 → 生成人类可读的公式描述
- 差分对比 → V1.2 vs V2.0 的语义变化
- 编译为 Go 函数 → 高性能执行

### 6.4 AST 编译

```go
// 直接求值（解释执行）
score, _ := ssam.EvalAST(ast, ctx)

// 编译为 Go 函数（编译执行）
compiled := ssam.ASTToFormula(ast)
score := compiled(domainScores, weights, threatCoeff, spcScore, edgeFactors)
```

编译路径的关键设计：**预热编译**——AST→Go 闭包的转换在配置加载时完成一次，后续调用零编译开销。

---

## 七、域语义学

### 7.1 四个正交风险域

SSAM 将安全风险分解为四个互不重叠的语义域：

| 域 | 含义 | 典型检查项 | 权重 |
|----|------|-----------|:--:|
| **Attack Surface** | 系统对外暴露的攻击面 | SSH 配置、开放端口、服务最小化 | 35 |
| **Business Continuity** | 系统持续提供服务的能力 | 关键服务状态、备份策略、冗余 | 25 |
| **Operation Trust** | 系统操作的可信程度 | 文件权限、审计日志、LSM 状态 | 25 |
| **Resilience** | 系统对抗攻击的韧性 | Fail2ban、SYN Cookie、IDS | 15 |

### 7.2 扩展域

核心 4 域覆盖通用安全评估。对于特定场景，可以扩展：

```go
weights = append(weights,
    WeightConfig{Domain: "kernel_security", Weight: 10},
)
```

扩展域独立于核心域之外，权重通过配置文件注入，不参与核心域归一化。

### 7.3 域评分的语义

每个域从 100 分开始（"完美安全"），未通过的检查项扣分：

$$S_{domain} = \max(0, \ 100 + \sum_{check \in domain \ | \ check.Passed = false} check.Delta)$$

`Delta` 为负数（如 -15），表示该检查不通过时的扣分值。分数下限为 0。

---

## 八、未来演化路径

### 8.1 短期（V2.1）

- **Delta 语义化**：将 `Delta` 从经验值迁移到形式化风险语义（基于 CVSS 权重映射）
- **边缘因子校准**：建立边缘因子值的调节方法论

### 8.2 中期（V3.0）

- **Risk Graph Engine**：边缘因子从独立触发器进化为**风险传播图**

```
No MFA → Credential Theft Risk ↑ → Lateral Movement Risk ↑ → Business Continuity ↓
```

- **公式 DSL 完善**：支持条件分支、风险时间序列、贝叶斯先验

### 8.3 长期愿景

- **标准化**：SSAM IR 成为安全评估领域的开放标准（类似 CVSS 之于漏洞评分）
- **认证体系**：SSAM 评分可被合规框架（等保、SOC2、ISO 27001）直接引用
- **社区公式库**：安全研究者可以贡献和共享 SSAM Formula AST

---

## 九、结论

SSAM 正处于从"安全工具"到"理论基础设施"的转型期。

它已经具备了纯函数化的架构纯度、三层语义的模型完整性、IR 的平台无关性、以及 AST 的可审计性——这些构成了一个安全风险求值语言运行时的核心要素。

长期来看，SSAM 的理论价值可能超过其最初的宿主平台 ASSCOR。因为平台是工程产物，而风险求值语言是理论基础设施——后者的生命周期通常更长。

SSAM 的定义式是：

> **接收原子断言，返回确定性风险判定与完全归因。其他什么都不做。**

这是它的力量所在。

---

## 参考文献

- CVSS v3.1 Specification Document — FIRST.org
- FAIR (Factor Analysis of Information Risk) — The Open Group
- NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments
- GB/T 22239-2019 — 信息安全技术 网络安全等级保护基本要求
- MITRE ATT&CK Framework — MITRE Corporation
- OPA (Open Policy Agent) — Rego Policy Language
