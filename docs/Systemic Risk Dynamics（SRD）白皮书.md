# Systemic Risk Dynamics（SRD）白皮书
## —— 面向复杂系统的风险语义、状态演化与系统塌缩理论
### 附：Prism 风险动力学引擎规范 v3.1 — Revision 2

---

# 文档信息

| 项 | 内容 |
|---|---|
| 项目名称 | Systemic Risk Dynamics |
| 简称 | SRD |
| 算法代号 | Prism（棱镜） |
| 类型 | 风险动力学理论框架 + 风险动力学引擎规范 |
| 核心方向 | 风险语义、风险演化、系统退化、系统塌缩、时空传播、状态推理 |
| 理论性质 | 可解释、可推导、半确定性风险系统 |
| 适用领域 | 安全、云平台、工业控制、复杂系统、AI基础设施 |
| 版本 | v3.1-R2 |
| 日期 | 2026-06-09（更新 2026-06-15） |
| 设计原则 | 最小可验证——只保留计算层不可替代的部分。确定性核心保持纯函数约束；模糊语义与未来推理内化为引擎一等能力 |

---

# 摘要（Abstract）

传统安全系统长期建立在 CVSS、Checklist、Compliance、Vulnerability Counting、Static Scoring 基础之上。这些模型默认风险是静态、离散、确定性的。

但真实系统具有：长期退化、风险传播、信任漂移、动态结构、模糊边界、非线性塌缩、时间累积、不确定输入。

因此：

## 风险并不是“漏洞数量”，而是“系统状态演化”。

SRD（Systemic Risk Dynamics）提出：**系统风险本质上是一种动态风险状态空间。** SRD 的核心目标不是“计算一个分数”，而是**理解系统如何退化、传播、累积与塌缩，并推导其未来状态**。

Prism 是 SRD 理论的工程实现——一个**风险动力学引擎**。它输出三份结构化报告，回答三个根本问题：

1. **Raw Risk Report**——系统发生了什么？（确定性求值）
2. **Semantic Risk Report**——系统当前是什么状态？（模糊语义归属）
3. **Future Risk Report**——系统未来可能变成什么状态？（状态推理）

其他一切——服务分类、危害标注、信任域定义、数据采集、持久化、API暴露、可视化展示——都属于调用方（ASSCOR Kernel）的职责。

---

# 第一部分：SRD 理论基础

---

# 1. 问题定义

## 1.1 传统安全系统的问题

传统安全系统通常采用：

$$Risk = \sum_i Score_i$$

即风险是问题的线性累积。这种模型存在根本缺陷：

| 问题 | 描述 |
|---|---|
| 静态性 | 无法描述风险演化 |
| 独立性假设 | 默认风险彼此独立 |
| 无时间维度 | 无法描述长期退化 |
| 无传播语义 | 无法描述风险扩散 |
| 无系统上下文 | 无法描述影响范围 |
| 无塌缩语义 | 无法描述系统性失效 |
| 无模糊状态 | 默认输入确定 |
| 无可信度模型 | 无法表达信任下降 |

因此传统系统得到的通常只是“统计结果”，而不是“系统真实状态”。

---

# 2. SRD 核心理论

SRD 提出：

## 风险不是漏洞。风险是系统状态退化。

系统并不是瞬间失效，而是**长期退化**。风险也不是孤立事件，而是**信任结构传播**。

因此 SRD 采用：

## 风险语义 + 状态演化 + 模糊推导 + 状态推理

构建风险动力学系统。

---

# 3. Prism 三层模型

Prism 被定义为**风险动力学引擎（Risk Dynamics Engine）**，由三个层次组成：

```
Prism
│
├── Core Layer        — 确定性求值层
├── Semantic Layer    — 模糊语义层
└── Inference Layer   — 状态推理层
```

**核心原则**：

- **Core Layer**：纯函数、可重复、可解释、可审计。负责时间、空间、传播、债务、塌缩的确定性计算。
- **Semantic Layer**：将 Core Layer 的数值输出映射为风险状态隶属度，回答“系统当前处于什么状态”。
- **Inference Layer**：基于当前状态和**任意可插拔的状态推理模型**，推导未来状态概率分布，回答“系统未来可能变成什么状态”。

**禁止事项**：Core Layer 不允许概率推理、机器学习、贝叶斯预测、神经网络。

---

# 4. 风险语义空间（Risk Semantic Space）

SRD 将风险定义为**多维风险语义**。系统风险由以下维度构成：

| 维度 | 含义 | 实现位置 |
|---|---|---|
| Service Type | 服务语义 | 调用方 CMDB 数据 |
| Hazard Type | 危害语义 | SSAM 检查项 Domain/Delta 中已蕴含 |
| System Weight | 系统重要性 | 拓扑图中边的密度与方向隐含 |
| Impact Scope | 影响范围 | 拓扑图的连通性隐含 |
| Impact Duration | 持续时间 | FailSince → 安全债务公式 |
| Collapse Potential | 系统塌缩能力 | 多重债务并发时自然体现 |
| Trust State | 信任状态 | SSAM 分数已量化 |
| Persistence Level | 风险驻留性 | Delta 值大小隐含 |

**关键原则**：这些维度是**理论概念**，不是代码枚举。它们的工程表达分散在 SSAM 输出、调用方拓扑数据和 Prism 的债务公式中，不需要单独建模。

---

# 5. 风险状态空间（Risk State Space）

## 5.1 四态风险模型

SRD 定义四种风险状态：

| 状态 | 含义 |
|---|---|
| Stable | 稳定——系统处于可接受的安全水平 |
| Degraded | 退化——部分防护能力下降，风险正在累积 |
| Untrusted | 不可信——信任结构受损，系统可能已被部分突破 |
| Collapse | 塌缩——系统性失效，核心控制丧失 |

## 5.2 模糊状态归属

现实风险并非 TRUE/FALSE 的布尔判断，而是部分可信、部分退化、部分失控的模糊状态。因此，系统可**同时属于多个状态**。

例如：
- Stable: 0.10
- Degraded: 0.70
- Untrusted: 0.35
- Collapse: 0.05

这表示系统当前**主要以 Degraded 状态为主，但已出现 Untrusted 的显著征兆**。

## 5.3 状态转移

系统状态会随时间演化：

$$Stable \rightarrow Degraded \rightarrow Untrusted \rightarrow Collapse$$

SRD 的目标不是“追求零风险”，而是**长期维持可接受状态**，并在状态转移发生时及时感知。

---

# 6. 风险时间演化（Temporal Risk Dynamics）

SRD 认为**风险会持续演化**：累积、扩散、放大、漂移、塌缩。

因此风险是时间函数：

$$R(t) = R_0 \cdot e^{\lambda t}$$

或：

$$R(t) = R_0 + \alpha \cdot \log(1 + t)$$

工程实现采用 Prism 的安全债务公式（见 §14.3）。

---

# 7. 网络语义归约（Network Semantic Reduction）

SRD 不试图完整求解网络拓扑。因为现实网络具有 Overlay、Mesh、VPN、NAT、SDN、Dynamic Routing、Kubernetes、Cloud Fabric 等复杂结构，完整网络求解复杂度极高。

因此 SRD 采用**安全语义归约**——将复杂网络归约为有向加权图：

- 节点 = 已评估资产（状态来自 SSAM IR）
- 边 = 业务连接（RiskTransmission 由调用方根据业务知识设定）

调用方（ASSCOR）负责从 CMDB/NetBox 同步拓扑，并在边上直接标注风险传递率。Prism 不推导传输率——调用方更清楚自己的网络。

---

# 8. Collapse Potential — 系统塌缩

SRD 引入 Collapse Potential：**系统塌缩能力**。传统系统将风险视为线性累积，但现实中某些控制失效会导致**系统整体可信性下降**。

例如：无 SIEM、无 MFA、无 Backup、无 IDS、无 Audit——这些问题不是简单扣分，而是**系统信任塌缩**。

SRD 使用：

$$Risk = S \times C$$

**工程实现**：Collapse 效应通过安全债务的累积自然体现——当多个关键检查项长期未通过时，债务呈超线性增长，等效于塌缩修正。Core Layer 在 RawRiskReport 中输出 CollapseModifier，供 Semantic Layer 进行状态判断。

---

# 9. 可解释性原则

SRD 明确拒绝**黑盒 AI 风险评分**。因此 SRD 采用**受约束推理**：

- **Core Layer — 确定性求值**：纯函数，完全可审计
- **Semantic Layer — 模糊语义归属**：基于确定性输出的隶属度映射，规则透明可追溯
- **Inference Layer — 状态推理**：仅推理状态转移概率，不推理风险评分；推理模型可插拔且规则透明
- **Traceable**：每个输出都可追溯到具体检查项、拓扑边或状态转移记录

---

# 10. 风险动力学三元组

SRD 统一采用风险动力学三元组定义风险，强调可观测、可测量、可预测：

$$R = (State, Velocity, Forecast)$$

其中：

- $State$ = **Current State**（当前状态）——来自 Semantic Layer
- $Velocity$ = **Risk Velocity**（风险变化速率）——来自 Core Layer 的时间导数和动力学趋势
- $Forecast$ = **Future State Forecast**（未来状态预测）——来自 Inference Layer

这一三元组取代了传统的单一风险评分范式。Velocity 是可测量的：例如“评分每日下降 0.12”，直接反映了风险的恶化速度。它使抽象的风险动力学变得具体而可操作。

---

# 11. 核心原则

1. 风险不是漏洞数量
2. 风险不是分数
3. 风险不是概率
4. 风险是系统状态在时间与空间中的持续演化
5. 风险具有时间语义
6. 风险具有传播性
7. 风险具有模糊边界
8. 风险会长期退化
9. 系统存在塌缩效应
10. 风险必须可解释
11. 理论层必须稳定与纯净
12. 安全评估的目标应是理解系统如何退化、传播、累积与塌缩，并推导其未来状态
13. 安全目标是长期维持可接受状态

---

# 第二部分：Prism 工程规范

---

# 12. 设计原则

## 12.1 三层架构，单一纯函数核心

Prism 采用三层架构：

- **Core Layer**：纯函数式内核——相同输入产生相同输出，无内部可变状态，无 I/O、无网络调用、无锁、无 goroutine，仅依赖 Go 标准库及 `math` 包。
- **Semantic Layer**：模糊推理层——基于 Core Layer 输出的确定性变换，无 I/O、无外部依赖，隶属度函数参数化可配置。
- **Inference Layer**：状态推理层——支持任意状态推理模型，默认提供马尔可夫链实现，模型由调用方传入或使用内置先验。不执行 I/O，保持纯计算。

## 12.2 单一职责

Prism 仅做三件事：

1. **Core Layer — 计算动态评分与风险速度**：给定节点的 SSAM 分数、失败检查项的时间线和入边列表，返回包含评分、债务、传播、塌缩修正及风险变化速度的原始风险报告。
2. **Semantic Layer — 计算语义状态**：基于原始风险报告，返回四态隶属度及当前主导状态。
3. **Inference Layer — 推导未来状态**：基于当前语义状态和可选的推理模型，返回给定时间窗口内的状态预测及置信度。

Prism 不负责：数据采集、漏洞扫描、威胁情报、配置管理、持久化、API暴露、分类枚举、可视化展示。

## 12.3 职责边界

| 组件 | 职责 |
|---|---|
| SSAM (ssam-lib) | 单节点风险求值，输出 SSAM IR |
| **Prism (prism-lib)** | **风险动力学引擎：原始风险 + 语义状态 + 未来推理** |
| ASSCOR 平台 | 数据采集、拓扑同步、状态管理、API暴露、调度、持久化、可视化展示 |

**关键决策**：ServiceType 枚举、HazardType 分类、TrustZone 定义——这些都在 ASSCOR 层，不在 Prism 层。Prism 只接收调用方准备好的数据，执行计算，返回结构化报告。

---

# 13. 数据模型

## 13.1 输入：节点状态

```go
type NodeState struct {
    HostID       string
    SSAMScore    float64        // 来自 SSAM IR 的 FinalScore（0-100）
    FailedChecks []CheckFailure // 未通过检查项及其首次失败时间
}

type CheckFailure struct {
    CheckID  string
    Delta    float64  // 来自 SSAM 的检查项 Delta（负数，如 -15）
    FailUnix int64    // 首次失败时间戳 — 调用方记录，恢复后移除
}
```

## 13.2 输入：拓扑边

```go
type EdgeState struct {
    Source           string  // 上游节点 HostID
    Target           string  // 下游节点 HostID
    RiskTransmission float64 // 风险传递率 (0, 1]
                             // 由调用方根据业务知识设定
                             // 1.0 = 完全信任邻接（公网→DMZ）
                             // 0.1 = 隔离良好（生产→SIEM 日志上报）
}
```

## 13.3 配置

```go
type PrismConfig struct {
    // Core Layer 参数
    DebtAlpha     float64 // 债务超线性指数，默认 1.2
    PropCap       float64 // 传播惩罚上限，默认 0.25
    DebtCap       float64 // 债务惩罚上限，默认 0.30
    DebtNormDays  float64 // 债务归一化分母，默认 1500
    PathDecay     float64 // 路径衰减因子，默认 0.80
    MaxPathDepth  int     // 最大搜索深度，默认 5
    ScoreFloor    float64 // 下界稳定项，默认 0.40
    CollapseBeta  float64 // 塌缩超线性指数，默认 1.5

    // Semantic Layer 参数
    StableThreshold    float64 // Stable 隶属度上界阈值，默认 0.90
    DegradedThreshold  float64 // Degraded 隶属度上界阈值，默认 0.70
    UntrustedThreshold float64 // Untrusted 隶属度上界阈值，默认 0.50
    // Collapse 阈值由 UntrustedThreshold 下界隐含

    // Inference Layer 参数
    HorizonDays    int     // 默认预测时间窗口（天），默认 7
}
```

**无硬编码系数表。Cap 类参数通过分数语义定义，Norm 类参数通过标定场景反算，Semantic 阈值参数化可配置。**

## 13.4 Core Layer 输出：原始风险报告

```go
type RawRiskReport struct {
    HostID           string
    SsamScore        float64 // 原始 SSAM 分数
    PrismScore       float64 // 正交化动态评分 [0, 100]
    ExternalRisk     float64 // 本节点的外部风险 E(v) ∈ [0, 1]
    PropagatedRisk   float64 // 入边传播风险 R_prop ∈ [0, 1]
    PropPenalty      float64 // 实际传播惩罚 ∈ [0, Cap_prop]
    DebtRaw          float64 // 未归一化的债务总值
    DebtPenalty      float64 // 归一化后的债务惩罚 ∈ [0, Cap_debt]
    CollapseModifier float64 // 塌缩修正值 ∈ [0, 1]
    RiskVelocity     float64 // 风险变化速度（评分/天，负值表示恶化）
}
```

## 13.5 Semantic Layer 输出：语义风险报告

```go
type SemanticRiskReport struct {
    HostID                string
    StableMembership      float64   // Stable 隶属度 [0, 1]
    DegradedMembership    float64   // Degraded 隶属度 [0, 1]
    UntrustedMembership   float64   // Untrusted 隶属度 [0, 1]
    CollapseMembership    float64   // Collapse 隶属度 [0, 1]
    CurrentState          string    // 主导状态
    StateVector           [4]float64 // 归一化状态向量
}
```

## 13.6 Inference Layer 输出：未来风险报告

```go
type FutureRiskReport struct {
    HostID         string
    HorizonDays    int
    StableProb     float64 // P(Stable) at t+HorizonDays
    DegradedProb   float64 // P(Degraded) at t+HorizonDays
    UntrustedProb  float64 // P(Untrusted) at t+HorizonDays
    CollapseProb   float64 // P(Collapse) at t+HorizonDays
    Confidence     float64 // 预测置信度 [0, 1]，基于模型适用性和输入质量
    Trend          string  // "improving" / "stable" / "degrading" / "collapsing"
    CollapseRisk   float64 // 塌缩风险摘要：P(Untrusted) + P(Collapse)
}
```

## 13.7 路径搜索结果

```go
type PathResult struct {
    Path           []string  // 节点序列
    CumulativeRisk float64   // 累积风险
}
```

---

# 14. 计算公式

## 14.1 节点外部风险（Core Layer）

给定节点 $v$ 的 SSAM 评分 $S_{ssam}(v) \in [0, 100]$，其**外部风险**（作为攻击跳板对其他节点的威胁）：

$$E(v) = \frac{100 - S_{ssam}(v)}{100}$$

**正交性保证**：传播惩罚仅依赖**上游节点**的外部风险，与当前节点自身的 SSAM 评分完全独立。

## 14.2 传播风险与跳跃衰减（Core Layer）

对于边 $e: u \to v$，$u$ 对 $v$ 的风险溢出为：

$$\text{spillover}(u \to v) = E(u) \times \lambda_{trans}(e)$$

节点 $v$ 的总传播风险 $R_{prop}(v)$ 为所有入边溢出的**平方和开方**：

$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} \text{spillover}(e)^2 }\right)$$

**跳跃衰减**：路径搜索中，第 $n$ 跳的风险贡献乘以衰减因子 $\gamma^{n-1}$（默认 $\gamma = 0.8$）：

$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1}$$

## 14.3 安全债务 — 天归一化（Core Layer）

当调用方记录某检查项首次失败时刻 $t_{fail}$，债务函数以**天**为单位：

$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**选择天的理由**：Unix 秒级时间导致数值溢出风险。使用天为单位后，30 天产生 $30^{1.2} \approx 59$ 量级的值，数值稳定且直观可解释。

$\alpha > 1$ 确保风险随暴露时间超线性增长。债务在检查项恢复通过时立即清零。

## 14.4 正交化动态评分（Core Layer）

$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - P_{prop}(v)) \times (1 - P_{debt}(v, t))\right)$$

其中：

$$P_{prop}(v) = \min(Cap_{prop},\ R_{prop}(v))$$

$$P_{debt}(v, t) = \min\left(Cap_{debt},\ \frac{\sum_c D(c, t)}{Norm_{debt}}\right)$$

**正交性分析**：

| 维度 | 来源 | 是否独立于本节点 SSAM |
|------|------|:---:|
| $S_{ssam}$ | SSAM 输出 | — (基值) |
| $P_{prop}$ | 上游节点 SSAM × λ | ✅ 完全独立（依赖上游，非本节点） |
| $P_{debt}$ | 时间 × Δ | ✅ 完全独立（时间维度，非评分维度） |

## 14.5 风险变化速度（Core Layer）

风险速度 $V_{risk}$ 测量评分的瞬时变化率，以“评分/天”为单位。它通过时间窗口内的评分差分计算：

$$V_{risk}(v, t) = \frac{S_{prism}(v, t) - S_{prism}(v, t - \Delta t)}{\Delta t}$$

当无历史快照时，可通过债务增长率和传播变化率近似估算。负值表示风险恶化。该值输出至 `RawRiskReport.RiskVelocity`。

## 14.6 塌缩修正（Core Layer）

CollapseModifier 由多债务并发时的超线性叠加导出：

$$CollapseModifier(v, t) = \min\left(1.0,\ \left(\frac{\sum_c D(c, t)}{Norm_{debt} \times Cap_{debt}}\right)^{\beta}\right)$$

其中 $\beta > 1$（默认 $\beta = 1.5$），确保多债务并发时塌缩效应超线性增长。

## 14.7 四态隶属度计算（Semantic Layer）

基于归一化 PrismScore $S_{norm} = S_{prism} / 100$，采用参数化梯形隶属度函数：

**Stable 隶属度**：
$$\mu_{Stable}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{S_{norm} - T_{degraded}}{T_{stable} - T_{degraded}}\right)\right)$$

**Degraded 隶属度**：
$$\mu_{Degraded}(S_{norm}) = \max\left(0,\ \min\left(\frac{S_{norm} - T_{untrusted}}{T_{degraded} - T_{untrusted}},\ \frac{T_{stable} - S_{norm}}{T_{stable} - T_{degraded}}\right)\right)$$

**Untrusted 隶属度**：
$$\mu_{Untrusted}(S_{norm}) = \max\left(0,\ \min\left(\frac{S_{norm} - T_{collapse}}{T_{untrusted} - T_{collapse}},\ \frac{T_{degraded} - S_{norm}}{T_{degraded} - T_{untrusted}}\right)\right)$$

**Collapse 隶属度**：
$$\mu_{Collapse}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{T_{untrusted} - S_{norm}}{T_{untrusted} - T_{collapse}}\right)\right)$$

其中 $T_{stable} = 0.90$, $T_{degraded} = 0.70$, $T_{untrusted} = 0.50$, $T_{collapse} = 0.0$（默认值，可通过 PrismConfig 调整）。

**输出归一化**：隶属度向量归一化为 $\sum \mu_i = 1.0$，作为 StateVector 输出。

## 14.8 未来状态推理（Inference Layer）

Inference Layer 支持**任意状态推理模型**，调用方可通过标准接口注入。内置默认实现为**马尔可夫链模型**。

给定当前状态向量 $S_t$ 和状态转移矩阵 $\mathbf{T}$，未来状态概率分布为：

$$S_{t+k} = S_t \times \mathbf{T}^k$$

**默认状态转移矩阵**（基于专家知识先验，单日步长）：

$$\mathbf{T} = \begin{bmatrix}
0.95 & 0.04 & 0.01 & 0.00 \\
0.02 & 0.90 & 0.07 & 0.01 \\
0.00 & 0.03 & 0.85 & 0.12 \\
0.00 & 0.00 & 0.05 & 0.95
\end{bmatrix}$$

状态顺序：Stable, Degraded, Untrusted, Collapse。

**置信度计算**：置信度反映预测的可靠性，由以下因素综合：
- 输入状态向量的集中度（熵越低置信度越高）
- 推理模型与当前场景的匹配程度（可配置）
- 预测时间跨度（跨度越长置信度递减）

默认实现中，置信度取状态向量最大隶属度与时间衰减因子的乘积：$Confidence = \max(StateVector) \times e^{-k/K}$，其中 $K$ 为时间衰减常数。

**趋势判定**：
- 若 $P(Collapse) + P(Untrusted)$ 增长 $> 0.1$，判定 `"collapsing"`
- 若 $P(Degraded) + P(Untrusted)$ 增长 $> 0.1$，判定 `"degrading"`
- 若 $P(Stable)$ 增长 $> 0.1$，判定 `"improving"`
- 否则判定 `"stable"`

---

# 15. 参数总表

| 参数 | 默认值 | 含义 | 所属层 |
|------|:---:|------|:---:|
| `DebtAlpha` | 1.2 | 债务超线性指数 | Core |
| `PropCap` | 0.25 | 传播惩罚上限 | Core |
| `DebtCap` | 0.30 | 债务惩罚上限 | Core |
| `DebtNormDays` | 1500 | 债务归一化分母 | Core |
| `PathDecay` | 0.80 | 路径衰减因子 | Core |
| `MaxPathDepth` | 5 | 最大搜索深度 | Core |
| `ScoreFloor` | 0.40 | 下界稳定项 | Core |
| `CollapseBeta` | 1.5 | 塌缩超线性指数 | Core |
| `StableThreshold` | 0.90 | Stable 上界阈值 | Semantic |
| `DegradedThreshold` | 0.70 | Degraded 上界阈值 | Semantic |
| `UntrustedThreshold` | 0.50 | Untrusted 上界阈值 | Semantic |
| `HorizonDays` | 7 | 默认预测窗口 | Inference |

**无自由参数**：所有参数均可通过正交性约束、基准场景标定或专家知识设定。

---

# 16. 下界稳定（ScoreFloor）— 防止永久塌缩

乘性结构 $S_{ssam} \times (1-P_{prop}) \times (1-P_{debt})$ 在长期运行中存在**无限衰减**风险：每次评估叠加新的惩罚，系统分数持续下降，最终所有系统都趋近于 0——从该状态无法恢复。

解决方案：在公式中引入**下界稳定项** $\mathsf{Floor}$，使得评分不低于 SSAM 原始评分的固定比例：

$$S_{prism}(v, t) \geq S_{ssam}(v) \times \mathsf{Floor}$$

默认 $\mathsf{Floor} = 0.40$。这意味着即便最坏情况（传播饱和 + 债务饱和），系统仍保留 SSAM 原始评分的 40%。这等价于“可恢复性保障”——系统不会因为多重独立惩罚因子而永久塌缩。

---

# 17. 纯函数接口

## 17.1 Core Layer 接口

```go
// ComputeRawRisk 计算节点的原始风险报告。
// allNodes 用于查找上游节点的 SSAM 分数。
// previousScore 可选，用于计算风险速度；为 nil 时速度估算。
func ComputeRawRisk(
    node *NodeState,
    incomingEdges []EdgeState,
    allNodes map[string]*NodeState,
    cfg PrismConfig,
    nowUnix int64,
    previousScore *float64, // 可选的上次评分，用于速度计算
) RawRiskReport

// FindPropagationPaths 查找源到目标的前 N 条最高风险路径。
func FindPropagationPaths(
    source, target string,
    nodes map[string]*NodeState,
    edges []EdgeState,
    cfg PrismConfig,
    nowUnix int64,
    maxDepth int,
    limit int,
) []PathResult
```

## 17.2 Semantic Layer 接口

```go
// ComputeSemanticRisk 基于原始风险报告计算四态隶属度。
func ComputeSemanticRisk(
    raw RawRiskReport,
    cfg PrismConfig,
) SemanticRiskReport
```

## 17.3 Inference Layer 接口

```go
// StateInferenceModel 定义了状态推理模型的接口。
// 任何满足此接口的模型均可注入 Inference Layer。
type StateInferenceModel interface {
    // Predict 基于当前状态向量和预测天数，返回未来状态概率分布。
    Predict(currentState [4]float64, horizonDays int) [4]float64
    // Confidence 返回给定预测的置信度。
    Confidence(currentState [4]float64, horizonDays int) float64
}

// InferFutureRisk 基于当前语义状态和推理模型推导未来状态概率分布。
// model 可选：nil 时使用默认马尔可夫链模型。
func InferFutureRisk(
    current SemanticRiskReport,
    horizonDays int,
    model StateInferenceModel, // nil = 使用默认模型
    cfg PrismConfig,
) FutureRiskReport
```

**完整评估管线**（调用方视角）：
```go
raw := ComputeRawRisk(node, edges, allNodes, cfg, now, &previousScore)
semantic := ComputeSemanticRisk(raw, cfg)
future := InferFutureRisk(semantic, cfg.HorizonDays, nil, cfg)
```

**原则不变**：所有函数为纯函数。调用方传入数据，Prism 返回结果。无副作用，无状态。

---

# 18. 状态归属：Prism 永远只消费快照

Prism 是纯函数库。它不管理状态。具体来说：

| 数据 | 归属 | 说明 |
|------|------|------|
| `NodeState.SSAMScore` | ASSCOR 缓存 | 来自最近一次 SSAM 评估 |
| `CheckFailure.FailUnix` | ASSCOR `failTracker` | 首次失败时间戳由 ASSCOR 记录和更新 |
| `EdgeState.RiskTransmission` | ASSCOR 拓扑管理器 | 由调用方从 CMDB 或配置读取 |
| 历史评分序列 | ASSCOR 持久化层 | Prism Core 通过 `previousScore` 参数接收，不存储 |
| 历史状态序列 | ASSCOR 持久化层 | 用于训练自定义推理模型，由调用方管理 |

**Prism 只是“吃快照，吐报告”。**

---

# 19. 全图重计算与增量传播（未来方向）

当前实现中，`ComputeRawRisk` 每次评估一个节点时需要遍历所有入边——复杂度 $O(|E_{in}|)$。在多主机部署（N 个节点，每个有 N-1 条入边）中，单次调用复杂度为 $O(N)$。

当 N 增长到 100k+ 时，需要引入**增量传播模型**：

- **脏标记传播**：仅重算受影响子图
- **拓扑分区**：按 TrustZone / ServiceType 分区
- **批量调度**：批次后批量计算
- **推理模型在线学习**：ASSCOR 持久化层积累状态转移序列后，训练自定义模型注入 Prism

**但现在不做**。当前最重要的是保持架构纯净：
- Prism 保持纯函数
- ASSCOR 通过调度层控制调用频率和范围
- 等 `N > 100` 后有真实性能数据再决策

---

# 20. 与 SSAM 及 ASSCOR 的集成

## 20.1 数据流

1. ASSCOR Agent 采集数据 → Kernel 完成 SSAM 评估 → 生成 SSAM IR
2. ASSCOR 状态管理器更新 NodeState，记录 FailUnix，并保留上次评分供速度计算
3. ASSCOR 从 CMDB 同步拓扑 → 构建 EdgeState 列表
4. 每次状态变更或定时触发 → ASSCOR 调用 Prism 三层管线：Raw → Semantic → Future
5. ASSCOR 将三份报告通过 API 暴露 / 写入持久化
6. ASSCOR 持久化层积累状态序列，周期性训练自定义推理模型，注入 Prism Inference Layer

## 20.2 项目结构

```
prism/
├── types.go              # 数据结构定义（含推理模型接口）
├── core.go               # Core Layer
├── semantic.go           # Semantic Layer
├── inference.go          # Inference Layer（默认马尔可夫链实现）
├── config.go             # DefaultConfig
├── core_test.go
├── semantic_test.go
├── inference_test.go
├── go.mod                # 独立 module，零外部依赖
```

---

# 21. 已裁减与归位的特性

| 特性 | 状态 | 理由 |
|------|------|------|
| ServiceType 枚举 | 裁减 | CMDB 数据，调用方定义 |
| HazardType 枚举 | 裁减 | SSAM 隐含 |
| ImpactScope 枚举 | 裁减 | 拓扑图隐含 |
| TrustZone 枚举 | 裁减 | 边上直接设传输率 |
| 独立 CollapseModifier | 裁减 | 债务 + CollapseBeta 自然体现 |
| 硬编码 RiskTransmission | 裁减 | 调用方设定 |
| SystemWeight 系数 | 裁减 | 拓扑隐含 |
| PersistenceLevel 系数 | 裁减 | Delta 隐含 |
| FuzzyMembership | 归位 Semantic Layer (v3.1) | 状态语义是风险认知核心 |
| FutureState 预测 | 归位 Inference Layer (v3.1) | 动力学自然延伸 |
| 硬编码贝叶斯模型 | 归位为可插拔接口 (v3.1-R2) | 支持任意推理模型 |

---

# 22. 算法局限性

- 传播风险仅考虑合法业务连接，非法横向移动需“潜在攻击边”扩展
- 安全债务假设单调递增，未考虑缓解措施后的利用概率下降
- 依赖 SSAM 评估准确性
- 参数标定需生产数据修正
- 隶属度函数为梯形近似
- 默认转移矩阵为专家先验，预测精度随数据积累可提升
- 马尔可夫假设可能掩盖路径依赖效应
- 置信度计算为启发式方法，需结合实际验证反馈校准

---

# 23. 未来方向

- **领域专用推理模型**——贝叶斯网络、HMM、生存分析、统计回归等模型的注入与评估
- **置信度校准**——基于历史预测准确率的置信度动态调整
- **非线性塌缩模型**——多债务乘性交互
- **动态权重**——实时威胁情报调整 λ
- **集群聚合评分**——多节点集合风险
- **Prism IR 标准化**——三层报告结构化输出

---

# 24. 版本演进

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-06-01 前 | 初始概念设计 |
| v2.0 | 2026-05-28 | SRD + Prism 合并，完整类型/枚举/系数 |
| v3.0 | 2026-05-28 | MVP 精简：4 类型，6 参数，2 函数，0 硬编码系数 |
| v3.1 | 2026-05-30 | 正交化修复，乘性，天归一化，跳跃衰减 |
| v3.2 | 2026-05-30 | 下界稳定 ScoreFloor，FailUnix 归位，增量传播记录 |
| v3.1-R1 | 2026-06-08 | 三层架构：Core/Semantic/Inference；三元组 R=(S,D,F) |
| **v3.1-R2** | **2026-06-08** | **推理模型可插拔接口，移除贝叶斯原生声明；增加置信度输出；三元组升级为 R=(State, Velocity, Forecast)；Core Layer 输出风险速度** |

---

# 25. 结论

SRD 提出：系统风险并非漏洞数量，也并非一个分数。

**风险是系统状态在时间与空间中的持续演化。**

Prism v3.1-R2 是这一理论的**风险动力学引擎实现**。它不做分类、不做枚举、不管理数据、不做可视化展示。它只做三件事：

1. **Core Layer**：计算传播风险、时间债务、塌缩修正与风险变化速度——回答“系统发生了什么，变化有多快”
2. **Semantic Layer**：将数值转化为风险状态隶属度——回答“系统当前是什么状态”
3. **Inference Layer**：基于可插拔的推理模型，推导未来状态概率与置信度——回答“系统未来可能变成什么状态，这个预测有多可靠”

当 SSAM 回答“这台机器此刻有多安全”时，Prism 回答：

- “在整个网络的动态演化中，风险正在流向何方，以多快的速度恶化”
- “系统当前处于什么状态——稳定、退化、不可信还是已经塌缩”
- “如果维持现状，未来最可能走向哪种状态，这个预测的可信程度如何”

所有关于“是什么类型”“有多重要”“属于哪个域”“该展示成什么颜色”的问题——都是调用方的职责。

Prism 的边界到此为止。这就是它能做的一切。这就是它应该做的一切。

---

# 附录 A：核心术语

| 术语 | 含义 |
|---|---|
| Systemic Risk | 系统性风险 |
| Risk State | 风险状态（Stable / Degraded / Untrusted / Collapse） |
| Risk Dynamics | 风险动力学——风险在时间和空间中的演化规律 |
| Risk Velocity | 风险速度——风险评分的瞬时变化率，可测量 |
| Risk Triad | 风险三元组：$R = (State, Velocity, Forecast)$ |
| Trust Drift | 信任漂移 |
| Collapse Potential | 系统塌缩潜力 |
| Security Debt | 安全债务——未修复缺陷随时间的累积风险 |
| Spillover | 风险溢出——上游节点对下游的风险传递 |
| Fuzzy Membership | 模糊隶属度——系统同时属于多个风险状态的程度 |
| State Inference Model | 状态推理模型——可插拔的未来状态预测接口 |
| Confidence | 置信度——预测的可靠性度量 |
| Prism | 棱镜——SRD 理论的风险动力学引擎 |

---

# 附录 B：核心公式

## Core Layer 公式

**自身风险**：
$$E(v) = \frac{100 - S_{ssam}(v)}{100}$$

**风险溢出**：
$$\text{spillover}(u \to v) = E(u) \times \lambda_{trans}(e)$$

**传播风险聚合**：
$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} (E(src_e) \times \lambda_e)^2 }\right)$$

**跳跃衰减**：
$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1},\quad \gamma = 0.8$$

**安全债务（天归一化）**：
$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**正交化动态评分**：
$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - \min(Cap_{prop}, R_{prop}(v))) \times \left(1 - \min\left(Cap_{debt}, \frac{\sum D(c,t)}{Norm_{debt}}\right)\right)\right)$$

**风险速度**：
$$V_{risk}(v, t) \approx \frac{S_{prism}(v, t) - S_{prism}(v, t - \Delta t)}{\Delta t}$$

**塌缩修正**：
$$CollapseModifier(v, t) = \min\left(1.0,\ \left(\frac{\sum_c D(c, t)}{Norm_{debt} \times Cap_{debt}}\right)^{\beta}\right),\quad \beta = 1.5$$

## Semantic Layer 公式

**Stable 隶属度**：
$$\mu_{Stable}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{S_{norm} - T_{degraded}}{T_{stable} - T_{degraded}}\right)\right)$$

**状态向量归一化**：
$$StateVector_i = \frac{\mu_i}{\sum_{j} \mu_j}$$

## Inference Layer 公式

**未来状态预测（默认马尔可夫链）**：
$$S_{t+k} = S_t \times \mathbf{T}^k$$

**置信度（默认启发式）**：
$$Confidence = \max(StateVector) \times e^{-k/K}$$

**默认转移矩阵**：
$$\mathbf{T} = \begin{bmatrix}
0.95 & 0.04 & 0.01 & 0.00 \\
0.02 & 0.90 & 0.07 & 0.01 \\
0.00 & 0.03 & 0.85 & 0.12 \\
0.00 & 0.00 & 0.05 & 0.95
\end{bmatrix}$$

## 风险动力学三元组

$$R = (State, Velocity, Forecast)$$

- $State$ = Current State Vector（Semantic Layer）
- $Velocity$ = RiskVelocity（Core Layer）
- $Forecast$ = FutureRiskReport（Inference Layer）

---

# 附录 C：输出模型总览

| 报告 | 所属层 | 核心问题 | 性质 |
|---|---|---|---|
| RawRiskReport | Core Layer | 系统发生了什么？变化有多快？ | 确定性、可审计 |
| SemanticRiskReport | Semantic Layer | 系统当前是什么状态？ | 模糊推理、可解释 |
| FutureRiskReport | Inference Layer | 未来可能怎样？预测有多可靠？ | 概率推理、可验证 |

---

## 状态反馈（调用方职责）

Prism 不自发调整传播率或推理模型。调用方可实现：

- **传播率反馈**：根据上游状态动态调整边上的 `RiskTransmission`
- **推理模型反馈**：积累历史状态序列，训练自定义模型（贝叶斯网络、HMM、生存分析等），通过 `StateInferenceModel` 接口注入

这样 Prism 保持纯函数性质，动态行为由调用方管理。