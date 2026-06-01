# Systemic Risk Dynamics（SRD）白皮书
## —— 面向复杂系统的风险语义、状态演化与系统塌缩理论
### 附：Prism 最小可验证计算规范 v3.0（MVP）

---

# 文档信息

| 项 | 内容 |
|---|---|
| 项目名称 | Systemic Risk Dynamics |
| 简称 | SRD |
| 算法代号 | Prism（棱镜） |
| 类型 | 风险动力学理论框架 + 最小可验证计算规范 |
| 核心方向 | 风险语义、风险演化、系统退化、系统塌缩、时空传播 |
| 理论性质 | 可解释、可推导、半确定性风险系统 |
| 适用领域 | 安全、云平台、工业控制、复杂系统、AI基础设施 |
| 版本 | v3.0 — MVP |
| 日期 | 2026-05-28 |
| 设计原则 | 最小可验证——只保留计算层不可替代的部分。其余均归位于调用方 |

---

# 摘要（Abstract）

传统安全系统长期建立在 CVSS、Checklist、Compliance、Vulnerability Counting、Static Scoring 基础之上。这些模型默认风险是静态、离散、确定性的。

但真实系统具有：长期退化、风险传播、信任漂移、动态结构、模糊边界、非线性塌缩、时间累积、不确定输入。

因此：

## 风险并不是"漏洞数量"，而是"系统状态演化"。

SRD（Systemic Risk Dynamics）提出：**系统风险本质上是一种动态风险状态空间。** SRD 的核心目标不是"计算一个分数"，而是**推导系统是否正在进入不可接受状态**。

Prism 是 SRD 理论的工程实现——一个纯函数式的时空风险计算库。它仅做两件事：

1. 计算节点在网络传播与时间累积下的**动态风险评分**
2. 查找节点间的**风险传播路径**

其他一切——服务分类、危害标注、信任域定义、模糊隶属度展示、风险趋势预测——都属于调用方（ASSCOR Kernel）的职责。

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

因此传统系统得到的通常只是"统计结果"，而不是"系统真实状态"。

---

# 2. SRD 核心理论

SRD 提出：

## 风险不是漏洞。风险是系统状态退化。

系统并不是瞬间失效，而是**长期退化**。风险也不是孤立事件，而是**信任结构传播**。

因此 SRD 采用：

## 风险语义 + 状态演化 + 模糊推导

构建风险动力学系统。

---

# 3. 风险语义空间（Risk Semantic Space）

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

# 4. 风险状态机（Risk State Machine）

SRD 定义**风险状态转移**：

| 状态 | 含义 | 分数区间 |
|---|---|---|
| Stable | 可接受 | Score ≥ 90 |
| Degraded | 部分退化 | 70 ≤ Score < 90 |
| Untrusted | 不可信 | 50 ≤ Score < 70 |
| Collapse | 系统塌缩 | Score < 50 |

系统状态会随时间演化：

$$Stable \rightarrow Degraded \rightarrow Untrusted \rightarrow Collapse$$

SRD 的目标不是"追求零风险"，而是**长期维持可接受状态**。

**注意**：四态分类的定义在理论层。如何将连续分数映射为离散状态、如何在前端展示模糊隶属度——这些是消费层的工程决策，不在 Prism 计算库的范围内。

---

# 5. 风险时间演化（Temporal Risk Dynamics）

SRD 认为**风险会持续演化**：累积、扩散、放大、漂移、塌缩。

因此风险是时间函数：

$$R(t) = R_0 \cdot e^{\lambda t}$$

或：

$$R(t) = R_0 + \alpha \cdot \log(1 + t)$$

工程实现采用 Prism 的安全债务公式（见 §10.4）。

---

# 6. 网络语义归约（Network Semantic Reduction）

SRD 不试图完整求解网络拓扑。因为现实网络具有 Overlay、Mesh、VPN、NAT、SDN、Dynamic Routing、Kubernetes、Cloud Fabric 等复杂结构，完整网络求解复杂度极高。

因此 SRD 采用**安全语义归约**——将复杂网络归约为有向加权图：

- 节点 = 已评估资产（状态来自 SSAM IR）
- 边 = 业务连接（RiskTransmission 由调用方根据业务知识设定）

调用方（ASSCOR）负责从 CMDB/NetBox 同步拓扑，并在边上直接标注风险传递率。Prism 不推导传输率——调用方更清楚自己的网络。

---

# 7. Collapse Potential — 系统塌缩

SRD 引入 Collapse Potential：**系统塌缩能力**。传统系统将风险视为线性累积，但现实中某些控制失效会导致**系统整体可信性下降**。

例如：无 SIEM、无 MFA、无 Backup、无 IDS、无 Audit——这些问题不是简单扣分，而是**系统信任塌缩**。

SRD 使用：

$$Risk = S \times C$$

**工程实现**：Collapse 效应通过安全债务的累积自然体现——当多个关键检查项长期未通过时，债务呈超线性增长，等效于塌缩修正。不需要独立的 Collapse Modifier 参数。

---

# 8. 可解释性原则

SRD 明确拒绝**黑盒 AI 风险评分**。因此 SRD 采用**受约束模糊推理**：

- Deterministic Core — 确定性求值（SSAM + Prism）
- Fuzzy Semantic Layer — 模糊语义层（消费方实现）
- Traceable — 每个输出都可追溯到具体检查项或拓扑边

---

# 9. 核心原则

1. 风险不是漏洞数量
2. 风险是系统状态
3. 风险具有时间语义
4. 风险具有传播性
5. 风险具有模糊边界
6. 风险会长期退化
7. 系统存在塌缩效应
8. 风险必须可解释
9. 理论层必须稳定与纯净
10. 安全目标是维持长期可接受状态

---

# 第二部分：Prism 工程规范（MVP）

---

# 10. 设计原则

## 10.1 纯函数式内核

Prism 与 SSAM 对齐为"纯函数式核心 / Imperative Shell"模式。所有计算函数均满足：
- 相同输入产生相同输出
- 无内部可变状态
- 无 I/O、无网络调用、无锁、无 goroutine
- 仅依赖 Go 标准库及 `math` 包

## 10.2 单一职责

Prism 仅做两件事：

1. **计算动态评分**——给定节点的 SSAM 分数、失败检查项的时间线和入边列表，返回传播风险与债务修正后的评分
2. **查找传播路径**——给定源和目标，返回前 N 条最高风险路径

Prism 不负责：数据采集、漏洞扫描、威胁情报、配置管理、持久化、API暴露、分类枚举、状态展示、趋势预测。

## 10.3 职责边界

| 组件 | 职责 |
|---|---|
| SSAM (ssam-lib) | 单节点风险求值，输出 SSAM IR |
| **Prism (prism-lib)** | **传播风险 + 安全债务 = 动态评分** |
| ASSCOR 平台 | 数据采集、拓扑同步、状态管理、API暴露、调度、持久化、分类展示 |

**关键决策**：ServiceType 枚举、HazardType 分类、TrustZone 定义、Fuzzy Membership 展示——这些都在 ASSCOR 层，不在 Prism 层。Prism 只接收调用方准备好的数据，执行数学计算，返回数字结果。

---

# 11. 数据模型（仅 4 个结构体）

## 11.1 节点状态

```go
type NodeState struct {
    HostID       string
    SSAMScore    float64       // 来自 SSAM IR 的 FinalScore（0-100）
    FailedChecks []CheckFailure // 未通过检查项及其首次失败时间
}

type CheckFailure struct {
    CheckID  string
    Delta    float64  // 来自 SSAM 的检查项 Delta（负数，如 -15）
    FailUnix int64    // 首次失败时间戳 — 调用方记录，恢复后移除
}
```

## 11.2 拓扑边

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

## 11.3 配置

```go
type PrismConfig struct {
    DebtAlpha     float64 // 债务超线性指数，默认 1.2
    PropCap       float64 // 传播惩罚上限，默认 0.25
    DebtCap       float64 // 债务惩罚上限，默认 0.30
    DebtNormDays  float64 // 债务归一化分母，默认 1500
    PathDecay     float64 // 路径衰减因子，默认 0.80
    MaxPathDepth  int     // 最大搜索深度，默认 5
}
```

**6 个参数，无硬编码系数表。Cap 类参数通过分数语义定义，Norm 类参数通过标定场景反算。**

## 11.4 返回结果

```go
type AssetRiskResult struct {
    HostID         string
    SsamScore      float64   // 原始 SSAM 分数
    PrismScore     float64   // 正交化动态评分 [0, 100]
    ExternalRisk   float64   // 本节点的外部风险 E(v) ∈ [0, 1]
    PropagatedRisk float64   // 入边传播风险 R_prop ∈ [0, 1]
    PropPenalty    float64   // 实际传播惩罚 ∈ [0, Cap_prop]
    DebtRaw        float64   // 未归一化的债务总值
    DebtPenalty    float64   // 归一化后的债务惩罚 ∈ [0, Cap_debt]
}

type PathResult struct {
    Path           []string  // 节点序列
    CumulativeRisk float64   // 累积风险
}
```

---

# 12. 计算公式

## 12.1 节点外部风险

给定节点 $v$ 的 SSAM 评分 $S_{ssam}(v) \in [0, 100]$，其**外部风险**（作为攻击跳板对其他节点的威胁）：

$$E(v) = \frac{100 - S_{ssam}(v)}{100}$$

**正交性保证**：传播惩罚仅依赖**上游节点**的外部风险，与当前节点自身的 SSAM 评分完全独立。这意味着一个 SSAM=20 的上游对下游的影响相同，无论下游自身评分是多少。

## 12.2 传播风险与跳跃衰减

对于边 $e: u \to v$，$u$ 对 $v$ 的风险溢出为：

$$\text{spillover}(u \to v) = E(u) \times \lambda_{trans}(e)$$

节点 $v$ 的总传播风险 $R_{prop}(v)$ 为所有入边溢出的**平方和开方**：

$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} \text{spillover}(e)^2 }\right)$$

**跳跃衰减**：路径搜索中，第 $n$ 跳的风险贡献乘以衰减因子 $\gamma^{n-1}$（默认 $\gamma = 0.8$），确保长路径不会无限叠加：

$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1}$$

## 12.3 安全债务（天归一化）

当调用方记录某检查项首次失败时刻 $t_{fail}$，债务函数以**天**为单位：

$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**选择天的理由**：Unix 秒级时间导致 $2592000^{1.2}$ 的极大数据溢出，必须用极小权重 $1.6 \times 10^{-8}$ 压制——本质是数值不稳定。使用天为单位后，30 天产生 $30^{1.2} \approx 59$ 量级的值，数值稳定且直观可解释。

$\alpha > 1$ 确保风险随暴露时间超线性增长。债务在检查项恢复通过时立即清零。

## 12.4 正交化动态评分

$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - P_{prop}(v)) \times (1 - P_{debt}(v, t))\right)$$

其中 $\mathsf{Floor} = 0.40$（默认）。此下界保证：**无论传播如何恶化、债务如何累积，动态评分不会低于 SSAM 原始评分的 40%**。这解决了长期运行中惩罚因子无限叠加导致系统**永久不可恢复**的问题。下界值通过"可恢复性约束"反推：即便在最坏情况下，系统仍保留基础可操作性。

其中：

$$P_{prop}(v) = \min(Cap_{prop},\ R_{prop}(v))$$

$$P_{debt}(v, t) = \min\left(Cap_{debt},\ \frac{\sum_c D(c, t)}{Norm_{debt}}\right)$$

**正交性分析**：

| 维度 | 来源 | 是否独立于本节点 SSAM |
|------|------|:---:|
| $S_{ssam}$ | SSAM 输出 | — (基值) |
| $P_{prop}$ | 上游节点 SSAM × λ | ✅ 完全独立（依赖上游，非本节点） |
| $P_{debt}$ | 时间 × Δ | ✅ 完全独立（时间维度，非评分维度） |

三项来自**不同维度**，不存在重复扣分。乘法结构保证：满分节点不受传播和债务影响，低分节点同时受两个独立惩罚时效应正确叠加。

## 12.5 参数

| 参数 | 默认值 | 含义 | 来源 |
|------|:---:|------|------|
| `DebtAlpha` | 1.2 | 债务超线性指数 | 理论分析（α>1） |
| `PropCap` | 0.25 | 传播惩罚上限（25%） | 工程约束 |
| `DebtCap` | 0.30 | 债务惩罚上限（30%） | 工程约束 |
| `DebtNormDays` | 1500 | 债务归一化分母 | 标定：Delta=-15 × 30天¹·² / 1500 ≈ 0.20 |
| `PathDecay` | 0.80 | 路径衰减因子 | 工程约束 |
| `MaxPathDepth` | 5 | 最大搜索深度 | 工程约束 |
| `ScoreFloor` | 0.40 | 下界稳定项 | 可恢复性约束 |

**无自由参数**：所有参数均可通过正交性约束或基准场景标定。

## 12.6 下界稳定（ScoreFloor）— 防止永久塌缩

乘性结构 $S_{ssam} \times (1-P_{prop}) \times (1-P_{debt})$ 在长期运行中存在**无限衰减**风险：每次评估叠加新的惩罚，系统分数持续下降，最终所有系统都趋近于 0——从该状态无法恢复。

解决方案：在公式中引入**下界稳定项** $\mathsf{Floor}$，使得评分不低于 SSAM 原始评分的固定比例：

$$S_{prism}(v, t) \geq S_{ssam}(v) \times \mathsf{Floor}$$

默认 $\mathsf{Floor} = 0.40$。这意味着即便最坏情况（传播饱和 + 债务饱和），系统仍保留 SSAM 原始评分的 40%。这等价于"可恢复性保障"——系统不会因为多重独立惩罚因子而永久塌缩。

## 12.7 状态归属：Prism 永远只消费快照

Prism 是纯函数库。它不管理状态。具体来说：

| 数据 | 归属 | 说明 |
|------|------|------|
| `NodeState.SSAMScore` | ASSCOR 缓存 | 来自最近一次 SSAM 评估 |
| `CheckFailure.FailUnix` | ASSCOR `failTracker` | 首次失败时间戳由 ASSCOR 记录和更新 |
| `EdgeState.RiskTransmission` | ASSCOR 拓扑管理器 | 由调用方从 CMDB 或配置读取 |
| 历史评分序列 | ASSCOR 持久化层 | Prism 不需要历史数据 |

Prism 的函数签名为：

```go
func ComputeDynamicScore(node *NodeState, incomingEdges []EdgeState, allNodes map[string]*NodeState, cfg PrismConfig, nowUnix int64) AssetRiskResult
```

**所有状态参数 = 调用方传入的瞬时快照。** Prism 不持锁、不存状态、不记录时间戳。调用方在调用前完成：SSAM 评估 → 更新 failTracker → 收集拓扑快照 → 传入 Prism。Prism 只是"吃快照，吐数字"。

## 12.8 全图重计算与增量传播（未来方向）

当前实现中，`ComputeDynamicScore` 每次评估一个节点时需要遍历所有入边——复杂度 $O(|E_{in}|)$。在多主机部署（N 个节点，每个有 N-1 条入边）中，单次调用复杂度为 $O(N)$。

当 N 增长到 100k+ 时，需要引入**增量传播模型**：

- **脏标记传播**：仅重算受影响子图（上游 SSAM 变化 → 传播到下游 → 再传播到更下游）
- **拓扑分区**：按 TrustZone / ServiceType 分区，跨区传播在粗粒度计算
- **批量调度**：不在每次单主机评估时立即调用 Prism，而是收集批次后批量计算

**但现在不做**。当前最重要的是保持架构纯净：
- Prism 保持纯函数（增量传播需要状态，不能在纯函数内实现）
- ASSCOR 通过调度层控制调用频率和范围
- 等 `N > 100` 后有真实性能数据再决策

这些决策记录在此处，供未来参考。**

---

# 13. 纯函数接口（仅 2 个）

```go
func DefaultConfig() PrismConfig {
    return PrismConfig{
        DebtAlpha:     1.2,
        PropCap:       0.25,
        DebtCap:       0.30,
        DebtNormDays:  1500.0,
        PathDecay:     0.80,
        MaxPathDepth:  5,
        ScoreFloor:    0.40,
    }
}

// ComputeDynamicScore 计算节点的动态风险评分。
// allNodes 用于查找上游节点的 SSAM 分数。
func ComputeDynamicScore(
    node *NodeState,
    incomingEdges []EdgeState,
    allNodes map[string]*NodeState,
    cfg PrismConfig,
    nowUnix int64,
) AssetRiskResult

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

**仅 2 个函数**。调用方传入数据，Prism 返回结果。无副作用，无状态。

---

# 14. 与 SSAM 及 ASSCOR 的集成

## 14.1 数据流

1. ASSCOR Agent 采集数据 → Kernel 完成 SSAM 评估 → 生成 SSAM IR
2. ASSCOR 状态管理器更新 NodeState：写入 SSAMScore，检查项失败时记录 FailUnix，恢复时移除
3. ASSCOR 从 CMDB 同步拓扑 → 构建 EdgeState 列表（直接在边上设 RiskTransmission）
4. 每次状态变更或定时触发 → ASSCOR 调用 `ComputeDynamicScore` / `FindPropagationPaths`
5. ASSCOR 将结果通过 API 暴露 / 写入持久化

## 14.2 项目结构

```
prism/
├── types.go        # 4 个结构体
├── core.go         # 2 个核心函数
├── core_test.go    # 单元测试
├── config.go       # DefaultConfig
├── go.mod          # 独立 module，仅依赖 Go 标准库
```

---

# 15. 已裁减的特性清单

以下特性曾出现在 v2.0 草案中，已在 v3.0 MVP 中移除。移除理由遵循一条原则：**凡是调用方能自行决定的，不应进入计算库。**

| 移除项 | 移除理由 | 替代方案 |
|--------|---------|---------|
| ServiceType 枚举（12 种） | 服务分类是 CMDB 数据，不应在计算层硬编码 | 调用方在配置文件中定义 |
| HazardType 枚举（9 种） | 危害语义已隐含在 SSAM Domain/Delta 中 | 不需要重复建模 |
| ImpactScope 枚举（7 种） | 影响范围由拓扑图连通性隐含 | 图本身已包含此信息 |
| TrustZone 枚举（5 种） | 传输率由调用方在边上直接设 | EdgeState.RiskTransmission |
| CollapseModifier 乘子 | 塌缩效应由债务超线性累积自然体现 | $D(c,t) \propto t^{1.2}$ |
| FuzzyMembership 函数 | 四态分类是仪表盘展示逻辑 | 消费端自行实现 |
| PredictFutureState 函数 | 趋势预测是分析层的事 | 持久化层 + 独立分析模块 |
| SystemWeight 系数 | 节点关键性由图拓扑（边的有无和方向）隐含 | 不额外标注 |
| PersistenceLevel 系数 | 不同检查项的持久性差异已体现在 Delta 大小中 | 不需要额外参数 |
| 硬编码 RiskTransmission 表 | 传输率应基于实际网络环境 | 调用方直接设定 |
| ServicePropagationWeight 表 | 服务权重是对调用方的过度假设 | 调用方通过边权重表达 |

---

# 16. 算法局限性

- 传播风险仅考虑合法业务连接。攻击者可能利用的非法横向移动路径需通过添加"潜在攻击边"来扩展。
- 安全债务假设风险随暴露时间单调递增，未考虑缓解措施部署后的实际利用概率下降。
- 动态评分依赖于 SSAM 评估的准确性；若 SSAM 输入缺失或错误，Prism 结果亦受影响。
- 参数标定基于基准场景，实际部署后可能需要根据生产数据重新标定。

---

# 17. 未来方向

以下方向值得探索，但在有实证数据支撑之前，不会进入 Prism 计算库：

- 非线性塌缩模型——多重债务的乘性交互
- 贝叶斯状态预测——不确定条件下的状态推理
- 动态权重——基于实时威胁情报的 λ 自动调整
- 集群聚合评分——多节点的集合风险度量
- Prism IR 标准化——可审计的结构化输出格式
- 模糊信任系统——在调用方层面提供隶属度计算辅助

---

# 18. 版本演进

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-06-01 前 | 初始概念设计（Prism.md 独立文档） |
| v2.0 | 2026-05-28 | SRD + Prism 合并，含完整类型/枚举/系数体系 |
| **v3.0** | **2026-05-28** | **精简为 MVP**：51→4 类型，9→6 参数，7→2 函数，35→0 硬编码系数 |
| **v3.1** | **2026-05-30** | **正交化修复**：减性→乘性，秒→天归一化，跳跃衰减 γⁿ，状态反馈调用方化 |
| **v3.2** | **2026-05-30** | **下界稳定**：ScoreFloor 40%防止永久塌缩；FailUnix 状态归位 ASSCOR；增量传播决策记录 |

---

# 19. 结论

SRD 提出：系统风险并非漏洞数量，而是**系统状态演化**。

Prism v3.0 是这一理论的**最小可验证实现**。它不做分类、不做枚举、不做预测、不做展示。它只做一件事：

**给定节点评分、失败时间线和拓扑关系，计算出传播风险与时间累积修正后的动态评分。**

当 SSAM 回答"这台机器此刻有多安全"时，Prism 回答"在整个网络的动态演化中，风险正在流向何方，又在何处加速累积"。

所有关于"是什么类型""有多重要""属于哪个域""该展示成什么颜色"的问题——都是调用方的职责。

Prism 的边界到此为止。这就是它能做的一切。这就是它应该做的一切。

---

# 附录 A：核心术语

| 术语 | 含义 |
|---|---|
| Systemic Risk | 系统性风险 |
| Risk State | 风险状态（Stable / Degraded / Untrusted / Collapse） |
| Trust Drift | 信任漂移 |
| Collapse Potential | 系统塌缩潜力 |
| Impact Duration | 影响持续时间 |
| Semantic Reduction | 语义归约 |
| Security Debt | 安全债务——未修复缺陷随时间的累积风险 |
| Spillover | 风险溢出——上游节点对下游的风险传递 |
| Prism | 棱镜——SRD 理论的工程计算库 |

---

# 附录 B：核心公式

**自身风险**：

$$R_{self}(v) = \frac{100 - S_{ssam}(v)}{100}$$

**风险溢出**：

$$\text{spillover}(u \to v) = R_{self}(u) \times \lambda_{trans}(e)$$

**传播风险聚合**：

$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} \text{spillover}(e)^2 }\right)$$

**安全债务**：

$$D(c, t) = |\Delta(c)| \times (t - t_{fail})^{\alpha}$$

**Prism 正交化动态评分**：

$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - \min(Cap_{prop}, R_{prop}(v))) \times \left(1 - \min\left(Cap_{debt}, \frac{\sum D(c,t)}{Norm_{debt}}\right)\right)\right)$$

**传播风险聚合**：

$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} (E(src_e) \times \lambda_e)^2 }\right)$$

**安全债务（天归一化）**：

$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**跳跃衰减路径风险**：

$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1},\quad \gamma = 0.8$$

## 状态反馈（调用方职责）

Prism 不自发调整传播率。但调用方可以实现状态反馈：**检查上游节点状态，若发现关键控制缺失（如 SIEM 离线），在传入 Prism 之前提高该上游出边的 `RiskTransmission` 值**。这样 Prism 保持纯函数性质，动态行为由调用方管理。
