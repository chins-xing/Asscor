# ARGUS APT 攻击分析与检测增强白皮书

> **版本：** v1.0 | **适用：** ARGUS v0.1.2-MVP / ATT&CK Module v2.0.0 | **日期：** 2026-05-25  
> **配套文档：** SSAM 1.3 白皮书、工程实现白皮书、SPC 安全态势计算模块技术白皮书

## 摘要

高级持续性威胁（Advanced Persistent Threat，APT）是当前网络安全领域最具破坏性的攻击形态。与传统攻击不同，APT 攻击者具备国家级或组织级资源，采用多阶段、多战术的攻击链，长期潜伏于目标网络中。传统的基于签名和阈值的检测方法难以应对 APT 的低慢小（Low-and-Slow）特征和高度定制化工具。

ARGUS v0.1.2-MVP 在 MITRE ATT&CK V19 框架基础上，构建了完整的 APT 攻击分析与检测增强模块。该模块通过四大核心能力——攻击链重构、行为检测、APT 归因和威胁狩猎——实现了从"单点告警"到"攻击链可视化"的范式跃迁。本白皮书系统阐述各核心能力的设计原理、算法实现、数据模型和工程实践，并说明其与 SSAM 评估体系的协同机制。

## 1. 设计哲学

### 1.1 从单点检测到链式分析

传统安全检测关注"某个事件是否异常"，而 APT 分析关注"一系列异常事件是否构成有意义的攻击链"。这一范式转变的核心洞察是：

> 单个告警可能是误报，但按 ATT&CK 战术顺序排列的多个告警，构成攻击链的概率随阶段数指数增长。

ARGUS APT 模块的设计遵循三个原则：

| 原则 | 含义 | 工程体现 |
|------|------|----------|
| **证据融合** | 不依赖单一数据源，综合告警、异常、IOC 等多源证据 | `ReconstructAttackChain` 聚合三类证据 |
| **可解释归因** | 每个归因结论都可追溯到具体的技术重叠和 IOC 匹配 | `AttributionResult.Evidence` 记录完整证据链 |
| **假设驱动** | 狩猎不是盲目搜索，而是基于攻击转移矩阵生成可验证假设 | `AutoGenerateHypotheses` 基于转移概率生成假设 |

### 1.2 与 SSAM 评估体系的关系

APT 模块不是 SSAM 的替代，而是增强。两者形成双向闭环：

```
SSAM 评估 → 检测低分域 → ATT&CK 差距分析 → 缓解建议 → 安全加固 → SSAM 评分提升
     ↑                                                              │
     └──── APT 攻击链检测 → 策略联动 → 自动响应 ←──────────────────┘
```

- **正向路径**：SSAM 评估发现某主机韧性域得分偏低，ATT&CK 评估子模块执行差距分析，识别防御缺口并生成缓解建议
- **反向路径**：APT 模块检测到攻击链，通过事件总线触发策略管理器自动响应（如隔离主机），同时影响该主机的 SSAM 评估结果

## 2. 攻击链重构引擎

### 2.1 问题定义

APT 攻击的典型特征是多阶段、跨战术的攻击链。例如一次典型的 APT28 攻击可能包含：

```
鱼叉钓鱼 (TA0001/T1566) → PowerShell 执行 (TA0002/T1059) → 凭证转储 (TA0006/T1003) → 横向移动 (TA0008/T1021) → C2 通信 (TA0011/T1071)
```

攻击链重构引擎的目标是：从散落的告警、异常和 IOC 证据中，自动识别并重构这样的多阶段攻击链。

### 2.2 数据模型

```go
type AttackChain struct {
    ID           string             // 攻击链唯一标识
    Name         string             // 自动生成的链名称
    HostIDs      []string           // 涉及的主机列表
    Stages       []AttackStage      // 按战术顺序排列的攻击阶段
    TotalScore   float64            // 链综合评分
    Severity     string             // 严重等级 (critical/high/medium/low)
    Attribution  *AttributionResult  // 归因结果（可选）
    Status       string             // 状态 (active/contained/resolved)
    FirstSeen    time.Time          // 最早证据时间
    LastSeen     time.Time          // 最新证据时间
    DetectedAt   time.Time          // 检测时间
}

type AttackStage struct {
    Order         int       // 阶段序号（按战术顺序）
    TacticID      string    // ATT&CK 战术 ID (如 TA0001)
    TacticName    string    // 战术名称
    TechniqueID   string    // ATT&CK 技术 ID (如 T1566)
    TechniqueName string    // 技术名称
    AlertIDs      []string  // 关联的告警 ID
    HostIDs       []string  // 涉及的主机
    IOCIDs        []string  // 关联的 IOC
    AnomalyIDs    []string  // 关联的异常事件
    Confidence    float64   // 阶段置信度 (0-1)
    Evidence      []string  // 证据描述
    Timestamp     time.Time // 证据时间戳
}
```

### 2.3 重构算法

攻击链重构采用三步流程：

**第一步：证据收集**

从三类数据源中筛选与目标主机相关的证据：

| 数据源 | 筛选条件 | 权重 |
|--------|----------|------|
| 告警 (DetectionAlert) | `HostID ∈ hostIDs && !Acknowledged` | 高 |
| 异常 (AnomalyEvent) | `HostID ∈ hostIDs && Score ≥ 0.5` | 中 |
| IOC (IOCEntry) | 全量（与主机关联通过告警间接建立） | 低 |

**第二步：阶段构建**

将证据按 ATT&CK 战术-技术映射构建攻击阶段：

1. 每条告警/异常携带 `TechniqueID` 和 `TacticIDs`
2. 按 ATT&CK 战术顺序（TA0001→TA0002→…→TA0011）排列
3. 同一战术下的多个技术合并为同一阶段的不同证据
4. 计算每个阶段的置信度：基于证据数量和来源多样性

**第三步：链评分与归因**

- **链综合评分**：综合各阶段置信度和严重等级
- **链严重等级**：取最高阶段严重等级，若跨≥3 个战术则升级一级
- **自动归因**：对重构的攻击链执行 APT 归因分析（详见第 4 章）

### 2.4 多主机关联

攻击链重构支持跨主机关联。当指定多个 `hostIDs` 时，引擎会：

1. 分别收集各主机的证据
2. 通过共享的 IOC（如同一 C2 地址、同一恶意文件哈希）建立主机间关联
3. 将关联主机的证据合并到同一攻击链中
4. 每个阶段记录涉及的 `HostIDs`，支持"主机 A 被钓鱼→主机 B 被横向移动"的跨主机链路

### 2.5 多指标关联

`CorrelateMultiIndicator` 方法提供跨指标类型的关联分析：

```go
type MultiIndicatorCorrelation struct {
    HostID         string    // 主机标识
    CorrelatedAt   time.Time // 关联时间
    AlertCount     int       // 关联告警数
    AnomalyCount   int       // 关联异常数
    IOCCount       int       // 关联 IOC 数
    BeaconCount    int       // 关联信标检测数
    Techniques     []string  // 涉及的 ATT&CK 技术
    Severity       string    // 综合严重等级
    Confidence     float64   // 关联置信度
}
```

关联置信度计算：

$$
Confidence = \min(1.0, \frac{AlertCount \times 0.3 + AnomalyCount \times 0.2 + IOCCount \times 0.3 + BeaconCount \times 0.2}{Threshold})
$$

## 3. 行为检测引擎

### 3.1 设计动机

传统基于签名的检测对已知攻击有效，但对 APT 的定制化工具和零日漏洞几乎无效。行为检测通过建立"正常行为基线"，检测偏离基线的异常行为，从而发现未知威胁。

### 3.2 行为指标体系

行为指标（BehavioralIndicator）定义了"什么样的行为是可疑的"：

```go
type BehavioralIndicator struct {
    ID          string         // 指标唯一标识
    Name        string         // 指标名称
    TechniqueID string         // 对应的 ATT&CK 技术 ID
    TacticIDs   []string       // 对应的 ATT&CK 战术 ID 列表
    Category    string         // 指标类别 (process/network/file/credential/privilege)
    Metric      string         // 监控指标名称
    Operator    string         // 比较运算符 (gt/lt/eq/gte/lte)
    Threshold   float64        // 阈值
    Window      time.Duration  // 检测窗口
    Severity    string         // 严重等级
    Description string         // 描述
    Enabled     bool           // 是否启用
}
```

**指标类别与典型示例：**

| 类别 | 监控指标 | ATT&CK 技术 | 示例阈值 |
|------|----------|-------------|----------|
| process | `process_create_rate` | T1059 命令脚本解释器 | > 50/min |
| network | `outbound_connection_rate` | T1071 应用层协议 | > 200/min |
| credential | `failed_login_rate` | T1110 暴力破解 | > 10/min |
| file | `sensitive_file_access_rate` | T1005 本地数据收集 | > 5/min |
| privilege | `privilege_escalation_attempts` | T1068 漏洞利用提权 | > 0 |

### 3.3 行为基线管理

每台主机维护独立的行为基线：

```go
type BehavioralBaseline struct {
    HostID      string             // 主机标识
    Metrics     map[string]float64 // 各指标的基线值
    SampleCount int                // 采样次数
    Period      time.Duration      // 基线计算周期
    ComputedAt  time.Time          // 基线计算时间
}
```

基线更新策略：

1. **冷启动**：首次采集的指标值直接作为初始基线
2. **渐进更新**：后续采样按指数移动平均（EMA）更新基线

$$
Baseline_{new} = \alpha \times Metric_{current} + (1 - \alpha) \times Baseline_{old}
$$

其中 $\alpha = 0.3$（可配置），平衡灵敏度和稳定性。

3. **偏差检测**：当当前指标值偏离基线超过阈值时触发行为告警

```go
type BehavioralAlert struct {
    ID           string    // 告警 ID
    HostID       string    // 主机标识
    IndicatorID  string    // 触发的行为指标 ID
    Metric       string    // 异常指标名
    BaselineValue float64  // 基线值
    ActualValue  float64   // 实际值
    Deviation    float64   // 偏差程度
    Severity     string    // 严重等级
    TechniqueID  string    // ATT&CK 技术 ID
    Timestamp    time.Time // 告警时间
}
```

### 3.4 C2 信标检测

命令与控制（C2）信标是 APT 攻击最典型的行为特征之一。被植入后门的主机会定期向 C2 服务器发送心跳包（信标），其连接间隔通常呈现低抖动（low jitter）特征。

**检测算法：**

1. **时间序列收集**：收集目标主机的出站网络连接时间序列

```go
type TimeSeriesPoint struct {
    Timestamp time.Time // 连接时间
    Value     float64   // 连接指标（如字节数）
}
```

2. **间隔计算**：计算相邻连接的时间间隔序列

3. **统计特征提取**：
   - 均值间隔 $\bar{I} = \frac{1}{n}\sum_{i=1}^{n} I_i$
   - 标准差 $\sigma_I = \sqrt{\frac{1}{n}\sum_{i=1}^{n}(I_i - \bar{I})^2}$
   - 抖动系数 $J = \frac{\sigma_I}{\bar{I}}$

4. **评分规则**：

| 抖动系数 J | 信标评分 | 判定 |
|------------|----------|------|
| J < 0.1 | 0.95 | 极强信标特征（机械定时） |
| 0.1 ≤ J < 0.2 | 0.85 | 强信标特征 |
| 0.2 ≤ J < 0.3 | 0.70 | 中等信标特征 |
| 0.3 ≤ J < 0.5 | 0.50 | 弱信标特征 |
| J ≥ 0.5 | — | 不判定为信标（正常流量） |

5. **最低数据量要求**：至少 10 个数据点，至少 5 个有效间隔

**检测输出：**

```go
type BeaconDetection struct {
    ID          string    // 检测 ID
    HostID      string    // 主机标识
    Destination string    // 目标地址
    Interval    float64   // 平均间隔（秒）
    Jitter      float64   // 抖动系数
    Score       float64   // 信标评分 (0-1)
    TechniqueID string    // ATT&CK 技术 ID (T1071.001)
    DataPoints  int       // 数据点数量
    FirstSeen   time.Time // 首次发现
    LastSeen    time.Time // 最近发现
}
```

## 4. APT 归因引擎

### 4.1 设计目标

APT 归因引擎回答一个关键问题：**观察到的攻击行为最可能来自哪个 APT 组织？**

归因不是精确科学，但通过系统化的证据融合方法，可以提供有价值的置信度评估，辅助安全团队优先调查最可能的威胁行为体。

### 4.2 多源证据融合算法

归因引擎采用加权多源融合策略，综合两类核心证据：

**证据源一：TTP 重叠（权重 60%）**

计算观察到的技术与已知 APT 组织技术画像的重叠度：

$$
S_{ttp}(g) = \frac{|T_{observed} \cap T_{group}(g)|}{|T_{observed}|} \times \frac{\sum_{t \in T_{observed} \cap T_{group}(g)} w(t)}{|T_{observed} \cap T_{group}(g)|}
$$

其中 $w(t)$ 为技术 $t$ 的置信度权重（来自告警/异常的置信度分数）。

**证据源二：IOC 匹配（权重 40%）**

计算 IOC 指标与已知 APT 组织的关联度：

$$
S_{ioc}(g) = \sum_{i \in IOC} c(i) \cdot \mathbb{1}[actor(i) = g]
$$

其中 $c(i)$ 为 IOC $i$ 的置信度，$\mathbb{1}$ 为指示函数。

**综合评分：**

$$
S_{combined}(g) = 0.6 \times S_{ttp}(g) + 0.4 \times S_{ioc}(g)
$$

当 TTP 和 IOC 证据同时指向同一组织时，额外加成 0.10：

$$
S_{combined}(g) = \min(1.0, S_{combined}(g) + 0.10) \quad \text{if } S_{ttp} > 0 \land S_{ioc} > 0
$$

**行业对齐加成：**

当攻击目标行业与 APT 组织的已知目标行业匹配时，额外加成：

$$
S_{combined}(g) = \min(1.0, S_{combined}(g) + S_{sector} \times 0.15)
$$

### 4.3 归因结果

```go
type AttributionResult struct {
    PrimaryActor      string               // 最可能的 APT 组织名称
    PrimaryGroupID    string               // 组织 ID (如 G0007)
    Confidence        float64              // 归因置信度 (0-1)
    Evidence          []AttributionEvidence // 证据列表
    AlternativeActors []AlternativeActor   // 替代行为体（最多 5 个）
    Methodology       string               // 归因方法 (multi_source_fusion)
    Country           string               // 归属国家（可选）
    Motivation        string               // 动机（可选）
}

type AttributionEvidence struct {
    Type        string  // 证据类型 (ttp_overlap/ioc_match/target_sector/no_match)
    Description string  // 证据描述
    Weight      float64 // 证据权重
    Source      string  // 证据来源
}

type AlternativeActor struct {
    GroupID    string  // 替代组织 ID
    Name       string  // 组织名称
    Confidence float64 // 置信度
    Reason     string  // 原因描述
}
```

### 4.4 置信度归一化

原始综合评分需要归一化为 0-1 范围的置信度：

$$
Confidence = \min(1.0, S_{combined} \times (1 + 0.05 \times \min(N_{overlap}, 10)) \times (1 + 0.02 \times \min(N_{evidence}, 10)))
$$

其中 $N_{overlap}$ 为技术重叠数量，$N_{evidence}$ 为证据总数。这确保了：
- 少量技术重叠（1-2 个）的归因置信度较低
- 大量技术重叠（5+ 个）且有多源证据的归因置信度较高
- 置信度上限为 1.0

### 4.5 过滤阈值

为避免低质量归因结果干扰分析，引擎设置最低置信度阈值：

- 综合评分 < 0.10 的候选项直接过滤
- 替代行为体仅保留置信度 ≥ 0.15 的前 5 个
- 无任何匹配时返回 `PrimaryActor: "Unknown"`，置信度为 0

## 5. 威胁狩猎框架

### 5.1 假设驱动狩猎

威胁狩猎遵循"假设→验证→结论"的科学方法论：

```
假设生成 → 假设管理 → 假设执行 → 结果确认 → 知识沉淀
```

与传统"钓鱼式"搜索不同，假设驱动狩猎从已知的攻击技术出发，预测攻击者可能使用的下一步技术，主动寻找证据验证或否定假设。

### 5.2 狩猎假设模型

```go
type HuntHypothesis struct {
    ID          string    // 假设 ID
    Name        string    // 假设名称
    Description string    // 假设描述
    TechniqueID string    // 目标 ATT&CK 技术 ID
    TacticIDs   []string  // 目标战术 ID 列表
    DataSource  string    // 数据来源类型
    Query       string    // 搜索查询表达式
    Priority    string    // 优先级 (critical/high/medium/low)
    Status      string    // 状态 (active/confirmed/dismissed/expired)
    CreatedAt   time.Time // 创建时间
}
```

### 5.3 自动假设生成

`AutoGenerateHypotheses` 方法基于三种驱动源自动生成狩猎假设：

**驱动源一：告警驱动（Alert-Driven）**

当主机产生未确认告警时，基于攻击技术转移矩阵预测攻击者可能使用的下一步技术：

$$
P(T_{next} | T_{current}) = \frac{TransCount(T_{current}, T_{next})}{\sum_{t} TransCount(T_{current}, t)}
$$

转移矩阵从历史攻击数据和 ATT&CK 框架的战术顺序关系构建。对于每个已观察技术，生成其 Top-K 后继技术的狩猎假设。

**驱动源二：异常驱动（Anomaly-Driven）**

当主机产生高分异常（Score ≥ 0.5）且异常关联了 ATT&CK 技术时，生成"深入调查"类假设：

```
假设：异常行为 {technique} 在主机 {host} 上被检测到，需要进一步调查
```

**驱动源三：信标驱动（Beacon-Driven）**

当信标检测发现 C2 通信特征时，生成与 C2 相关技术的狩猎假设：

- T1071.001（Web 协议信标）
- T1573.001（加密信道对称加密）
- T1105（入口工具传输）

### 5.4 假设执行与确认

```go
type HuntResult struct {
    ID            string    // 结果 ID
    HypothesisID  string    // 关联的假设 ID
    HostID        string    // 目标主机
    Confirmed     bool      // 是否确认
    Findings      []string  // 发现描述
    Confidence    float64   // 确认置信度
    ExecutedAt    time.Time // 执行时间
}
```

假设执行逻辑：

1. 根据假设的 `TechniqueID` 查找该主机是否存在相关的未确认告警
2. 查找是否存在相关的异常事件
3. 查找是否存在相关的信标检测
4. 综合以上证据计算确认置信度：

$$
Confidence = \min(1.0, N_{findings} \times 0.3)
$$

5. 确认的假设通过事件总线发布 `attck.apt.hunt_confirmed` 事件

### 5.5 去重机制

自动生成的假设通过 `{TechniqueID}|{DataSource}` 组合键去重，避免重复生成相同假设。已存在的假设不会被覆盖，仅新增不重复的假设。

## 6. 与 SSAM 评估体系的集成

### 6.1 事件总线集成

APT 模块通过 μKernel 事件总线与其他模块通信：

| 事件主题 | 发布者 | 订阅者 | 语义 |
|----------|--------|--------|------|
| `attck.apt.chain_detected` | APT 链重构 | 策略管理器 | 攻击链被检测到，可能触发自动响应 |
| `attck.apt.attribution` | APT 归因 | 日志收集器 | 归因结果需记录审计日志 |
| `attck.apt.hunt_confirmed` | 威胁狩猎 | 策略管理器 | 狩猎假设被确认，可能触发响应 |
| `attck.behavioral.alert` | 行为检测 | 策略管理器 | 行为告警触发响应 |
| `attck.behavioral.beacon` | 信标检测 | 策略管理器 | C2 信标检测触发响应 |
| `attck.detection.alert` | 检测引擎 | APT 链重构 | 新告警可能更新攻击链 |

### 6.2 DI 容器集成

ATT&CK 模块通过 `ATTACKInterface` 接口注册到 DI 容器，其他模块可通过依赖注入获取：

```go
type ATTACKInterface interface {
    // 检测与分析 (4 方法)
    RegisterDetectionRule(rule DetectionRule) error
    EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error)
    GetAlerts(hostID, severity string, limit int) []DetectionAlert
    CorrelateAlerts(hostID string) []CorrelationResult

    // 威胁情报 (5 方法)
    AddIOC(entry IOCEntry) error
    SearchIOC(value string) []IOCEntry
    UpsertThreatActor(profile ThreatActorProfile) error
    MatchThreatActor(detectedTechniques []string) []APTMatchResult
    EnrichAlertWithTI(alertID string) (*DetectionAlert, map[string]interface{})

    // 对手仿真 (4 方法)
    CreateScenario(scenario EmulationScenario) error
    GenerateScenarioFromActor(actorID string) (*EmulationScenario, error)
    RunEmulation(scenarioID, hostID string, safeMode bool) (*EmulationResult, error)
    GetEmulationResults(scenarioID string, limit int) []EmulationResult

    // 评估与工程 (4 方法)
    PerformGapAnalysis(hostID string) (*AssessmentReport, error)
    GetControlMapping(techniqueID string) *ControlMapping
    CreateImprovementTrack(track ImprovementTrack) error
    CalculateImprovementProgress(trackID string) (float64, error)

    // APT 增强 (11 方法)
    ReconstructAttackChain(hostIDs []string) (*AttackChain, error)
    RegisterBehavioralIndicator(indicator BehavioralIndicator) error
    EvaluateBehavioralIndicators(hostID string, metrics map[string]float64) []BehavioralAlert
    DetectBeaconing(hostID string, events []TimeSeriesPoint) []BeaconDetection
    PerformAttribution(chainID string) (*AttributionResult, error)
    GenerateAPTAnalysisReport(hostIDs []string) (*APTAnalysisReport, error)
    CreateHuntHypothesis(hypothesis HuntHypothesis) error
    ExecuteHunt(hypothesisID string, hostID string) (*HuntResult, error)
    AutoGenerateHypotheses(hostID string) ([]HuntHypothesis, error)
    UpdateBaseline(hostID string, metrics map[string]float64)
    GetBaseline(hostID string) *BehavioralBaseline
}
```

### 6.3 SPC 联动

APT 归因结果可与 SPC 态势计算交叉验证：

- APT 归因识别的威胁行为体已知的利用偏好，可用于验证 SPC 的 CVE 匹配结果
- 例如：APT29 偏好利用 CVE-202X-YYYY，若 SPC 在该主机上匹配到此 CVE，则 $P_{score}$ 的置信度提升
- 反之，若 SPC 匹配到的 CVE 与归因组织的已知偏好不符，可能提示归因结果需要重新评估

### 6.4 策略联动

APT 检测结果通过事件总线触发策略管理器的自动响应：

| APT 事件 | 策略响应 | 条件 |
|----------|----------|------|
| 攻击链检测（severity=critical） | `isolate_host` | 链跨≥3 个战术且包含凭证访问/横向移动 |
| 攻击链检测（severity=high） | `notify_admin` | 链跨≥2 个战术 |
| 信标检测（score≥0.85） | `block_ip` + `notify_admin` | 强信标特征 |
| 行为告警（severity=critical） | `increase_assessment` | 提高评估频率 |
| 狩猎确认 | `notify_admin` | 任何确认的狩猎假设 |

## 7. 并发安全设计

APT 模块的所有共享状态通过 `ATTACKModule.mu`（`sync.RWMutex`）保护：

| 数据字段 | 访问模式 | 保护方式 |
|----------|----------|----------|
| `alerts` | 写：规则评估；读：查询/关联 | `Lock`/`RLock` |
| `anomalies` | 写：记录异常；读：查询/攻击链 | `Lock`/`RLock` |
| `iocs` | 写：增删；读：搜索/归因 | `Lock`/`RLock` |
| `attackChains` | 写：链重构；读：查询 | `Lock`/`RLock` |
| `baselines` | 写：更新基线；读：评估 | `Lock`/`RLock` |
| `beaconDetections` | 写：信标检测；读：查询 | `Lock`/`RLock` |
| `huntHypotheses` | 写：创建/删除假设；读：列表 | `Lock`/`RLock` |

所有公开方法在入口处获取锁，在 `defer` 中释放。写操作使用 `Lock()`，读操作使用 `RLock()`，确保读多写少场景下的并发效率。

## 8. 扩展点体系

APT 模块注册了 12 个扩展点，支持第三方插件在关键事件发生时注入自定义逻辑：

| 扩展点 | 触发时机 | 典型用途 |
|--------|----------|----------|
| `attck.coverage.complete` | 覆盖率分析完成 | 生成合规报告 |
| `attck.apt.matched` | APT 组织匹配 | 通知安全运营团队 |
| `attck.risk.predicted` | 预测性风险评估 | 调整防御优先级 |
| `attck.detection.alert` | 检测告警触发 | 集成 SOAR 平台 |
| `attck.detection.anomaly` | 高分异常检测 | 触发深度调查 |
| `attck.emulation.complete` | 对手仿真完成 | 生成红队报告 |
| `attck.assessment.complete` | 差距分析完成 | 生成改进计划 |
| `attck.apt.chain_detected` | 攻击链重构 | 触发自动响应 |
| `attck.apt.attribution` | APT 归因执行 | 通知威胁情报团队 |
| `attck.apt.hunt_confirmed` | 狩猎假设确认 | 启动事件响应 |
| `attck.apt.report_generated` | APT 分析报告生成 | 归档与分享 |
| `attck.behavioral.alert` | 行为告警触发 | 集成 SIEM |
| `attck.behavioral.beacon` | C2 信标检测 | 自动阻断 C2 通道 |

## 9. 性能考量

### 9.1 攻击链重构性能

- 证据收集：O(A + N + I)，其中 A 为告警数、N 为异常数、I 为 IOC 数
- 阶段构建：O(S × T)，其中 S 为阶段数、T 为每阶段技术数
- 归因计算：O(G × T_obs)，其中 G 为 APT 组织数、T_obs 为观察技术数

典型规模（100 告警、50 异常、30 APT 组织）下，攻击链重构耗时 < 50ms。

### 9.2 信标检测性能

- 间隔计算：O(N)，N 为数据点数
- 统计计算：O(N)
- 最低数据量要求：10 个数据点

### 9.3 归因计算性能

- TTP 重叠计算：O(G × T_obs × T_group)
- IOC 匹配：O(I × G)
- 排序：O(G log G)

典型规模（30 APT 组织、20 观察技术、100 IOC）下，归因计算耗时 < 10ms。

## 10. 局限性与未来工作

| 局限 | 说明 | 计划 |
|------|------|------|
| 攻击链时序精度 | 当前按证据时间戳排序，未考虑证据间因果关系 | 引入因果推理模型 |
| 基线冷启动 | 首次部署时基线不准确，可能产生误报 | 引入群体基线（同类主机平均） |
| 归因确定性 | 归因本质是概率性的，无法 100% 确定 | 引入贝叶斯网络提升归因质量 |
| 信标检测误报 | 某些合法服务（如 NTP 同步）也呈现低抖动特征 | 引入目标地址信誉库过滤 |
| 狩猎自动化 | 当前假设执行逻辑较简单 | 集成 YARA/Sigma 规则引擎 |
| 跨主机攻击链 | 跨主机的攻击链关联依赖 IOC 重叠 | 引入网络流量分析建立横向移动证据 |

## 版本历史

- **v1.0** — 2026-05-25 初稿，与 ARGUS v0.1.2-MVP ATT&CK Module v2.0.0 同步发布
