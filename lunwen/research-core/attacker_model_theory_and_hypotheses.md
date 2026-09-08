# Attacker Model：已确定理论与待验证推算

> 版本：2026-08-14  
> 目的：整理目前围绕 **ATT&CK + SRD + SSAM + IntentGuider/Engage** 所形成的攻击者行为模型。  
> 原则：严格区分 **已有证据支持的事实/理论** 与 **目前由观察推导出的假设**，不把推算写成结论。

---

## 1. 当前模型的核心问题

目标不是简单预测：

> “攻击者下一步使用哪个 ATT&CK Technique？”

而是建立：

```text
Observation
    ↓
Attacker State Estimation
    ↓
Intent / Capability / Experience / Belief
    ↓
Likely Action Distribution
    ↓
Engagement / Deception
    ↓
New Evidence
    ↓
State Update
    ↓
Repeat
```

最终形成：

```text
探测
→ 定位
→ 响应
→ 报告
→ 阻断
→ 修复
→ 验证
→ 重定位
→ 归档
→ 再循环
```

其中攻击者侧增加：

```text
情报收集
→ 行为推演
→ 预测
→ 引导
→ 获取新情报
→ 更新模型
→ 再预测
```

---

# 2. 已确定 / 有直接证据支撑的内容

## 2.1 ATT&CK 可以作为攻击行为的标准化语义层

ATT&CK 适合承担：

- Technique / Sub-technique 标识
- 攻击阶段语义
- TTP 序列表达
- 不同数据源之间的行为归一化

因此：

```text
原始情报
    ↓
行为抽取
    ↓
ATT&CK Mapping
    ↓
统一行为表示
```

**结论：**

ATT&CK 更适合作为“攻击行为语言”，而不是完整的攻击者预测模型。

---

## 2.2 攻击行为不能只看单个 Technique，需要看序列和上下文

2026 DBIR 对技术观察的处理本身就是跨 threat intelligence、red team activity 和 incident 数据进行 ATT&CK 映射，并强调不同来源观察到的技术分布存在差异。

例如 DBIR 指出，OS Credential Dumping（T1003）在其 threat intelligence 数据集中出现率为 34%，在 incidents 数据集中为 20%；不同数据源之间存在明显差异。

来源：2026 DBIR。  
文件证据：fileciteturn2file1L132-L192

**结论：**

单纯统计某个 TTP 的出现频率不足以描述攻击者状态。

应该保留：

```text
Technique
+ 前置行为
+ 后续行为
+ 目标环境
+ 数据来源
+ 时间
```

---

## 2.3 不同数据源存在明显偏差，不能把单一来源当作“真实攻击者总体”

2026 DBIR 明确指出：

- 很多 breach 不会被报告；
- 许多 breach 在受害者发现之前甚至未知；
- 公开披露事件更容易进入数据集；
- 某些事件类型因为样本丰富而可能被过度代表；
- DBIR 自身明确承认 sampling bias 和 confirmation bias。

来源：2026 DBIR。  
文件证据：fileciteturn2file0L11-L76

**结论：**

你的 Attacker Knowledge Base 必须保留：

```text
Source
SourceType
CollectionTime
Confidence
Provenance
```

不能简单：

```text
出现 100 次 = 真实概率 100 倍
```

---

## 2.4 社会工程是重要的攻击入口，但不能简单宣称“全局第一”

目前已有数据支持：

- Social Engineering 是重要攻击模式；
- Phishing 是其中的重要形式；
- 在不同产业/场景中，其排名不同；
- 初始访问并非所有场景都由社会工程占第一。

例如 2026 DBIR 的教育行业数据中，初始访问向量为：

- 漏洞利用：34%
- Phishing：22%
- Credential Abuse：8%

来源：2026 DBIR。  
文件证据：fileciteturn1file3L386-L395

因此：

> “社会工程是首要初始访问技术”

不能作为无条件的总体结论。

更准确的理论表达：

> **Social Engineering 是一种重要的 Initial Access / Identity Acquisition / Trust Exploitation 路径，其重要性具有明显的场景依赖性。**

---

## 2.5 人的因素在安全事件中仍然非常重要

2026 DBIR 给出的总体指标中，Human Element 在多个分析中占据重要位置；例如报告相关数据中显示 human element 达到较高比例。

教育行业的案例中，Social attacks 占 22% 的 breaches，其中 81% 属于经典 phishing，88% 的这些 social attacks 通过 email 投递。

来源：2026 DBIR。  
文件证据：fileciteturn1file3L428-L436

**结论：**

“人”可以作为攻击路径中的状态变量，而不是仅作为漏洞的一种。

---

## 2.6 攻击者可以通过身份/信任关系获得初始优势

2026 DBIR 的多个分析显示：

- 凭据滥用与身份问题仍然是重要攻击因素；
- 不安全认证、缺少 MFA、凭据轮换不足、权限过大等问题会把身份优势转换为后续攻击能力；
- 北韩 IT Worker 案例显示攻击者可以通过伪造身份和远程招聘流程获得组织内部位置。

例如 DBIR 对北韩 IT Worker 的分析估计其可能使用约 15,000 个被盗身份，典型 IT Worker 同时使用约 3–5 个身份。

来源：2026 DBIR。  
文件证据：fileciteturn2file8L793-L826  
文件证据：turn2file3L324-L362

**结论：**

“获得身份/信任/信息优势”可以作为攻击者状态变化，而不仅仅是一个 Technique。

---

# 3. 当前可以成立为“工程理论”的模型

以下内容不是说已经被外部研究完全证明，而是目前基于项目已有设计可以作为工程模型。

## 3.1 Attacker State Model

建议攻击者状态至少包含：

```text
AttackerState
├── Capability
├── Experience
├── Intent
├── TTP_Repertoire
├── SharedCapability
├── IndividualCapability
├── AI_Dependence
├── TargetKnowledge
├── BeliefState
└── Objective
```

其中：

### Capability
攻击者实际可执行的能力集合。

### Experience
过去成功/失败行为形成的经验。

### Intent
当前阶段的目的，例如：

- Reconnaissance
- Credential Access
- Lateral Movement
- Data Theft
- Web Attack

### TTP_Repertoire
攻击者实际熟悉/可调用的 TTP 子集。

### SharedCapability
来自公共工具、共享代码、公开知识、地下生态、AI 等的能力。

### IndividualCapability
攻击者自己的经验、目标知识、习惯、基础设施等。

### AI_Dependence
攻击者在决策/执行过程中对 AI 的依赖程度。

### TargetKnowledge
攻击者对当前目标的已知程度。

### BeliefState
攻击者对目标环境的主观认知。

---

# 4. 当前尚未证明、但值得验证的推算

以下全部属于 **Hypothesis / 推算**，暂时不能写成理论事实。

---

## H1：攻击者会倾向使用自己已经验证过的 TTP

目前观察：

- 新手学习路径通常强调选择较容易掌握的编程语言；
- 通过实战积累经验；
- 实战经验会影响后续攻击方式选择。

因此推测：

```text
Previous Success
       ↓
Experience
       ↓
TTP Preference
       ↓
Repeated TTP Selection
```

可以定义：

> **H1：攻击者过去成功的行为会提高其未来再次选择相关 TTP 的概率。**

需要数据验证：

```text
Experience ↑
    ↕
TTP reuse ↑
```

---

# H2：能力越高，经验依赖可能越强

当前推算：

低能力攻击者：

```text
知识不足
→ 尝试公开教程/常见方法
→ 行为较随机
```

高能力攻击者：

```text
经验丰富
→ 已知成功路径更多
→ 更容易快速判断可行方案
→ 可能减少无效探索
```

因此：

> **H2：Capability / Experience 增长可能提高对个人已验证 TTP repertoire 的依赖。**

但必须特别注意：

**“高手一定更保守/更依赖经验”尚未得到充分证明。**

高手也可能拥有更大的 TTP repertoire，因此必须区分：

```text
TTP repertoire size
```

和：

```text
TTP reuse rate
```

---

# H3：攻击者可能优先寻求 Initial Advantage，而不是直接技术突破

这是目前非常重要的推算。

所谓 Initial Advantage 不仅指已经取得权限，也包括：

```text
Identity
Trust
Target Knowledge
Relationship
Credential
Environmental Information
```

推测：

```text
Information / Identity Gain
        ↓
Uncertainty ↓
        ↓
Expected Success of later action ↑
```

因此：

> **H3：部分攻击者会优先选择能降低目标不确定性的行为，而不是直接选择技术攻击。**

这可以进一步定义：

```text
InformationGain(action)
```

作为 Attacker Model 的一个变量。

---

# H4：Social Engineering 的价值不能由事件占比直接决定

你观察到：

> 社会工程学相关泄露数量自 2021 年以来下降，2025 年约占 20%。

即使这一趋势成立，也不能直接推导：

```text
Prevalence ↓
→ Strategic Value ↓
```

因为社会工程可能只是攻击链的早期步骤，后续仍会转入：

```text
Credential Abuse
Privilege Escalation
Lateral Movement
Data Access
```

因此待验证假设应该是：

> **H4：Social Engineering 的价值更适合由其带来的 Information / Identity / Trust Gain 衡量，而不是单纯由出现频率衡量。**

---

# H5：攻击者之间存在 Shared Capability Layer

已有观察：

- APT/攻击组织存在代码复用；
- 工具、框架和 TTP 可以被多个攻击者/组织共享；
- 公共工具与知识使不同攻击者拥有部分相同能力。

因此可以建立：

```text
Capability_i
=
SharedCapability
+
IndividualCapability_i
```

这不是说两个攻击者能力相同，而是：

> **攻击者能力空间存在公共子集。**

这对归因非常重要：

```text
Observed Similarity
≠
Same Actor
```

必须先排除：

```text
Public Tool
Shared Code
Common TTP
Shared Infrastructure
AI-generated/common strategy
```

---

# H6：AI 可能扩大 Shared Capability Layer

这是目前最重要、同时也最不确定的推算之一。

已有 DBIR 相关材料支持：

> AI 正在被用于既有攻击技术的自动化和规模化，而不是仅仅产生大量全新的技术。

因此可以提出：

```text
AI
 ↓
Execution Cost ↓
TTP Accessibility ↑
Shared Capability ↑
```

但：

> **AI 是否真的造成跨攻击者行为“同化”，目前不能作为事实。**

---

# H7：AI 可能造成 Strategy Convergence

这是你目前最核心的新假设。

定义：

> **AI-assisted attackers 的 TTP 分布/行为序列可能向共同的高概率策略先验收敛。**

概念模型：

```text
                    Shared AI Prior
                          ↓
                 Common Strategy Set
                    ↙    ↓    ↘
                   A     B     C
                   ↓     ↓     ↓
              Individual Experience
                   ↓     ↓     ↓
              Individual Strategy
```

因此：

```text
AI dependence ↑
        ↓
Shared prior influence ↑
        ↓
Cross-attacker behavioral distance ?
```

真正需要验证的是最后一个 `?`。

---

# H8：AI 同化与攻击者能力不是同一个维度

可能出现：

```text
AI Assistance ↑
Capability ↑
Strategy Diversity ↓
```

三个变量同时成立。

即：

> AI 可以让更多人执行某个 TTP，但不意味着更多人能够独立创造新的策略。

因此：

```text
EffectiveCapability
=
HumanCapability
+
Experience
+
Tooling
+
AI_Assistance
```

而：

```text
StrategyDiversity
=
f(
    Experience,
    AI_Dependence,
    TargetKnowledge,
    SharedCapability
)
```

---

# H9：高经验攻击者可能更容易偏离 AI 的共同策略先验

这是 H7 的补充假设。

```text
Low Experience
    ↓
AI recommendation
    ↓
High adoption
    ↓
Strategy convergence

High Experience
    ↓
AI recommendation
    +
Personal experience
    +
Target knowledge
    ↓
Selective adoption
    ↓
Potential divergence
```

因此：

> **AI 可能对低经验攻击者产生更强的策略收敛效应，而高经验攻击者可以通过自身经验抵消部分收敛。**

目前仍未证明。

---

# H10：攻击者预测的目标应该从“下一 TTP”升级为“下一行动概率分布”

最终模型不应该：

```text
NextTechnique = X
```

而应该：

```text
P(Action | AttackerState, TargetState, Observation)
```

例如：

```text
P(Information Acquisition)
P(Credential Access)
P(Lateral Movement)
P(Exploitation)
P(Persistence)
P(Data Theft)
```

然后再在每个 Action 内部预测：

```text
P(TTP | Action, AttackerState)
```

这更符合你的闭环设计。

---

# 5. 当前最重要的理论结构

目前可以形成：

```text
                  ┌─────────────────────┐
                  │  Shared Capability  │
                  │ Tools / Code / AI   │
                  └──────────┬──────────┘
                             ↓
                       Common Prior
                             │
                             ↓
┌───────────┐         ┌───────────────┐
│ Experience│────────→│ AttackerState │
└───────────┘         └───────┬───────┘
                              │
┌───────────┐                 │
│ Capability│─────────────────┤
└───────────┘                 │
                              │
┌───────────┐                 │
│  Intent   │─────────────────┤
└───────────┘                 │
                              ↓
                       Action Selection
                              ↓
                 ┌────────────┴────────────┐
                 ↓                         ↓
          Technical Path            Human / Trust Path
                 │                         │
                 └────────────┬────────────┘
                              ↓
                      Initial Advantage
                              ↓
                         New Evidence
                              ↓
                        Belief Update
                              ↓
                         SRD Dynamics
                              ↓
                         Engage / Guide
                              ↓
                         New Observation
```

---

# 6. 目前最值得验证的五个核心假设

如果后续要做实证研究，优先级建议：

| 编号 | 假设 | 当前状态 | 优先级 |
|---|---|---|---|
| H1 | 成功经验提高 TTP 复用概率 | 有观察基础 | ★★★★★ |
| H2 | 能力/经验越高，对个人已验证 TTP 的依赖越强 | 推算 | ★★★★★ |
| H3 | 攻击者会主动寻求信息/身份/信任优势 | 有案例与理论基础 | ★★★★★ |
| H7 | AI 会导致跨攻击者策略收敛 | 核心推算 | ★★★★★ |
| H9 | 高经验攻击者能够抵消部分 AI 收敛 | 推算 | ★★★★☆ |

---

# 7. 当前不应该写进理论的内容

以下暂时不要当成结论：

1. “高手一定比新手更依赖经验。”
2. “高手一定更喜欢社会工程。”
3. “社会工程一定是第一初始访问技术。”
4. “AI 一定会降低攻击行为熵。”
5. “AI 一定会让不同攻击者使用相同路径。”
6. “APT 代码相似就代表同一个攻击组织。”
7. “Dread 上观察到的行为可以代表全部攻击者。”
8. “某个 TTP 出现次数 = 该 TTP 的真实成功概率。”

---

# 8. 下一阶段的数据需求

为了验证上述假设，数据至少需要保留：

```text
Evidence
├── Source
├── Timestamp
├── Actor / ActorCluster
├── Target
├── Intent
├── TTP
├── TTP Sequence
├── Tool
├── Shared/Public Tool?
├── AI Assistance?
├── Experience Proxy
├── Capability Proxy
├── Information Gain
├── Outcome
├── Confidence
└── Provenance
```

尤其不要只保存：

```text
Actor → TTP
```

而要保存：

```text
Actor
→ Context
→ Intent
→ Available Capability
→ Selected Action
→ Outcome
→ Next Action
```

否则无法验证“经验导致行为选择”或“AI 导致策略收敛”。

---

# 9. 关于当前上传的 ScienceDirect 论文包

目前这 10 篇论文中，并不是所有论文都直接支持攻击者行为模型。

目前能够明确认为**值得进一步深挖**的方向主要是：

- Psychological pathways to digital safety
- Cultural, organisational, and individual factors contributing to cyber incident reporting
- Employee knowledge and smart technology adoption

这些论文目前更适合作为：

```text
Human behavior
Knowledge
Experience
Technology adoption
Incident response behavior
```

的理论补充。

**不能因为论文讨论“knowledge / technology adoption / digital safety”，就直接把它们外推为“攻击者会如何选择 TTP”。**

因此在后续精读之前，它们暂时不能升级为 H1/H2/H7 的直接证据。

---

# 10. 当前阶段的总判断

目前最稳固的部分是：

```text
ATT&CK
    ↓
行为标准化

多源 CTI
    ↓
Evidence

Attacker State
    ↓
Intent / Capability / Experience / Belief

SRD
    ↓
动态状态与风险演化

Engage / IntentGuider
    ↓
改变攻击者感知环境并获取新证据
```

真正具有原创潜力、但必须验证的部分是：

```text
Shared Capability
        +
AI Assistance
        ↓
Strategy Convergence
        ↓
Attacker Predictability
```

以及：

```text
Experience
        ↓
TTP Preference / Reuse
        ↓
Predictability
```

最终要验证的不是：

> “AI 会不会让黑客更强？”

而是：

> **AI、共享工具和个人经验如何共同塑造攻击者的行动概率分布，以及这种分布是否可以被防御者观测、预测和主动改变。**

这才是目前这套系统最值得继续发展的理论核心。
