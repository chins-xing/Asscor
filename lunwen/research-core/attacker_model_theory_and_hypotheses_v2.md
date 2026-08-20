# Attacker Model：确定理论、证据支持与待验证推算

> 版本：2026-08-14  
> 目的：整理目前围绕 **ATT&CK + SRD + SSAM + IntentGuider / Engage** 所形成的攻击者行为模型。  
> 原则：严格区分 **已有证据支持的理论/现象**、**方法论支持** 与 **仍需直接验证的推算**。

---

## 1. 当前模型目标

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

整体防御闭环：

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

攻击者侧：

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

# 2. 已有较强证据支持的基础理论/现象

## 2.1 ATT&CK 是攻击行为的标准化语义层

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

## 2.2 单一 Technique 不足以描述攻击者状态

真实攻击行为需要结合：

```text
Technique
+ 前置行为
+ 后续行为
+ 目标环境
+ 时间
+ 数据来源
```

2026 DBIR 的不同数据集显示，同一 ATT&CK 技术在 threat intelligence、incidents 等来源中的分布存在明显差异。

例如 OS Credential Dumping 在不同数据集中具有不同观察比例。

**结论：**

不能简单使用：

```text
TTP 出现次数
```

作为攻击者下一步行为的确定性依据。

---

## 2.3 多源数据存在明显 sampling / reporting bias

2026 DBIR 明确讨论了：

- breach 未必被报告；
- 很多事件在发现前长期未知；
- 公开披露事件更容易进入数据集；
- 某些事件类型可能因样本丰富而被过度代表；
- 数据集存在 sampling bias / confirmation bias。

因此攻击者知识库必须保留：

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

# 3. H1–H6：能力、经验、初始优势与共享能力

## H1：过去成功经验会提高相关 TTP 的复用概率

**状态：🟡 有观察与理论基础，仍需专门数据验证。**

当前观察：

```text
Previous Success
       ↓
Experience
       ↓
TTP Preference
       ↓
Repeated TTP Selection
```

待验证形式：

\[
P(TTP_{t+1}=TTP_i \mid TTP_i\ 曾成功)
\]

是否随着经验提高而增加。

---

## H2：能力/经验与攻击效率及行为选择正相关

**状态：🟢 已获得学术研究直接支持；但“更依赖已验证 TTP”仍属于进一步推论。**

2024 年《Computers in Human Behavior》的实证研究以 69 名参与者研究黑客效率。研究基于“犯罪专业技能范式”，假设具有更多黑客经验和 IT 技能的参与者会进行更高效的黑客攻击；回归模型支持该假设。

研究同时强调犯罪专业技能在犯罪者做出选择时起重要作用，包括其 modus operandi。

因此应拆成：

### H2a：直接支持

```text
Objective IT Skill
        ↓
Hacking Efficiency ↑
```

以及：

```text
Criminal Expertise
        ↓
Offender Choice
        ↓
Modus Operandi
```

### H2b：项目进一步推论

```text
Capability / Experience ↑
        ↓
对自身已验证有效路径的调用倾向可能 ↑
        ↓
TTP Reuse / Behavioral Stability ↑
```

**注意：**

不能把 H2a 直接等同于 H2b。

“黑客效率更高”已经有直接实证支持；

“能力越高就越依赖自己验证过的 TTP”仍需要专门的数据验证。

---

## H3：攻击者可能优先寻求 Initial Advantage

**状态：🟢 获得多源有力支持。**

Initial Advantage 不仅意味着已经获得权限，也包括：

```text
Identity
Trust
Target Knowledge
Relationship
Credential
Environmental Information
```

现有证据包括：

1. 2026 DBIR：第三方相关 breaches 同比增加 60%，达到全部 breaches 的 48%，说明供应链/第三方关系已经成为重要攻击路径。
2. 帮助台身份差距、身份欺诈、凭据与信任关系可成为后续攻击的入口。
3. 侦察研究强调需要获得“正确、相关且及时的信息”，从而确定当前环境中哪些 TTP 可行，以及实现目标的有效方式。

因此可以提出：

\[
InitialAdvantage =
f(InformationGain,\ IdentityGain,\ TrustGain,\ AccessGain)
\]

以及：

```text
Information / Identity Gain
        ↓
Target Uncertainty ↓
        ↓
Expected Success of Later Actions ↑
```

**结论：**

H3 可以作为攻击者状态模型中的重要机制。

但“第三方入侵就是有意寻求 Initial Advantage”仍然是模型解释，而不是 DBIR 原文提出的概念。

---

## H4：Social Engineering 的战略价值不能由事件占比单独决定

**状态：🟢 方法论上成立，且获得现实事件支持。**

社会工程事件的总体占比不能直接代表其战略价值。

现实案例显示：

- 单次社会工程攻击可能造成极高经济损失；
- Scattered Spider 等攻击中，社会工程可以成为后续身份/权限攻击的早期步骤；
- 语音钓鱼等方式能够直接获得身份、权限或内部信息。

因此：

\[
StrategicValue \neq Frequency
\]

更合理的指标是：

```text
Strategic Value
=
Information Gain
+
Identity Gain
+
Trust Gain
+
Downstream Attack Gain
```

**结论：**

H4 的核心原则成立：

> 社会工程学的价值应同时考虑其带来的信息、身份、信任以及后续攻击链增益，而不能只看出现频率。

---

## H5：攻击者之间存在 Shared Capability Layer

**状态：🟢 获得直接证据支持。**

Cisco Talos 对 Transparent Tribe 等威胁行为者的研究发现，不同威胁行为者之间存在 VBA 代码共享。

更广泛的威胁研究也指出：

- 通用攻击链组件被多个威胁组织使用；
- 代码复用；
- 工具包共享；
- 恶意软件代码跨 campaign 复用；
- 公共工具和 TTP 可造成多个攻击者之间的行为相似。

因此：

\[
Capability_i =
SharedCapability +
IndividualCapability_i
\]

攻击者能力空间不是完全独立的，而存在公共子集。

特别重要的是：

```text
Observed Similarity
        ↓
Shared Capability ?
        ↓
Individual Fingerprint ?
```

不能直接：

```text
Similarity → Same Actor
```

**结论：**

H5 可以作为攻击者模型的基础事实/工程理论。

---

# 4. H6–H9：AI、共享能力与策略收敛

## H6：AI 正在扩大 Shared Capability Layer

**状态：🟢 获得强有力支持；“扩大共享能力层”是模型化表达。**

已有研究与威胁情报显示：

- LLM 可加速侦察；
- 可辅助钓鱼与社会工程；
- 可辅助脚本/恶意软件开发；
- 可降低部分既有 TTP 的执行门槛；
- 多个国家级威胁行为者集群和犯罪团伙已经出现 LLM 使用案例；
- AI 目前更主要表现为加速、自动化和规模化既有能力，而不是必然产生全新的攻击能力。

因此：

```text
AI
 ↓
Execution Cost ↓
TTP Accessibility ↑
Shared Capability ↑
```

可以定义：

\[
EffectiveCapability =
HumanCapability +
Experience +
Tooling +
AI\_Assistance
\]

**结论：**

AI 确实正在扩大攻击者可以低成本调用的能力集合。

但：

> “共享能力扩大”不等于“攻击者行为必然同化”。

后者属于 H7。

---

## H7：AI 可能造成 Strategy Convergence

**状态：🟠 核心推算，尚未直接证明。**

假设：

```text
AI Assistance
      ↓
Shared Strategy Prior
      ↓
Common Strategy Set
      ↓
Cross-attacker convergence ?
```

你的核心观点：

> AI 可以降低能力门槛，但由于模型倾向于提供高概率、常见、可行的方案，因此不同攻击者可能更多地从相同策略集合中选择。

形式化：

\[
AI\ Dependence \uparrow
\Rightarrow
CrossAttackerDistance \downarrow \; ?
\]

真正需要实验验证的是：

```text
AI-assisted attackers
vs
Human-only attackers
```

的：

- TTP entropy
- TTP sequence diversity
- 行为序列距离
- 策略簇分布
- 跨攻击者相似度

是否出现显著差异。

---

## H8：AI 同化与攻击者有效能力是两个独立维度

**状态：🟠 理论推算。**

可能同时发生：

```text
AI Assistance ↑
        ↓
Effective Capability ↑

AI Assistance ↑
        ↓
Strategy Diversity ↓
```

即：

> AI 可以让更多攻击者执行某个 TTP，但不意味着更多攻击者具备独立创造新策略的能力。

因此：

\[
EffectiveCapability
=
f(HumanSkill, Experience, Tools, AI)
\]

而：

\[
StrategyDiversity
=
f(Experience, AI\ Dependence, TargetKnowledge, SharedCapability)
\]

二者必须分开建模。

---

## H9：高经验攻击者可能抵消部分 AI 策略收敛

**状态：🟠 理论推算。**

可能存在：

```text
Low Experience
    ↓
AI Recommendation
    ↓
High Adoption
    ↓
Strategy Convergence

High Experience
    ↓
AI Recommendation
+
Personal Experience
+
Target Knowledge
    ↓
Selective Adoption
    ↓
Potential Divergence
```

即：

> AI 对低经验攻击者可能产生更强的策略收敛效应，而高经验攻击者可以通过个人经验和目标知识偏离共享策略先验。

**尚未证明。**

---

# 5. H10：预测目标从“下一 TTP”升级为“下一行动概率分布”

**状态：🟢 方法论获得支持；具体概率模型仍需实验验证。**

这是当前模型非常重要的结构升级。

## 5.1 为什么不应该使用确定性预测

部分实证研究将真实攻击行为描述为具有：

- 非线性
- 路径变化
- 行为混乱
- 不严格按照固定 Kill Chain 顺序执行

因此：

```text
TTP₁ → TTP₂ → TTP₃
```

这种单一路径确定性预测不足以覆盖真实攻击行为。

---

## 5.2 应预测 Action Distribution

更合理的形式：

\[
P(A_{t+1}\mid S_t,O_t)
\]

其中：

- \(A_{t+1}\)：下一行动
- \(S_t\)：当前攻击者状态
- \(O_t\)：当前观测

例如：

```text
Current State
      ↓
┌─────┼─────┬─────┐
↓     ↓     ↓     ↓
A₁    A₂    A₃    A₄
│     │     │     │
p₁    p₂    p₃    p₄
```

而不是：

```text
NextTTP = X
```

---

## 5.3 上下文必须进入预测

预测至少应该考虑：

```text
AttackerState
TargetState
Observation
Intent
Capability
Experience
TargetKnowledge
PreviousActions
PreviousOutcomes
```

因此：

\[
P(A_{t+1}\mid
AttackerState_t,
TargetState_t,
Observation_t)
\]

比：

\[
P(TTP_{t+1}\mid TTP_t)
\]

更符合你的模型目标。

---

## 5.4 “最可能 / 最有益 / 最坏情况”应该同时存在

攻击者下一步不应该只有一个答案。

模型可以同时输出：

```text
Most Likely
Most Beneficial
Worst Case
Most Dangerous
Most Observable
Most Deceptive
```

示例：

| Action | Probability | Potential Impact |
|---|---:|---:|
| Information Acquisition | p₁ | Medium |
| Credential Access | p₂ | High |
| Lateral Movement | p₃ | High |
| Persistence | p₄ | Critical |
| Data Theft | p₅ | Critical |

上表中的概率只是模型形式示例，不代表真实测量值。

---

## 5.5 从 Action 到 TTP 仍然保留 ATT&CK

可以使用两层模型：

\[
P(Action)
\]

以及：

\[
P(TTP\mid Action)
\]

最终：

\[
P(TTP_i)
=
\sum_j
P(TTP_i\mid Action_j)
P(Action_j)
\]

因此 ATT&CK 并没有被替代。

而是：

```text
Attacker State
      ↓
Action Distribution
      ↓
ATT&CK TTP Distribution
```

---

# 6. H10 与 Engage / IntentGuider 的直接关系

概率化预测会直接改变引导机制。

系统不再问：

> “攻击者下一步是什么？”

而是：

> “攻击者目前有哪些可能的下一行动？哪个最可能？哪个最危险？哪个最容易被引导？”

形成：

```text
Observation
     ↓
Attacker State
     ↓
Action Distribution
     ↓
Select Engagement
     ↓
Attacker Response
     ↓
New Observation
     ↓
State Update
     ↓
New Action Distribution
```

这与现有 IntentGuider：

```text
Intent Recognition
      ↓
Deception Plan
      ↓
Decoy Deployment
      ↓
Observation
```

可以形成闭环。

---

# 7. 当前理论树

```text
H1
经验 → TTP 复用
        │
        ↓
H2
能力/专业技能 → 攻击效率 / 行为选择
        │
        ↓
H3
信息/身份/信任 → Initial Advantage
        │
        ↓
H4
不能用频率衡量战略价值
        │
        ↓
H5
攻击者之间存在 Shared Capability
        │
        ↓
H6
AI 扩大 Shared Capability
        │
        ↓
H7
AI 是否导致 Strategy Convergence？
        │
        ↓
H8/H9
有效能力与策略多样性分离
        │
        ↓
H10
从确定性下一 TTP → 下一行动概率分布
        │
        ↓
Attacker Predictability
        │
        ↓
Engagement / Guidance
        │
        ↓
New Evidence
        │
        └────────→ State Update
```

---

# 8. 当前证据等级总表

| 编号 | 命题 | 当前状态 | 证据等级 |
|---|---|---|---|
| H1 | 成功经验提高相关 TTP 复用概率 | 待直接验证 | ★★★☆☆ |
| H2a | IT 技能与黑客效率正相关 | 学术实证支持 | ★★★★★ |
| H2b | 能力/经验提高已验证 TTP 依赖 | 进一步推论 | ★★★☆☆ |
| H3 | 攻击者会寻求 Initial Advantage | 多源支持 | ★★★★☆ |
| H4 | 社工战略价值不能由频率单独衡量 | 方法论/案例支持 | ★★★★☆ |
| H5 | 存在 Shared Capability Layer | 直接证据 | ★★★★★ |
| H6 | AI 扩大共享能力可获取性 | 强支持 | ★★★★★ |
| H7 | AI 导致 Strategy Convergence | 待验证核心假设 | ★★☆☆☆ |
| H8 | 有效能力与策略多样性独立 | 理论推算 | ★★★☆☆ |
| H9 | 高经验可抵消 AI 收敛 | 待验证 | ★★☆☆☆ |
| H10 | 应预测 Action Distribution | 方法论支持 | ★★★★☆ |

---

# 9. 明确不能提前写成结论

以下目前不要直接写成“已证明”：

1. 能力越高一定越依赖自己的 TTP。
2. 高能力攻击者一定更喜欢社会工程。
3. 社会工程一定是所有场景的第一初始访问技术。
4. AI 一定降低攻击行为熵。
5. AI 一定使不同攻击者执行相同路径。
6. APT 代码相似就意味着同一攻击组织。
7. 地下社区观察可以代表全部攻击者。
8. 某个 TTP 出现次数可以直接作为真实成功概率。
9. 概率模型一定比确定性模型预测准确。
10. 任意一种具体概率模型一定优于其他模型。

---

# 10. 下一阶段数据结构

为了验证上述模型，建议情报记录至少保存：

```text
Evidence
├── Source
├── SourceType
├── Timestamp
├── Actor / ActorCluster
├── Target
├── Intent
├── Action
├── TTP
├── TTP Sequence
├── Tool
├── Shared/Public Tool?
├── Shared Code?
├── AI Assistance?
├── Experience Proxy
├── Capability Proxy
├── Target Knowledge
├── Information Gain
├── Identity Gain
├── Trust Gain
├── Outcome
├── Confidence
└── Provenance
```

特别不能只保存：

```text
Actor → TTP
```

应该尽量保存：

```text
Actor
→ Context
→ Intent
→ Available Capability
→ Selected Action
→ TTP
→ Outcome
→ Next Action
```

这样才能真正验证：

```text
Experience → TTP Preference
Shared Capability → Behavioral Similarity
AI → Strategy Convergence
State → Action Distribution
Engagement → State Change
```

---

# 11. 当前理论核心

目前最稳固的部分：

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

最具有原创潜力、同时最需要实证验证的部分：

```text
Shared Capability
        +
AI Assistance
        ↓
Strategy Convergence ?
        ↓
Attacker Predictability
        ↓
Probability Distribution
        ↓
Active Engagement
        ↓
New Evidence
        ↓
State Update
```

最终研究问题可以凝练为：

> **AI、共享工具/代码和个人经验如何共同塑造攻击者的行动概率分布，以及防御者能否利用观测、欺骗和引导主动改变这一分布？**

这比单纯的“预测下一步 ATT&CK Technique”更接近当前系统真正的理论核心。
