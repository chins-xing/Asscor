# 自动化攻击者建模与主动防御链路改进方向

> 版本：2026-08-14

## 1. 总体方向

现有链路：

```text
探测 → 定位 → 响应 → 报告 → 阻断 → 修复 → 验证 → 重定位 → 归档 → 循环
```

不需要推翻。核心升级是把攻击者模型从流水线中的一个功能模块，升级为整个自动化链路的认知内核：

```text
Observation
    ↓
Evidence Fusion
    ↓
Attacker State Estimation
    ↓
Intent / Capability / Experience / Knowledge
    ↓
Next Action Distribution
    ↓
Engagement / Deception / Block
    ↓
New Evidence
    ↓
State Update
    ↓
Repeat
```

---

## 2. 双闭环

防御闭环：

```text
探测 → 定位 → 响应 → 报告 → 阻断 → 修复
 ↑                                  ↓
 └──── 验证 ← 重定位 ← 归档 ←──────┘
```

攻击者认知闭环：

```text
观测
 ↓
状态估计
 ↓
行为预测
 ↓
引导 / 欺骗
 ↓
攻击者响应
 ↓
新情报
 ↓
状态更新
 ↓
再次预测
```

---

## 3. Evidence Fusion

SSAM、ATT&CK、日志、网络行为、诱饵触发、威胁情报等数据不应直接进入预测器。

```text
SSAM
ATT&CK
Logs
Network
Decoy
Threat Intelligence
Incident History
        │
        ▼
Evidence Fusion
        │
        ▼
Attacker State
```

建议：

```text
Evidence {
    Source
    SourceType
    Timestamp
    Actor
    Intent
    Action
    TTP
    Target
    Confidence
    Provenance
}
```

不能简单把“出现次数”当作真实概率。

---

## 4. Multi-layer Temporal Graph

单纯的：

```text
Host ── connects ── Host
```

不足以描述攻击者、身份、工具、代码、TTP、证据和时间状态。

建议建立多层时序图。

### Network Layer

```text
Host
Service
Subnet
Gateway
Internet
```

### Dependency Layer

```text
Service
   ↓
Service
```

### Identity Layer

```text
User
Account
Credential
Role
Privilege
```

### Attacker Layer

```text
Actor
Actor Cluster
Campaign
Infrastructure
```

### Capability Layer

```text
Tool
Code
TTP
Exploit
AI Capability
```

### Evidence Layer

```text
Observation
Event
Alert
Decoy Trigger
Incident
```

关系可以形成：

```text
ATTACKER
   │
   ├── uses ── TOOL
   │             │
   │             └── implements ── TTP
   │
   └── targets ── ASSET
                       │
                       └── exposes ── SERVICE

TTP
 │
 └── produces ── ACTION
                    │
                    └── produces ── OBSERVATION
                                         │
                                         └── EVIDENCE
```

---

## 5. Attacker State Engine

建议新增：

```text
AttackerState {
    Intent
    Capability
    Experience
    TTPRepertoire
    SharedCapability
    IndividualCapability
    AIDependence
    TargetKnowledge
    BeliefState
    Objective
    Confidence
}
```

状态动态更新：

```text
OldState
    +
Evidence
    ↓
State Update
    ↓
NewState
```

SRD 可以作为动态状态演化层。

---

## 6. 从 Next TTP 改成 Next Action Distribution

不要：

```text
PredictNextTTP()
```

而是：

```text
PredictNextAction()
```

输出：

```text
ActionDistribution {
    Reconnaissance: 0.xx
    CredentialAccess: 0.xx
    Discovery: 0.xx
    LateralMovement: 0.xx
    Persistence: 0.xx
    Collection: 0.xx
    Exfiltration: 0.xx
}
```

再：

```text
Action
    ↓
Candidate TTP
    ↓
ATT&CK Mapping
```

因此 ATT&CK 是攻击行为语义层，而不是完整预测器。

---

## 7. Initial Advantage

攻击者状态应增加：

```text
Information Gain
Identity Gain
Trust Gain
Access Gain
```

可以抽象：

```text
InitialAdvantage =
f(
    InformationGain,
    IdentityGain,
    TrustGain,
    AccessGain
)
```

并建模：

```text
Initial Advantage ↑
        ↓
Target Uncertainty ↓
        ↓
Expected Success of Later Actions ↑
```

---

## 8. IntentGuider 升级

现有：

```text
Intent Recognition
        ↓
Deception Plan
        ↓
Decoy Deployment
```

保留已有诱饵映射：

```text
横向移动 → 假 SSH
凭据窃取 → 假凭据
数据窃取 → 假文档
Web 攻击 → 假 Web
扫描探测 → 扫描端口
```

升级为：

```text
Intent
+
Current Belief
+
Information Need
+
Expected Information Gain
        ↓
Engagement Plan
        ↓
IntentGuider
        ↓
Decoy Deployment
```

核心变化：

> 从“根据意图部署诱饵”升级为“选择能够最大化新情报获取量的干预”。

---

## 9. 让诱饵成为传感器

诱饵不应只记录：

```text
Triggered = true
```

而应记录：

```text
Timestamp
Source
Interaction Type
Credential Attempt
Command / Request
Sequence
Follow-up Action
TTP
Outcome
```

例如假 SSH：

```text
攻击者连接
 ↓
尝试账号
 ↓
尝试凭据
 ↓
执行命令
 ↓
系统发现
 ↓
连接其他服务
```

因此：

> Deception Object = Sensor + Control Point

---

## 10. Engagement Planner

从：

```text
发现 Intent
 ↓
Deploy Decoy
```

升级为：

```text
Candidate Engagements
        ↓
Evaluate
        ↓
Select
        ↓
Execute
```

候选动作可评价：

```text
Information Gain
Detection Probability
Attribution Value
State Separation
Risk
Exposure
```

可抽象：

\[
Utility(E)=
lpha IG(E)
+eta DP(E)
+\gamma AV(E)
-\delta Risk(E)
\]

目标：

> 选择最有价值的干预动作，使攻击者暴露更多对预测有用的信息。

---

## 11. 验证后的重定位

传统：

```text
修复 → 验证 → 完成
```

升级：

```text
Fix
 ↓
Validation
 ↓
Rebuild Target State
 ↓
Rebuild Attacker State
 ↓
Recalculate Attack Surface
 ↓
Recalculate Action Distribution
 ↓
Relocate
```

原因：

> 修复一个节点可能改变攻击者的最优路径，攻击者本身也可能在防御行动后改变策略。

验证不是终点，而是下一轮预测的输入。

---

## 12. Shared Capability 纳入拓扑

支持：

```text
Actor A ── uses ── Code X
Actor B ── uses ── Code X
Actor C ── uses ── Tool Y

Code X ── implements ── TTP Z
Tool Y ── implements ── TTP Z
AI ── assists ── TTP Z
```

形成：

```text
A
 \
  Code X ── TTP Z
 /             \
B               C
```

可计算：

```text
Capability Centrality
Capability Reuse
TTP Sharedness
Actor Similarity
```

注意：

```text
Similarity ≠ Same Actor
```

共享能力只能作为关联证据。

---

## 13. AI Dependence

建议记录：

```text
AIDependence ∈ [0, 1]
```

示意：

```text
0.00  无明显 AI 依赖
0.25  辅助查询
0.50  辅助分析 / 代码
0.75  大量依赖生成与决策
1.00  高度依赖 AI
```

研究关系：

```text
AI Dependence
      ↓
Shared Capability Influence
      ↓
Strategy Diversity
```

用于验证：

```text
AI Dependence ↑
        ↓
Strategy Convergence ?
```

---

## 14. 预测置信度

不要：

```text
下一步：横向移动
```

而是：

```text
Prediction

Lateral Movement      0.41
Credential Access     0.27
Discovery             0.18
Persistence           0.09
Collection             0.05

Confidence: 0.63
```

策略：

```text
Confidence Low
    ↓
优先收集情报

Confidence High
    ↓
允许更主动的 Engagement
```

---

## 15. 最终自动化链路

```text
                    ┌─────────────────────┐
                    │   Target Topology   │
                    │ Multi-layer Graph   │
                    └──────────┬──────────┘
                               │
                               ▼
┌──────────────┐       ┌──────────────────┐
│   Detection  │──────▶│ Evidence Fusion  │
└──────────────┘       └────────┬─────────┘
                                │
                                ▼
                      ┌──────────────────┐
                      │ Attacker State   │
                      │ SRD State Model  │
                      └────────┬─────────┘
                               │
                               ▼
                     ┌───────────────────┐
                     │ Action Prediction │
                     │ Probability Dist. │
                     └─────────┬─────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
                 Observe    Engage      Block
                              │
                              ▼
                       IntentGuider
                              │
                    ┌────────┼────────┐
                    ▼        ▼        ▼
                  SSH      Cred      Web
                 Decoy     Decoy     Decoy
                    │        │        │
                    └────────┼────────┘
                             ▼
                       New Evidence
                             │
                             ▼
                       State Update
                             │
                             ▼
                       Risk Recompute
                             │
                             ▼
                       Response / Fix
                             │
                             ▼
                          Validate
                             │
                             ▼
                          Relocate
                             │
                             ▼
                           Archive
                             │
                             └──────────────↺
```

---

## 16. 推荐模块

```text
/core
    /graph
        topology
        identity
        capability
        temporal
    /evidence
        fusion
        provenance
        confidence
    /attacker
        state
        intent
        capability
        experience
        belief
    /prediction
        action_distribution
        ttp_mapping
        confidence
    /engagement
        planner
        utility
        intent_guider
    /deception
        ssh
        credential
        document
        web
        port
    /response
        block
        remediation
        validation
        relocation
    /archive
```

四个最值得新增的核心组件：

```text
Graph Engine
State Engine
Prediction Engine
Engagement Planner
```

已有：

```text
SSAM
SRD
ATT&CK
IntentGuider
Deception Plans
```

作为已有能力接入。

---

## 17. 最小可行升级路线

### Phase 1：Graph

先完成：

```text
Multi-layer Temporal Graph
```

重点：

- Asset
- Service
- Identity
- Attacker
- Tool
- TTP
- Evidence

### Phase 2：State

建立：

```text
AttackerState
```

初期不需要复杂概率模型。

### Phase 3：Prediction

实现：

```text
ActionDistribution
```

初期可以使用规则 + 权重。

### Phase 4：Engagement

把已有：

```text
IntentGuider
```

接入：

```text
ActionDistribution
```

### Phase 5：Information Gain

最终实现：

```text
Predict
 ↓
Select Engagement
 ↓
Observe
 ↓
Update
 ↓
Predict
```

---

## 18. 最终核心

系统最终不应该只是：

> 自动化响应攻击。

也不应该只是：

> 预测攻击者下一步。

而应该是：

> **持续估计攻击者状态，并预测其下一行动概率分布，通过主动观察、欺骗和引导改变可观测性，再利用新情报更新攻击者模型，形成持续自适应的攻击者—防御者闭环。**

核心形式：

\[
State_t + Evidence_t
ightarrow
P(Action_{t+1})
\]

然后：

\[
P(Action_{t+1})
ightarrow
Engagement_t
\]

再：

\[
Engagement_t
ightarrow
Evidence_{t+1}
\]

最终：

\[
oxed{
State_t
ightarrow
Prediction
ightarrow
Engagement
ightarrow
Evidence
ightarrow
State_{t+1}
ightarrow \cdots
}
\]
