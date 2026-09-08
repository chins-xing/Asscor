# ASSCOR v0.3.0 主动防御设计白皮书审计报告

**日期**: 2026-08-14 | **对象**: `docs/ASSCOR-Research-Core/主动防御设计白皮书.md` | **范围**: 理论合理性 + 落地可行性

---

## 一、执行摘要

白皮书在**理论基座与假设分级**上严谨（引用准确、H1–H10 证据等级划分正确、严格区分证据与推算），但在**落地可行性**上存在系统性高估：白皮书将多个"防御侧组件"描述为可复用的"攻击者侧组件"，且提出的 4 个新增核心引擎全部为零基础绿地，同时**整套体系缺少最关键的证据源**——没有任何现有组件能观测到 H1–H10 验证所需的"攻击者 TTP 序列 / AI 依赖 / 经验代理"数据。

| 维度 | 评分 | 结论 |
|------|:---:|------|
| 理论合理性 | A- | 引用准确、假设分级严谨，两处方法论瑕疵 |
| 落地可行性 | C+ | 证据源缺口是根本障碍，新增组件工程量远超路线图暗示 |

---

## 二、理论合理性审计

### 2.1 站得住的部分

- **理论基座引用准确**：I-POMDP²（Shinde & Doshi）、博弈论（Zhu / Anwar & Kamhoua）、欺骗三域（Zhang & Thing）、MTD 五原则（Lei et al.）、DBIR 数据均正确引用，无张冠李戴。
- **假设分级严谨**：H1–H10 的证据等级（H2a/H5/H6 ★★★★★，H7 ★★☆☆☆）与"明确不能写成结论"十条清单符合项目"严格区分证据与推算"原则。
- **战略定位自洽**：从阻断到引导的转向有决策论支撑（level-3 防御者"先伪装被动再欺骗"），且与项目既有决策 `guided_active_defense_strategy`、`intent_driven_lightweight_deception` 一致。

### 2.2 方法论瑕疵（2 处，P2）

| ID | 位置 | 问题 |
|:--:|------|------|
| R01 | §2.1 + §7 | **理论基座与落地求解之间存在鸿沟**：白皮书论证了 I-POMDP² 的价值（递归推理 + 认知建模），但 §7 又声明"不引入完整 I-POMDP² 求解器（代价高昂）"，改为"规则+权重近似"。论文自己承认 I-POMDP 受 curse of dimensionality 困扰，白皮书却未给出替代求解方法（攻击图博弈论文中的 HSVI / POMDP-embedded / OS-POSG 等近似方法均未采纳）。结果是引用了高阶理论、落地却退化为未具体化的规则表。 |
| R02 | §5.5 | **效用函数与决策论基座轻微不一致**：`Utility(E) = α·IG + β·DP + γ·AV − δ·Risk` 本质是博弈论/效用论的方法，而 §2.1 刚论证"决策论优于博弈论"。二者可调和（效用函数只是决策准则），但白皮书未点明这一关系，读者易混淆。 |

### 2.3 "决策论优于博弈论"论证略偏颇（P2）

| ID | 问题 |
|:--:|------|
| R03 | §2.1 论证博弈论"对称理性假设"不适合，但未充分承认博弈论也提供 hypergame、POSG、signaling game 等处理不完全信息/主观认知的机制（白皮书 §2.1 自己引用了这些）。"决策论唯一适合"的表述偏强，更准确应是"决策论更适合本项目对认知偏差建模的需求"。 |

---

## 三、落地可行性审计

### 3.1 现有组件复用映射核查（白皮书 §8）

对白皮书 §8 的"复用"声明逐项核实代码库：

| 白皮书声称 | 实际代码 | 结论 |
|---|---|---|
| ATT&CK 复用为"行为标准化" | `internal/attck` 是**防御侧覆盖率分析**（`ATTACKProvider` 计算 tactic 覆盖/杀伤链），不识别攻击者 TTP 序列 | ⚠️ 过乐观 |
| SRD 复用为"动态状态演化层" | `internal/engine/srd` 是**主机风险动力学**（Prism Core→Semantic→Inference，评分主机风险），不演化攻击者意图/能力/信念 | ⚠️ 概念挪用 |
| topology 升级为 Multi-layer Graph | `internal/topology` 仅主机/子网拓扑，无 identity/capability/evidence 层 | ❌ 纯绿地 |
| cti 提供 Evidence | `internal/cti` 是**威胁情报系数**（OTX/MISP 拉取调整评分），非证据融合 | ⚠️ 过乐观 |
| IntentGuider 升级为 Engagement Planner | `mitre-engage` 现有 IntentGuider 是**固定规则表**（`deceptionPlans` map：5 意图 → 假端口/假文件），无效用优化 | ⚠️ 从规则表到效用优化是大跃迁 |

### 3.2 新增 4 个核心引擎全部零基础

`GraphEngine / StateEngine / PredictionEngine / EngagementPlanner` 在代码库中 **grep 结果为 0**，无任何雏形。五阶段路线图（Phase 1–5）每条仅一行描述，**无工作量估计、依赖关系、验收标准**，其暗示的规模与实际工程量严重不符。

### 3.3 最根本缺口：证据源不存在（P0）

这是**决定性的落地障碍**。白皮书 §6 要求 Evidence 含 `Actor / TTP Sequence / AI Assistance / Experience Proxy / Capability Proxy / Shared Code` 等字段，但 ASSCOR 现有数据源全部是**防御侧数据**：

- 80 项检查：主机配置合规；
- 21 适配器：外部工具（Trivy/Nuclei 等）的漏洞扫描；
- CTI：威胁情报系数；
- 日志收集：agent 上报的日志条目。

**没有任何组件能观测到"攻击者的 TTP 序列""AI 依赖度""经验代理"**。H1–H10 的验证数据在当前架构下无法采集。白皮书 §6 提出数据需求却未回答"这些数据从哪来"。

### 3.4 预测输入不存在（P0）

\[
P(A_{t+1}\mid AttackerState_t, TargetState_t, Observation_t)
\]

需要 `AttackerState`（Intent/Capability/Experience/Belief），但现有 `AttackerLocation` 仅 7 个字段（FootholdHost/EntryHost/LateralPath/ActiveSubnets/C2Indicators/APTGroup/Confidence），**全是拓扑定位，不含意图/能力/经验/信念**。预测模型的输入在当前架构下不可得。

### 3.5 诱饵传感器化的观测环节空洞（P1）

白皮书 §5.6 设想"假 SSH 记录：连接→尝试账号→尝试凭据→执行命令→系统发现→连接其他服务"。实际 `mitre-engage` 的 `CaptureInfo` 仅有 SourceIP/Port/Credential/File/Technique/Quality——**凭据与文件级有捕获，但无命令级、无交互序列**（honeypot 是纯端口绑定，不执行交互）。"诱饵 = 传感器"的完整交互链需要从零实现。

### 3.6 与微内核零膨胀原则的张力（P1）

白皮书未说明 4 个新引擎是 build-tag 可选还是常编译。若常编译，违背刚完成的微内核剥离（`fcff4ef`）；若 build-tag，需按 `engine_types.go` 模式新增契约类型 + 接线桩。此项未规划。

---

## 四、问题分级汇总

| 等级 | 数量 | 清单 |
|:---:|:---:|------|
| P0 | 2 | 证据源不存在（F01）；预测输入 AttackerState 不存在（F02） |
| P1 | 2 | 诱饵传感器观测环节空洞（F03）；微内核零膨胀张力未规划（F04） |
| P2 | 3 | I-POMDP² 与规则近似之间缺求解方法（R01）；效用函数与决策论不一致（R02）；"决策论唯一适合"表述偏强（R03） |

---

## 五、结论与建议

**白皮书作为"方向宣言"合格，作为"设计文档"不合格。** 理论部分可直接保留；落地部分必须补足证据源这个前提，否则整个 H1–H10 体系是空中楼阁。

### 建议（按优先级，不立即修复，归档备查）

1. **P0 前置**：先明确"攻击者观测数据从哪来"。若 ASSCOR 定位是主机安全评估而非攻击者行为捕获，则 H1–H10 中依赖攻击者 TTP 序列的假设（H1/H2/H7/H9/H10）在当前产品形态下**不可验证**，白皮书应把"攻击者行为观测"标记为 v0.3.0 的**前置能力缺口**，而非默认已有。
2. **P0 前置**：AttackerState 的最小可行版本应基于**现有可观测字段**（AttackerLocation + CaptureInfo.Technique + CTI）构建，而非设想中的 Intent/Capability/Experience/Belief 全量。
3. **P1**：诱饵传感器化需明确命令级交互捕获是 honeypot 的重写（现有纯端口绑定），单独估量。
4. **P1**：4 引擎的 build-tag 门控策略（契约类型 + on/off 桩）需写入路线图。
5. **P2**：补一节"求解方法"，从 HSVI / POMDP-embedded / OS-POSG 中选型，替代空洞的"规则+权重近似"。

---

*审计完成于 2026-08-14。仅审计归档，不立即修复（v0.3.0 为可选方向，目录已 gitignore）。*
