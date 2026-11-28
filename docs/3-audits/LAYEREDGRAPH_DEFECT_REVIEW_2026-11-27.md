# LayeredGraph 缺陷文档复核（2026-11-27）

> 对象：用户提供的《ASSCOR LayeredGraph 现存缺陷汇总》19 条陈述。
> 方法：逐条对照 `internal/topology` 与 `extensions/federation` 当前代码（ARC 分支）。
> 结论：**16 条成立，2 条需修正表述，1 条不成立**。本文只做复核与整改排序，不改代码。

## 1. 逐条核对

| # | 原陈述 | 结论 | 代码证据 / 修正 |
|---|---|---|---|
| 1.1 | 分层是静态标记，无自动推导 | ✅ 成立 | `BuildLayeredGraph` 只消费 `HostFacts` 的 `Subnets/VLANs/Zone`；无 ARP/路由推导 |
| 1.2 | 协议/端口仅作为策略字符串存储，不参与搜索 | ◐ **表述需修正** | `PolicyRule`/`PolicyFact` 实际只有 `From/To/Allow`，**连协议/端口字段都没有**；不是“存了但不用”，而是“模型层未建模” |
| 1.3 | Zone 仅元数据，不强制域间拒绝 | ✅ 成立 | `Zone` 只进入 `CriticalityForZone`；不生成默认 deny 策略 |
| 1.4 | `policyKnown` 是全局布尔 | ✅ 成立 | `LayeredGraph.policyKnown` 单字段；无按子网/来源粒度 |
| 2.1 | 最大深度硬编码，耗尽不区分“不可达” | ✅ 成立 | `HostReachable(...,maxHops)`，`maxHops<=0` 默认 5；无路径时统一返回 `blocked`/`"no shared subnet or denied"`，不标记 `max_hops_exhausted` |
| 2.2 | 仅返回最优路径，不枚举全部独立路径 | ❌ **不成立** | `HostReachable` 用 DFS 把所有简单路径 append 到 `out`；`CheckMerged` 还输出 `Paths` 计数。只有 `Best` 字段是为展示挑一条，不代表算法只算一条 |
| 2.3 | 有状态会话仅 `established` | ✅ 成立 | `StatefulInput bool` + `replyAllowed`；无 related/invalid/track 状态机、无超时 |
| 2.4 | 不处理 NAT | ✅ 成立 | `HostFact` 只有 IP/Subnet；无 NAT 映射与地址转换步骤 |
| 2.5 | 无最长前缀/路由聚合 | ✅ 成立 | 策略匹配为 `subnetMatch` 字符串/CIDR 对齐；`normalizeFactSubnet` 只取网络地址；无 LPM 路由表 |
| 3.1 | 合并只做集合并，无冲突消解 | ✅ 成立 | `mergedFactsFrom` 策略 key 含 `allow`，allow+deny 可同时保留；Host 的 Zone/Forwards/StatefulInput 后到覆盖；无冲突告警 |
| 3.2 | master 只合并、不校验上报事实 | ✅ 成立 | master 收取 `NodeReport` 后直接合并；未见 IP/子网/策略语义校验或来源置信度 |
| 3.3 | 上报上限 2000/5000，静默截断 | ✅ 成立 | `MaxHostFacts=2000`、`MaxPolicyFacts=5000`；`plugin.go` 直接切片截断，无告警 |
| 3.4 | 合并后无来源元数据 | ✅ 成立 | `HostFact`/`PolicyFact` 无 `SourceNode` 字段；合并只保留最终值 |
| 4.1 | 拓扑无原生时间轴 | ✅ 成立 | `HostFact` 无生效/过期时间；整体替换快照 |
| 4.2 | 无单条事实置信度 | ✅ 成立 | 只有全局 `policyKnown`；无 per-fact confidence |
| 4.3 | 拓扑→SRD 单向耦合 | ✅ 成立 | 拓扑供 SRD 传播；未发现 SRD 结果回写拓扑链路/策略 |
| 5.1 | 只有小场景测试，无大规模压测 | ✅ 成立（抽查） | `layers_*_test.go` 均为手工小图；未见万级随机拓扑套件 |
| 5.2 导出语义 | ✅ 已补齐 | `TopologyExport` 增加 `conflicts`、`policy_unknown_subnets`、`stats`、`generated_at`；策略保留 L4/元数据；内部调试字段仍是有损子集。测试：`TestMergedTopologyCarriesSemantics` |
| 5.1 缺少大图压测 | ✅ 基准已加 | `layers_bench_test.go`：1024 节点构建、1024 链查询、256 密集查询；dl360（Xeon E5-2695 v4）约 5.9ms / 68µs / 396µs |
| 5.2 | 导出 JSON 丢失内部语义 | ◐ **基本成立** | `exportFromFacts` 只导出 Host/Policy 子集，调试字段/来源/置信度不导出；需按“兼容 srd-roc 的刻意子集”表述 |
| 5.3 | 文档高估真实网络仿真能力 | ✅ 成立 | 缺陷文档本身已列出边界；现行白皮书应显式声明 L4/NAT/LPM/置信度缺失 |

**统计**：16 ✅、2 ◐、1 ❌。

## 2. 对缺陷清单的两处修正

### 2.1 第 2.2 条应删除或改写

代码已经枚举所有简单路径：

- `HostReachable` 的 `dfs` 在到达 `to` 时 `out = append(out, pv)`；
- `CheckMerged` 输出 `Paths = len(verdicts)`，并单独给出 `Best`；
- 因此“只能返回一条路径”是把**展示层 `Best`** 误当成**算法层输出**。

若仍要提多路径风险，应改为：“**未对路径做独立性/ disjointness 去重，也未按路径数量做风险度量**”，而不是“未枚举”。

### 2.2 第 1.2 条应加强，而不是弱化

`PolicyRule`/`PolicyFact` 没有协议/端口字段，说明问题比原文更严重：

- 不是“协议端口存了但不参与搜索”；
- 而是**数据模型层就没有 L4 五元组**，因此无法通过“补搜索”修复，必须先扩 schema。

## 3. 整改优先级

### P0：会直接导致错误判定

1. **2.1 深度耗尽与真实阻断混为一谈**：增加 `SearchStatus`（`found/blocked/exhausted/unknown`），耗尽时返回 `probable` 或显式 `max_hops_exhausted`，不能报 `blocked`。
2. **3.1 合并冲突**：策略 key 改为 `(from,to)`，保留 allow/deny 双方并挂 `Conflicts []Conflict`，禁止“先匹配到哪条算哪条”的不确定行为。
3. **1.4 全局 `policyKnown`**：改为按子网/来源的 `policyStatus`，至少支持 `known/partial/unknown` 三态。
4. **3.4 来源溯源**：为 `HostFact/PolicyFact` 增加 `SourceNode`（以及可选 `ObservedAt`），合并冲突与审计都依赖它。

### P1：能力边界，影响“真实网络”宣称

5. **1.2 L4 建模**：策略扩为 `(src,dst,proto,sport,dport,allow)`，路径搜索按端口/协议过滤；否则文档必须明确“仅主机级可达”。
6. **2.3 会话状态**：至少支持 `new/established/related/invalid` 与超时；否则只称“established 放行模型”。
7. **2.5 路由语义**：引入最长前缀匹配/路由表；否则不要声称复现真实路由。
8. **4.1/4.2 时间与置信度**：每条事实带 `valid_from/valid_to/confidence`；拓扑从“快照”升级为“时间切片”。
9. **3.3 截断告警**：超限必须返回 `truncated=true` 与丢弃计数，不能静默。

### P2：增强与文档

10. **1.1 自动推导**：ARP→广播域、路由表→网关链路；在采集侧做，拓扑层只消费。
11. **1.3 Zone 策略**：域间默认拒绝/显式策略生成。
12. **2.4 NAT**：SNAT/DNAT 映射与转换后的路径。
13. **4.3 反向耦合**：SRD 故障/风险结果回写链路状态（需定义反馈稳定性，避免循环放大）。
14. **5.1 压测**：万级节点随机图 + 路径爆炸基准。
15. **5.3 文档边界**：白皮书显式列出“不支持 L4/NAT/LPM/单条置信度”的边界。

## 4. 建议的验收用例

- **深度耗尽**：构造 `maxHops=2` 但存在 3 跳可达路径，断言结果为 `exhausted` 而非 `blocked`。
- **合并冲突**：两节点对同一 `(from,to)` 分别 allow/deny，断言输出 `Conflicts` 且不静默选边。
- **LPM**：`10.0.0.0/8` 与 `10.1.0.0/16` 同时存在时，按最长前缀命中。
- **部分策略未知**：子网 A 已知、子网 B 未知，断言 B 路径为 `probable`，A 不受污染。
- **来源溯源**：冲突结果能回溯到 `SourceNode`。
- **截断**：超过 2000 条事实时输出 `truncated=true` 与丢失计数。

## 5. 结论

- 这份缺陷文档可以作为整改输入，但**第 2.2 条应删除/改写**，否则会重复实现已有的多路径枚举。
- 真正的硬缺口是 **L4 五元组缺失、部分策略未知、合并冲突、来源/时间/置信度**，优先级高于“多路径”。
- 本文不改代码；若进入实现，建议按 P0→P1 顺序，每项先补失败用例再改行为。


## 6. 整改进度（2026-11-28）

| 项 | 状态 | 实现 / 说明 |
|---|---|---|
| 2.1 深度耗尽 | ✅ 已完成 | `HostReachable` 截断时返回 `probable` + `Unknowns=["max_hops_exhausted"]`；仅在前沿仍有未访问邻居时标记，真实无路径仍 `blocked`。测试：`layers_depth_test.go` |
| 2.5 最长前缀路由 | ◐ 查询辅助完成 | `HostFacts.Routes` + `LayeredGraph.LookupRoute`（最长前缀、同前缀按 metric）；尚未接入 `HostReachable`/ACL 首匹配。测试：`TestLookupRouteLongestPrefix` / `TestLookupRouteMetricTieBreak` |
| 3.1 合并冲突（全局策略） | ✅ 已完成 | `topology.PolicyConflict` + `LayeredGraph.SetPolicyConflicts`；merge 保留 allow/deny 双方并记录 `allow_sources/deny_sources`；冲突对路径返回 `probable`；`CheckMerged.Conflicts` 暴露。测试：`merge_conflict_test.go` |
| 4.1/4.2 时间轴/单条置信度 | ✅ 完成（模型+判定） | `HostFacts/PolicyRule/HostFact/PolicyFact` 增加 `ObservedAt/ValidUntil/Confidence`；过期事实过滤；merge 保留最新观测/最早过期/最小正置信度；`Confidence < threshold` 的主机/策略判 `probable`。测试：`TestExpiredHostAndPolicyAreFiltered`、`TestLowConfidenceHostDowngrades`、`TestLowConfidencePolicyDoesNotBlock`、`TestMergePreservesMetadata`；agent 策略规则与心跳 Host 事实均已填充 `ObservedAt/Confidence`，HostFact→TopoNode→HostFact 全链路保留 |
| 3.3 上报截断静默 | ✅ 已完成 | `NodeReport` 增加 `Truncated/DroppedHosts/DroppedPolicies`；`collectFacts` 返回丢弃计数；测试：`TestCollectFactsTruncationVisible` |
| 3.2 master 只合并不校验 | ✅ 已完成 | `ValidateNodeReport` 校验 node_id、主机 ID、IP/CIDR、端口、协议与上限；master POST 返回 400。测试：`TestValidateNodeReport*` |
| 3.4 来源溯源 | ✅ 已完成 | `HostFact/PolicyFact.SourceNodes`；合并与 `TopologyExport` 保留来源。测试：`TestMergeProvenanceIsPreserved` |
| 1.2 L4 协议/端口 | ✅ 完成（基础） | `PolicyRule/PolicyFact/TopoPolicyRule` 增加 L4 字段；`HostReachableFlow`；federation 合并/冲突按 L4 区分；agent nft/iptables 解析基础 tcp/udp 端口，复杂模块仍“不猜”。测试：`TestHostReachableFlowPorts`、`TestDifferentPortsDoNotConflict`、`TestParseNftL4Ports`、`TestParseIptablesL4Ports` |
| 1.4 全局 `policyKnown` | ✅ 已完成（按子网范围） | `BuildLayeredGraphWithPolicyScope` + `PolicyUnknownSubnets`；联邦按未知节点的主机子网标记 unknown，跨未知子网判 probable。测试：`TestPartialPolicyUnknownBySubnet` / `TestMergePartialPolicyUnknown` |
| 3.1 host 级 inbound/outbound 冲突 | ✅ 已完成 | merge 按 `(host,direction,from,to)` 收集 allow/deny；`PolicyConflict.Host/Direction` 暴露；路径经过冲突主机判 `probable`。测试：`TestHostLevelPolicyConflict` |

