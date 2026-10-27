# SRD v2.3 计划（2026-10-27 起草）

> 前置：v2.2.6 已收口（五层图 + 会话策略 + L1/L2/L5 语义），审计 A-1…A-9 关闭。
> 本文定义 v2.3 的目标、范围、验收与风险；实现顺序按"先证据、后语义"排列。

## 1. 目标

1. **域内 ACL 细化**：同子网/同 VLAN 内主机对之间的策略（当前同域一律直通）。
2. **状态化建模**：把 `ct state` / 规则顺序纳入判定，减少"已建立会话"误判。
3. **跨环境证据**：在至少两个拓扑（不同网段/VLAN 布局）上重复 ROC，报告置信区间。
4. **可观测输出**：`srd paths` / `srd reach` CLI 查询，让运维能直接问"为什么判不通"。

## 2. 范围与非目标

| 属于 v2.3 | 不属于 v2.3 |
|---|---|
| 域内主机对策略、`ct state` 语义、CLI 查询、跨环境 ROC | 新的传播算法/评分公式（SSAM 侧不动） |
| agent 侧采集扩展（按需） | 图数据库/可视化前端 |
| 性能：大拓扑（>200 节点）路径枚举上限 | 多租户隔离 |

## 3. 任务与验收

### T1 域内 ACL（P0）

- 采集：agent 解析 `nft`/`iptables` 中**同子网**的 host-to-host 规则（saddr/daddr + /32 或子网）；
- 模型：`LayeredGraph` 增加 `IntraSubnet` 规则集；同子网邻接除 L2/入向外，再判域内策略；
- 验收：
  - 单测：同子网 allow/deny、规则顺序、未知数据不阻断；
  - 数据集：新增 4 轮"域内 deny"场景，layered AUC ≥ 0.95 且负样本覆盖；
- 风险：容器内 INPUT 规则只看本机，跨主机域内 ACL 可能采不到 ⇒ 允许"未知"降级。

### T2 状态化建模（P1）

- 表达：规则带 `Stateful bool`（`ct state established,related accept` 存在时为真）；
- 判定：显式 deny + 有状态 accept ⇒ 新连接 blocked、已建立会话 reachable（需要会话状态输入）；
- 验收：构造"drop 在 ct accept 之后"的场景，模型预测与实测一致；单测覆盖顺序敏感性。

### T3 CLI 可观测（P1）

- 新增 `srd check <src> <dst>`：输出 tier（reachable/probable/blocked）、路径、阻断点、未知项；
- 数据来源：kernel 内存中的 `LayeredGraph`（SRD 插件暴露查询接口）；
- 验收：CLI 输出与 `HostReachable` 单测一致；无图时明确报错。

### T4 跨环境 ROC（P1）

- 拓扑 B：另建 3–4 个网段 + 1 个 VLAN 隔离网段（需 VLAN-aware bridge 或 VM 网络）；
- 每环境 8 轮随机事实组合，报告均值 ± 95% CI；
- 验收：两环境 AUC 差异在 CI 内；报告写入 `2-experiments`。

## 4. 版本与发布

- v2.3.0：T1 + T2；v2.3.1：T3；v2.3.2：T4 数据；
- 每个版本必须：更新 `SRD_CHANGELOG`、`SRD_CONFIGURATION`（如有新键）、跑一次审计。

## 5. 风险

| 风险 | 缓解 |
|---|---|
| 域内 ACL 数据在容器不可得 | 允许未知降级；在 VM 环境补证 |
| 状态化建模引入会话状态依赖 | 先只做"新连接"判定，会话表作为可选输入 |
| 跨环境拓扑成本高 | 优先用 VM + VLAN-aware bridge，复用现有 PVE 资源 |

## 6. 相关文档

- 配置：[SRD 配置参考](../reference/SRD_CONFIGURATION.md)
- v2.2 发布：[SRD v2.2 发布说明](../reference/SRD_v2.2_RELEASE_NOTES.md)
- 当前设计：[SRD 分层图设计](SRD_LAYERED_GRAPH_DESIGN_2026-10-27.md)
- 审计：[SRD v2.2 审计报告](../../3-audits/SRD_V22_AUDIT_2026-10-27.md)
