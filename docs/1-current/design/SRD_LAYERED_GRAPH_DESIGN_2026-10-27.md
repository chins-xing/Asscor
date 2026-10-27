# SRD 分层拓扑图模型（quasi-3D multi-layer graph）· SRD v2.0 · 2026-10-27

> 用户裁定（2026-10-27）：SRD 要"真正理解拓扑图"，而不是节点之间的路径；
> 不用单层图，用**多重互相重叠混合的图**构建"类三维"结构。
> **不同层在语义上必须不重复**；节点**可以重复**（甚至大范围重复）——
> 一个节点同时存在于多张不同层的图中，表达多种位置语义。

> 版本：本设计随 **SRD v2.0** 落地，变更记录见 `docs/1-current/reference/SRD_CHANGELOG.md`。

## 1. 为什么要分层（第一轮实验的直接教训）

第一轮实测（`docs/2-experiments/SRD_PATH_EXPERIMENT_DESIGN_2026-10-27.md` §6）暴露：

- c2：真实网络里 **nft 策略阻断** A→B，SRD 却报告路径 ⇒ 误报；
- c5：无 agent 的主机不可见 ⇒ 真实攻击链必然漏报；
- 调 `max_depth`/`path_decay` 无法修正任何一条 ⇒ **模型缺层，不是参数缺值**。

根因：单层图把"能不能到"压成一个"子网是否重叠"的布尔值，
把 VLAN 隔离、路由、策略、资产语义**全揉进一条边**。分层才能把这些语义分开表达。

## 2. 层的定义（语义互不重复）

| 层 | 语义（只表达这一件事） | 节点 | 边 | 数据来源 |
|---|---|---|---|---|
| **L1 `link`** | 链路/端口是否存在（物理或虚拟直连） | 接口 / 网桥端口 | `attached_to` | agent 接口列表、OVS/bridge 端口（当前缺失 ⇒ unknown） |
| **L2 `broadcast`** | 同一个二层广播域（VLAN）能否直接通信 | 广播域（VLAN/tag） | `member_of`（主机∈广播域） | agent 上报 `VLAN/tag`（新增采集） |
| **L3 `routed`** | 三层地址与路由：主机属于哪个子网、谁是网关 | 主机 / 子网 / 网关 | `addressed_in`、`routes_via` | agent 上报 `LocalIPs/Subnets`、网关 |
| **L4 `policy`** | 策略是否放行（ACL/NAT 边界） | 策略边界（源子网→目的子网） | `allow` / `deny` | agent 上报 nft/iptables 结论（新增采集） |
| **L5 `asset`** | 资产角色与关键性（web/db/mon/shadow） | 主机 | `has_role` | 配置 + 资产清单 |

**节点重复规则**：同一主机 ID 在 L2/L3/L5 各有一个"位置节点"（`layer:id`），
它们通过 **`same_identity`** 边互指 —— 这就是"一个节点存在多张图中表达多种位置语义"。
层内边**不得**跨语义复用：L2 的 `member_of` 不能当路由用，L3 的 `addressed_in`
不能当策略放行用。

## 3. 可达性的合成规则（跨层）

对主机 h1 → h2：

```
exists path ⟺ 在 L3 存在 h1 ⇒ subnet(s1) ⇒ [gateway g: g∈s1 ∧ g∈s2] ⇒ subnet(s2) ⇒ h2
              且 每一步跨子网跳都被 L4 判定为 allow
              且 L2/L1 若明确为 down/deny，则该跳不可用
```

- **同广播域直连**（L2 同域）时不需要 L4 跨域判定（域内放行，若有域内 ACL 则按 L4 细化）；
- **跨域**必须经 L3 网关，且 L4 必须 allow；
- **数据缺失**（无 L2/L4 数据）≠ allow：必须显式标 `unknown`，
  可达性输出 `probable`（可能）而不是 `yes` —— 这正是 c5/c2 类问题的正确表达。

## 4. 输出模型（把"误报/漏报"变成可解释的量）

对每条候选路径输出：

| 字段 | 含义 |
|---|---|
| `verdict` | `reachable` / `blocked` / `probable`（未知层导致不确定） |
| `crossings` | 每一跳经过的层与判定（L3 子网、L4 策略、L2 域） |
| `unknowns` | 缺数据的层（如"无策略采集"） |
| `confidence` | 由未知层数量与证据强度折算 |

这样 c2 不再是"误报"，而是 `blocked`（L4 deny）；
c5 不再是"漏报"，而是 `probable`（目标主机不在 L3 层，但其子网已知）。

## 5. 迁移路径（不破坏现有行为）

1. **新增** `internal/topology/layers.go`：分层图构建 + 合成可达性（纯函数、可测）。
2. **SRD 构边**改为可切换：默认仍用现有"同子网"规则（保证历史可比）；
   配置 `[srd] layered_graph = true` 时用分层合成（L3+L4）。
3. 采集侧补字段：agent 上报 `VLAN/tag`（L2）与 `nft/iptables` 结论（L4）；
   缺失时标 `unknown`，不默认 allow。
4. `srdbench` 增加 `-graph layered|flat`，对同一 ground truth 对比两种模型。

## 6. 验收

- c1（同域）两种模型都应 `reachable`；
- **c2（策略阻断）分层模型必须 `blocked`**（旧模型误报）；
- c3/c4（经路由器）分层模型 `reachable`；
- **c5（目标主机不可见但其子网已知）分层模型必须 `probable`**（旧模型漏报）；
- 参数扫描：`max_depth` 只影响路径枚举深度，`policy` 层的 deny 不受任何参数影响。

## 7. v2.2.6 实现对照（2026-10-27）

| 语义 | 代码位置 | 测试 |
|---|---|---|
| 五层图构建 / 邻接 | `internal/topology/layers.go`（`BuildLayeredGraph`、`Adjacent`） | `layers_test.go`、`layers_relay_test.go` |
| 会话语义（转发） | `layers.go`（`sessionVerdict`） | `layers_session_test.go` |
| 主机入向策略（含 daddr / 顺序） | `layers.go`（`inboundAllowed`）、`internal/agent/policy.go`（解析） | `layers_a4a5_test.go`、`layers_a5_test.go`、`policy_daddr_test.go` |
| L1 链路 | `layers.go`（`linkUp`）、`agent` 上报 `Links` | `layers_v22_test.go`（`TestLinkDownBlocksAdjacency`） |
| L2 广播域 | `layers.go`（`broadcastCompatible`） | `layers_semantics_test.go` |
| L5 区域/角色 | `layers.go`（`CriticalityForZone`/`CriticalityForRole`）、`srd/pipeline.go` | `layers_semantics_test.go` |
| 配置 | `srd/manager.go`（`unwrapConfig`+`loadConfig`）、`types.go` | `config_params_test.go`、`config_unwrap_test.go`、`config_init_test.go` |
| 数据落库 | `internal/comms/services.go`（`RecordNetworkFacts`） | 现场日志 `topology facts recorded` |

**可调参数**：见 [SRD 配置参考](../reference/SRD_CONFIGURATION.md)。
**量化证据**：8 轮混合数据集 layered **0.959 ± 0.034**（flat 0.462），
见 [v2.2 事实数据集](../../2-experiments/srd-bench/v22-facts-dataset-20261027.md)。

**当前限制**：`ct state` 类规则按"不猜"忽略；容器内 VLAN 需 env 覆盖；
域内主机对 ACL 未建模（v2.3 计划见 [SRD v2.3 计划](SRD_V2.3_PLAN_2026-10-27.md)）。
