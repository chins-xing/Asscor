# SRD 版本与变更记录

> 当前版本：**SRD 2.0**（`internal/version.SRDVersion`）。
> 版本号随内核/Agent 启动横幅与插件清单一起输出（`kernel` 启动横幅里的 `SRD:` 字段、
> 插件 `srd_adapters` 的 `version`）。

## v2.2（2026-10-27）—— 补齐四项：L1 链路 / 域内入向 ACL / VLAN 覆盖 / L5 角色

v2.1 遗留了四项"采集了但模型不用/用不了"的语义；v2.2 全部接上：

1. **L1 链路事实显式化**
   - agent 上报 `Links[]`（接口名、up/down、所属子网、VLAN）；
   - 分层图的邻接判定要求**双方在该子网的链路均 up**；链路 down 判 `blocked`，
     不再依赖"不上报该子网"的隐式表达。
2. **域内/主机级 ACL（入向策略）**
   - agent 解析 `nft` 的 `input` 链与 `iptables -A INPUT`，产出 `Direction="inbound"` 规则；
   - 模型对"同子网"也查目标主机的入向策略：来源子网被拒 ⇒ 不邻接（`blocked`）；
   - 无入向数据 ⇒ 不阻断（未知 ≠ 拒绝）。
3. **容器内 VLAN 采集的运维覆盖**
   - PVE SDN 的 tag 在宿主 OVS 端口上，容器内看不到；
   - 支持 `ASSCOR_AGENT_VLANS="eth0=101,eth1=102"` 显式覆盖，也识别 802.1Q 命名
     （`eth0.101`）与 `/proc/net/vlan/*`。
4. **L5 业务角色语义**
   - 新增 `[srd] roles = host=role,...`（如 `domA-db=db,domC-router=router`）；
   - `CriticalityForRole`：db/core 0.95、router/fw 0.90、web/app 0.70、
     monitor/siem 0.60、shadow/decoy 0.30、未知 0.50；
   - **角色优先于区域**（角色更贴近资产重要性）。

### 同时修复的接线缺陷

- `RecordNetworkFacts` 此前**从未被 comms 调用**（agent 上报的 VLAN/策略/转发
  实际没有进注册表）；v2.2 起心跳会把 `vlans/forwards/policies(direction)/policyKnown/links`
  全部落库，`BuildLayeredFromRegistry` 才能看到真实事实。

### 测试

新增 6 例：链路 down 阻断、入向策略拒绝同子网、入向规则按来源生效、入向未知不阻断、
角色映射、注册表 links+inbound 全链路接线。

### 仍受环境限制

- 容器内 `iptables`/`auditd` 等能力受非特权限制（不影响本版语义，只影响可加固项）；
- 宿主 OVS 端口的 VLAN tag 仍需运维用环境变量覆盖。

## v2.1（2026-10-27）—— 语义补完 + 数据接线

v2.0 定义了五层语义，但 **L2（广播域）与 L5（资产）只是采集、模型没用**；v2.1 把它接上：

1. **L2 广播域闸门**：同子网但 VLAN 不同 ⇒ 不邻接（重叠地址 + VLAN 隔离场景）。
   - 双方 VLAN 都已知且无交集 ⇒ 阻断；
   - 任一方未知 ⇒ 不阻断（未知 ≠ 拒绝），保持既有行为；
   - `SharedSubnets`/`Adjacent`/路径 DFS 起始跳全部经过该闸门。
2. **L5 区域语义接线**：agent 上报的 `NetworkZone` → `CriticalityForZone()`
   → 传入 `prism.NodeState.Criticality`，让"位置语义"真正参与风险传播计算。
3. **可观测性**：`LayeredGraph.Stats()` 输出主机/子网/VLAN/策略/转发者数量与
   策略已知标记，供调试与测试断言。
4. **测试**：新增 6 例（VLAN 阻断/同域可达/未知不阻断/区域映射/统计/注册表接线全链路）。

已知限制：容器内通常采不到 VLAN（`VLANs` 为空 = 未知，不阻断）；域内 ACL 仍未建模。

## v2.0（2026-10-27）—— 分层拓扑图 + 策略语义

**这是 SRD 的一次模型级升级，不是参数调整。** 核心变化：

1. **多层图取代单层图**（`internal/topology/layers.go`）
   - L1 链路 / L2 广播域 / L3 路由 / L4 策略 / L5 资产，五层语义互不重复；
   - 同一主机 ID 可在多层各有一个"位置节点"，构成"类三维"拓扑表达；
   - 可达性跨层合成：逐跳 L3 邻接 + 每次跨子网经 L4 判定。
2. **"未知 ≠ 放行"**：无策略数据 ⇒ `probable`；目标主机不可见但其子网已知 ⇒ `probable`。
   旧单层模型对这两类情况直接判"可达"（误报）或"不存在"（漏报）。
3. **会话语义**（`sessionVerdict`）：一次会话要求去程+回程同时放行。
   真实防火墙 `ct state established,related accept` 常排在 drop 之后 ⇒ 单向 deny
   会让回程包也被丢，双向不可达。修复了此前的"非对称误报"。
4. **接口级 ACL 解析**（`internal/agent/policy.go`）：`iifname/oifname`、
   `iptables -i/-o` 通过"接口→子网"映射还原成子网对策略；真实配置**无需改造**即可被理解。
5. **L4 事实采集**：agent 上报 `VLANs`/`Forwards`/`Policies`/`PolicyKnown`；
   只有**显式转发**（router/ip_forward）的主机才能作为中继（双网卡 ≠ 路由器）。
6. **默认开启**：`[srd] layered_graph` 默认 `true`；需要历史行为时设 `false` 回退。

### 量化依据（实测，非模拟）

10 轮随机接口级 ACL，每轮全量重测 84 条 ICMP 真值（折叠成 49 主机对）：

| 模型 | AUC 均值 | 95% CI | 范围 |
|---|---|---|---|
| 单层（v1.x 行为） | 0.474 | ±0.035 | 0.408–0.599 |
| **分层（v2.0）** | **0.888** | **±0.039** | 0.804–0.990 |

单轮极端配置下分层可达 0.990；多轮随机化后的 0.888 是可信估计。
数据与脚本见 `docs/2-experiments/SRD_PATH_EXPERIMENT_DESIGN_2026-10-27.md` §7–§11
与 `docs/2-experiments/srd-bench/`。

### 兼容性

- 配置向后兼容：`[srd] layered_graph = false` 回到 v1.x 构边行为；
- 输出兼容：`SRDResult` 结构未变；新增的语义（probable/blocked）通过既有字段表达；
- 含 `srd_adapters` 插件版本号从 `1.0.0` 升为 `2.0`（与 SRD 模型版本对齐）。

### 已知限制

- 会话模型假设面向连接协议；无状态单向场景会偏保守；
- 域内（同子网）ACL 尚未建模；
- 容器内 L2 VLAN 通常采集不到（`VLANs` 为空 = 未知）；
- L4 策略解析只处理"能看到 saddr+daddr+verdict"与"接口对+verdict"的规则，
  取反/扩展匹配/用户链**不猜**。

## v1.x（历史）

单层图：同子网即邻接，按源 SSAM 分数加权传播；无策略、无可见性语义。
