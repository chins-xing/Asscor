# SRD 版本与变更记录

> 当前版本：**SRD 2.0**（`internal/version.SRDVersion`）。
> 版本号随内核/Agent 启动横幅与插件清单一起输出（`kernel` 启动横幅里的 `SRD:` 字段、
> 插件 `srd_adapters` 的 `version`）。

## v2.2.3（2026-10-27）—— 审计收口：A-7 / A-8 修复，A-4 / A-5 用例补齐

1. **A-7（zone 误判，已修）**：`inferZone` 旧实现用 `!ip.IsPrivate()` 判公网，
   把 **IPv6 链路本地（fe80::/10）/ ULA（fc00::/7）** 当成公网 ⇒ 纯私网主机被判
   `dmz`（实测 `domC-router` 显示 dmz，污染 L5 关键性）。新增 `isPublicAddress()`
   显式排除回环/私网/链路本地/未指定/ULA，只认全局单播。
   测试：`TestIsPublicAddress`、`TestInferZonePrivateWithLinkLocalIsInternal`。
2. **A-8（agent 退出卡死，已修）**：收到 SIGTERM 只 `cancel()`，但主循环只看
   `running` 且继续重连重试 ⇒ systemd 一直 deactivating，必须 `kill -9`。
   现在信号处理器同时置 `running=false`，循环每轮检查 `ctx.Err()` 立即返回。
3. **A-4（方向性，已用例化）**：新增 `TestInboundPolicyIsDirectional` 钉住
   "入向规则只作用于目标方向"（A→B 被 B 的 INPUT 拒 ⇒ blocked；B→A 不受影响）。
   有状态回程包语义仍不建模，已在审计报告写明。
4. **A-5（ct state 边界，已用例化）**：新增 `TestNftInputCtStateRuleIgnored`：
   `ct state established accept` 这类无 saddr 规则必须被忽略，只有带 saddr 的
   drop 才转成入向策略（"不猜"边界）。

5. **A-6（ROC 复验，已完成）**：用 v2.2.3 模型对同一批 10 轮实测真值重跑，
   AUC **0.888 ± 0.039（与 v2.0 一致）**。原因：该数据集只有转发策略事实，
   没有 L1/L2/入向事实，v2.2 新语义不改变判定 ⇒ **v2.2 增益未被这批数据测到**，
   需要含这些事实的新数据集（审计报告 §7 已记录该限制）。

## v2.2.2（2026-10-27）—— 修复 A-1：`[srd]` 参数在启动时真正生效

**根因（诊断日志实证）**：`srd.Manager.Init` 里 `kc.GetConfigObj()` 返回的是
**适配器**（`*srdwrapper.srdConfigAdapter`），不是 `*config.Config`；直接交给
`loadConfig` 后类型断言（`*config.Config` / `Get(string) string`）全部落空
⇒ `[srd]` 全部配置被静默忽略（v2.2.1 的"可调"因此在生产不成立）。

**修复**：新增 `unwrapConfig()`，沿 `GetConfigObj()` 适配器链解包（最多 4 层防环），
再交给 `loadConfig`。启动诊断日志现在会打印解包后的配置类型。

**现场验证（VM 910，kernel.ini 写入验证值）**：

```
SRD config source       cfg_type=*config.Config  get_supported=true  srd.layered_graph=false
SRD effective config    layered_graph=false transmission=0.42 max_path_depth=7
                        path_decay=0.65 prop_cap=0.25 aggregation=max horizon_days=7
```

与配置文件逐项一致 ⇒ **参数可调已在生产成立**（此前 A-1 的"不能声称"限制解除）。

**测试**：`TestUnwrapConfigReachesRealConfig`（嵌套适配器 → 解包 → loadConfig 生效）、
`TestUnwrapConfigPassthrough`。

## v2.2.1（2026-10-27）—— 参数接线修复（[srd] 配置此前被静默忽略）

**问题**：`srd.Manager.loadConfig` 通过 `interface{ Get(string) string }` 读配置，
但 `config.Config` **没有 `Get` 方法** ⇒ 类型断言失败，`[srd] layered_graph` /
`roles` / `sync_interval_sec` 全部被静默忽略（配置里写了也不生效）。

**修复与补齐**：

1. `config.Config.Get(key)`：暴露 adapter/section 配置（键形如 `srd.layered_graph`）。
2. 新增可调参数（全部从 `[srd]` 读取，非法值忽略、保持默认）：
   | 键 | 默认 | 作用 |
   |---|---|---|
   | `transmission` | 0.1（或 `[prism] default_transmission`） | 基础风险传输率 |
   | `max_path_depth` | 5 | 路径枚举深度（影响多跳召回） |
   | `path_decay` | 0.80 | 路径风险衰减 |
   | `prop_cap` | 0.25 | 传播惩罚上限 |
   | `aggregation` | rss | 传播聚合模式（rss/max/linear） |
   | `horizon_days` | 7 | 推理层预测窗口 |
   | `sync_interval_sec` | 3600 | 拓扑同步周期 |
   | `layered_graph` | true | 分层图开关 |
   | `roles` | 空 | L5 业务角色映射 |
3. 这些参数经 `PrismConfigFrom()` 注入 prism 引擎（此前 prism 永远用库默认值）。
4. 启动日志新增 **`SRD effective config`**，逐项打印生效值——配置是否被接受，
   不再靠猜。

> ✅ **A-1 已修复（v2.2.2）**：v2.2.1 时 `[srd]` 配置在启动时未生效（适配器未解包）；
> v2.2.2 修复并现场验证通过。详见 `docs/3-audits/SRD_V22_AUDIT_2026-10-27.md`。

**测试**：`TestGetExposesSectionKeys`（config）、`TestLoadConfigParsesAllAdjustableParams`、
`TestLoadConfigIgnoresInvalidValues`、`TestPrismConfigFromMapsParams`（srd）。

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
