# SRD 版本与变更记录

> 当前版本：**SRD 2.0**（`internal/version.SRDVersion`）。
> 版本号随内核/Agent 启动横幅与插件清单一起输出（`kernel` 启动横幅里的 `SRD:` 字段、
> 插件 `srd_adapters` 的 `version`）。

## 附加模块：T4 联邦 demo（2026-10-28，插件 v0.1.0）

**目的**：在**同一网络**里跑**多套配置/多套模型参数**——主 kernel 聚合、节点 kernel 各自评估、
agent 只连接所属节点 kernel。

**形态**：
- `internal/federation`：`[federation] role=master|node|off`；node 周期（默认 30s）
  向 master 上报 `NodeReport`（node_id、config_hash、生效参数、hosts 数、zone 平均 SSAM）；
  master 提供 `POST /federation/report`、`GET /federation/nodes`（token 校验）；
- CLI：`federation status [--json]`；
- 节点隔离：每个节点 kernel 独立 CA，agent 证书只被所属节点接受（mTLS 强制）；
- 安全边界（demo 级）：共享 token + 明文 HTTP；生产需 mTLS + 独立凭证。

**v0.2（同日）**：节点上报图事实（host_facts/policy_facts），主端 `BuildMergedGraph`
合并成跨节点分层图；新增 `federation check <src> <dst>` 与
`GET /federation/check`；插件版本 0.2.0（demo 级）。
端到端验证：合并图 40 主机，节点入向 ACL 判 `blocked` 且与实测一致；
期间修复"裸 IP 策略匹配"与"回程出向检查"两个缺陷。

**实测**：主 kernel 收到 3 个节点，`config_hash` 互不相同（79afc807…/b46db6c8…/15270025…），
证明"单网络多套配置"；master 监听失败会降级（不拖垮 kernel）。

文档：`docs/2-experiments/T4_FEDERATION_DESIGN_2026-10-28.md`、
`docs/2-experiments/T4_FEDERATION_ENV_2026-10-28.md`、`docs/1-current/design/FEDERATION_DEMO_DESIGN_2026-10-28.md`。


## 附加实验：T4 联邦 AUC 对照（2026-10-28）

同一批实测真值（870 对：30 源 × 29 目标，941 INPUT 拒 940）：

| 模型 | AUC |
|---|---|
| **V2 主端合并图（40 主机）** | **0.992** |
| **V1 单节点视角（每节点 10 主机）** | **0.873** |
| 差值 | **+0.119** |

结论：联邦合并的增益来自**可见性**——单节点看不到跨节点目标、也不含共享路由器，
跨节点对被判 0 分；主端合并图把策略事实与全部主机合起来后接近满分。
报告：`docs/2-experiments/T4_FEDERATION_AUC_2026-10-28.md`；
工具：`cmd/fevauc`（ARC）；数据：`docs/2-experiments/srd-bench/t4-auc-*-20261028.csv`。


## 附加实验：T4 联邦 AUC 大规模对照（37 主机 × 3 轮，2026-10-28）

全部数据面 asc 主机（30 T4 agent + 6 旧域主机 + 路由器 = 37 端点，1332 对/轮），
三轮递增 ACL（A→B / +C→D / +B→C），负样本 100→164→244，合并 508：

| 轮 | V2 合并图 | V1 单节点 |
|---|---|---|
| R1 | 0.930 | 0.546 |
| R2 | 0.914 | 0.542 |
| R3 | 0.879 | 0.548 |
| **合并（3996 对）** | **0.912** | **0.545** |

**delta = +0.367**；三 profile AUC 一致（<0.001），证明 decay/depth 只影响风险排序。
期间修复"策略地址带主机位"（`172.22.10.1/24`）导致 deny 永不匹配的 bug（0.65→0.91）。
报告：`docs/2-experiments/T4_FEDERATION_AUC_LARGE_2026-10-28.md`。


## 附加模块：联邦解耦为扩展包（v0.3，2026-10-28）

- `internal/federation` → **`extensions/federation`**（实现 + CLI 命令自包含）；
- `internal/cli` 新增通用钩子 `RegisterExtensionCommand`，不再 import 联邦包；
- `cmd/kernel` 只剩 `newExtensionPlugins()`（tag 文件），main 无 federation 字样；
- 新命令：`federation export`（主端合并拓扑）、`federation report-now`（节点立即上报）；
- 插件版本 0.3.0（demo 级 0.x）；42 个扩展测试 + 内核带/不带 tag 构建均通过。
文档：`docs/1-current/design/FEDERATION_EXTENSION_2026-10-28.md`。


## 附加模块：联邦进程隔离（v0.4，2026-10-29）

- 新增 `federation-mod` 子进程与内核 `Proxy`（JSON-Lines RPC），
  用 `-tags "federation,federation_proc"` 启用；默认仍为进程内模式；
- 本地事实通过 RPC 推送，合并用 `BuildMergedGraphWithLocal`；
- 线上验证：杀子进程内核存活；分数与进程内一致（3 节点各 10 主机、avg SSAM 58.3，
  样例单机 55.93 NOT ACCEPTABLE）；性能：status/check ~15ms、export 16–25ms，
  子进程 RSS 5.7–11MB。报告 `docs/2-experiments/T4_FEDERATION_PROCESS_2026-10-29.md`。

## v2.3.6（2026-10-28）—— 可调参数补齐：主评分引擎接入 [prism]

**缺口**：`config.ini` 的 `[prism]` 段早已写全 13 个参数，但 kernel 主评分引擎固定
`prism.NewEngine()`（库默认值）⇒ 所有 `[prism]` 参数**从未生效**；SRD 侧也只暴露了 5 个。

**修复**：
- 新增 `internal/engine/prism.ConfigFromMap` / `NewEngineFromMap`：统一解析
  `prism.*`（兼容 `srd.*`）13 个参数，非法值忽略、保留默认；
- `cmd/kernel/engine_on.go`：`newPrismEngine(cfg)` 用配置构造引擎，并输出
  `prism effective config` 启动日志；
- `srd.Config` 增加 8 个 prism 参数（debt_alpha / debt_cap / debt_norm_days /
  score_floor / collapse_beta / stable/degraded/untrusted_threshold），
  `PrismConfigFrom` 全量映射，`SRD effective config` 同步输出；
- 新增参数总览文档 `docs/1-current/reference/CONFIG_PARAMETERS.md`。

**测试**：prism `ConfigFromMap` 全参数/非法值/前缀兼容三例；srd 配置解析与映射。

## v2.3.2 ~ v2.3.5（2026-10-28）—— T3 可观测：`srd check <src> <dst>`

**能力**：
- `srd check <src> <dst> [--json]`：输出 verdict（reachable/probable/blocked）、
  路径、逐跳步骤、阻断点、原因、未知项、分层统计；
- 实现：`srd.Manager.CheckReachability` + CLI 内置命令 `srd` + kernel Bootstrap 后注入；
- 图来源：优先 `BuildLayeredFromRegistry()` 现场重建（注入快照仅兜底）。

**过程中修掉的三个真实缺陷**：
1. v2.3.3：直连快捷路径的 blocked 只有泛化原因，补调 `Adjacent` 给出具体原因与阻断点；
2. v2.3.4：socket 会话不渲染 `Err` ⇒ 命令"静默无输出"；错误同时写 `Output`。
   同时兼容 `srd check A B` 位置参数（Params 未映射时回退 `ctx.Args`）；
3. v2.3.5：注入图滞后（启动早期只有 1 个 host ⇒ 误报 source/target unknown），
   改为现场重建。

**测试**：`TestCheckReachabilityBlocked` / `TestCheckReachabilityReachable` /
`TestCheckReachabilityWithoutGraph` / `TestCheckReachReturnsSame`。
报告：`docs/2-experiments/srd-bench/v23-t3-srd-check-20261028.md`。

## v2.3.1（2026-10-28）—— T2 状态化建模（ct established 放行回程）

**问题**：v2.2.5 的会话语义把 `ct state established,related accept` 的情况也判成
"双向全断"，而真实环境中"目标机自己发起"的反向会话是通的 ⇒ 单向可达被误判。

**实现**：
- `NetworkInfo/TopoNode/HostFacts` 增加 `StatefulInput`；agent 检测 nft/iptables 的
  `ct state established,related accept`；
- 邻接与端点改为**方向性会话三查**：源端 OUTPUT → 目标 INPUT（新连接）→
  回程（源端有状态则放行，否则静态 INPUT 判定）；
- srdroc 支持 `stateful_input` 输入。

**实测（domA-db 的 INPUT：ct accept 在前、`ip saddr 172.22.10.11/32 drop` 在后）**：

| 方向 | 实测 | 模型 |
|---|---|---|
| domA-web → domA-db | 不通 | blocked |
| domA-db → domA-web | **通** | reachable |

79 条实测真值下 **layered AUC = 1.000**（flat 0.427）。
报告：`docs/2-experiments/srd-bench/v23-t2-stateful-20261028.md`。
**测试**：`TestStatefulFirewallAsymmetricReachability`、`TestStatelessFirewallBlocksBothDirections`、
`TestStatefulDoesNotBypassOutbound`、`TestRegistryWiresStateful`、`TestParseNftStatefulDetectsCTAccept`。

## v2.3.0（2026-10-28）—— T1 域内 ACL：主机级 /32 规则 + OUTPUT 出向

**能力**：
1. **主机级匹配**：`HostFacts` 增加 `IPs`，入向规则支持 `/32`（`hostInCIDR`），
   不再只按子网串匹配——`nft input ip saddr 172.22.10.11/32 drop` 这类规则此前会被忽略；
2. **出向策略（OUTPUT）**：新增 `outboundAllowed`；agent 解析 `nft output` 与
   `iptables OUTPUT` → `Direction=outbound`；源主机出向被拒 ⇒ 会话失败（双向）；
3. **数据接线**：`RecordNetworkFacts` 增加 `ips`；comms 传 `LocalIPs`；srdroc 支持
   `inbound.to` / `outbound` / `ips` 输入。

**实测（域 A 同子网，3 轮）**：

| 轮 | 规则 | 负样本 | layered AUC |
|---|---|---|---|
| R0 | 无（控制） | 0 | — |
| R1 | `domA-db` INPUT `saddr 172.22.10.11/32 drop` | 2 | **1.000** |
| R2 | `domA-web` OUTPUT `daddr 172.22.10.12/32 drop` | 2 | **1.000** |

报告：`docs/2-experiments/srd-bench/v23-t1-intra-subnet-20261028.md`。
**测试**：`TestIntraSubnetHostInboundRule`、`TestIntraSubnetOutboundRule`、
`TestOutboundRuleScopedBySubnet`、`TestOutboundUnknownDoesNotBlock`、
`TestRegistryWiresOutboundAndIPs`、`TestNftOutputDaddrRuleParsed`、`TestIptablesOutputRuleParsed`。

## v2.2.6（2026-10-27）—— A-5 入向规则语义补齐；A-3 VLAN 数据链路验证

### A-5（已关闭）

- **daddr-only 入向规则**：`nft` 的 `ip daddr X drop` 与 `iptables -A INPUT -d X -j DROP`
  此前被丢弃（只认 saddr）；现在解析为 `Direction=inbound, To=X`。
- **目标子网维度**：`inboundAllowed(target, sourceSubnet, targetSubnet)` 同时匹配
  From（来源）与 To（目标），`To` 为空表示任意目标。
- **顺序语义**：首条匹配即生效（解析侧保持规则顺序）。
- 测试：`TestNftInputDaddrRuleParsed`、`TestIptablesInputDaddrRuleParsed`、
  `TestInboundRuleScopedByTargetSubnet`、`TestInboundRuleOrderFirstMatch`。
- 数据集复算（A-5 改动后）：8 轮均值仍 **0.959**，无回归。

### A-3（数据链路已验证；真实 L2 隔离场景受环境限制）

- 新增 `ASSCOR_AGENT_VLANS="eth0=101"` 的端到端验证：在 921/922 注入不同 VLAN 后，
  kernel 日志出现 `vlans=1`（`topology facts recorded`）⇒ **agent → comms → 拓扑注册表**
  的 L2 事实链路已打通，模型侧 L2 闸门由单测覆盖。
- 同时修掉一个真 bug：`collectVLANs` 在容器内 `/proc/net/vlan` 不存在时
  `return nil`，把 env 覆盖也丢了（vlans 恒为 0）。改为 `return vlans`。
- **限制**：本实验的容器共享同一 bridge，无法造出"同子网 + 不同 VLAN"的真实隔离，
  因此只验证数据链路与模型单测，不做"真值 vs 预测"的 L2 端到端评测。

## v2.2.5（2026-10-27）—— A-4 修复：入向 ACL 会话语义（双向）

**问题**：v2.2.x 的入向策略只在**同子网直连**时检查，跨子网目标的最后一跳完全不受影响；
且只校验目标侧 ⇒ "B 的 INPUT 拒绝 A" 时，B→A 会话（回程包被 B 的 INPUT 丢）被误判可达。
数据集入向轮 AUC 仅 **0.681–0.775**。

**修复**：
- `Adjacent`：同子网邻接要求**两个方向**的入向策略都放行；
- `finalizePath`：路径**端点**也按会话语义校验（目标拒绝来源 ⇒ blocked；
  源端拒绝目标网段 ⇒ 回程被丢，同样 blocked）。

**同一批真值复算（无需重测）**：

| 轮 | v2.2.4 | **v2.2.5** |
|---|---|---|
| R2（入向） | 0.775 | **0.977** |
| R3（入向） | 0.681 | **1.000** |
| 全体均值 | 0.884（±0.074） | **0.959（±0.034）** |

**测试**：`TestInboundPolicySessionSemantics`（A→B 与 B→A 均 blocked）；
`internal/topology` 全量通过。

## v2.2.4（2026-10-27）—— A-7c：CGNAT/保留网段不再算公网（zone 误判真正根因）

**A-7b 诊断实证**（新增 `topology facts recorded` 日志）：

```
host_id=domC-router zone=dmz    subnets=5 ...
host_id=domC-mon    zone=public subnets=1 ...
```

**根因**：实验网 domC 使用 `100.64.0.0/24`（CGNAT / RFC 6598 共享地址空间）。
Go 的 `net.IP.IsPrivate()` **不包含** 100.64/10，而 `IsGlobalUnicast()` 对其返回 true
⇒ 被判成公网地址 ⇒ 纯内网主机被推断为 `dmz`/`public`。

**修复**：`nonPublicV4` 显式排除
`100.64.0.0/10`、`198.18.0.0/15`、`192.0.0.0/24`、TEST-NET-1/2/3、`240.0.0.0/4`。

**现场验证**（v2.2.4 agent 分发 7 台后）：

```
topology list
  domC-router          internal   ... 172.22.10.1/24, 172.23.10.1/24, 100.64.0.1/24, ...
  domC-mon             internal   ... 100.64.0.11/24
```

**测试**：`isPublicAddress` 增加 CGNAT/保留网段用例；`inferZone` 增加
"私网 + CGNAT ⇒ internal" 断言；新增 **A-9 集成测试**
`TestManagerInitAppliesConfig` / `TestManagerInitWithoutConfig`（KernelContext → Init →
loadConfig → cfg + pipeline 全链路）。

**A-7b 状态**：关闭（A-7b 的诊断结论是"注册表更新侧无问题，是输入数据被判成公网"）。


### 含 L1/入向事实的数据集（同日晚）

为回答"v2.2 语义有没有增益"，构造了 8 轮混合数据集（转发 ACL / 主机入向 ACL / 链路 down），
每轮全量实测真值，并向模型提供 `policies` / `inbound` / `links` 三族事实：

| 指标 | flat | **layered（v2.2.4）** |
|---|---|---|
| AUC 均值 | 0.462 | **0.884** |
| 95% CI | ±0.033 | ±0.074 |
| 链路 down 轮 | ~0.45 | **0.955–0.979** |
| 入向 ACL 轮 | ~0.42 | **0.681–0.775** |

- **L1 链路语义有效**（0.96+）；
- **入向语义部分有效**，低分轮正是审计 A-4 的"有状态回程未建模"；
- 报告：`docs/2-experiments/srd-bench/v22-facts-dataset-20261027.md`。

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
