# SRD 配置参考（v2.2.6）

> 本文是 `[srd]` 段的**唯一权威配置说明**。代码位置：
> `internal/config/config.go`（键解析）、`internal/engine/srd/manager.go`（消费）、
> `internal/engine/srd/types.go`（默认值）、`internal/topology/layers.go`（语义）。
> 变更记录见 [SRD_CHANGELOG.md](SRD_CHANGELOG.md)。

## 1. 键一览

| 键 | 默认 | 取值范围 | 作用 |
|---|---|---|---|
| `layered_graph` | `true` | true/false | 启用五层拓扑图（L1–L5）；false = 回退 v1.x 单层"同子网即邻接" |
| `transmission` | `0.1`（缺省时回落 `[prism] default_transmission`） | (0, 1] | 基础风险传输率，影响边权 |
| `max_path_depth` | `5` | ≥1 | 路径枚举最大深度，直接影响多跳召回 |
| `path_decay` | `0.80` | (0, 1] | 路径风险衰减（逐跳） |
| `prop_cap` | `0.25` | [0, 1] | 传播惩罚上限 |
| `aggregation` | `rss` | `rss`/`max`/`linear` | 多路径聚合模式 |
| `horizon_days` | `7` | ≥1 | 推理层预测窗口（天） |
| `sync_interval_sec` | `3600` | ≥1 | 拓扑同步周期（秒） |
| `roles` | 空 | `host=role,…` | L5 业务角色；优先级高于区域推断 |

非法值（负数、越界、未知枚举）会被**忽略并保留默认**，启动日志会显示实际生效值。

## 2. 示例

```ini
[srd]
layered_graph = true
transmission = 0.3
max_path_depth = 7
path_decay = 0.65
prop_cap = 0.2
aggregation = max
horizon_days = 14
sync_interval_sec = 600
roles = domA-db=db,domC-router=router,domA-web=web,shadow-1=shadow
```

## 3. 角色与关键性映射

| 角色 | 关键性 | 角色 | 关键性 |
|---|---|---|---|
| `db` / `database` / `core` | 0.95 | `monitor` / `mon` / `siem` | 0.60 |
| `router` / `gateway` / `fw` | 0.90 | `shadow` / `decoy` / `honeypot` | 0.30 |
| `web` / `app` | 0.70 | 未配置 | 按区域：internal 0.80 / dmz 0.60 / cloud 0.60 / public 0.40 / wan 0.30 / 未知 0.50 |

## 4. Agent 侧环境变量

| 变量 | 作用 |
|---|---|
| `ASSCOR_AGENT_VLANS` | 显式覆盖接口 VLAN，格式 `eth0=101,eth1=102`。PVE SDN 的 tag 配在宿主 OVS 端口上，容器内看不到，此时用它补齐 L2 事实；留空 = 未知（不阻断）。 |

## 5. 如何确认配置真的生效

1. **启动横幅**：`Framework: …  SSAM: …  SRD: 2.2.6`（版本必须匹配）。
2. **生效配置日志**（v2.2.1 起）：

```
msg="SRD effective config" component=srd layered_graph=true transmission=0.3
max_path_depth=7 path_decay=0.65 prop_cap=0.25 aggregation=rss horizon_days=14
roles=1 sync_interval_sec=600
```

3. **配置源诊断**（v2.2.2 起）：`msg="SRD config source" cfg_type=*config.Config get_supported=true`。
   若出现 `*srdwrapper.srdConfigAdapter` 或 `get_supported=false`，说明适配器未解包（A-1 回归）。
4. **拓扑事实**（v2.2.6 起）：`msg="topology facts recorded" host_id=… zone=… subnets=… policies=… links=… vlans=…`。
5. **拓扑视图**：`topology list`（CLI）应显示 `ZONE`、子网与状态。

## 6. 回退与排障

| 现象 | 处理 |
|---|---|
| 想让 SRD 回到单层行为 | `layered_graph = false`（重启 kernel 生效） |
| 配置改了但日志没变 | 确认改的是 kernel 实际加载的文件（`systemctl cat asscor-kernel` 里的 `--config`） |
| `SRD effective config` 缺失 | 内核版本 < v2.2.1，或 SRD 插件未加载（build tag `srdwrapper`） |
| 大量 `probable` | 缺少策略/链路事实：检查 agent 是否上报 `PolicyKnown` / `Links`；容器内 VLAN 需 `ASSCOR_AGENT_VLANS` |

## 7. 相关文档

- 语义与设计：[SRD 分层图设计](../design/SRD_LAYERED_GRAPH_DESIGN_2026-10-27.md)
- 发布说明：[SRD v2.2 发布说明](SRD_v2.2_RELEASE_NOTES.md)
- 变更与量化证据：[SRD_CHANGELOG.md](SRD_CHANGELOG.md)
- 数据集与 ROC：[v2.2 事实数据集](../../2-experiments/srd-bench/v22-facts-dataset-20261027.md)
