# 联邦扩展参考（`extensions/federation`，v0.3.0）

> 状态：demo 级（0.x）。代码：`extensions/federation`；构建：`-tags federation`。
> 设计背景见 [FEDERATION_EXTENSION](../design/FEDERATION_EXTENSION_2026-10-28.md) 与
> [FEDERATION_DEMO_DESIGN](../design/FEDERATION_DEMO_DESIGN_2026-10-28.md)（v0.1/v0.2 历史设计）。

## 1. 配置（`[federation]`）

| 键 | 默认 | 说明 |
|:---|:---|:---|
| `role` | `off` | `master` 收集节点事实；`node` 周期上报；`off` 不启用 |
| `node_id` | 空 | node 身份；master 按此去重，后到覆盖 |
| `master_url` | 空 | node 上报地址（如 `http://192.168.30.50:5099`） |
| `listen_addr` | `:5099` | master 收集端点监听地址 |
| `report_interval_sec` | `30` | node 上报周期（秒） |
| `token` | 空 | 共享 token（`X-Federation-Token`）；空时只允许回环访问 |

配置经 `internal/config` 白名单 `adapterSections["federation"]` 进入 `AdapterConfig`；
扩展通过 `cfg.Get("federation.*")` 读取（`unwrapConfig` 兼容 adapter）。

## 2. HTTP 协议（master）

| 方法/路径 | 说明 |
|:---|:---|
| `POST /federation/report` | node 上报 `NodeReport`（JSON，≤1 MiB） |
| `GET /federation/nodes` | 节点表（`{"count":N,"nodes":[...],"updated_at":...}`） |
| `GET /federation/check?src=&dst=` | 合并图可达性（verdict/路径/阻断点/统计） |
| `GET /federation/export` | 合并拓扑导出（`policy_known/policies/hosts[]`，AUC/可视化用） |

所有端点要求 `X-Federation-Token`；`token` 为空时只接受回环地址（fail-closed）。

## 3. `NodeReport` 数据协议（v0.2+）

```json
{
  "node_id": "nk1",
  "config_hash": "79afc807735fe501...",
  "params": {"prism.debt_alpha": "1.2", "..." : "..."},
  "hosts": 10,
  "zones": {"internal": {"hosts": 10, "scored": 10, "avg_ssam": 58.3}},
  "avg_ssam": 58.3,
  "reported_at": "2026-10-28T11:31:03Z",
  "policy_known": true,
  "host_facts": [
    {"id": "asc-agt-nk1-01", "ips": ["172.22.10.101", "192.168.30.101"],
     "subnets": ["172.22.10.0/24"], "zone": "internal",
     "forwards": false, "stateful_input": false,
     "inbound": [{"from": "172.22.10.11", "allow": false}],
     "links": {"172.22.10.0/24": true}}
  ],
  "policy_facts": [{"from": "172.22.10.0/24", "to": "172.23.10.0/24", "allow": false}]
}
```

体积上限：`MaxHostFacts=2000`、`MaxPolicyFacts=5000`（超出截断）。

## 4. 合并语义（`BuildMergedGraph`）

- 同一 `host.id`：子网/IP 取并集；`zone/forwards/stateful_input` 后到优先；inbound/outbound 追加；
- 策略按 `(from,to,allow)` 去重；
- 主 kernel **本地拓扑**自动并入（旧实验域）；
- 子网与策略地址统一归一到网络地址（`172.23.10.101/24` → `172.23.10.0/24`）；
- 裸 IP 策略（`ip saddr 1.2.3.4/32` 被 nft 规范化为 `1.2.3.4`）按精确匹配。

## 5. CLI

| 命令 | 角色 | 输出 |
|:---|:---|:---|
| `federation status [--json]` | 两者 | master 节点表；node 配置/参数/最近上报 |
| `federation check <src> <dst> [--json]` | master | verdict/路径/阻断点/原因 |
| `federation export [--json]` | master | 合并拓扑 JSON |
| `federation report-now` | node | 立即上报一次 |

命令由扩展包 `init()` 通过 `cli.RegisterExtensionCommand` 自注册；
不带 `-tags federation` 构建时命令不存在。

## 6. 独立 CA 约束（"agent 不连主 kernel"）

节点 kernel 各自持有独立 CA；agent 证书由**所属节点**签发，主 kernel 不签发任何
agent 证书。因此即使把 agent 的 `--kernel` 改为主 kernel，mTLS 也会拒绝。

## 7. 已知限制

- 编译期扩展（非动态加载）；动态化需 kernel 先定义 facts RPC（v2.4）。
- 合并图每次查询全量重建；demo 规模（40 主机）毫秒级。
- 安全边界：共享 token + 明文 HTTP（管理网内）；生产需 mTLS + 独立凭证。
- `[federation]` 只在 Init 读取，改配置需重启 kernel。
