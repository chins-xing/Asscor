# SRD v2.3 T1：域内（同子网）主机级 ACL 实测（2026-10-28）

> 目标：验证 v2.3 T1 的域内 ACL——同子网主机之间的 **INPUT（入向）/32** 与
> **OUTPUT（出向）/32** 规则能否被采集、建模，并与实测一致。

## 1. 场景（域 A：172.22.10.0/24，共 3 轮）

| 轮 | 主机规则 | 说明 |
|---|---|---|
| R0 | 无 | 控制组，验证基线全通 |
| R1 | `domA-db` INPUT：`ip saddr 172.22.10.11/32 drop` | 入向 /32 主机级 ACL |
| R2 | `domA-web` OUTPUT：`ip daddr 172.22.10.12/32 drop` | 出向 /32 主机级 ACL |

每轮全量实测 7 源 × 其余主机全部 IP（79 条），折叠成 49 个主机对后评估。

## 2. 结果

| 轮 | 负样本 | 正样本 | layered AUC | 模型判定（关键对） |
|---|---|---|---|---|
| R0 | 0 | 79 | —（无负样本） | `domA-web ⇄ domA-db` 均 reachable |
| R1 | **2** | 77 | **1.000** | 双向 `blocked`，原因 `inbound policy denies … → domA-db` |
| R2 | **2** | 77 | **1.000** | 双向 `blocked`，原因 `outbound policy denies domA-web → domA-db` |

- 真值与模型**完全一致**：入向/出向 /32 规则都只影响该主机对，其他对不受影响；
- 双向判定符合会话语义（回程包同样被丢）；
- 控制组无负样本，模型全判 reachable。

## 3. 实现要点（v2.3.0）

- `HostFacts` 增加 `IPs` 与 `Outbound`；`inboundAllowed` 支持 `/32` 规则
  （`hostInCIDR`），不再只按子网串匹配；
- 新增 `outboundAllowed`：OUTPUT 链策略按"目标子网或目标主机 IP"匹配；
- agent 解析 `nft output` 与 `iptables OUTPUT` → `Direction=outbound`；
- `RecordNetworkFacts` 增加 `ips` 参数，comms 传 `LocalIPs`。

## 4. 排障记录（重要）

- **第一版实验作废**：清理路由器时把 `ip filter forward` 刷成 policy drop 且没补
  `accept`，导致控制组 33 条不可达、负样本虚高。修复：`nft add rule ip filter forward
  ct state established,related accept` + `accept`。
- 容器内 `/tmp/measure.sh` 已不存在 ⇒ 改为**内联 ping** 测量，不依赖临时脚本。
- `ip link down` 会丢默认路由（v2.2 数据集时踩过）；本实验不涉及。

## 5. 结论

T1 的"域内主机级 ACL"三项（采集 / 入向 / 出向）在真实环境验证通过，
**v2.3.0 T1 完成**。剩余 T2（状态化建模）、T3（CLI 查询）、T4（跨环境 ROC）按计划推进。
