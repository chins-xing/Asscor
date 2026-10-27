# SRD v2.2 发布说明（v2.0 → v2.2.6，2026-10-27）

> 面向使用者与运维：**改了什么、怎么升级、怎么验证、有什么限制**。
> 详细变更见 [SRD_CHANGELOG.md](SRD_CHANGELOG.md)；设计见
> [SRD 分层图设计](../design/SRD_LAYERED_GRAPH_DESIGN_2026-10-27.md)；配置见
> [SRD 配置参考](SRD_CONFIGURATION.md)。

## 1. 一句话

SRD 从"同子网即邻接、只按 SSAM 分数加权传播"的单层图，升级为
**五层拓扑图（L1 链路 / L2 广播域 / L3 路由 / L4 策略 / L5 资产）+ 会话语义策略**，
并且**默认开启**。

## 2. 能力清单

| 层 | v2.2 能力 |
|---|---|
| L1 链路 | agent 上报接口 up/down 与所属子网；链路 down ⇒ 该子网不可用（判 `blocked`） |
| L2 广播域 | 同子网但 VLAN 不同 ⇒ 不邻接；未知 VLAN 不阻断；容器可用 `ASSCOR_AGENT_VLANS` 补齐 |
| L3 路由 | 只有当主机显式转发（`ip_forward=1`）时才可作中继；跨子网需网关 |
| L4 策略 | 转发策略（接口级 ACL 解析）+ 主机入向策略（`nft input` / `iptables INPUT`）；**会话语义双向**：去程或回程被拒都判 blocked；`ip daddr` 规则与首条匹配顺序 |
| L5 资产 | `NetworkZone` → 关键性；`[srd] roles` 业务角色优先于区域 |

补充原则：**未知 ≠ 放行**。缺策略数据判 `probable`，只有显式 allow 才判 `reachable`；
数字输出用连续分数 `1 - exp(-Σ 0.9^(hops-1) × 权重)`，`blocked` 恒 0。

## 3. 量化证据（实测真值，非模拟）

| 数据集 | 规模 | 单层 flat | **分层 layered** |
|---|---|---|---|
| 10 轮随机转发 ACL（v2.0 起） | 49 主机对/轮，负样本 9–16 | 0.474 ± 0.035 | **0.888 ± 0.039** |
| 8 轮混合（转发 / 入向 ACL / 链路 down） | 每轮 84 条实测 ICMP | 0.462 ± 0.033 | **0.959 ± 0.034** |
| └ 其中 L1 链路 down 轮 | — | ~0.45 | **0.955–0.979** |
| └ 其中入向 ACL 轮（v2.2.5 后） | — | ~0.42 | **0.977–1.000** |

数据集报告：[v2.2 事实数据集](../../2-experiments/srd-bench/v22-facts-dataset-20261027.md)。

## 4. 升级步骤

1. **换 kernel 与 agent 二进制**（两者必须同时升到 2.2.6；agent 侧新增了 Links/入向策略/VLAN 采集）。
2. 确认 `[srd] layered_graph` 为 `true`（v2.2 起为默认值；显式 `false` 可回退单层）。
3. 重启 kernel，检查启动横幅含 `SRD: 2.2.6`、插件 `srd_adapters 2.2.6`。
4. 检查 `SRD effective config` 日志与 ini 一致。
5. 重启 agent，确认 `topology facts recorded` 中出现 `links=` / `vlans=` 等字段、`topology list` 的 zone 正确。

**兼容性**：`[srd]` 全部为可选键；`SRDResult` 结构未变；老 agent（不报 Links/入向）仍可工作，
相应能力退化为 `probable`，不会误判为放行。

## 5. 已知限制

- **有状态协议假设**：会话双向判定适用于 TCP/ICMP 类；无状态单向场景偏保守。
- **容器内 VLAN**：PVE SDN tag 在宿主 OVS 端口，容器内取证不到，需 `ASSCOR_AGENT_VLANS`。
- **`ct state` 不建模**：入向链里 `ct state established accept` 之类的规则被显式忽略（"不猜"）。
- **域内（同 VLAN 内主机对）细化 ACL** 尚未建模——留给 v2.3。
- **证据口径**：上述 AUC 来自单一实验环境（7 台主机、PVE 容器），跨环境复验尚未做。

## 6. 升级后自检清单

```bash
# 1) 版本
journalctl -u asscor-kernel | grep -E "Framework:|srd_adapters version"
# 2) 生效配置
grep "SRD effective config" /var/log/asscor-kernel.log | tail -1
# 3) 拓扑事实
grep "topology facts recorded" /var/log/asscor-kernel.log | tail -3
# 4) 拓扑视图
asscor-cli  # → topology list
```

## 7. 复用与引用

- 审计结论：[SRD v2.2 审计报告](../../3-audits/SRD_V22_AUDIT_2026-10-27.md)（A-1…A-9 全部关闭）
- 归档时间线：[SRD v2.2 系列发布归档](../../4-archive/releases/SRD_v2.2_RELEASE_2026-10-27.md)
- 后续计划：[SRD v2.3 计划](../design/SRD_V2.3_PLAN_2026-10-27.md)
