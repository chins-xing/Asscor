# T4 联邦架构 demo 设计（2026-10-28）

> 目标：在**同一网络**里跑**多套配置/多套模型参数**的 SRD 评估；
> 用"主 kernel + 多个节点 kernel + 各自 agent"的联邦形态演示。
> 本文是总体设计；代码见 `extensions/federation/`，配置见 `configs/federation/`。

## 1. 架构

```
                    ┌──────────────────────────────┐
                    │  主 kernel（VM 910）          │
                    │  192.168.30.50:50051/50052    │
                    │  [federation] role=master     │
                    │  HTTP :5099 收集节点摘要       │
                    │  CLI: federation status       │
                    └───────────▲──────────────────┘
                    HTTPS/HTTP  │ 节点摘要（每 30s）
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
   ┌──────┴───────┐     ┌───────┴──────┐     ┌────────┴─────┐
   │ 节点 kernel  │     │ 节点 kernel   │     │ 节点 kernel   │
   │  nk1 (:50051)│     │ nk2 (:50051)  │     │ nk3 (:50051)  │
   │ 独立 CA/配置 │     │ 独立 CA/配置  │     │ 独立 CA/配置  │
   └──▲───▲───▲───┘     └──▲───▲───▲────┘     └──▲───▲───▲───┘
      │   │   │  10 agents  │   │   │ 10 agents   │   │   │ 10 agents
   CT 940-949            CT 950-959            CT 960-969
   数据面：vnetA/B/C/D 轮转（172.22/172.23/100.64/172.26）
   控制面：vmbr0 管理网（192.168.30.0/24）
```

## 2. 强制隔离：agent 只能连所属节点 kernel

不是靠"配置写对"，而是**密码学强制**：

- 每个节点 kernel 首次启动生成**自己的 CA**；
- 该节点下的 10 个 agent 证书由**该节点 kernel** 签发；
- 主 kernel（VM 910）有自己的 CA，**没有**签发这 30 个 agent 的任何证书；
- mTLS 双向校验 ⇒ agent 即使把地址写成主 kernel，也会因 CA 不匹配被拒。

验收时额外检查主 kernel 的 `:50051` 上没有这 30 个 agent 的会话（双重保险）。

## 3. 多套配置与模型参数（"单网络多配置"的核心）

三个节点 kernel 使用**完全独立的配置文件**，模型参数明显不同：

| 节点 | debt_alpha | path_decay | max_path_depth | aggregation | SRD roles |
|---|---|---|---|---|---|
| nk1 | 1.2 | 0.80 | 5 | rss | 无 |
| nk2 | 1.5 | 0.65 | 7 | max | 2 条 |
| nk3 | 1.8 | 0.50 | 9 | linear | 3 条（不同角色） |

每个节点启动日志会打印 `prism effective config` / `SRD effective config`，
验收脚本对比三份日志，证明"同网络、不同模型"。

主 kernel 只做**聚合视图**（收到的是节点摘要：node_id、config_hash、生效参数、
hosts 数、zone 平均分、上报时间），不参与节点内评估。

## 4. 网络结构

| 角色 | CT/VM | 控制面 | 数据面 |
|---|---|---|---|
| 主 kernel | VM 910 | 192.168.30.50（既有） | — |
| 节点 kernel×3 | CT 930/931/932 | 192.168.30.71/72/73 | 单网卡（mgmt） |
| agent×30 | CT 940-969 | 192.168.30.101-130 | eth0 轮转 vnetA/B/C/D |
| 旧实验域 | 920-927 | 192.168.30.x | vnetA/B/C/D（不动） |

分组：940-949→nk1、950-959→nk2、960-969→nk3。
agent 的数据面 IP 从各 vnet 的 `/24` 未占用段分配（基建子代理统一登记，
`/root/t4/inventory.tsv` 为唯一事实来源）。

## 5. 模板差异（100% 不同 CT 模板）

在现有 debian-12 模板基础上派生 3 个模板并 `pct template` 固化：

| 模板 | 用途 | 差异 |
|---|---|---|
| `tpl-asscor-min` | 最小镜像 | 仅基础系统 + ssh/chrony |
| `tpl-asscor-web` | Web/加固型 | nginx + 常见 web 包 + 加固项（sshd 收紧、umask） |
| `tpl-asscor-mon` | 监控/日志型 | rsyslog + sysstat + 日志轮转配置 |

30 个 agent 轮转使用 3 个模板（每组 10 个：4/3/3 分布），使清单里模板列不同，
避免"30 台一模一样的机器"。

## 6. 启动顺序

1. 节点 kernel：证书初始化 → 启动（`role=node`）→ `:50051` 监听；
2. 各节点签发自己 10 个 agent 证书 → agent CT 启动（指向所属节点）；
3. 主 kernel：合并 `[federation] role=master` → 重启（新增 :5099 收集端点）；
4. 等 30-90s：三节点上报 → `federation status` 显示 3 个节点。

## 7. 验收

`scripts/federation-verify.sh`（rc 非 0 即失败）：

1. 33 台 CT running；
2. 30 个 agent 配置指向所属节点 kernel；
3. 每个节点 `:50051` 有连接、日志有 agent 心跳；
4. 主 kernel `:50051` 无这 30 个 agent 的会话；
5. 主 kernel `federation status` / `GET /federation/nodes` 列出 3 个 node_id；
6. 三节点 `prism effective config` 参数互不相同。

## 8. 安全边界与 demo 局限

- demo 级共享 **token**（`asscor-t4-demo`）+ 明文 HTTP（管理网内）；
  生产应改为 mTLS + 独立 token/短期凭证；
- v0.2 起节点上报**图事实**（主机/策略/链路），主端可合并回答跨节点可达性
  （`federation check`）；仍不传原始 check 明细，主 kernel 无节点数据面访问权；
- 节点 kernel 的 SRD 图数据仍留在本地，联邦层不做跨节点路径合并（这是 v2.4 话题）；
- 30 个 agent 的评估并发会占用节点 kernel CPU，`report_interval_sec` 建议 ≥30s。

## 9. 相关文档

- 环境与验收细节：`docs/2-experiments/T4_FEDERATION_ENV_2026-10-28.md`
- 配置：`configs/federation/nk1.ini` / `nk2.ini` / `nk3.ini` / `master.ini`
- 代码：`extensions/federation/`（插件、收集器、上报客户端）
