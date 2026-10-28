# T4 联邦进程隔离（v0.4）实验记录（2026-10-29）

> 目标：把联邦从"DI 容器内共享内存"推进到"独立进程 + RPC 宿主"，并在真实拓扑上
> 跑两轮：**分数轮**（看评估结果）与**性能轮**（看延迟/资源/吞吐/隔离）。

## 1. 架构：内核代理 + `federation-mod` 进程

```
┌──────────────────────────── kernel 进程 ────────────────────────────┐
│ kernel runtime（插件/DI/bus/89 扩展点）                              │
│   └─ federation Proxy (kernel.Plugin)                               │
│        • BuildNodeReport(kc)        ← 只读内核拓扑/评估              │
│        • localFactsFromTopology()   ← 本地事实快照                   │
│        • JSON-Lines RPC ─────────────────────────────┐              │
└──────────────────────────────────────────────────────┼──────────────┘
                                                       ▼
                                     ┌──────── federation-mod 进程 ────────┐
                                     │ configure / snapshot / status       │
                                     │ check / export / report-now         │
                                     │ master: HTTP :5099 + merge          │
                                     │ node:   reporter → master           │
                                     └─────────────────────────────────────┘
```

- 协议：stdin/stdout **行分隔 JSON**（`configure|snapshot|status|check|export|report-now|shutdown|ping`）。
- 子进程**不 import `internal/kernel`**：只复用 `extensions/federation` 的纯逻辑
  （collector/master/reporter/merge/export）；本地事实由内核通过 `snapshot` 推送，
  合并图用新增的 `BuildMergedGraphWithLocal` / `MergedTopologyWithLocal`。
- 装配：`-tags "federation,federation_proc"` 走 `Proxy`；默认仍保留进程内模式。

## 2. 隔离验证（线上）

```text
$ sudo kill -9 <federation-mod pid>          # 杀掉子进程
$ systemctl is-active asscor-kernel          → active
$ ps -p <kernel pid>                         → kernel 存活

$ federation status
  Federation (master)
  Running:        true
  Listen:         :5099
  Config error:   write child: write |1: broken pipe   ← 仅联邦能力降级

$ systemctl restart asscor-kernel            # 恢复
→ federation-mod 重新拉起（新 pid），节点上报恢复
```

结论：**子进程崩溃不再拖垮内核**；代价是当前需要重启内核（或后续加自动重启）恢复。

## 3. 分数轮（Run 1）

环境：VM910 master + 3 节点 kernel（930-932）+ 30 T4 agent + 旧实验域 7 台；
三节点配置仍为 nk1 `1.2/0.80/5/rss`、nk2 `1.5/0.65/7/max`、nk3 `1.8/0.50/9/linear`。

| 指标 | 值 |
|---|---|
| 节点上报 | **3 节点，各 10 主机** |
| 每节点平均 SSAM | **58.3 / 58.3 / 58.3** |
| 合并图规模 | 37 主机（30 T4 + 7 旧域） |
| 样例 `federation check` | `nk1-01 → nk2-01`：**reachable**，路径经 `domC-router` |
| 样例单机评分 | `asc-agt-nk1-01`：**55.93 / 100，NOT ACCEPTABLE**；Prism `Untrusted (collapsing, 0.91)`；81 checks（31 pass / 49 fail / 1 skip） |

> 分数与进程内模式一致（同配置/同数据），说明 RPC 隔离没有改变评估语义。

## 4. 性能轮（Run 2）

| 指标 | 值 | 说明 |
|---|---|---|
| `federation status`（CLI 端到端） | **15.1 ms** avg（14–18） | 含 CLI 连接 + 内核代理 + RPC + 子进程 |
| `federation check`（合并图查询） | **15.3 ms** avg（14–18） | 37 主机合并图重建 + 查询 |
| `federation export` | **16–25 ms，11.2 KB** | 合并拓扑 JSON 经 RPC 回传 |
| 子进程 HTTP `/federation/nodes` | **8 ms 中位数**（avg 23.3，首包 304 ms） | 子进程内 HTTP 处理 |
| master kernel RSS | **~146 MB** | 含全部内核模块 |
| master `federation-mod` RSS | **~9–11 MB** | 联邦独立进程 |
| node kernel RSS（nk1） | **~19 MB** | |
| node `federation-mod` RSS（nk1） | **~5.7 MB** | |
| 吞吐（nk1 最近 5 min） | **63 heartbeat / 63 topology facts / 13 assessment** | 10 台 agent，30s 心跳 |

## 5. 结论与限制

**结论**
- 进程隔离成立：联邦逻辑与 HTTP 服务都在子进程，崩溃只影响联邦能力（内核存活）；
- 分数与进程内模式一致，RPC 开销在 **~15 ms/次** 量级（管理面查询足够）；
- 子进程 RSS 5.7–11 MB，内核 RSS 与进程内模式接近（代理本身很薄）。

**限制（下一步）**
1. 子进程崩溃后**没有自动重启**（健康检查会 degraded，需重启 kernel 恢复）；
2. RPC 单飞（一次一请求），高频状态查询会排队；
3. 快照推送间隔 = `report_interval_sec`（30s），评估分数变化最多滞后一个周期；
4. 内核二进制未显著变小：联邦包仍被编进内核（Proxy 与纯逻辑同包），
   真正减重要把纯逻辑拆到独立 module（下一步）。
