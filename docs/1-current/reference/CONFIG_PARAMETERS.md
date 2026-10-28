# ASSCOR 可调参数总览（v2.3.6）

> 目标：回答"哪些行为可以不改代码就调"。本表按**配置文件段**组织；
> 标 ✅ 的键已接线并有测试/现场验证，标 ⚠️ 的键需要重启进程生效。
> 新增参数时**必须同时更新本文件**，否则视为文档债。

## 1. 评分与风险模型（kernel 主评分引擎 + SRD 插件共用）

配置文件：`[prism]`（推荐）或 `[srd]`（兼容，同名键）。v2.3.6 起**主评分引擎也读取**。

| 键 | 默认 | 作用 |
|---|---|---|
| `debt_alpha` | 1.2 | 安全债务超线性指数 |
| `prop_cap` | 0.25 | 传播惩罚上限 |
| `debt_cap` | 0.30 | 债务惩罚上限 |
| `debt_norm_days` | 1500 | 债务归一化分母（天） |
| `path_decay` | 0.80 | 路径风险衰减 |
| `max_path_depth` | 5 | 路径枚举深度 |
| `score_floor` | 0.15 | 下界稳定项 |
| `collapse_beta` | 1.5 | 塌缩超线性指数 |
| `aggregation` | `rss` | `rss` / `max` / `linear` |
| `stable_threshold` | 0.90 | Stable 隶属度上界 |
| `degraded_threshold` | 0.70 | Degraded 隶属度上界 |
| `untrusted_threshold` | 0.50 | Untrusted 隶属度上界 |
| `horizon_days` | 7 | 推理层预测窗口（天） |

验证：启动日志 `prism effective config`（v2.3.6 起）。

## 2. SRD 分层图（`[srd]`）

| 键 | 默认 | 作用 |
|---|---|---|
| `layered_graph` | true | 五层图开关（false 回退单层） |
| `transmission` | 0.1（回落 `[prism] default_transmission`） | 基础风险传输率 |
| `sync_interval_sec` | 3600 | 拓扑同步周期 |
| `roles` | 空 | `host=role,…`（L5 业务角色） |

验证：启动日志 `SRD effective config` / `SRD config source`；`srd check` 查询。

## 3. 评分权重与可接受性（`[weights]` / `[acceptability]`）

| 键 | 默认 | 作用 |
|---|---|---|
| `[weights] attack_surface / business_continuity / operation_trust / resilience / kernel_security` | 见 config.ini | SSAM 五域权重 |
| `[acceptability] threshold` | 80 | 可接受性判定阈值 |

## 4. Agent（`agent.ini`，端侧）

| 键 | 默认 | 作用 |
|---|---|---|
| `heartbeat_sec` | 60 | 心跳周期 |
| `check_interval_sec` | 300 | 扫描周期 |
| `check_timeout_sec` | 60 | 单次检查超时 |
| `max_retries` | 3 | 连续失败上限（超过则退出，等待 systemd 重启） |
| `reconnect_sec` | 5 | 重连间隔 |
| `tls_enabled` / `tls_skip_verify` / `tls_server_name` / `cert_dir` | 见 agent.ini | mTLS 连接 |

## 5. 通信与运行（`[comms]` / `[grpc]` / `[log]` / `[config]`）

| 键 | 作用 |
|---|---|
| `[comms] require_mtls` | 是否强制 mTLS |
| `[grpc] listen_addr` | gRPC 监听地址 |
| `[log] level / format` | 日志级别与格式 |
| `[config] watch_interval_sec` | 配置文件热加载检测周期 |
| `[integrity] verify_algo / anti_debug` | 算法防护开关 |

## 6. 拓扑与采集（`[topology]`）

| 键 | 作用 |
|---|---|
| `exclude_cidrs` | 拓扑采集排除网段（管理网/虚拟网） |

## 7. 已知未暴露（明确记录，不是遗漏）

- **SSAM 评分公式内部常数**：属于算法完整性基线（`[integrity]` 校验对象），
  **故意不可配**，改动会被算法防护检测。
- **Prism 语义层 Collapse 阈值**：由 `untrusted_threshold` 隐含推导，无独立键。
- **CLI 历史条数**：目前写死（默认 500），如需可配列入下一版。

## 8. 相关文档

- 配置参考：[SRD 配置参考](SRD_CONFIGURATION.md)
- 变更记录：[SRD_CHANGELOG](SRD_CHANGELOG.md)
- 参数验证：启动日志 `prism effective config` / `SRD effective config` / `topology facts recorded`
