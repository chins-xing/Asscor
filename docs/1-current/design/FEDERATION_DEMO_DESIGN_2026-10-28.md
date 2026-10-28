# SRD 联邦 demo 设计（一个网络，多套配置）· T4 · 2026-10-28

> 状态：草稿（demo 级）。代码：`internal/federation`（模块 0.1.0）+ `internal/cli/federation_commands.go` +
> `cmd/kernel/federation_on.go`（`-tags federation`）。
> 目标：证明同一张物理网络里可以并存 **主 kernel + N 个节点 kernel**，每个节点 kernel
> 使用**自己的配置与模型参数**（独立 CA 强制 agent 归属），主 kernel 只收**聚合摘要**，
> 不接管节点内的 agent 会话。

---

## 1. 动机

SRD 实验需要对比"同一份 agent 数据在不同模型参数下的评估结论"。若所有 agent 都连同一个
kernel，就只能得到一套配置；若每套配置起一个完全独立的实验环境，又无法在同一张网络里
同时观察。联邦 demo 用最小改动实现：

- **一个网络**：所有 CT 在同一个 PVE 宿主、同一组 vnet 上互通（数据网可隔离，管理网共用）；
- **多套配置**：每个节点 kernel 有独立 `config.ini`，`[prism]`/`[srd]` 参数明显不同；
- **聚合可见**：主 kernel 用 `federation status` 看到每个节点上报的配置指纹、主机数、
  按 zone 的平均 SSAM —— 一眼看出"同样的资产，三套模型给出了什么"。

---

## 2. 架构

```
                    ┌──────────────────────────────────────────────┐
                    │ 主 kernel（VM 910，192.168.30.50:50051）      │
                    │   [federation] role=master                   │
                    │   listen_addr=:5099                          │
                    │   /federation/report  (POST, 收摘要)         │
                    │   /federation/nodes   (GET, 查已收节点)      │
                    │   CLI: federation status [--json]            │
                    └───────▲──────────────▲──────────────▲────────┘
                            │ HTTP(S) 摘要  │              │
              ┌─────────────┴───┐  ┌───────┴─────────┐  ┌─┴───────────────┐
              │ 节点 kernel nk1 │  │ 节点 kernel nk2 │  │ 节点 kernel nk3 │
              │ 192.168.30.71   │  │ 192.168.30.72   │  │ 192.168.30.73   │
              │ role=node       │  │ role=node       │  │ role=node       │
              │ 独立 CA nk1     │  │ 独立 CA nk2     │  │ 独立 CA nk3     │
              │ 独立 cfg/模型   │  │ 独立 cfg/模型   │  │ 独立 cfg/模型   │
              └───▲───▲───▲─────┘  └───▲───▲───▲─────┘  └───▲───▲───▲─────┘
                  │   │   │            │   │   │            │   │   │
              10 个 agent（各自只连所属节点 kernel，mTLS 证书由所属节点 CA 签发）
              asc-agt-11 … 110        asc-agt-21 … 210        asc-agt-31 … 310
```

- 主 kernel 与节点 kernel 之间**只有**联邦 HTTP 通道（单向：节点 → 主，主只应答）。
- agent 只与所属节点 kernel 的 `:50051` 建立 mTLS 会话，永不连主 kernel。
- 节点 kernel 之间不互联（demo 刻意保持：避免"联邦"被误读为节点间数据面互通）。

---

## 3. "agent 只能连所属节点 kernel"的强制手段

**不是配置约定，而是密码学边界：每个节点 kernel 有自己的 CA。**

| # | 手段 | 作用 |
|---|---|---|
| 1 | 每个节点 kernel 首次启动用自己的 `--cert-dir`（如 `/opt/asscor/certs-nk1`）生成**独立 CA** | 三套 CA（ca.crt/ca.key）互不信任，节点之间无法互相验证对方的 agent |
| 2 | 30 个 agent 的客户端证书**只由所属节点 kernel 的 CA 签发**（`--issue-agent-cert`） | 证书链只在所属节点有效 |
| 3 | 主 kernel 的 CA **不签发任何实验 agent 证书** | 主 kernel 的 `:50051` 即使被误连也会在 TLS 握手阶段拒绝 |
| 4 | agent.ini 的 kernel 地址只写所属节点 IP | 降低误配概率（第一道防线，非强制） |
| 5 | 节点 kernel 监听 `:50051` 时 mTLS 校验客户端证书链 | 连错节点 ⇒ 握手失败（`certificate signed by unknown authority`），不是应用层"策略拒绝" |

验证方式（实验脚本 `scripts/federation-verify.sh`）：
- 每个节点 kernel 日志/`ss` 中只出现本组 10 个 host-id；
- 主 kernel 上不存在这 30 个 agent 的 mTLS 会话（`ss -tnp` / 日志）；
- 用 nk1 签发的 agent 证书去连 nk2，必须 TLS 握手失败。

> 注意：mTLS 的"独立 CA"约束的是 **agent 客户端证书**。主/节点 kernel 之间的联邦通道
> 在 demo 中走 HTTP + 共享 token（§5.3），不复用 agent mTLS。

---

## 4. 每节点独立配置与模型参数

`configs/federation/nk{1,2,3}.ini` 由另一任务产出，差异示例：

| 参数 | nk1 | nk2 | nk3 |
|---|---|---|---|
| `[prism] debt_alpha` | 1.2 | 1.5 | 1.8 |
| `[prism] path_decay` | 0.80 | 0.65 | 0.50 |
| `[prism] max_path_depth` | 5 | 7 | 9 |
| `[prism] aggregation` | rss | max | linear |
| `[srd] layered_graph` | true | true | true |
| `[srd] roles` | 2 角色 | 2 不同角色 | 3 角色 |

每套节点配置都带：

```ini
[federation]
role = node
node_id = nk1
master_url = http://192.168.30.50:5099
report_interval_sec = 30
token = <demo 共享密钥>
```

主 kernel 的现有 `kernel.ini` **不整体覆盖**，只追加/合并：

```ini
[federation]
role = master
listen_addr = :5099
token = <同一 demo 共享密钥>
```

### 4.1 配置读取路径（实现备注）

`[federation]` 段必须出现在 `internal/config.buildAdapterConfig` 的 `adapterSections`
白名单里，否则解析器会把整段丢弃，`cfg.Get("federation.role")` 永远为空
（与 v2.2.1 的 `[srd]` 被静默忽略是同一类坑）。本次在 `internal/config/config.go`
只加了一行 `"federation": true`，不改变任何既有分段语义。

插件读取方式与 `internal/engine/srd/manager.go` 一致：

```go
cfgObj := unwrapConfig(kc.GetConfigObj()) // 兼容"适配器包一层"的组装方式
cfg, err := federation.ParseConfig(configGetter(cfgObj)) // cfg.Get("federation.role") …
```

非法配置（未知 role、`report_interval_sec` 非正整数、node 缺 `master_url`）**不会中断
kernel Bootstrap**：插件打印 Warn、角色降级为 `off`，`federation status` 里显示
`Config error`，`HealthCheck` 返回该错误。demo 期间配置写错不应把实验环境搞挂。

master 监听失败（端口被占用、地址不可用）同样**不中断 kernel**：插件打印 Warn、保持
`Started` 状态但没有 collection endpoint，`federation status` 显示 `Listen error`
（`--json` 里是 `listen_error`），`HealthCheck` 返回 degraded 错误；`Stop` 对 nil server
安全。修复 `listen_addr` 后重启 kernel 即可恢复，节点侧上报会自动继续（节点不依赖主端在线）。

---

## 5. 上报协议

### 5.1 摘要内容（`NodeReport`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `node_id` | string | 节点标识（缺省取 hostname） |
| `config_hash` | string | 对"生效配置关键参数"排序后的 SHA-256（下称配置指纹） |
| `params` | map[string]string | `prism.*` / `srd.*` 生效参数键值（去敏，仅模型调参） |
| `hosts` | int | 本 kernel 拓扑注册表里的主机总数 |
| `zones` | map[string]{hosts,scored,avg_ssam} | 按 zone 汇总的 SSAM 平均分（只对已评估主机取均值） |
| `avg_ssam` | float64 | 按 `scored` 加权的总平均 |
| `reported_at` | RFC3339 | 节点侧生成时间 |
| `received_at` | RFC3339 | **主端**收到时间（主端时钟，防节点时钟漂移掩盖失联） |

配置指纹 = `sha256("asscor-federation-config-v1\n" + 排序后的 k=v 行)`；只要任一
`prism.*`/`srd.*` 键变化（含删除），指纹即变化。主端表格里展示前 16 位，`--json` 给全量。

> 只报聚合量、不报主机明细：主 kernel 不应成为节点资产清单的第二份副本。

### 5.2 端点

| 方法 | 路径 | 认证 | 响应 |
|---|---|---|---|
| `POST` | `/federation/report` | `X-Federation-Token`（配置了 token 时必填） | `200 {"ok":true,"node_id":…,"nodes":N}` |
| `GET` | `/federation/nodes` | 同上 | `200 {"count":N,"updated_at":…,"nodes":[NodeReport…]}` |

- 请求体上限 1 MiB；非法 JSON / 空 `node_id` → `400`；非 POST/GET → `405`；token 错误 → `401`。
- 收集器为内存态、`sync.RWMutex` 保护，按 `node_id` **覆盖更新**（去重，不重复追加）；
  `Nodes()` 返回按 `node_id` 排序的深拷贝，供 CLI/HTTP 并发读取。

### 5.3 上报时序与可靠性

- node 角色 Start 后**立即**上报一次，此后每 `report_interval_sec`（默认 30s）一次；
- 单次上报超时默认 5s；失败按指数退避重试（0.5s→1s→2s，封顶 5s），
  一轮最多 3 次尝试；整轮失败只记录状态，下个 tick 继续（不退出循环）；
- `Stop`：取消在途请求 → 等待上报 goroutine 退出 → 关闭 master HTTP 端点（3s 上限），
  优雅退出且不阻塞 kernel Shutdown。

### 5.4 安全边界（demo 级，明确不作为生产方案）

**已实现**
- 共享 token：仅当 `[federation] token` 非空时校验（常量时间比较），否则端点裸奔；
- 只监听 `listen_addr`（demo 为管理网 `:5099`）；报告体量上限；两段校验严格；
- 聚合摘要去敏：不含主机名/主机 ID/检查项明细；
- 与 agent mTLS 平面完全隔离（联邦 HTTP 不复用 kernel 证书/私钥）。

**明确未实现（demo 局限，评审时不要当作安全能力）**
1. **传输未加密**：默认 `http://`。管理网内网 demo 可接受；生产须 HTTPS/mTLS，
   或经 SSH 隧道/tailnet 承载；
2. **无节点身份认证**：共享 token 意味着任一节点泄密即可伪造其它 `node_id`；
   没有 per-node 证书、没有签名、没有防重放（无 nonce/时间窗）；
3. **无持久化**：主 kernel 重启后节点列表清空，等下一个上报周期恢复；
4. **无版本协商/能力发现**：`NodeReport` 加字段只能做向后兼容；
5. **主端单点**：master 不可用时节点继续本地工作，但聚合视图缺失；
6. **无访问审计**：`/federation/nodes` 的访问没有独立审计日志（token 错误仅 HTTP 401）；
7. **token 明文配置**：与其它 adapter 密钥同样支持 `FEDERATION_TOKEN` 环境变量覆盖
   （`internal/config` 的 secret 解析链），但 demo 配置文件里是明文；
8. **配置热加载不生效**：`[federation]` 只在插件 Init 时解析，`config reload` 不会重建
   上报循环/监听地址（重跑 kernel 生效）。

---

## 6. CLI

```
federation status [--json]
```

- **master**：`Listen`、已上报节点数、节点表（`NODE_ID / CONFIG_HASH / HOSTS / AVG_SSAM /
  LAST_REPORT`）+ 每节点 zone 明细；
- **node**：`master_url`、上报周期、自身配置指纹与参数、主机数、平均分、zone 明细、
  最近一次上报时间/尝试次数/错误；
- **off**：明确显示 `federation disabled ([federation] role = off)`；
- 未带 `-tags federation` 构建时：命令存在但输出
  `error: federation 插件未加载（构建需 -tags federation）` —— **错误写在 `Output`**，
  因为 unix socket 会话只渲染 `Output`（`internal/cli/socket.go`），只写 `Err` 在
  远程会话里会"静默失败"。

注入方式与 `cli.SetReachChecker` 同型：`cmd/kernel/main.go` 在 `k.Bootstrap()` **之后**
断言插件实现并调用 `cli.SetFederationProvider(fp)`；未编译联邦时 `federationPlugin==nil`。

---

## 7. 构建与运行

```bash
# 编译（Windows/Linux 均可）
go build -tags "federation,engine,srdwrapper,comms" ./cmd/kernel/

# 节点
./asscor-kernel --config nk1.ini --cert-dir /opt/asscor/certs-nk1 --listen :50051
# 主 kernel（现有环境只加 [federation] 段）
./asscor-kernel --config kernel.ini          # [federation] role=master listen_addr=:5099

# 主端查看
asscor-kernel --cli /opt/asscor/asscor-cli.sock   # 交互式
> federation status
> federation status --json

# 或直接 HTTP（带 token）
curl -s -H "X-Federation-Token: $TOKEN" http://192.168.30.50:5099/federation/nodes | jq .
```

Build tag 组合：`federation_on.go`（`//go:build federation`）与 `federation_off.go`
（`//go:build !federation`）成对，`-tags "engine,srdwrapper,comms"`（无 federation）与
无任何 tag 的构建均已验证可编译；`internal/federation` 本身不带 tag，CLI 包始终可引用
其状态类型，只有插件装配是 tag 门控的。

---

## 8. 实验对照与验收

| # | 验收项 | 方法 | 期望 |
|---|---|---|---|
| 1 | 三个节点都上报 | 主 `federation status` | 3 行，`CONFIG_HASH` 互不相同 |
| 2 | 节点归属隔离 | nk1 证书连 nk2 | TLS 握手失败 |
| 3 | 主 kernel 无 agent 会话 | 主 `ss -tnp` / 日志 | 无 30 个 agent 的 mTLS 会话 |
| 4 | 每节点只连本组 | 节点 `ss`/日志 | nkX 只见本组 10 个 host-id |
| 5 | 模型参数确实不同 | `federation status --json` 的 `params` | 三套 `debt_alpha/path_decay/...` 不同 |
| 6 | 上报失败不致命 | 停掉主 kernel 一段时间 | 节点日志有 Warn，kernel 不退出；主恢复后自动续报 |
| 7 | 未编译联邦的错误可见 | 无 tag 构建执行 `federation status` | `Output` 中可见 "插件未加载" |
| 8 | master 监听失败降级 | 先占用 `:5099` 再启动 master kernel | kernel 不退出；`federation status` 显示 `Listen error`，`HealthCheck` 报 degraded |
| 9 | `role=off` 是信息态 | `role=off` 执行 `federation status` | 成功退出并显示"未启用"，不是 error |

---

## 9. 实现对照表

| 关注点 | 代码位置 |
|---|---|
| `[federation]` 解析/角色校验 | `internal/federation/config.go`（`ParseRole`/`ParseConfig`） |
| 摘要模型与配置指纹 | `internal/federation/types.go`（`NodeReport`/`ZoneSummary`/`ConfigHash`） |
| master 内存收集器（去重/线程安全） | `internal/federation/collector.go` |
| master HTTP 端点 | `internal/federation/master.go` |
| node 上报客户端（重试/超时/优雅停止） | `internal/federation/reporter.go` |
| kernel 插件（Init/Start/Stop/State/HealthCheck + Snapshot） | `internal/federation/plugin.go` |
| CLI 命令与渲染 | `internal/cli/federation_commands.go` |
| 注册进 CLI 内建命令表 | `internal/cli/engine.go`（builtins） |
| 装配（tag 开/关） | `cmd/kernel/federation_on.go` / `federation_off.go` |
| Bootstrap 后注入 CLI | `cmd/kernel/main.go`（`cli.SetFederationProvider`） |
| 配置段白名单 | `internal/config/config.go`（`adapterSections["federation"]`） |
| 单元测试 | `internal/federation/*_test.go`、`internal/cli/federation_commands_test.go` |

---

## 10. 后续（若要走出 demo）

1. 联邦通道 mTLS（主端 CA 签节点证书）+ 报告签名 + nonce/时间窗，去掉共享 token；
2. 主端持久化（SQLite）与每节点历史趋势，支持"同一资产跨配置对比"；
3. 报告版本与能力协商；选择性聚合（按 zone/角色订阅）；
4. 从 HTTP 收集改为 gRPC 流（复用现有 comms 栈），主端可实时下发"请重报"；
5. 让 `[federation]` 支持热加载（配置变更后重建上报循环/监听）。

## 10. v0.2：图事实上报 + 主端合并推理（2026-10-28）

**问题**：v0.1 只上报聚合摘要，主端无法回答跨节点可达性——"联邦"只剩看板。

**v0.2 协议扩展**（`NodeReport`）：
- `host_facts[]`：id / IPs / subnets / zone / ssam / forwards / stateful_input /
  inbound[] / outbound[] / links{};
- `policy_facts[]`：转发策略（from/to/allow）；
- `policy_known`：是否采集到策略；
- 体积上限：2000 主机 / 5000 策略（demo 级防滥用，超出截断）。

**主端合并规则**（`BuildMergedGraph`）：
- 同一 host id：子网/IP 取并集；Zone/SSAM/Forwards/StatefulInput 以后上报者为准；
- 策略按 `(from,to,allow)` 去重取并集；
- 主 kernel 本地拓扑（老实验域）自动并入合并图；
- 排序后构建，保证同一输入产生同一图。

**新接口**：
- HTTP：`GET /federation/check?src=&dst=`（带 token），返回 verdict/路径/阻断点/原因/统计；
- CLI：`federation check <src> <dst> [--json]`（仅 master 角色可用）。

**版本**：插件 `0.2.0`（仍是 demo 级 0.x，不并入 SRD/ASSCOR 版本号）。

**已知限制**：合并是"全量重建"（每次查询从节点上报重建图，无增量）；
冲突用"后到优先"；不传原始 check 明细；跨节点路径语义仍受各节点采集能力限制。

### 10.1 端到端验证（2026-10-28）

环境：主 kernel（VM 910）+ 3 节点 kernel（930-932）+ 30 agent。
`federation check asc-agt-nk1-01 asc-agt-nk1-02`：

```
verdict : blocked   (paths=1, merged hosts=40)
path    : asc-agt-nk1-01 -> domC-router -> asc-agt-nk1-02
blocked : asc-agt-nk1-02
reason  : inbound policy denies 172.22.10.0/24 -> asc-agt-nk1-02
```

真值：`940 -> 941` ping 失败（941 的 INPUT 拒绝 940）。模型与真值一致。

过程中修复两个真实缺陷：
1. **裸 IP 策略匹配**：真实 nft 会把 `ip saddr X/32` 上报为裸 IP（无 `/32`），
   旧 `hostInCIDR/subnetMatch` 只认 CIDR ⇒ 规则永远不匹配；
2. **回程出向检查**：方向性会话判定漏了"回程由目标机 OUTPUT 发出"——
   `TestIntraSubnetOutboundRule` 抓出后补齐 `outboundAllowed(reply)`。

插件版本：**0.2.0**（demo 级 0.x，不并入 SRD/ASSCOR 版本号）。
