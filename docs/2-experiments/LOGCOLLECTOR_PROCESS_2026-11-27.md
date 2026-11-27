# 进程隔离试点 #2：log collector（2026-11-27）

> 目标（A1）：把第二个模块从内核进程搬到独立进程，验证“Proxy + JSON-Lines RPC”模式可复用。
> 选择 collector 的原因：`kernel.LogCollectorInterface` 只有 3 个方法（`Append`/`AppendBatch`/`LogPath`），
> 状态集中在 append-only 文件写入，风险低于 assessor/SPC/CTI。

## 1. 结构

```text
kernel 进程
└─ logcollector.Proxy (kernel.Plugin)
   ├─ Init: 计算 <data_dir>/ASSCOR-kernel.log，Bind LogCollectorInterface
   ├─ Start: 启动 logcollector-mod，发送 configure(path)
   ├─ Append/AppendBatch → RPC → child 写 JSONL → 成功后由 proxy 触发 log.entry_received 扩展点
   └─ HealthCheck: ping
                                        │
                    JSON-Lines RPC      ▼
                         ┌──── logcollector-mod ────┐
                         │ configure / append      │
                         │ append_batch / log_path │
                         │ ping / sync / shutdown  │
                         └─────────────────────────┘
```

- 新增 `extensions/logcollector`：`core.go`（Writer）、`rpc.go`（RunChild）、`proxy.go`（kernel 侧）。
- 新增 `cmd/logcollector-mod`。
- 装配：`-tags "collector,collector_proc"` 使用 Proxy；`-tags collector`（无 `collector_proc`）仍是原进程内实现。

## 2. 已验证

- 构建：
  - `go build -tags collector ./cmd/kernel`（进程内）
  - `go build -tags collector,collector_proc ./cmd/kernel`（Proxy）
  - `go build ./cmd/logcollector-mod`
- 单元测试：`go test ./extensions/logcollector`（Writer append/batch）。
- 子进程 RPC smoke：configure → append → log_path → ping → shutdown；日志文件实际写入：

```json
{"host_id":"h1","level":"info","message":"hello","source":"agent","timestamp":"..."}
```

## 3. 行为差异 / 限制

1. **扩展点**：child 不执行内核扩展点；proxy 在写入成功后补发 `log.entry_received`（每批逐条）。
2. **无自动重启**：本试点未复用 federation 的 supervisor；child 崩溃后 Append 返回错误，需重启 kernel。
3. **RPC 串行**：与 federation 相同的单飞模型，日志写入量极大时可能成为瓶颈；批量接口缓解。
4. **同步刷盘**：child 当前没有后台 flush loop；仅在 `Stop`/`sync` 显式刷盘，后续按 in-process 的 30s 周期补齐。

## 4. 下一步

- 复用 federation supervisor（D-12 候选）为 logcollector-mod 加自动重启。
- 对 AppendBatch 设置批量上限/背压。
- 再把 CTI 或 sourcemanager 按同一模式迁移，形成 `extensions/proc` 通用契约。
