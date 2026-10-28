# 联邦扩展包：`extensions/federation`（v0.3，2026-10-28）

> 把 T4 联邦从内核树里解耦出来：**扩展包自己拥有实现与 CLI 命令**，
> `internal/cli` 与 `cmd/kernel` 不再包含任何 federation 专有代码。

## 1. 为什么不是 pluginsdk（RPC 进程插件）

`pluginsdk` 是**独立进程 + JSON-RPC** 的扩展模型，适合"零内核依赖"的插件；
联邦需要读取进程内的拓扑注册表、评估结果并复用 `topology` 图算法，
放进独立进程就得再发明一套 facts RPC。因此本轮采用**编译期扩展包**：
同模块、独立目录、按 build tag 装配，接口面只有两处：

1. `kernel.Plugin`（生命周期：Init/Start/Stop/HealthCheck/Status）；
2. `cli.RegisterExtensionCommand`（命令自注册）。

## 2. 目录与职责

```
extensions/federation/
  config.go       [federation] 解析、PluginVersion=0.3.0
  types.go        NodeReport（图事实）、ZoneSummary、ConfigHash
  facts.go        HostFact / PolicyFact（v0.2 协议）
  collector.go    主端节点表（按 node_id 去重）
  master.go       HTTP：/federation/report|nodes|check|export
  reporter.go     node 周期上报 + 重试
  merge.go        BuildMergedGraph / CheckMerged（跨节点合并）
  export.go       MergedTopology（可评分拓扑导出）
  plugin.go       kernel.Plugin 实现（master/node/off）
  command.go      CLI 命令自注册：status/check/export/report-now
  *_test.go       42 个测试（含命令行为）
```

## 3. 内核侧只剩两个通用钩子

### 3.1 CLI（`internal/cli/extension.go`）

```go
cli.RegisterExtensionCommand(info, handler) // 扩展包 init() 调用
cli.ExtensionCommandNames()                 // 测试/自检
```

`RegisterBuiltinCommands` 在内置命令之后统一注册扩展命令；
`internal/cli` **不 import 任何扩展包**（`grep -r federation internal/cli` 为空）。

### 3.2 内核装配（`cmd/kernel`）

```go
// extensions_on.go  //go:build federation
func newExtensionPlugins() []kernel.Plugin {
    return []kernel.Plugin{federation.New()}
}

// extensions_off.go //go:build !federation
func newExtensionPlugins() []kernel.Plugin { return nil }
```

`main.go` 只写 `plugins = append(plugins, newExtensionPlugins()...)`，
没有任何 federation 字样。

## 4. 命令

| 命令 | 角色 | 说明 |
|---|---|---|
| `federation status [--json]` | 两者 | master 节点表；node 自身配置/最近上报 |
| `federation check <src> <dst> [--json]` | master | 合并图跨节点可达性（verdict/路径/阻断点） |
| `federation export [--json]` | master | 导出合并拓扑（AUC/可视化实验用） |
| `federation report-now` | node | 立即上报一次 |

`role=off` 时 `status` 是信息态（`federation 未启用（[federation] role = off）`，ExitOK）；
未带 `-tags federation` 构建时命令**不存在**（扩展未编译进来）。

## 5. 验证（2026-10-28 实测）

- 宿主构建：`go build -tags "federation,engine,…" ./cmd/kernel` OK；
  不带 federation tag 也 OK（扩展插件为空）。
- `extensions/federation` 测试 42 个全绿；`internal/cli` 测试全绿。
- 部署 master + 3 节点后：
  - master `federation status` 显示 3 节点（config_hash 互异）；
  - master `federation export` 输出合并拓扑 JSON；
  - 节点 `federation report-now` 输出 `federation report sent`；
  - 节点 `federation status` 显示 node_id/master_url/params/hosts/last report。

## 6. 迁移说明

- `internal/federation` 已删除（git mv），历史提交中的 import 需改成 `extensions/federation`；
- CLI 注入接口 `cli.SetFederationProvider`/`FederationProvider` 已删除；
  扩展命令通过 `currentPlugin` 直接持有实例；
- 构建脚本里的 `federation` tag 不变（部署无需改）。

## 7. 限制

- 仍是**编译期**扩展（非动态加载）；动态化需要先给 kernel 定义 facts RPC（v2.4 话题）。
- `export`/`check` 每次全量重建合并图（demo 规模 40 主机毫秒级）。
- 安全边界未变：共享 token + 明文 HTTP（管理网内），生产需 mTLS。
