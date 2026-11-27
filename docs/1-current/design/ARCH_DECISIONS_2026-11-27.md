# 架构决策记录（2026-11-27）

> 对应未完成项 A6：`adapterhub` 孤儿、`attck` 双形态、`comms_on.go` 手工装配。
> 决策原则：不为了“统一”引入新的生命周期复杂度；先冻结现状、明确主形态，再随 A1（模块进程隔离）统一处理。

## ADR-001：`internal/adapterhub` 冻结，不接入 kernel

**背景**

- `internal/adapterhub`（builder/manager/rules/wrapper，7 文件）**没有任何 kernel/cmd 引用**；`internal/kernel/adapter_integration.go` 已经承担了适配器接入与同步。
- 两者在 manager 生命周期、同步周期上与 `extmgr` 有重叠，直接接入会产生双份调度。

**决策**

1. 不把 `adapterhub` 接入 kernel；包标记为 **frozen / orphan**，不再新增功能。
2. 若 2.4 前仍无消费者，整包删除；若需要其 rules/builder 能力，优先合并进 `adapter_integration`，而不是引入第二套 manager。
3. 现有 `rules_test.go` 保留，作为未来合并时的行为参考。

## ADR-002：ATT&CK 以 kernel 可选包为主形态，`cmd/asscor` 注入为受支持的嵌入模式

**背景**

- kernel 中 ATT&CK 走 `attck_ext` optional pack + `assessor.SetATTACKProvider`；
- `cmd/asscor` 通过 `attck.New()` 构造后注入 provider，走的是同一份 `internal/attck` 实现，只是生命周期由 CLI 宿主管理。

**决策**

- **主形态**：kernel optional pack（`attck_ext` tag），负责总线/DI 生命周期与扩展点。
- **嵌入形态**：`cmd/asscor` 的 provider 注入保留，用于无 kernel 的 CLI/批处理；不得复制 ATT&CK 逻辑。
- 后续若统一，收敛到“共享 `attck.Module` + 两种宿主装配”，不合并宿主生命周期。

## ADR-003：`comms_on.go` 显式装配暂不 DI 化

**背景**

- `newCommsRuntime` 目前显式接收 9 个模块接口（heartbeat/commander/cti/assessor/persistence/spc/logCollector/sourceManager 等），装配顺序与 nil 语义是显式的。
- 改为 DI 容器会隐藏“谁依赖谁、何时为 nil”，并与 A1 的进程隔离改造冲突。

**决策**

- 短期保留显式参数装配；只在参数继续增长时引入 `commsDeps` 结构体聚合，不引入运行时 DI 解析。
- A1 迁移下一个模块时，随该模块的进程边界一起重审 comms 装配；在此之前不做结构性重构。

## 结果

- A6 从“待决策”转为“已决策”：adapterhub 冻结、attck 双形态明确、comms 装配延后。
- 新增 `internal/adapterhub/doc.go` 标注冻结状态，避免后来者误接。
- 跟踪项：2.4 前复核 adapterhub 是否删除（并入 L-2/架构清理）。
