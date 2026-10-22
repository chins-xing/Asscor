# 扩展体系能否以扩展包实现生命周期链 — 专项审计

**日期**: 2026-08-12 | **版本**: v0.2.3 | **范围**: 扩展体系 vs 新生命周期链

---

## 核心结论

**完整生命周期链无法作为纯外部扩展包实现。**

ASSCOR 存在**两套扩展机制**，必须先区分：

| 机制 | 载体 | 运行方式 | 能力 |
|------|------|---------|------|
| **A. extmgr 运行时扩展包** | `ExtensionSpec` + 外部可执行文件 | `exec.CommandContext` 拉起外部进程，事件触发即跑即退 | 订阅既有扩展点 + 注入数据，**无法**定义新扩展点/接口/插件/常驻 goroutine |
| **B. build-tag 可选 Go 模块** | `//go:build attck_ext` Go 包 | 编译进 kernel 二进制 | 可触达内核类型，但**必须重新编译内核**，等同改内核构建 |

---

## 五个关键问题的明确回答

| # | 问题 | 答案 | 依据 | 严重度 |
|:--:|------|:---:|------|:---:|
| 1 | 扩展包能否定义新扩展点 (`locate.*`/`block.*`)? | **不能** | `RegisterPoint` 仅在 `*ExtensionRegistry`，不暴露给插件 (extensions.go:18-26, 56; kernel.go:94) | CRITICAL |
| 2 | 扩展包能否注入新接口 (`Locator`/`Blocker`) 到 DI? | **不能(运行时)** | DI 容器仅经 `KernelContext.Container()`，只传给进程内 Plugin；extmgr 是外部进程永不接触 DI (di.go:23; plugin.go:56; extension_executor.go:173) | HIGH |
| 3 | 扩展包能否注册新 `kernel.Plugin`? | **不能(运行时)** | `RegisterPlugin` 仅 main.go:258 启动期调用一次，无动态注册路径 | HIGH |
| 4 | 扩展包能否实现生命周期循环(常驻状态机)? | **不能** | extmgr 执行模型是"事件→外部进程→30s 超时强杀" (extension_executor.go:166-170)；`adapter/custom` 类型安装即无操作 | CRITICAL |
| 5 | 什么必须内核核心 vs 可外部? | 见下表 | — | — |

---

## 生命周期各阶段分类

| 阶段 | 可否扩展包实现 | 依据 |
|------|:---:|------|
| 探测 | ✅ 可 | `assessor.pre/post_evaluate`、`adapter.*`、`attck.detection.*`；check_module 注入检查逻辑 |
| **定位** | ❌ **必须内核** | 无 `locate.*` 点、无 Locator 接口；最接近的 `attck.apt.chain_detected/attribution` 只能被动接结果，无法驱动定位 |
| 响应 | ✅ 可 | `policy.action_decided/notify`、`siem.*`、`cli.command.register` |
| 报告 | ✅ 可 | `assessor.report_generated/outbound`、`log.*`、`persistence.dashboard_written` |
| **阻断** | ❌ **必须内核** | 无 `block.*` 点；且调度本身断裂 (policy.go:151 发布 PolicyAction 结构体 vs commander.go:388 断言 map)；无 isolate_host 原语 |
| 修复 | ✅ 可 | `remediation.pre/post_apply/action_resolved`、`commander.*`、`source.*` |
| 验证 | ✅ 可 | `verify.pre_check/post_check/status_changed` |
| **定位(再次)** | ❌ **必须内核** | 同上 |
| 归档 | ✅ 可 | `archive.pre/post_write/rotation`、`persistence.pre/post_append` |
| **重复(循环)** | ❌ **必须内核** | 无 `lifecycle.*`/`orchestration.*` 点；链靠 `assessor.result` 单消息事件副作用串联，无显式状态机；extmgr 扩展无状态、30s 超时，无法承载循环 |

**统计**: 6 阶段可外部实现，4 阶段（定位×2 + 阻断 + 循环）必须内核核心支持。

---

## 必须内核核心的最小改造面

| 改造 | 位置 | 说明 |
|------|------|------|
| 新增 `locate.*` 扩展点 | `platform_extensions.go` | `locate.completed`/`locate.threat_active` |
| 新增 `block.*` 扩展点 | `platform_extensions.go` | `block.pre_apply`/`post_apply`/`confirmed` |
| 新增 `lifecycle.*` 扩展点 | `platform_extensions.go` | `lifecycle.phase_entered`/`phase_exited`/`repeat`/`completed` |
| 新增 `LifecycleEngine` 插件 | `internal/kernel/` | 持 goroutine 状态机，驱动循环 |
| 新增 `Locator`/`Blocker` 接口 | `internal/kernel/` | 进程内接口，供 LifecycleEngine 调用 |
| 修复阻断调度断裂 | `commander.go:388` | 断言 `PolicyAction` 而非 map |

---

## 附带发现：阻断调度硬伤（复现）

- `policy.go:151-156`：发布 `Payload: action`（`*PolicyAction` **结构体**）
- `commander.go:388`：`msg.Payload.(map[string]interface{})` **断言类型不匹配**
- 结果：`hostID`/`actionStr` 恒为空，阻断命令永远下发失败

即使扩展点齐全，阻断→修复这条链当前已断裂，必须内核核心修复后才能被外部扩展接上。

---

## 最终裁定

**扩展体系的边界** = "订阅既有扩展点 + 注入数据 + 跑外部无状态脚本"。它足以覆盖 `探测/响应/报告/修复/验证/归档` 6 阶段的旁路增强，但无法提供新扩展点、新接口、常驻状态机。

**推荐架构**: 内核核心落地最小改造面（3 组扩展点 + LifecycleEngine 插件 + 2 接口 + 1 处调度修复），然后 6 个旁路阶段由外部扩展包编排执行，`定位/阻断/循环` 由内核 LifecycleEngine 驱动、通过扩展点回调外部扩展。

---
*审计完成于 2026-08-12T23:52+08:00。仅审计，不立即修复。*
