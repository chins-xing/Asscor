# ASSCOR 代码质量审计报告

**日期**: 2026-08-14 | **版本**: v0.2.3 | **范围**: 微内核重构 (`fcff4ef`) 新增/修改代码 + 全仓库静态分析

---

## 一、执行摘要

本次审计针对「游离组件归入扩展体系」重构（`fcff4ef`）后的代码质量，重点核查 build-tag 门控一致性、stub 与真实实现的 API 对齐、契约类型上移后的跨包引用残留。

| 等级 | 数量 | 关键领域 |
|:---:|:---:|------|
| P0 | 0 | 无关键/数据丢失/构建破坏问题 |
| P1 | 2 | resilience stub API 不一致、extmgr.SetAssessor 未接线 |
| P2 | 1 | 本次重构引入的 gofmt 对齐偏差（已修复） |

历史遗留（非本次引入，未修复）：全仓库 163 文件 gofmt 对齐债务。

---

## 二、审计方法与结果

### 2.1 静态分析（全部通过）

| 检查项 | 默认（无 tag） | 全 tag (18 模块) |
|------|:---:|:---:|
| `go build ./...` | ✅ | ✅ |
| `go vet ./...` | ✅ | ✅ |
| `go test ./internal/...` | ✅ | ✅（42 包，排除已知 srd Windows 锁） |

### 2.2 契约上移一致性（全部通过）

- `internal/kernel/` 包中 `internal/engine` 残留引用：**0 处**
- `extmgr` / `cli` 对 `internal/engine` 依赖：**0 处**
- `kernel.HookRegistrar` 与 `engine.Assessor.RegisterHook/UnregisterHook` 签名精确匹配 ✅
- `AssessorModule.SetATTACKProvider` 满足 `kernel.ATTACKInjectionTarget` ✅

---

## 三、P1 缺陷（2 项，均已修复）

### 3.1 resilience stub API 不一致

| ID | 文件 | 缺陷 | 风险 |
|:--:|------|------|------|
| **Q01** | `internal/resilience/stub_off.go` (`//go:build !resilience`) | `State` 类型缺少 `StateClosed/StateOpen/StateHalfOpen` 常量与 `String()` 方法；`Snapshot` 缺 5 字段；`ModuleHealth` 缺 4 字段；含无意义 `var _ = time.Now` hack | 无 tag 构建下引用 `resilience.StateClosed` 等符号会编译失败 |

**修复**：补齐 stub 为与真实实现完全一致的 API（State 常量 + String 方法、Snapshot/ModuleHealth 全字段、删除 time hack）。

### 3.2 extmgr.SetAssessor 从未被调用

| ID | 文件 | 缺陷 | 风险 |
|:--:|------|------|------|
| **Q02** | `internal/extmgr/extension_manager.go:124` | `SetAssessor(kernel.HookRegistrar)` 仅有定义无调用点，legacy engine-hook 注册路径（`a.RegisterHook`）永远不生效 | hook 类型扩展只能走 `kernelExtensions.RegisterExtension` 扩展点路径，legacy 路径为死代码 |

经 `git log -S` 确认重构前后均如此（非本次引入）。有 nil 防护不 panic，但属未接线遗留。

**修复**：`ScoringEngine` 添加 `RegisterHook/UnregisterHook` 转发方法（委托内部 `engine.Assessor`）满足 `kernel.HookRegistrar`，`cmd/kernel/main.go` 在 extmgr 桥接处断言并调用 `mgr.SetAssessor(hr)`（含 nil 安全断言）。

---

## 四、P2 缺陷（1 项，已修复）

| ID | 缺陷 | 修复 |
|:--:|------|------|
| **Q03** | 本次重构引入的 gofmt 对齐偏差：`internal/engine/assessor.go`/`extensibility.go` 类型别名块手工对齐不精确，`cmd/kernel/engine_on.go` import 排序错误 | `gofmt -w` 修复 |

---

## 五、遗留问题（未修复）

### 5.1 全仓库 gofmt 历史债务

`gofmt -l` 报告 **163 个文件**未格式化，均为历史遗留的 struct 字段对齐问题（人工排版 vs gofmt 标准），贯穿 `internal/`、`cmd/`、`optional/`。本次重构新增文件已全部格式化干净。建议后续单独批量 `gofmt -w` 处理，但会引入大范围 diff，需单独评估。

---

## 六、质量结论

| 维度 | 评分 | 说明 |
|------|:---:|------|
| 契约上移彻底性 | A | kernel 包 0 处 engine 残留引用 |
| stub 模式一致性 | A | 修复后 API 完整对齐 |
| 门控构建正确性 | A | 默认 + 全 tag 双模式构建/vet/测试全绿 |
| 跨包解耦 | A | extmgr/cli 零 engine 依赖 |
| 格式化合规 | C | 163 文件历史债务未清偿 |

本次微内核重构代码质量良好：契约上移彻底、stub 模式经补齐后 API 完整一致、双模式构建测试全绿。两项 P1 缺陷（resilience stub API、extmgr.SetAssessor 接线）已修复，163 文件 gofmt 历史债务留待单独处理。

---

*审计完成于 2026-08-14。已修复 Q01/Q02/Q03，历史 gofmt 债务未修复。*
