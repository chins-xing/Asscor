# ASSCOR 扩展点架空问题专项审计

**日期**: 2026-07-08 | **范围**: 26 个扩展点 + 9 个 extmgr 类型

---

## 审计结论: 26/26 HOLLOW, 已修复 3/9 extmgr 架空

---

## 一、扩展点全貌

### 注册点分布 (26 个)

| 模块 | 数量 | 点名称 |
|------|:----:|--------|
| kernel | 6 | pre_init, post_init, pre_start, post_start, pre_stop, post_stop |
| assessor | 2 | pre_evaluate, post_evaluate |
| spc | 3 | pre_calculate, post_calculate, cve_updated |
| attck | 13 | coverage.complete, apt.matched, risk.predicted, detection.alert/anomaly, emulation.complete, assessment.complete, apt.chain_detected/attribution/hunt_confirmed/report_generated, behavioral.alert/beacon |
| webui | 1 | route.register |
| cli | 1 | command.register |

### 执行状态

- **26/26 被执行** (Execute 调用 32 次, 部分点调用 2 次)
- **0/26 有订阅者** (RegisterExtension 在整个代码库中**零调用**)
- **0/26 LIVE**
- **100% HOLLOW**

---

## 二、根本原因

**`RegisterExtension` 方法定义存在但零调用。** 唯一的代码位置是 `extensions.go:53` 的方法体。extmgr 声明了扩展类型但从不通向 `ExtensionRegistry`。

### extmgr 各自为政

| ExtType | 状态 | 行为 |
|---------|:----:|------|
| CheckModule | ✅ 可用 | 直接调用 `checks.Register` |
| Domain | ✅ 可用 | 直接调用 `model.RegisterDomain` |
| EdgeFactor | ✅ 可用 | 直接调用 `model.RegisterEdgeFactor` |
| Hook | ✅ 可用 | 直接调用 `assessor.RegisterHook` |
| **ScoringPlugin** | ⚠️ 假 | 仅日志, 未调用 `Engine.RegisterFormula` |
| **CLICommand** | ⚠️ 假 | 仅日志, 未调用扩展点 |
| **WebPanel** | ⚠️ 假 | 仅日志, 未调用扩展点 |
| Adapter | ⚠️ 假 | 仅日志, 未桥接 `adapter.Register` |
| Custom | ⚠️ 假 | 仅日志 |

**关键**: extmgr 正确接线的 4 个类型 (CheckModule/Domain/EdgeFactor/Hook) 都绕过了 `ExtensionRegistry`, 直接调用目标 registry。

---

## 三、本次修复

为 extmgr 添加回调机制, 保持模块低耦合（不导入 kernel/webui/cli 包）:

```go
type ExtensionManager struct {
    ...
    OnCLICommand    func(spec ExtensionSpec)  // 由调用方注入
    OnScoringPlugin func(spec ExtensionSpec)
    OnWebPanelRoute func(spec ExtensionSpec)
}
```

| 类型 | 修复前 | 修复后 |
|------|--------|--------|
| ScoringPlugin | 仅日志, 公式不生效 | 回调 → 调用方可注入 `Engine.RegisterFormula` |
| CLICommand | 仅日志, 命令不注册 | 回调 → 调用方可注入 `CLI.RegisterCommand` |
| WebPanel | 仅日志, 路由不注册 | 回调 → 调用方可注入 `webui.RegisterHandler` |

**保留不变**: 26 个扩展点仍为 HOLLOW — 这是设计问题（没有内置消费者），回调机制提供了接线能力, 实际使用由调用方决定。

---

## 四、统计

| 指标 | 值 |
|------|:--:|
| 注册扩展点 | 26 |
| 有订阅者 | 0 |
| 被执行 | 26 (100%) |
| HOLLOW 率 | **100%** |
| extmgr 架空类型 (修复前) | 5/9 |
| extmgr 架空类型 (修复后) | 2/9 (Adapter/Custom 需调用方注入) |
