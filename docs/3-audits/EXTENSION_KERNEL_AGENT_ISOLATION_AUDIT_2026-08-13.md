# 扩展包对内核与 Agent 的影响审计（隔离性审计）

- 日期：2026-08-13
- 类型：审计（归档 + 不立即修复）
- 范围：MITRE Engage 扩展包、ATT&CK 扩展包、multi-algo-orchestrator 模块、pkgmgr 对内核与 Agent 的编译/运行时影响
- 方法：依赖方向分析（grep import）、二进制依赖图（`go list -deps`）、构建标签分析、运行时加载机制分析（extmgr/pkgmgr）、构建验证

## 一、核心结论

**无隔离破坏。** 扩展→内核为单向依赖，内核与 Agent 均不回引任何扩展；MITRE Engage 当前未编译进任何二进制；唯一进入内核二进制的扩展是 build-tag 显式控制的 ATT&CK（设计内）。

## 二、依赖方向（谁依赖谁）

| 方向 | 结论 | 证据 |
|------|------|------|
| 扩展 → 内核 | 允许（扩展作为内核的库消费者） | `mitre-engage/engage.go` import `internal/kernel` |
| 内核 → 扩展 | **无** | `internal/` 下 grep `asscor/asscor/optional` 零匹配 |
| Agent → 扩展 | **无** | `cmd/agent/main.go` 仅 import `internal/agent` 等，零 optional |
| pkgmgr → 内核 | 无（仅 `internal/semver`） | `optional/pkgmgr` 为独立 `package main` |

## 三、二进制依赖图（`go list -deps` 实证）

| 构建目标 | optional 依赖 |
|----------|---------------|
| `./cmd/agent/` | **0**（完全隔离） |
| `./cmd/kernel/`（默认，无 tag） | **0** |
| `./cmd/kernel/` + `-tags attck_ext` | 仅 `optional/algorithms/packages/attck-ext-pack` |

三态构建验证均通过：`go build ./cmd/agent/`、`go build ./cmd/kernel/`、`go build -tags attck_ext ./cmd/kernel/`（exit 0）。

## 四、逐扩展包影响评估

### 1. MITRE Engage（`optional/adversary/packages/mitre-engage/`）
- **编译**：无 `//go:build` 标签，无任何 import（内核/agent/cmd 均不引用）。
- **运行时**：`EngageBlocker`/`IntentGuider` 类型实现 `kernel.Blocker`（未来可实现 `kernel.Guider`），但当前仅被本包测试引用，**未被任何二进制实例化**。
- **package.json 的 hooks**（`block.pre_apply`/`block.confirmed`/`locate.threat_active`）由独立 CLI `asscor-pkg`（pkgmgr）消费，**非内核运行时 extmgr**。extmgr 消费的是 `ExtensionSpec`（JSON，外部脚本进程），与 package.json 无关。
- **结论**：对内核/Agent 运行时影响为零。当前处于"源码库待接线"状态。

### 2. ATT&CK 扩展包（`optional/algorithms/packages/attck-ext-pack/`）
- 唯一经 `cmd/kernel/attck_ext_on.go`（`//go:build attck_ext`）编译进内核二进制的扩展。
- 默认构建走 `attck_ext_off.go`（no-op），不影响内核。
- **结论**：显式、设计内的编译期开关，无隔离问题。

### 3. multi-algo-orchestrator（`optional/algorithms/modules/multi-algo-orchestrator/`）
- 位于 `/modules/`（pkgmgr 跳过），无 package.json，无任何 import。
- README 明确"NOT part of core，需手动 clone + recompile"。
- **结论**：未编译进任何二进制，零影响。

### 4. pkgmgr（`optional/pkgmgr/`）
- 独立 `asscor-pkg` CLI，仅依赖 `internal/semver`。
- **结论**：不进入内核/Agent 二进制。

## 五、发现（问题清单）

### 发现-1 [低]：`guide.completed`/`guide.confirmed` 扩展点未注册
- 位置：`internal/kernel/lifecycle.go:299/304` 已触发 `Execute(ctx, "guide.completed"/"guide.confirmed", ...)`，但 `internal/kernel/platform_extensions.go` 的 `RegisterAllExtensionPoints` **未声明**这两个点。
- 影响：`Execute` 对未注册点当前是安全 no-op（无订阅者时空转），**不构成内核/Agent 破坏**；但任何扩展未来通过 `RegisterExtension` 订阅 `guide.*` 会得到 "extension point %s is not registered" 错误（`extensions.go:73-75`）。
- 修复方向：在 `platform_extensions.go` 补两个 `RegisterPoint`（引导阶段），并同步第 268 行生命周期注释（加入"引导"）。

### 发现-2 [信息]：「EngageBlocker 升级为 Guider」尚未在运行时生效
- 纠正记忆 `mitre_engage_blocker_conclusion` 要求 EngageBlocker 升级为 Guider；本次未提交改动只做了内核侧 `Guider` 接口 + `PhaseGuide` 接线，扩展侧尚无 `kernel.Guider` 实现。
- MITRE Engage 因此仍是"死代码库"，未接线到任何二进制，与发现-1 的 `guide.*` 订阅在运行时都不可达。

### 发现-3 [信息]：扩展点注册表注释滞后
- `platform_extensions.go:268` 生命周期注释仍为旧链路（探测→定位→响应→报告→阻断→…），未含"引导"阶段，与新 `PhaseGuide` 枚举不一致。

## 六、风险评估

- **隔离破坏**：无。
- **唯一内核→扩展耦合**：`-tags attck_ext` 编译期开关（显式、可控、默认关闭）。
- **MITRE Engage 现状**：源码库，运行时空转。未来接线应沿用 build-tag 模式（如 attck_ext）而非运行时 extmgr，以保持内核零膨胀（遵守 `lightweight_array_kernel_zero_bloat` 与 `extension_package_boundary_constraints`）。
- **本次未提交 lifecycle.go 改动**：纯内核增量，Agent 零影响；新增扩展点未注册属完整性缺口（发现-1），不属隔离问题。

## 七、建议

1. 修复发现-1：注册 `guide.completed`/`guide.confirmed` 并同步注释（属"检查"范畴，下一步执行）。
2. 扩展侧落地"EngageBlocker→Guider"：新增 `Guide(ctx, *AttackerLocation) (int, error)`，设计 `AttackerLocation→Intent` 推断映射，并补 `var _ kernel.Guider = (*EngageBlocker)(nil)` 断言。
3. 若未来 MITRE Engage 需进入内核，沿用 `//go:build mitre_engage` 编译标签模式，保持默认构建零膨胀。
