# ASSCOR 内核专项审计报告

**日期**: 2026-08-12 | **版本**: v0.2.2 | **范围**: `internal/kernel/` (68 文件, ~22K 行)

---

## 一、执行摘要

| 等级 | 数量 | 关键领域 |
|:---:|:---:|------|
| P0 | 0 | 无关键/数据丢失级别问题 |
| P1 | 12 | nil-guard 缺口、未触发扩展点、SPC 死接口方法、DI 绑定缺失、大文件 |
| P2 | 28 | orphan topic 常量、字符串/常量不匹配、ATT&CK 死方法、DI 辅助绑定缺失 |

---

## 二、P1 缺陷 (12 项)

### 2.1 nil-guard 缺口 (2 项)

| ID | 文件 | 方法 | 缺陷 |
|:--:|------|------|------|
| **K01** | `assessor.go:335` | `runSelfAssessment()` | `m.kernel.Bus().Publish()` 无 `m.kernel != nil` 保护。gRPC self-check 端点可触发 panic |
| **K02** | `heartbeat.go:218` | `checkTimeouts()` | `m.kernel.Bus().Publish()` 无 nil 保护。同函数中 `Extensions()` 已检查但 `Bus()` 被遗漏。goroutine 定时循环执行 |

### 2.2 未触发扩展点 (3 项)

| ID | 扩展点 | 定义位置 | 缺陷 |
|:--:|------|------|------|
| **K03** | `siem.push_failure` | `platform_extensions.go:188` | SIEM 推送失败未触发此扩展点 — `pushToSIEM()` goroutine 仅打日志 |
| **K04** | `breaker.state_changed` | `platform_extensions.go:243` | 熔断器状态变化内部回调未连接到扩展点 |
| **K05** | `ratelimit.limit_exceeded` | `platform_extensions.go:249` | 限流器内部回调 `onRejected` 未衔接到扩展点 |

### 2.3 SPC 接口死方法 (3 项)

| ID | 接口 | 方法 | 调用者 |
|:--:|------|------|:---:|
| **K06** | SPCCalculator | `MergeCVEs()` | 0 |
| **K07** | SPCCalculator | `AddCVEs()` | 0 |
| **K08** | SPCChecker | `ImportOSCAL()` | 仅测试文件 |

### 2.4 缺失 DI 绑定 (4 项)

| ID | 模块 | 接口 | 现状 |
|:--:|------|------|------|
| **K09** | SPCModule | SPCInterface | 通过类型断言 `impl.(SPCInterface)` 绕过 DI |
| **K10** | CommanderModule | CommanderInterface | 同上 |
| **K11** | AssessorModule | AssessorInterface | 同上 |
| **K12** | PolicyModule | — | 未暴露接口 |

这些模块已注册为插件但接口未绑定到 DI 容器。下游通过 duck-typing（类型断言）访问，使得 `Container.Inject()` 无法自动解析这些接口。

### 2.5 超大文件 (2 项)

| ID | 文件 | 行数 | 建议 |
|:--:|------|:---:|------|
| **K13** | `attck.go` | 1,567 | ATT&CK 子接口 (153 行) 内嵌而非独立文件 |
| **K14** | `assessor.go` | 1,023 | 含 4 种独立职责 (评估/SPC/ATT&CK/Prism 管线) |

---

## 三、P2 缺陷 (28 项)

### 3.1 事件总线 orphan 常量 (6 项)

| ID | 常量 | 值 | 问题 |
|:--:|------|------|------|
| K15 | TopicConfigChanged | "config.changed" | 定义但零发布/订阅 |
| K16 | TopicSPCUpdated | "spc.updated" | 同上 |
| K17 | TopicCTIUpdated | "cti.updated" | 同上 |
| K18 | TopicCommandEnqueued | "command.enqueued" | 同上 |
| K19 | TopicCommandResult | "command.result" | 同上 |
| K20 | TopicSourceManagerDeployed | "source_manager.deployed" | 同上 |

### 3.2 字符串字面量 vs 常量不匹配 (3 项)

| ID | 发布位置 | 使用字面量 | 可用常量 |
|:--:|------|------|------|
| K21 | heartbeat.go:121 | `"agent.heartbeat"` | TopicAgentHeartbeat |
| K22 | cti.go:377 | `"cti.threat_detected"` | TopicCTIThreatDetected |
| K23 | config_watcher.go:244 | `"config.reloaded"` | TopicConfigReloaded |

### 3.3 ATT&CK 死方法 (10 项)

| 方法 | 位置 | 调用者 |
|------|------|:---:|
| GetTransitionMatrix() | ATTCKAuxiliary | 0 |
| LoadYARARules() | ATTCKEnhanced | 0 |
| LoadSigmaRules() | ATTCKEnhanced | 0 |
| MatchYARARules() | ATTCKEnhanced | 0 |
| MatchSigmaRules() | ATTCKEnhanced | 0 |
| AnalyzeCrossHostConnections() | ATTCKEnhanced | 0 |
| ComputeCausalChain() | ATTCKEnhanced | 0 |
| PerformBayesianAttribution() | ATTCKEnhanced | 0 |
| FilterBeaconWithReputation() | ATTCKEnhanced | 0 |
| ApplyGroupBaseline() | ATTCKEnhanced | 0 |

这些方法已在接口注释中标记为 "0 callers — reserved"。

### 3.4 其他 (9 项)

| 项目 | 说明 |
|------|------|
| ATT&CK 子接口未拆分 | 153 行内嵌在 attck.go 底部，其他模块已全部拆分 |
| DI 辅助绑定缺失 | heartbeat/cti/persistence/source_manager 等 8 模块接口未绑定 |
| 类型断言绕过 DI | `assessor.go:565` 直接 cast 避免 Container.Inject |

---

## 四、总体评估

| 维度 | 评分 | 说明 |
|------|:---:|------|
| nil-guard 覆盖率 | B | 2 处 P1 缺口，已比审计前显著改善 |
| 扩展点完整性 | B | 74/77 触发，3 未接 |
| DI 使用一致性 | C | 仅 3 个模块全 DI，其余 duck-typing |
| 文件组织 | B+ | 17 类型拆分完成，2 文件仍超千行 |
| 接口质量 | B | 死方法已标注，13 个子接口大部分活跃 |

---

## 五、优先修复建议

| 优先级 | 修复项 | 估时 |
|:---:|------|:---:|
| 1 | K01 + K02 nil-guard (assessor self-check + heartbeat timeout) | 0.2h |
| 2 | K09-K12: 添加 DI Bind 调用 (SPC/Commander/Assessor/Policy) | 0.5h |
| 3 | K21-K23: 事件总线统一使用常量 | 0.3h |
| 4 | K03-K05: 未触发扩展点接线 | 0.5h |

---
*审计完成于 2026-08-12T21:22+08:00。仅审计，不立即修复。*
