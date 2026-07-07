# ASSCOR 技术债务专项审计报告

**日期**: 2026-07-07 | **版本**: v0.2.0 | **Go文件**: 184 (158源码 + 26测试)

---

## 执行摘要

审计涵盖 3 大类：**架构债务**（God 接口/死代码/重复代码）、**质量债务**（测试缺失/错误处理）、**配置债务**（INI 漂移/路径硬编码）。共发现 **49 项技术债务**：

| 严重度 | 数量 | 优先处理 |
|--------|------|----------|
| 🔴 CRITICAL | 12 | services.go/bus.go 零测试 + goroutine panic缺失 |
| 🟠 HIGH | 10 | io.Copy 错误丢弃 + 死代码方法 + 配置漂移 |
| 🟡 MEDIUM | 16 | God接口 + 重复代码 + SRD类型重复 |
| 🟢 LOW | 11 | defer Close无检查 + 版本头缺失 |

---

## 一、架构债务

### 1.1 God 接口 (3项)

| 接口 | 方法数 | 文件 | 严重度 |
|------|--------|------|--------|
| **ATTACKInterface** | **85** | `attck.go:1580-1670` | 🔴 HIGH |
| SPCInterface | 20 | `spc.go:906-927` | 🟡 MED |
| SourceManagerInterface | 14 | `source_manager.go:88-103` | 🟡 MED |

ATTACKInterface 涵盖 12 个不同关注点（战术/检测/IOC/情报/仿真/评估/攻击链/行为/归因/狩猎/Bayes/YARA），建议拆分为 12 个独立接口。

### 1.2 死代码 (8项)

| 方法 | 调用者 | 严重度 |
|------|--------|--------|
| `GetTransitionMatrix` | 0 | 🔴 HIGH |
| `LoadYARARules` / `LoadSigmaRules` | 0 | 🔴 HIGH |
| `ComputeCausalChain` / `AnalyzeCrossHostConnections` / `PerformBayesianAttribution` | 0 | 🔴 HIGH |
| `ExecuteHunt` / `RunEmulation` / `DetectBeaconing` / `GenerateScenarioFromActor` / `CreateImprovementTrack` | 仅测试 | 🟡 MED |

### 1.3 重复代码 (3项)

| 问题 | 文件 | 严重度 |
|------|------|--------|
| CopyFile 同一包两处实现 (权限不同) | `deploy/agent_linux.go` + `kernel_linux.go` | 🟡 MED |
| parseInt 两处实现，语义不同 | `srd/manager.go` + `kernel/interceptor.go` | 🟡 MED |
| setupTLS 中 22 处重复错误处理模式 | `cmd/kernel/main.go:402-600` | 🔴 HIGH |

---

## 二、质量债务

### 2.1 关键路径零测试 (9文件)

| 文件 | 未测试的关键函数 | 严重度 |
|------|-----------------|--------|
| `services.go` | Heartbeat/Register/GetSnapshot | 🔴 CRITICAL |
| `bus.go` | Publish/PublishSync/Subscribe/Stop | 🔴 CRITICAL |
| `circuitbreaker.go` | state/recordFailure/recordSuccess/Interceptor | 🔴 CRITICAL |
| `server.go` | handleConn/acceptLoop/Start/Stop | 🔴 CRITICAL |
| `config_watcher.go` | watchLoop/sighupLoop/forceReload | 🔴 CRITICAL |
| `collector.go` | Append/AppendBatch/flushLoop | 🔴 CRITICAL |
| `ratelimit.go` | allow/CleanupStale | 🟠 HIGH |
| `spc_persist.go` | saveCacheToDisk/loadCacheFromDisk | 🟠 HIGH |
| `cmd/kernel/main.go` | signal handler/setupTLS | 🟠 HIGH |

**总覆盖率不足 40% 的包**: deploy(0%), agent(0%), webui(0%), checks/linux(0%), common(0%), model(0%), config(15%), srd(14.7%), checks(12.5%)

### 2.2 错误处理缺失 (4项)

| 问题 | 位置 | 严重度 |
|------|------|--------|
| `io.Copy` 返回值静默丢弃 (2处) | `persistence.go:652,732` | 🔴 HIGH |
| `os.Remove` 误差静默丢弃 (4处) | `main.go:448-451`, `persistence.go:676,756` | 🔴 HIGH |
| `time.Parse` 误差静默丢弃 (3处) | `spc_fetch.go:638,640,643` | 🟠 HIGH |
| type assertion err静默丢弃 (4处) | `persistence.go:941-944` | 🟡 MED |

### 2.3 Goroutine Panic 保护缺口 (4处)

| 位置 | 严重度 |
|------|--------|
| `services.go:161` Heartbeat go func | 🔴 HIGH |
| `spc_fetch.go:386` NVD fetch goroutine | 🟡 MED |
| `ratelimit.go:46` Cleanup goroutine | 🟡 MED |
| `bus.go:211` Shutdown drain goroutine | 🟢 LOW |

### 2.4 预存测试失败

`TestSPCImportOSCALDuplicateHandling` 持续失败 — merge 逻辑覆盖原始值 bug。

---

## 三、配置债务

### 3.1 行业模板缺失 (7项)

6 个行业模板全部缺失: `[integrity]`、`[attck]`、`[prism]`、5 个 `[edge_factors]` 子键、`[weights].kernel_security`、`data_dir`、`console_report`。

### 3.2 配置键路径不匹配

`console_report` 代码读 `webui.console_report`，但 config.ini 放全局键。

### 3.3 重复 INI 节

hospital/enterprise/edu 模板存在重复的 `[spc.cnnvd]`/`[spc.cnvd]` 节。

### 3.4 硬编码路径

FHS 路径在 Go 源码中硬编码，非 root/容器部署时无法重定位 (低优先级)。

---

## 四、优先修复建议

| 优先级 | 行动 |
|--------|------|
| P0 | 为 `services.go` (Heartbeat/Register) + `bus.go` (Publish/Subscribe) 添加测试 |
| P0 | 为 `services.go:161` goroutine 添加 panic recovery |
| P1 | 修复 `persistence.go:652,732` 中 `io.Copy` 丢弃误差 |
| P1 | 清理死代码方法 (YARA/Sigma/Bayesian 等 8 个) |
| P1 | 补齐 6 行业模板的 `[integrity]`/`[attck]`/`[prism]` 节 |
| P2 | 拆分 ATTACKInterface (85方法 → ~12接口) |
| P2 | 统一 CopyFile 实现 |
| P3 | 补齐 agent/checks/webui/config 包测试 |
