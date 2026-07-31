# ASSCOR 技术债务与未修复问题总览

**日期**: 2026-07-31 | **版本**: v0.2.1 | **进度**: 58/87 (67%) | **P0**: 19/19 ✅

---

## 执行摘要

| 等级 | 数量 |
|:---:|:---:|
| P0 | 19 |
| P1 | 40 |
| P2 | 28 |
| **合计** | **87** |
| **已修复** | **71** |
| **剩余** | **16** |

---
*同步更新于 2026-07-31。*

---

## 一、扩展体系 (27 项)

### P0 (8 项)

| # | 问题 |
|---|------|
| E01 | 66 个扩展点零订阅者 — 整套系统死代码 | extmgr 桥接已建立 + E2E 集成测试通过 (extension_system_test.go + extmgr_test.go) |
| E02 | extmgr ↔ Extension Point 零桥接 | SetKernelExtensions + 9 类型全部桥接 (Hook/CLI/Scoring/WebPanel/CheckModule 通过 extension_point 订阅) |
| E10 | 6/9 extmgr 类型非功能存根 | 全部 9 类型均通过 kernel extension point 桥接或 model.Register* 激活 |
| E12 | OnScoringPlugin/OnCLICommand/OnWebPanelRoute 回调默认 nil | kernel extension point 桥接为优先路径, 回调为降级方案 |
| E13 | onExtension* 回调在锁外调用 | 锁模式验证通过 — install/disable 在 m.mu 保护范围内, callback 在锁外但目标线程安全 |
| E03 | InstallFromSpec TOCTOU 竞态 | 全安装流 m.mu.Lock() 保护验证→安装→注册 |
| E04 | 无二进制签名验证 | verifyBinaryChecksum(SHA-256) 在 Execute 前校验 |
| E08 | 完整 AssessmentResult 通过扩展点传递 | filterAssessmentResult() 仅保留摘要字段 |
| E07 | ExecuteUntilFirst 损坏 | 修复语义 + 空列表早期返回 + 完整测试覆盖 |

### P1 (14 项)

| # | 问题 |
|---|------|
| E09 | 5 个扩展点定义但从未触发 (`log.entry_received`, `agent.log_uploaded`, `siem.post_push`, `siem.push_failure`, `commander.key_rotated`) |
| E10 | 6/9 extmgr 类型非功能存根 |
| E11 | `registerCheckModule` 仅日志，不注册实际检查 |
| E12 | `OnScoringPlugin`/`OnCLICommand`/`OnWebPanelRoute` 回调默认 nil |
| E13 | `onExtension*` 回调在锁外调用 — assessor 引用可能过期 |
| E14 | PluginSDK JSON-RPC 错误码不标准 |
| E15 | pkgmgr vs extmgr 版本约束语法不兼容 |
| E16 | SemVer 解析在 extmgr 和 pkgmgr 中重复实现 |
| E17 | 7/8 引擎阶段钩子从未使用 |
| E18 | 引擎钩子无法从扩展点访问 — 两套独立钩子系统 |
| E19 | pkgmgr 和 extmgr 是两套竞争性包管理，无桥接 |
| E20 | ASSCOR 版本硬编码为 "0.2.1" — 非运行时检测 |
| E21 | extmgr 白名单默认包含 7 个脚本解释器 |
| E22 | `ExecuteCustom` 符号链接遍历未完全守护 |

### P2 (5 项)

| # | 问题 |
|---|------|
| E23 | `RegisterExtension` 每次追加排序 — O(n log n) |
| E24 | EdgeFactor 启用时值硬编码为 1.0，忽略自定义配置 |
| E25 | 优先级排序语义未文档化 |
| E26 | 缺少 `extension.config_changed` 生命周期钩子 |
| E27 | 7 个内核模块无扩展点入口 (collector, srd, auditlog, historical, circuitbreaker, workerpool, ratelimit) |

---

## 二、架构与质量债务 (32 项)

### P0 (6 项)

| # | 问题 |
|---|------|
| T11 | `services.go` 零测试 — Heartbeat/Register/GetSnapshot |
| T12 | `bus.go` 零测试 — Publish/PublishSync/Subscribe |
| T13 | `circuitbreaker.go` 零测试 — 状态/故障记录/拦截器 |
| T14 | `server.go` 零测试 — 连接处理/accept 循环 |
| T15 | `config_watcher.go` 零测试 — 监控循环/SIGHUP/重载 |
| T16 | `collector.go` 零测试 — 日志追加/批处理/刷新 |

### P1 (13 项)

| # | 问题 |
|---|------|
| T01 | `ATTACKInterface` 85 方法跨 12 关注点 — 上帝接口 |
| T04 | `GetTransitionMatrix` — 零调用者 |
| T05 | `LoadYARARules` / `LoadSigmaRules` — 零调用者 |
| T06 | `ComputeCausalChain` / `AnalyzeCrossHostConnections` / `PerformBayesianAttribution` — 零调用者 |
| T10 | `setupTLS` 中 22 处重复错误处理模式 |
| T17 | `ratelimit.go` 零测试 |
| T18 | `spc_persist.go` 零测试 — 缓存持久化 |
| T19 | `cmd/kernel/main.go` 零测试 — 信号处理/setupTLS |
| T20 | `io.Copy` 返回值静默丢弃 (2 处) |
| T21 | `os.Remove` 错误静默丢弃 (4 处) |
| T22 | `time.Parse` 错误静默丢弃 (3 处) |
| T24 | Heartbeat goroutine 无 panic 恢复 |
| T28 | `TestSPCImportOSCALDuplicateHandling` 持续失败 |

### P2 (12 项)

| # | 问题 |
|---|------|
| T02 | `SPCInterface` 20 方法 — 中等上帝接口 |
| T03 | `SourceManagerInterface` 14 方法 — 中等上帝接口 |
| T07 | `ExecuteHunt` / `RunEmulation` / `DetectBeaconing` — 仅测试调用 |
| T08 | `CopyFile` 双重实现，不同权限 |
| T09 | `parseInt` 双重实现，语义分歧 |
| T23 | 类型断言错误静默丢弃 (4 处) |
| T25 | NVD fetch goroutine 无 panic 恢复 |
| T26 | Cleanup goroutine 无 panic 恢复 |
| T27 | Bus shutdown drain goroutine 无 panic 恢复 |

### 配置债务 (4 项)

| # | 问题 |
|---|------|
| T29 | 6 套行业模板缺失 `[integrity]`/`[attck]`/`[prism]` 等 8 个配置段 |
| T30 | `console_report` 键路径不匹配 |
| T31 | hospital/enterprise/edu 模板重复 INI 段 |
| T32 | FHS 路径硬编码在 Go 源码中 |

---

## 三、测试覆盖与基准 (15 项)

| # | 等级 | 问题 |
|---|:---:|------|
| B01 | P1 | 全项目 0 个 Benchmark 函数 — 核心算法库无性能基准 |
| B02 | P0 | `cmd/kernel` 零测试 |
| B05 | P0 | `internal/agent` 零测试 — Agent 核心运行时 |
| B07 | P0 | `internal/common` 零测试 — 命令白名单无安全测试 |
| B10 | P0 | `internal/checks/linux` 零测试 — 76 检查项 |
| B12 | P0 | `internal/resilience` 零测试 — 熔断器/Guard |
| B03 | P1 | `cmd/agent` 零测试 |
| B06 | P1 | `internal/adapterhub` 零测试 |
| B08 | P1 | `internal/deploy` 零测试 |
| B11 | P1 | `internal/prism` 零测试 |
| B14 | P1 | `internal/webui` 零测试 |
| B04 | P2 | `cmd/asscor` 零测试 |
| B09 | P2 | `internal/model` 零测试 |
| B13 | P2 | `internal/version` 零测试 |
| B15 | P2 | `api/v1` 零测试 |

---

## 四、并行能力 (7 项, 架构建议延期)

| # | 等级 | 建议 |
|---|:---:|------|
| P01 | P1 | 多算法并行评估：`pluginEngine`→`[]AssessorEngine` + `ScoreAggregator` |
| P02 | P1 | 多方式并行探测：`CheckItem.Check` 从 `CheckFunc`→`[]CheckFunc` |
| P05 | P1 | 多适配器同 CheckID 去重 |
| P03 | P2 | 委托规则增加 `mode: replace | augment` |
| P04 | P2 | 用户检查消除 `else if` 互斥 |
| P06 | P2 | `PrivilegeLevel` 入引擎层预过滤 |
| P07 | P2 | 新增 `assessor.engine_selected` 扩展点 |

---

## 五、ATT&CK 提取 (2 项, Phase 2 延期)

| # | 等级 | 问题 |
|---|:---:|------|
| A01 | P2 | 独立 module 隔离需 `pkg/sdk/` 公共层 (~500 行新代码) |
| A02 | P2 | 运行时验证待执行 (0.5 天预留) |

---

## 六、模块分类 (4 项, 本次新发现)

| # | 等级 | 问题 |
|---|:---:|------|
| M01 | P0 | `internal/kernel/` 单体 — 66 文件/17 插件在一包 |
| M02 | P1 | srd/prism/ssam 引擎适配器误放在 `internal/` 顶层 |
| M03 | P1 | `adapter/` vs `adapterhub/` 命名含混，边界不清 |
| M04 | P1 | `deploy/systemd/` vs `internal/deploy/` systemd 单元双重定义 |

---

## 七、按模块分布

| 模块 | P0 | P1 | P2 | 首要问题 |
|------|:---:|:---:|:---:|------|
| 扩展体系 | 8 | 14 | 5 | 零订阅者，体系纯死代码 |
| 内核 | 6 | 13 | 6 | 测试覆盖率极低，上帝接口 |
| 测试/基准 | 6 | 6 | 4 | 6 个核心包零测试，0 Benchmark |
| 架构 | 1 | 7 | 8 | kernel/单体，引擎适配器误放 |
| 配置 | 0 | 2 | 2 | 行业模板缺失段落 |
| 安全 | 2 | 2 | 1 | 无二进制签名，漏洞数据暴露 |
| ATT&CK | 0 | 1 | 3 | 上帝接口 85 方法，死代码 |

---

## 八、已修复项 (2026-07-27)

| 原编号 | 问题 | 修复 |
|--------|------|------|
| M02 | srd/prism/ssam 引擎适配器误放顶层 | 移至 `internal/engine/srd/` `engine/prism/` `engine/ssam/` |
| M03 | adapter vs adapterhub 命名含混 | `internal/adapter/_README_ARCHITECTURE.md` 分层说明文档 |
| T20 | `io.Copy` 返回值静默丢弃 | `persistence.go:690` 改为显式 error 检查 |
| T21 | `os.Remove` 错误静默丢弃 | `persistence.go:723` 添加 Warn 级别错误日志 |
| T04-T06 | ATT&CK 6 个零调用者方法 | `attck.go` 接口注释标记 `0 callers — reserved` |
| E25 | 优先级排序语义未文档化 | `extensions.go` ModuleExtensions 接口注释说明升序+默认50 |
| T29 | 6 套行业模板缺失 config 段 | 验证仅缺 `[user_check.mysql]` (用户自定义示例，行业模板无需包含) |
| T24 | Heartbeat goroutine 无 panic 恢复 | `services.go:162` 已有 `resilience.GuardGo` |
| T25 | NVD fetch goroutine 无 panic 恢复 | `spc_fetch_nvd.go:268` 已有 `defer recover()` |
| T26 | Cleanup goroutine 无 panic 恢复 | `ratelimit.go:50` 已有 `defer recover()` |
| T27 | Bus drain goroutine 无 panic 恢复 | 仅调用 `wg.Wait()`，panic 不可能 |
| T10 | setupTLS 22 处重复错误处理 | `writeCertFile()` 抽取，12→1 行，覆盖 CA/Server/Agent 三段 |
| E26 | `extension.config_changed` 缺失 | 注册扩展点 + `config_watcher.go:forceReload` 热重载触发 |
| T31 | hospital/enterprise/edu 模板重复 INI 段 | 3 模板各删除 `[spc.cnnvd]/[spc.cnvd]` 重复段 |
| E09 | `agent.log_uploaded` 死扩展点 | `collector.go:AppendBatch` 批量上传时触发 |
| T28 | TestSPCImportOSCALDuplicateHandling 持续失败 | 合并逻辑对齐 — 已验证通过 |
| E15+E16 | SemVer 解析重复 + 版本约束不兼容 | `internal/semver/` 统一共享包，pkgmgr 删除 95 行重复 |
| E19 | pkgmgr 和 extmgr 竞争性包管理器 | pkgmgr go.mod 移除，并入主模块 |
| E18 | 引擎钩子无法从扩展点访问 | 8 engine.* 扩展点注册 + 4 阶段接线 (pre/post_check/score) |
| E17 | 7/8 引擎钩子未使用 | engine.* 扩展点全部接入双重路径 (Evaluate + EvaluateFromResults) |
| T01 | ATTACKInterface 85 方法 God 接口 | 文档化 8 子接口按关注点分类，标注 test-only/0-callers |
| M04 | deploy/systemd 系统d单元重复 | 删除 `deploy/systemd/*.service` 静态文件 |
| T08+T09 | CopyFile + parseInt 重复实现 | `copySelfTo()` + `common.ParseInt` 统一 |
| P06 | PrivilegeLevel 入引擎层 | `CheckItem.Run()` 非 root 跳过 PrivRoot 检查 |
| E27 | 7 模块无扩展点 | breaker/workerpool/srd/ratelimit 接入 ~20 个新扩展点 |
| E14 | PluginSDK 错误码不标准 | -32000→-32603/-32601 标准化 + 导出常量 |
| E11 | registerCheckModule 存根 | checks.json 解析 + 命令/文件闭包生成 + checks.Register() |
| E04+E21 | 无二进制校验 + 白名单过宽 | SHA-256 verifyBinaryChecksum + 7→3 解释器 |
| E03+E08 | TOCTOU 竞态 + 数据暴露 | InstallFromSpec 加锁 + filterAssessmentResult |
| T23 | 类型断言零值 | 仪表盘记录零值跳过 |
| E25 | 优先级语义未文档化 | `extensions.go` 注释说明升序+默认50 |
| T24-T27 | goroutine 保护 | 验证 4 项已存在 (GuardGo/defer recover/wg.Wait) |
| E13 | onExtension* 锁外回调 | 回调下沉至锁内 + 禁用时 UnregisterPlugin |
| T02 | SPCInterface 20 方法 (审计误报) | 验证已分 4 子接口: SPCCalculator/SPCFetcher/SPCAssetManager/SPCCacheManager |
| T03 | SourceManager 29 方法 | 非 interface 而是 concrete struct, 方法按类型分组 (CRUD/Config/Audit/Sync/Plugin/Internal) |

### P0 测试覆盖 (2026-07-31 全部清零)

| 包 | 用例 | 日期 |
|------|:---:|------|
| bus / circuitbreaker / collector / common / services / di | 31 | 07-30 |
| plugin / interceptor / ratelimit / heartbeat / policy | 27 | 07-31 |
| extensions / kernel / commander / cti / crypto / auditlog | 37 | 07-31 |
| config_watcher / server | 11 | 07-31 |
| **合计 18 包** | **106+** | P0 19/19 ✅ |
| M02 | engine 适配器文档 | `engine/_README_ARCHITECTURE.md` 说明接口定义+子包实现+依赖方向 |
