# 审计报告索引

## 活跃报告 (Active)

| 文件 | 日期 | 说明 |
|------|------|------|
| [SECURITY_PERFORMANCE_AUDIT_2026-08-14.md](SECURITY_PERFORMANCE_AUDIT_2026-08-14.md) | 2026-08-14 | 安全与性能审计 — 命令执行/密钥/TLS/路径遍历/输入验证 + goroutine/内存/锁/IO；1 安全 P1（命令输出日志）2 性能 P1（SPC 热路径 ToLower/日志） |
| [STABILITY_AUDIT_2026-08-14.md](STABILITY_AUDIT_2026-08-14.md) | 2026-08-14 | 全项目稳定性审计 — 错误处理/日志存留/模块与扩展包错误隔离/内核稳定性；2 P1（persistence 静默丢 sync 错误、pluginsdk 无 recover） |
| [CODE_QUALITY_AUDIT_2026-08-14.md](CODE_QUALITY_AUDIT_2026-08-14.md) | 2026-08-14 | 微内核重构后代码质量审计 — 契约上移/stub 一致性/门控构建；修复 resilience stub API 与 extmgr.SetAssessor 接线 |
| [PROJECT_COMPLETION_AUDIT.md](PROJECT_COMPLETION_AUDIT.md) | 2026-06-18 | **全量项目完成度审查** — 14大子系统逐项评级, 76检查项, 21适配器, 139测试函数 |
| [ARCHITECTURE_DEEP_DIVE.md](ARCHITECTURE_DEEP_DIVE.md) | 2026-06-05 | **深度架构分析** — 插件系统/DI/总线/SSAM V2.0/SPC/ATT&CK V19/适配器/扩展管理器 14章 |
| [SPC_MODULE_AUDIT.md](SPC_MODULE_AUDIT.md) | 2026-05-27 | SPC 安全态势计算模块专项审计 |
| [ATTACK_MODULE_AUDIT.md](ATTACK_MODULE_AUDIT.md) | 2026-05-27 | ATT&CK V19 威胁分析模块专项审计 |

## 历史修复报告 (History)

→ [history/](history/) — 记录各阶段修复的详细变更

| 文件 | 日期 | 说明 |
|------|------|------|
| [history/2026-05-27_全项目深度代码审计与修复报告.md](history/2026-05-27_全项目深度代码审计与修复报告.md) | 2026-05-27 | 第一批修复: 基础设施与协议层 (6项H级+8项M级+5项L级) |
| [history/2026-05-28_SSAM纯函数化解耦报告.md](history/2026-05-28_SSAM纯函数化解耦报告.md) | 2026-05-28 | SSAM 引擎抽取为独立 go module |
| [history/2026-05-28_ACI_SPC模块完成度审计报告.md](history/2026-05-28_ACI_SPC模块完成度审计报告.md) | 2026-05-28 | ACI/SPC 模块完成度评估 |
| [history/2026-05-28_耦合性专项审计报告.md](history/2026-05-28_耦合性专项审计报告.md) | 2026-05-28 | 模块间耦合度分析 |
| [history/2026-05-28_双Assessor统一修复报告.md](history/2026-05-28_双Assessor统一修复报告.md) | 2026-05-28 | Assessor 重复调用修复 |
| [history/2026-05-28_最终修复报告.md](history/2026-05-28_最终修复报告.md) | 2026-05-28 | 第二批修复收尾 |
| [history/2026-06-01_全项目代码审计报告.md](history/2026-06-01_全项目代码审计报告.md) | 2026-06-01 | 第三次全量代码审计 |

## 已归档 (Archive)

→ [archive/](archive/) — 已被更全面的报告取代

| 文件 | 原日期 | 被取代原因 |
|------|--------|-----------|
| [archive/ARCHITECTURE_ANALYSIS.md](archive/ARCHITECTURE_ANALYSIS.md) | 2026-06-05 | → ARCHITECTURE_DEEP_DIVE.md |
| [archive/CODE_AUDIT_FULL.md](archive/CODE_AUDIT_FULL.md) | 2026-05-27 | → PROJECT_COMPLETION_AUDIT.md |
| [archive/CODE_AUDIT_检查项与数据模型.md](archive/CODE_AUDIT_检查项与数据模型.md) | 2026-05-27 | → PROJECT_COMPLETION_AUDIT.md |
| [archive/CODE_WIKI.md](archive/CODE_WIKI.md) | 2026-05-26 | 早期百科 (53KB), 被结构化审计取代 |
| [archive/coupling_audit_20260603.md](archive/coupling_audit_20260603.md) | 2026-06-03 | → ARCHITECTURE_DEEP_DIVE.md 第2章 |
