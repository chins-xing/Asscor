# ASSCOR 文档索引

## 白皮书 (Whitepapers)

| 文档 | 说明 |
|------|------|
| [项目篇章-系统安全可接受性模型.md](项目篇章-系统安全可接受性模型.md) | SSAM 理论基础与核心概念 |
| [工程实现白皮书.md](工程实现白皮书.md) | ASSCOR 工程架构与实现细节 |
| [SPC安全态势计算模块技术白皮书.md](SPC安全态势计算模块技术白皮书.md) | 安全态势计算模块公式与数据源 |
| [APT攻击分析与检测增强白皮书.md](APT攻击分析与检测增强白皮书.md) | ATT&CK V19 集成与 APT 检测增强 |
| [ASSCOR 使用手册.md](ASSCOR%20使用手册.md) | 用户操作指南与配置说明 |
| [ASSCOR 扩展体系白皮书.md](ASSCOR%20扩展体系白皮书.md) | 插件/扩展/适配器开发指南 |
| [ASSCOR 扩展开发指南.md](ASSCOR%20扩展开发指南.md) | **面向使用者的扩展编写实战指南（8种扩展类型完整代码示例）** |
| [ASSCOR 扩展白皮书：内核安全域.md](ASSCOR%20扩展白皮书：内核安全域.md) | kernel_security 域的设计与实现 |
| [ASSCOR 外部接入源完整清单.md](ASSCOR%20外部接入源完整清单.md) | 21个外部工具适配器详情 |
| [SSAM接口规范与接入指南.md](SSAM接口规范与接入指南.md) | SSAM Provider 接口与集成指南 |
| [SSAM与SRD算法可移植性白皮书.md](SSAM与SRD算法可移植性白皮书.md) | 算法跨项目可移植性论述 |
| [Systemic Risk Dynamics（SRD）白皮书.md](Systemic%20Risk%20Dynamics（SRD）白皮书.md) | Prism/SRD 风险传播模型 |
| [等级保护检查项映射手册.md](等级保护检查项映射手册.md) | GB/T 22239-2019 等保映射 |

## 审计报告 (Audits)

→ [audits/](audits/)

| 文件 | 说明 | 日期 |
|------|------|------|
| [audits/PROJECT_COMPLETION_AUDIT.md](audits/PROJECT_COMPLETION_AUDIT.md) | 全量项目完成度审查 | 2026-06-18 |
| [audits/ARCHITECTURE_DEEP_DIVE.md](audits/ARCHITECTURE_DEEP_DIVE.md) | 深度架构分析 (14章) | 2026-06-05 |
| [audits/SPC_MODULE_AUDIT.md](audits/SPC_MODULE_AUDIT.md) | SPC 模块专项审计 | 2026-05-27 |
| [audits/ATTACK_MODULE_AUDIT.md](audits/ATTACK_MODULE_AUDIT.md) | ATT&CK V19 模块专项审计 | 2026-05-27 |
| [audits/history/](audits/history/) | 历史修复报告 (7篇) | 2026-05-27 ~ 06-01 |
| [audits/archive/](audits/archive/) | 已取代的旧版审计 (5篇) | 2026-05-26 ~ 06-03 |

## 架构审查报告 (Architecture Review)

→ [asscor-architecture-review/](asscor-architecture-review/)

| 章节 | 标题 | 内容 |
|------|------|------|
| [Chapter-01](asscor-architecture-review/Chapter-01-Project-Overview.md) | 项目概述 | ASSCOR 定位为"评估运行时"而非安全扫描器 |
| [Chapter-02](asscor-architecture-review/Chapter-02-Problem-Statement.md) | 问题陈述 | 现有评估范式的碎片化与"可接受性"的缺失 |
| [Chapter-03](asscor-architecture-review/Chapter-03-Conceptual-Model.md) | 概念模型 | Evidence → Context → Policy → Assessment → Decision |
| [Chapter-04](asscor-architecture-review/Chapter-04-Assessment-Engine.md) | 评估引擎 | SSAM 作为评估模型的实现, 领域分解与可解释性 |
| [Chapter-05](asscor-architecture-review/Chapter-05-Runtime-Architecture.md) | 运行时架构 | 持续运行的评估平台 vs 一次性命令行工具 |
| [Chapter-06](asscor-architecture-review/Chapter-06-Plugin-Architecture.md) | 插件架构 | 证据提供者/知识提供者/评估扩展/输出提供者四类 |
| [Chapter-07](asscor-architecture-review/Chapter-07-Evidence-Architecture.md) | 证据架构 | 证据独立于评估引擎, 归一化/验证/可追溯 |
| [Chapter-08](asscor-architecture-review/Chapter-08-System-Architecture.md) | 系统架构 | 六层分层架构: 运行时→插件→证据→评估→决策→呈现 |
| [Chapter-09](asscor-architecture-review/Chapter-09-Kernel-Architecture.md) | 内核架构 | 内核仅负责基础设施, 不执行安全评估 |
| [Chapter-10](asscor-architecture-review/Chapter-10-Lifecycle-Management.md) | 生命周期管理 | 组件 Init→Start→Stop→Destroy 统一生命周期 |
| [Chapter-11](asscor-architecture-review/Chapter-11-Provider-Service-Registry.md) | 提供者与服务注册表 | 依赖注入, 服务发现, 松耦合 |
| [Chapter-12](asscor-architecture-review/Chapter-12-Event-Bus-Architecture.md) | 事件总线架构 | 发布/订阅解耦, 运行时事件/评估事件/配置事件 |
| [Chapter-13](asscor-architecture-review/Chapter-13-Scheduler-Task-Management.md) | 调度器与任务管理 | 周期性/事件驱动/手动/一次性 四种调度策略 |
| [Chapter-14](asscor-architecture-review/Chapter-14-Configuration-System.md) | 配置系统 | Load→Parse→Validate→Normalize→Publish→Use 生命周期 |
| [Chapter-15](asscor-architecture-review/Chapter-15-Engineering-Evaluation.md) | 工程评估 | 模块化/可扩展性/可维护性/运行时成熟度评估 |
| [Chapter-16](asscor-architecture-review/Chapter-16-Architectural-Review.md) | 架构审查 | 稳定层/可变层分离, 长期演进策略 |
| [Chapter-17](asscor-architecture-review/Chapter-17-Architectural-Risks-Technical-Debt.md) | 架构风险与技术债务 | 内核膨胀/层泄露/接口不稳定/概念漂移 |
| [Chapter-18](asscor-architecture-review/Chapter-18-Future-Evolution.md) | 未来演进 | AI评估引擎/图推理/证据图/云运行时/分布式调度 |
| [Chapter-19](asscor-architecture-review/Chapter-19-Final-Assessment.md) | 最终评估 | 项目架构身份: 基础设施→证据→评估→决策 |
| [Chapter-20](asscor-architecture-review/Chapter-20-Engineering-Philosophy.md) | 工程哲学 | 架构优先于功能, 简单优先于复杂, 分离优于耦合 |

## 外部规范 (External Specs)

→ [superpowers/](superpowers/)

| 文件 | 说明 |
|------|------|
| [superpowers/specs/2026-06-09-prism-ir-design.md](superpowers/specs/2026-06-09-prism-ir-design.md) | Prism IR 设计规范 |
