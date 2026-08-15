# ASSCOR — 安全可接受性评估运行时

> **ASSCOR**（**ASS**ess + **COR**e）是一个开源的、面向生产的安全可接受性评估平台。
> 它不替代漏洞扫描器、SIEM 或渗透测试，而是作为上述系统的**"安全可接受性"聚合判断层**，
> 提供面向业务风险的统一视图。
>
> ASSCOR 内置两个核心算法引擎：
> - **SSAM 2.0**（系统安全可接受性模型）— 多维度可计算的评估公式
> - **Prism / SRD**（系统风险动力学）— 三层风险传播与预测引擎
>
> 全视、警惕、永不闭目——持续监控每一台主机的安全状态，不放过任何一个弱点。
>
> **SSAM V2.0 已独立为开源 Go 模块 [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam)**
> （位于 `ssam-lib/`），为零外部依赖的纯函数式引擎。
> **Prism 已独立为 [github.com/chins-xing/prism](https://github.com/chins-xing/prism)**
> （位于 `prism-lib/`），同样为零外部依赖。ASSCOR 平台通过薄适配层委托给这两个独立库。

**算法版本：** SSAM 2.0 | **项目版本：** ASSCOR v0.2.3  
**日期：** 2026-08-12  
**状态：** 发布  
**许可证：** [Apache License 2.0](LICENSE)

> ⚠️ **基本前提——也是最基本的限制**
>
> SSAM 是一个**数学模型**。它的分数是**近似，不是真理**。
>
> 一个 85 分的主机不一定比一个 72 分的更安全。评分告诉你的是模型
> 框架内可量化的维度表现——不是安全的全部。安全有太多无法被公式
> 捕获的东西：上下文、攻击者动机、管理员警觉性、未知的零日漏洞。
>
> **我们设计模型。但我们设计的不是现实。**
> 请永远把这个分数当作决策参考，而非决策本身。
>
> ---
>
> **Goodhart 定律**（一个指标成为目标后就不再是好指标）对安全评分
> 同样成立。如果管理员开始只为提高分数而修复被扣分的项，忽略未被
> 模型覆盖的风险，那么分数上升反而意味着真实安全在下降。
>
> SSAM 无法防止这种博弈。能防止的是制度：不要用分数奖惩人；不要
> 把分数写进服务等级协议；不要让任何单一数字替你做判断。
>
> 不要重蹈 CVSS 的覆辙——大家只看分不看上下文。
>
> 如果有一天，人们开始忘记分数只是模型——而不是它所描述的真相——
> 那才是最危险的安全漏洞。
>
> —— ASSCOR Maintainers

## 摘要

ASSCOR 是一个**运行时可扩展的安全评估平台**。它通过四个互不重叠的核心能力域——攻击面管理、业务连续性、操作可信度、韧性——与独立边缘修正因子、动态威胁系数及安全态势计算相结合，将系统安全状态量化为一个 0–100 的分数。

> **微内核架构：** ASSCOR 内核已从"上帝包"重构为**微内核 + build-tag 可选插件**架构。`internal/kernel/` 仅保留扩展框架（DI 容器、消息总线、扩展点注册表、插件生命周期）与生命周期引擎、接口契约，以及拦截器链等核心基础设施；全部功能模块（评估引擎、SPC、策略、CTI、指令下发、心跳、ATT&CK、日志收集、数据源管理、持久化、SRD 封装、通信服务、Web 仪表盘、完整性、韧性、检查项、适配器）已剥离为独立包，通过 Go build-tag 按需编译，实现**默认构建零膨胀**（无 tag 编译最小内核，全 tag 编译完整功能）。历史存储（historicalstore）、拓扑注册（topology）、OSCAL 导出（oscal）为常编译纯工具包。

ASSCOR 不替代漏洞扫描器、SIEM 或渗透测试，而是作为上述系统的"安全可接受性"聚合判断层，提供面向业务风险的统一视图。同时，SSAM 2.0 已实现与中国等级保护制度（GB/T 22239-2019）的双向映射，可作为等保合规效果的持续性量化验证工具。

其核心算法引擎 **SSAM 2.0**（系统安全可接受性模型）的核心创新包括：

- 四核心域互斥设计，消除重复评分
- 边缘因子以乘法修正方式反映高级防护缺失
- 动态威胁系数结合实时情报使评估结果随威胁环境变化
- 管理员完全自定义，权重、阈值、检查项均可按需调整
- 韧性维度强化，新增可接受沦陷指标（ACI），量化"部分失陷后的生存能力"
- 安全态势计算模块（SPC），将全局漏洞情报本地化，为每台主机生成独立的态势修正
- 等级保护制度接入，实现合规要求与安全能力的双向映射

## 1. ASSCOR 平台架构

ASSCOR 采用微内核 + 插件架构，通过 **gRPC + JSONRPC 双协议栈** 通信，支持 mTLS 加密。Kernel 负责评估协调和指令分发，Agent 负责本地检查执行与状态上报。核心能力见下表，完整细节见 [使用手册](docs/ASSCOR%20使用手册.md)。

| 组件 | 功能 |
|------|------|
| **内核 (Kernel)** | 微内核运行时：DI 容器、事件总线、熔断器、拦截器链、插件生命周期 |
| **评估引擎** | SSAM V2.0 三层加权平均评分 + SPC 安全态势修正 + ATT&CK V19 威胁分析 |
| **Agent** | 80 检查项并发执行，CPE 自动生成，HMAC 签名命令执行 |
| **21 个适配器** | Trivy/Nuclei/Lynis/Suricata 等 Fetch→Parse→Map→Validate 管线 |
| **Prism/SRD** | 三层风险引擎：Core(动态评分)→Semantic(四态模糊)→Inference(马尔可夫预测) |
| **扩展体系** | 90 个内核扩展点 (84 平台 + 6 生命周期) + 9 种 extmgr 类型 + 可选扩展包体系 (pkgmgr + package.json) |
| **微内核剥离** | 内核仅保留扩展框架+生命周期+接口契约；全部功能模块剥离为 build-tag 可选插件 (零膨胀默认构建) |
| **安全防护** | HMAC 评估签名 + 算法自校准完整性校验 + SHA-256 二进制校验 + mTLS |
| **Web 仪表盘** | 主机详情 + 历史趋势 + 边缘因子可视化 |
| **CLI** | 交互式终端 + Unix socket 远程连接 + 15 运维命令 |
| **部署** | 单二进制安装/升级/卸载 + systemd + Docker + FHS 布局 |

## 2. SSAM 2.0 评估引擎

### 2.1 四个互斥核心域

| 核心域 | 核心问题 | 典型检查项 |
|--------|----------|-----------|
| 攻击面管理 | 被动防御面是否最小化？ | 无用服务关闭、非必要端口静默、强认证策略、SSH 安全配置 |
| 业务连续性 | 安全策略是否影响业务运行？ | 关键服务状态、业务端口可达性、资源充裕度、备份机制 |
| 操作可信度 | 配置与操作是否防篡改且可追溯？ | 关键文件权限、审计日志、命令历史防篡改、供应链完整性、强制访问控制 |
| 韧性 | 系统在持续压力与部分失陷后能否保持核心防御？ | 自动封禁精度、内核抗压参数、连接数限制、服务降级策略、可接受沦陷指标 (ACI) |

各域得分范围 0–100，所有检查项互斥，避免同一弱点被重复扣分。

**互斥性声明：** 每项原子检查只归属唯一核心域。例如 SSH 配置（端口、密码策略）仅出现在攻击面管理中；而 SSH 审计日志的完整性则属于操作可信度。评估引擎在加载检查项时会执行冲突检测，确保无交叉。

### 2.2 边缘因子（乘法修正）

某些全局性安全能力无法归属单一域，但缺失时会削弱整体安全水平。边缘因子以乘法修正方式反映高级防护缺失。

> **SSAM 1.3 变更：** 供应链校验、自动封禁、资源紧张等项已移入对应核心域检查项（OT-004、RS-003、BC-003），以消除双重扣分。SYN Cookie 仍保留为边缘因子（因其在网络层全局生效）。SSAM V2.0 引入三层语义模型（本征/暴露/威胁），以独立风险层取代旧版 ThreatCoeff/SPCScore 双重罚分机制。

| 独立属性 | 缺失时因子 | 说明 |
|----------|------------|------|
| 双因素认证缺失 | ×0.85 | 未配置二次认证（EF-002FA） |
| SYN Cookie 未开启 | ×0.75 | 网络层全局防护缺失（EF-SYNCOOKIE） |
| SELinux 未启用 | ×0.80 | 强制访问控制缺失（EF-SELINUX） |
| AppArmor 未启用 | ×0.82 | 强制访问控制缺失（EF-APPARMOR） |
| SIEM 集成缺失 | ×0.90 | 安全事件集中管理缺失（EF-NO-SIEM） |
| IDS/IPS 缺失 | ×0.88 | 入侵检测/防御系统缺失（EF-NO-IDS） |
| 三因素认证未达标 | ×0.82 | 等保四级级联：触发时覆盖 EF-002FA 为 ×0.82（EF-3FA，CascadeOnly） |

所有因子数值均可由管理员调整。因子和权重均支持按节点标签/组覆盖，未覆盖者继承全局默认值。等保四级框架启用时自动加载 `edge_factors.level4_override` 覆盖配置。

### 2.3 威胁态势系数 μ

通过集成威胁情报（如 OTX、MISP），系统实时计算当前威胁系数 μ，范围 0.60–1.00。默认 1.00，当出现高危漏洞或活跃攻击时自动下调，立即影响所有受管主机的评估结果。

## 5. 评估公式

SSAM 2.0 的最终评估值由核心域加权得分、边缘因子修正、威胁态势系数及安全态势计算修正共同决定。SPC 采用平方和开方（√∑Penalty²）替代线性求和，防止大量低危 CVE 过早触底。

$$
SSAM_{final} = \left( \frac{\sum_{i=1}^{4} (S_i \times W_i)}{\sum_{i=1}^{4} W_i} \right) \times \prod_{j=1}^{m} M_j \times \mu \times P_{score}
$$

其中：

- $S_i$：第 i 个核心域得分（0–100）
- $W_i$：该域权重，默认值：攻击面管理 35，业务连续性 25，操作可信度 25，韧性 15
  - **权重之和推荐为 100；若非 100，引擎自动按 $\sum W_i$ 归一化，确保评分结果不受权重配置误差影响**
- $M_j$：第 j 个独立边缘因子（0.0–1.0）
- $\mu$：威胁态势系数（0.6–1.0）
- $P_{score}$：由 SPC 输出的个体化态势分数修正因子（0.60–1.00，详见第 5 章）

> **规划中**：SPC 可选输出的核心域权重临时偏移 $P_{weight}(i)$（总和为 0），用于在检测到某域防护与当前威胁极不匹配时动态调整权重聚焦。该偏移由 SPC 模块生成但尚未集成到评分公式，将在后续版本启用。

可接受阈值 T 由管理员设定（默认 80）。当 $SSAM_{final} \geq T$ 时，系统安全状态判为可接受。

## 6. 韧性指标增强：可接受沦陷指标（ACI）

传统的韧性评估关注系统抵御攻击的能力，但现实中"完全不被攻破"难以保证。SSAM 2.0 在韧性核心域中引入可接受沦陷指标（ACI），用于衡量：当系统的某一部分已被攻破时，能否将损害控制在可接受范围内，并维持核心业务的运行。

ACI 与抗打击韧性指标互为补充：前者衡量"破防后"，后者衡量"破防前"。两者不重叠、不重复扣分。

### 6.1 ACI 的设计目标

- **隔离能力**：受影响组件能否被快速隔离，阻止横向移动
- **最小权限有效性**：攻击者获得的权限是否被限制在极小的范围内
- **数据保护**：敏感数据是否加密、备份是否离线且不可篡改
- **恢复能力**：从检测到沦陷到恢复正常服务的时间（MTTR）
- **监控留存**：攻击者能否轻易清除入侵痕迹

### 6.2 ACI 的评估假设

ACI 评估默认假设攻击者已获得目标组件的基础访问权限（如 Web 服务用户、低权账户），并以此为前提衡量损害扩散范围。该假设提供了可比较的工程化基线。

### 6.3 ACI 评估项与计分

ACI 各项的扣分值直接在韧性域百分制内加减，扣至 0 分为止。

| 检查项 | 评估方法 | 默认扣分 |
|--------|----------|----------|
| 网络分段验证 | 检查 VLAN/防火墙策略，确认关键业务段是否隔离 | -15 |
| 本地管理员密码唯一性 | 是否部署 LAPS 或类似机制 | -10 |
| 离线备份完整性 | 验证最新备份可恢复且未被加密勒索 | -20 |
| 端点检测响应 (EDR) 部署 | 检查 EDR 是否运行并可检测凭证转储等行为 | -10 |
| 审计日志远程实时备份 | 日志是否发送到独立于被管主机的系统 | -10 |
| 应用程序白名单 | 是否限制可执行文件来源 | -10 |
| 数据防泄露 (DLP) 措施 | 敏感数据出口是否受控 | -5 |

每项扣分值可由管理员自定义配置。

## 7. 安全态势计算模块（SPC）

### 7.1 设计目标

SSAM 2.0 引入安全态势计算模块（Security Posture Calculator，SPC），解决"全局漏洞情报"与"单台主机实际风险"之间的鸿沟。SPC 通过持续追踪全球权威漏洞库，结合本地资产清单，为每台受管主机输出个体化的态势修正向量。

### 7.2 数据源体系

- **一级数据源**：NVD、CNNVD、CNVD 等全球漏洞库
- **二级数据源**：EPSS（漏洞利用预测）、CISA KEV（已知在野利用目录）
- **三级数据源**：Agent 采集的本地软件清单、服务、端口、拓扑

### 7.3 态势修正向量

SPC 为每台主机输出修正向量 $\vec{P_h} = (P_{score}, P_{weight}, P_{action})$：

- $P_{score}$：态势分数修正因子（0.60–1.00），作为乘数进入最终公式
- $P_{weight}$：核心域权重临时偏移（总和为 0）
- $P_{action}$：建议响应动作（如 isolate_host、notify_admin）

### 7.4 计算公式

$P_{score}$ 计算：

$$
P_{score}(h) = \max\left(0.60,\; 1.00 - \sqrt{\sum_{i=1}^{n} Penalty_i^2}\right)
$$

其中每个 CVE 的罚分为：

$$
Penalty_i = Impact(CVE_i) \times LocalFactor(CVE_i, h) \times TimeWindow(CVE_i)
$$

$$
Impact = 0.20 \cdot f_{cvss} + 0.50 \cdot f_{epss} + 0.30 \cdot f_{kev}
$$

$$
LocalFactor = MatchType \times ExposureLevel \times ControlFactor
$$

$$
TimeWindow = \max(0.3, 1.0 - days/90)
$$

EPSS 因子采用对数缩放，使高利用概率的 CVE 获得显著更高的权重：

$$
f_{epss} = \min\left(1.0,\; \frac{-\ln(1 - EPSS)}{5}\right)
$$

$P_{score}$ 下限为 0.60，防止 SPC 单方面"杀死"主机评分。多 CVE 罚分叠加采用平方和开方（√∑Penalty²）替代线性求和，防止大量低危 CVE 过早触底。

详细计算示例请参阅 [SPC 安全态势计算模块技术白皮书](docs/SPC安全态势计算模块技术白皮书.md)。

## 8. 等级保护制度接入

SSAM 2.0 已与 GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》（等保 2.0）建立映射关系。四个核心域覆盖等保"安全通信网络"、"安全区域边界"、"安全计算环境"和"安全管理中心"中可自动化评估的部分，物理安全、人员管理等人工审查项不在此列。

### 8.1 等保等级与 SSAM 阈值联动

| 等保等级 | 推荐 SSAM 阈值 | 适用场景 |
|----------|----------------|----------|
| 二级 | 65 | 一般信息系统 |
| 三级 | 80（默认） | 重要系统 |
| 四级及以上 | 90 | 关键基础设施 |

### 8.2 等保控制点映射原则

以等保三级安全计算环境为例，从身份鉴别、访问控制、安全审计、入侵防范、恶意代码防范、数据保护、备份恢复、剩余信息保护等方面推导出 53 项 SSAM 检查项，每一项均可追溯到具体的等保标准条款。所有映射详情请见第二篇章：等保检查项映射手册。

### 8.3 双向验证

ASSCOR 项目评估结果可与等保测评报告交叉验证：若等保三级通过而 SSAM < 80，可能存在配置漂移或防护未持续生效；反之若 SSAM ≥ 80 而等保未通过，则说明部分人工审查项需重点整改。

## 9. 动态扩展与社区驱动

ASSCOR 内置攻击向量插件槽（AVD），每个 AVD 定义为 {ID, 域, 检测逻辑, 分值, 紧急标记}。管理员或社区可编写 AVD 注册到引擎，使模型随威胁演进持续扩展。

## 10. 配置与管理员自定义

所有参数通过 config.ini 配置，无硬编码。支持节点标签覆盖、等保模板等。

```ini
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15

[acceptability]
threshold = 80.0
compliance_framework = GB/T 22239-2019 Level 3
```

## 11. 项目结构

```
ASSCOR/
├── cmd/
│   ├── kernel/        # 微内核服务端入口（gRPC + JSONRPC 双协议栈）
│   ├── agent/         # Agent 客户端入口（gRPC + JSONRPC）
│   └── asscor/        # 独立评估工具入口
├── ssam-lib/          # SSAM V2.0 纯函数式引擎（独立 Go module: github.com/chins-xing/ssam）
│   ├── types.go       #   V1.x 数据类型 (AssessmentInput/Output)
│   ├── types_v2.go    #   V2.0 数据类型 (RiskContext, RiskLayers, AssessmentInputV2/OutputV2)
│   ├── formulas.go    #   V1.x 公式实现 (ssam_v1.2, simple_weighted)
│   ├── formulas_v2.go #   V2.0 公式 (SSAMV20Formula, 三层语义模型)
│   ├── ir.go          #   SSAM IR JSON 中间表示导出
│   ├── ast.go         #   Formula DSL / AST 解析与求值引擎
│   ├── formulas_ast.go#   AST 驱动的公式实现
│   ├── ssam.go        #   Engine 核心：Provider 接口、校验、钩子
│   ├── engine_test.go #   完整测试覆盖
│   └── go.mod         #   独立 Go module，零外部依赖
├── prism-lib/         # Prism 风险动力学引擎（独立 Go module: github.com/chins-xing/prism）
│   ├── types.go       #   数据模型 (NodeState, PrismConfig, AssetRiskResult)
│   ├── config.go      #   默认配置 (DebtAlpha, PropCap, ScoreFloor 等)
│   ├── core.go        #   Core Layer — 确定性数值求值
│   ├── semantic.go    #   Semantic Layer — 四态模糊隶属度映射
│   ├── inference.go   #   Inference Layer — 马尔可夫链状态预测
│   ├── paths.go       #   风险传播路径搜索
│   └── go.mod         #   独立 Go module，零外部依赖
├── internal/
│   ├── kernel/        # 微内核核心（仅扩展框架 + 生命周期 + 接口契约）
│   │                   #  kernel.go/kernel_lifecycle.go — 内核引导、生命周期编排
│   │                   #  plugin.go — 插件接口、状态机、优先级/健康检查接口
│   │                   #  di.go — DI 容器 | bus.go — 消息总线 | ctxkey.go — 上下文键
│   │                   #  extensions.go/platform_extensions.go — 扩展点注册表
│   │                   #  lifecycle.go — 生命周期引擎 | locator.go — 定位器 | blocker.go — 阻断器
│   │                   #  *_interface.go/*_types.go — 各模块接口契约与共享类型
│   │                   #  interceptor.go/ratelimit.go/circuitbreaker.go/auditlog.go — 拦截器链
│   │                   #  crypto*.go — CA/证书管理 | workerpool*.go — 并发控制
│   │                   #  config_watcher.go — 配置监听 | adapter_integration*.go — 适配器集成
│   │                   #  siem_push.go — SIEM 推送 | source_manager_service.go — 源管理服务
│   ├── assessor/      # 评估引擎插件 (//go:build assessor) — AssessorModule + ScoringEngineModule
│   ├── spc/           # SPC 安全态势计算插件 (//go:build spc)
│   ├── policy/        # 策略管理插件 (//go:build policy)
│   ├── cti/           # 威胁情报插件 (//go:build cti)
│   ├── commander/     # 指令下发插件 (//go:build commander)
│   ├── heartbeat/     # 心跳监控插件 (//go:build heartbeat)
│   ├── attck/         # ATT&CK V19 插件 (//go:build attck_ext)
│   ├── collector/     # 日志收集插件 (//go:build collector)
│   ├── sourcemanager/ # 数据源管理插件 (//go:build sourcemanager)
│   ├── persistence/   # 持久化插件 (//go:build persistence)
│   ├── srdwrapper/    # SRD 封装插件 (//go:build srdwrapper)
│   ├── webui/         # Web 仪表盘插件 (//go:build webui)
│   ├── integrity/     # 完整性插件 (//go:build integrity) — HMAC 签名/算法校验/反调试
│   ├── resilience/    # 韧性插件 (//go:build resilience) — 熔断器/防护/健康
│   ├── comms/         # 通信服务插件 (//go:build comms) — server/services/grpc_server
│   ├── checks/        # 检查项库 (//go:build checks) — 80 项 Linux 检查项 + registry 框架
│   ├── adapter/       # 外部工具适配器框架 (//go:build adapter) — 21 个适配器（11 探测器 + 10 管理类），框架常编译
│   │   ├── scanner/   #   探测器适配器（Trivy, Nuclei, Lynis, OpenSCAP 等）
│   │   └── management/#   管理类适配器（Ansible, NetBox, FreeIPA, Jira 等）
│   ├── adapterhub/    # 适配器管理中枢 (//go:build adapter)
│   ├── engine/        # 评估引擎核心 + 引擎适配器 (//go:build engine) — ssam/prism/srd 子包
│   ├── historicalstore/ # 历史存储（纯工具包，常编译）
│   ├── topology/      # 拓扑注册（纯工具包，常编译）
│   ├── oscal/         # OSCAL 导出（纯工具包，常编译）
│   ├── cli/           # CLI 命令模块 + 安装/卸载/升级（internal/deploy 已并入）
│   ├── semver/        # SemVer 版本约束共享包
│   ├── extmgr/        # 扩展管理器（安装/卸载/生命周期/安全执行）
│   ├── agent/         # Agent 核心模块
│   ├── model/         # 数据模型定义
│   ├── config/        # 配置解析器（INI 格式，支持行业模板覆盖）
│   └── version/       # 版本信息
├── optional/           # 可选扩展模块与扩展包 (v0.2.3)
│   ├── algorithms/     #   算法扩展: modules/ (单模块) + packages/ (扩展包)
│   ├── pkgmgr/         #   扩展包管理器 CLI (asscor-pkg)
│   └── SCHEMA.md       #   package.json 格式规范
├── pluginsdk/          # Plugin SDK — JSON-RPC 独立进程插件运行时 (RPCPlugin 接口)
├── api/v1/            # gRPC 服务接口定义与消息类型
├── configs/           # 行业专用配置文件（政府、金融、医疗、教育等）
├── certs/             # TLS/mTLS 证书目录（已排除于版本控制）
├── docs/              # 技术文档与白皮书
├── build/             # 编译产物（Linux/Windows，已排除于版本控制）
├── config.ini         # 内核默认配置文件
└── agent.ini          # Agent 默认配置文件
```

## 3. 部署与快速开始

### 10.1 生产部署（systemd, FHS 布局）

```bash
# 单二进制安装
sudo ./ASSCOR-kernel-v0.2.3-linux-amd64 --install
sudo systemctl start asscor-kernel
sudo systemctl enable asscor-kernel  # 开机自启

# 版本检查
/opt/asscor/ASSCOR-kernel --version

# 远程 CLI（内核运行中连接）
/opt/asscor/ASSCOR-kernel --cli /opt/asscor/asscor-cli.sock

# 原地升级（无需手动停止）
sudo ./ASSCOR-kernel-v0.2.3-linux-amd64 --upgrade

# 卸载
sudo /opt/asscor/ASSCOR-kernel --uninstall
```

**FHS 文件系统布局：**

```
/etc/asscor/config.ini              # 内核配置
/etc/asscor/agent.ini               # Agent 配置
/opt/asscor/ASSCOR-kernel           # 内核二进制
/opt/asscor/agent/ASSCOR-agent      # Agent 二进制
/var/lib/asscor/                    # 数据（CVE 缓存/评估记录）
/var/log/asscor/                    # 日志
```

### 10.2 Agent 部署

```bash
sudo ./ASSCOR-agent-v0.2.3-linux-amd64 --install
sudo systemctl start asscor-agent
```

Agent 配置 `/etc/asscor/agent.ini` 支持心跳间隔、日志格式、mTLS 等。

### 10.3 Docker 部署

```bash
docker compose -f deploy/docker/docker-compose.yml up -d
curl http://localhost:8087/api/health
```

相关文件在 `deploy/docker/`：docker-compose.yml、config.docker.ini。
常用命令：`make -f deploy/Makefile docker-up/down/logs/clean`。

## 4. Prism / SRD 风险动力学引擎

Prism 是 SRD（Systemic Risk Dynamics）的工程实现——一个零外部依赖的纯函数式风险动力学引擎，独立为 Go 模块 [github.com/chins-xing/prism](https://github.com/chins-xing/prism)（位于 `prism-lib/`）。ASSCOR 平台通过 `internal/engine/prism/` 薄适配层委托调用。

**Prism 三层架构**：

| 层 | 职责 | 关键输出 |
|:---|:---|:---|
| **Core Layer** | 确定性数值求值——外部风险、传播风险、安全债务、正交化动态评分 | `PrismScore`（0-100） |
| **Semantic Layer** | 将 Core Layer 的 PrismScore 映射为四态隶属度向量 | `[μ_Stable, μ_Degraded, μ_Untrusted, μ_Collapse]` |
| **Inference Layer** | 基于马尔可夫链+贝叶斯模型预测 N 步后的状态概率分布与趋势判断 | 未来状态分布、趋势（improving/stable/degrading/collapsing） |

SRD 数据流管线（`internal/engine/srd/`）提供风险状态管理、数据处理管线及外部工具数据适配（OpenSCAP/Lynis 等），将第三方评估报告转化为 Prism 节点状态，参与拓扑风险传播计算。

## 14. 版本历史

SSAM 2.0 提供了一套严谨且可进化的安全可接受性度量标准。四个核心域与边缘因子、威胁系数、SPC 态势修正共同形成完整的风险评估体系。引入等保映射后，ASSCOR 项目既是对抗高级威胁的战术工具，也是衡量合规持续有效性的战略仪表盘。它不仅回答"系统安全吗"，更回答"在当下威胁中，我们的安全程度是否可以被接受"。

### 2.4 SSAM V2.0 项目拆分

自 SSAM V2.0 起，核心评分算法已独立为纯函数式库 [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam)（位于 `ssam-lib/`），ASSCOR 平台通过 `internal/engine/ssam/` 薄适配层委托调用：

```
┌─────────────────────────────────────────────────┐
│                  ASSCOR Platform                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Assessor │─▶│ DI       │─▶│ ssam Adapter  │  │
│  │ Module   │  │ Container│  │(internal/engine/ssam) │  │
│  └──────────┘  └──────────┘  └───────┬───────┘  │
│       │              ▲              │            │
│       ▼              │              ▼            │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Adapter  │  │ Config   │  │ ssam-lib      │  │
│  │ Pipeline │  │ Adapter  │  │(github.com/   │  │
│  └──────────┘  └──────────┘  │ asscor/ssam)  │  │
│                              └───────────────┘  │
└─────────────────────────────────────────────────┘
```

**关键设计原则：**

- **纯函数式内核**：ssam-lib 零外部依赖、无 goroutine、无锁、无 I/O、无 RPC、无插件——纯 Go 函数库
- **接口隔离**：SSAM 通过 `Provider` 聚合接口暴露能力（`ScoringProvider` + `DomainProvider` + `EdgeFactorProvider` + `HookProvider`）。V2.0 新增 `ScoringFormulaV2` 接口支持三层语义模型
- **依赖注入**：ASSCOR 通过 DI 容器绑定 `ssam.ScoringProvider` → Engine 实例，框架不直接依赖 Engine 具体类型
- **数据格式标准化**：`AssessmentInput` / `AssessmentOutput` 作为 V1.x DTO 保持向后兼容；`AssessmentInputV2` / `AssessmentOutputV2` 提供 V2.0 三层风险层详情
- **独立可用**：`github.com/chins-xing/ssam` 可被任意 Go 项目通过 `go get` 引入，无需 ASSCOR 框架
- **SSAM IR**：`AssessmentOutputV2.ToIR()` 输出机器可读的 JSON 中间表示（SSAMIR），便于下游工具链消费
- **Formula DSL / AST**：`formulas_ast.go` 提供 `ParseFormula(expression string) (FormulaAST, error)` 及 `EvaluateFormula`，支持运行时动态构造评分公式

详细接口规范与接入指南请参阅 [docs/SSAM接口规范与接入指南.md](docs/SSAM接口规范与接入指南.md)。

Prism 项目拆分已整合入 [§4 Prism/SRD](#4-prism--srd-风险动力学引擎)。

Prism 是 SRD（Systemic Risk Dynamics）理论的工程实现——一个零外部依赖的纯函数式风险动力学引擎，独立为 Go 模块 [github.com/chins-xing/prism](https://github.com/chins-xing/prism)（位于 `prism-lib/`）。ASSCOR 平台通过 `internal/engine/prism/` 薄适配层委托调用：

```
ASSCOR Platform
    │
    ├── internal/engine/prism/  (线程安全适配层：engine.go)
    │       │
    │       └── 委托给 → prism-lib/  (github.com/chins-xing/prism)
    │                        ├── types.go      — 数据模型 (NodeState, PrismConfig, AssetRiskResult)
    │                        ├── config.go     — 默认配置参数
    │                        ├── core.go       — Core Layer 确定性求值
    │                        ├── semantic.go   — Semantic Layer 四态隶属度
    │                        ├── inference.go  — Inference Layer 马尔可夫链预测
    │                        └── paths.go      — 风险传播路径搜索
    │
    └── internal/engine/srd/   (SRD 数据流管线)
                             ├── manager.go   — 风险状态管理器
                             ├── pipeline.go  — 数据处理管线
                             ├── adapter.go   — 外部工具数据适配
                             └── ...          — lynis/openscap/generic 适配器
```

**Prism 三层架构**：

| 层 | 文件 | 职责 | 关键输出 |
|:---|:---|:---|:---|
| **Core Layer** | `core.go` | 确定性数值求值——外部风险、传播风险、安全债务、正交化动态评分 | `PrismScore`（0-100） |
| **Semantic Layer** | `semantic.go` | 将 Core Layer 的 `PrismScore` 映射为四态隶属度向量 | `[μ_Stable, μ_Degraded, μ_Untrusted, μ_Collapse]` |
| **Inference Layer** | `inference.go` | 基于马尔可夫链预测 N 步后的状态概率分布与趋势判断 | 未来状态分布、趋势（improving/stable/degrading/collapsing） |

## 12. ATT&CK V19 威胁分析模块

ASSCOR v0.2.3 集成 MITRE ATT&CK V19 框架，构建了从检测、情报、仿真到评估的完整威胁分析能力链。该模块作为 μKernel 插件（`attck`，优先级 21，版本 1.0.0）运行，通过 DI 容器与 SSAM 评估引擎、SPC 态势计算器、CTI 威胁情报管理器深度集成。

### 13.1 四大核心子模块

| 子模块 | 实现文件 | 核心能力 |
|--------|----------|----------|
| **检测与分析** | `attck_detection.go` | 检测规则引擎、异常事件记录、告警关联分析、检测摘要统计 |
| **威胁情报** | `attck_ti.go` | IOC 管理、威胁行为体画像、TTP 追踪、告警情报富化 |
| **对手仿真与红队** | `attck_emulation.go` | 仿真场景管理、从 APT 组织自动生成场景、安全模式仿真执行 |
| **评估与工程** | `attck_assessment.go` | 差距分析、控制映射、缓解建议、持续改进追踪 |

### 13.2 APT 攻击分析与检测增强

在四大子模块基础上，APT 增强层提供高级威胁分析能力：

| 功能 | 实现文件 | 描述 |
|------|----------|------|
| **攻击链重构** | `attck_apt_chain.go` | 基于告警、异常、IOC 多源证据，按 ATT&CK 战术顺序自动重构多阶段攻击链 |
| **行为检测** | `attck_apt_detect.go` | 行为指标注册与评估、主机行为基线管理、C2 信标检测（间隔抖动分析） |
| **APT 归因引擎** | `attck_apt_attribution.go` | 多源证据融合（TTP 重叠 60% + IOC 匹配 40%），APT 组织匹配置信度评分 |
| **威胁狩猎框架** | `attck_apt_hunt.go` | 狩猎假设 CRUD、基于攻击转移矩阵自动生成假设、假设执行与确认 |

### 13.3 与 SSAM 模型的协同

ATT&CK 模块与 SSAM 评估体系形成双向增强闭环：

- **韧性域增强**：APT 攻击链检测结果通过事件总线（`attck.apt.chain_detected`）注入策略管理器，影响主机安全状态判定
- **SPC 联动**：APT 归因引擎输出的威胁行为体信息可与 SPC 漏洞情报交叉验证，动态调整 $P_{score}$
- **CTI 协同**：CTI 模块的威胁系数 $\mu$ 与 ATT&CK 威胁情报子模块共享数据源，确保威胁评估一致性
- **策略联动**：APT 检测告警（`attck.detection.alert`、`attck.behavioral.alert`）触发策略管理器自动响应动作

### 13.4 扩展点与事件

| 扩展点/事件主题 | 触发时机 |
|-----------------|----------|
| `attck.coverage.complete` | 覆盖率分析完成 |
| `attck.apt.matched` | APT 组织匹配检测 |
| `attck.detection.alert` | 检测告警触发 |
| `attck.detection.anomaly` | 高分异常检测 |
| `attck.apt.chain_detected` | APT 攻击链重构 |
| `attck.apt.attribution` | APT 归因执行 |
| `attck.apt.hunt_confirmed` | 威胁狩猎假设确认 |
| `attck.behavioral.alert` | 行为告警触发 |
| `attck.behavioral.beacon` | C2 信标检测 |
| `attck.emulation.complete` | 对手仿真完成 |
| `attck.assessment.complete` | 差距分析评估完成 |

### 13.5 模块架构

```
ATTACKModule (Plugin v1.0.0)
├── 检测与分析 (Detection & Analytics)
│   ├── DetectionRule 引擎 — 规则注册/评估/删除
│   ├── AnomalyEvent 记录 — 异常事件存储与查询
│   ├── AlertCorrelation — 告警关联分析
│   └── DetectionSummary — 检测统计摘要
├── 威胁情报 (Threat Intelligence)
│   ├── IOCEntry 管理 — 增删查搜、过期清理
│   ├── ThreatActorProfile — 威胁行为体画像
│   ├── TTPTrack — 战术/技术/程序追踪
│   └── AlertEnrichment — 告警情报富化
├── 对手仿真 (Adversary Emulation)
│   ├── EmulationScenario — 仿真场景 CRUD
│   ├── AutoGeneration — 从 APT 组织自动生成场景
│   ├── SafeModeExecution — 安全模式仿真执行
│   └── EmulationResult — 仿真结果记录
├── 评估与工程 (Assessment & Engineering)
│   ├── GapAnalysis — 防御差距分析
│   ├── ControlMapping — 安全控制映射
│   ├── MitigationRecommendation — 缓解建议
│   └── ImprovementTracking — 持续改进追踪
└── APT 增强层 (APT Analysis Enhancement)
    ├── AttackChainReconstruction — 多源证据攻击链重构
    ├── BehavioralDetection — 行为指标/基线/信标检测
    ├── AttributionEngine — 多源融合 APT 归因
    └── ThreatHunting — 假设驱动的威胁狩猎框架
```

## 13. 已知局限与后续工作

- ACI 基于假设攻击者已获基础权限，未覆盖所有攻陷场景
- SPC 精度依赖本地资产清单完整性和情报源质量
- 模型不评估物理安全、社会工程学等非技术向量
- 大规模环境下的检查项互斥验证和性能优化尚待持续完善

## 版本历史

- **SSAM 1.0** — 六维度原始模型
- **SSAM 1.1** — 四核心域 + 独立属性，消除维度重叠
- **SSAM 1.2** — 引入 ACI、SPC、等保映射、AVD 扩展机制、μKernel 联动
- **SSAM 1.3** — 移除4项重叠边缘因子（SYN Cookie/供应链/自动封禁/资源紧张），SPC 引入平方和衰减，增加边缘因子合规等级覆盖，内置冲突检测

### ASSCOR v0.2.3 — 2026-08-12 技术债务清偿与架构加固发布

**技术债务清偿 (87→5, 94%)**：P0 全部清零 (19/19)、内核 17 接口/类型文件拆分、25 测试文件/222 用例/5 Benchmark 覆盖全核心基础设施、10+ nil-guard 修复。

**架构变更**：引擎钩子↔内核扩展点桥接 (8 engine.* 阶段全接线)、SemVer 统一共享包 (internal/semver/)、引擎适配器归位 (srd/prism/ssam → internal/engine/)、SPC 模块独立包提取 (internal/spc/，16 文件/4,660 行)。

**安全加固**：算法自校准完整性校验 (sync.Once + init 自动计算 digest)、扩展检查命令白名单校验 (common.IsShellCommandAllowed)、Agent Goroutine 泄漏修复 (context.WithTimeout)、Agent 防重放 (5 分钟过期检查)、配置文件大小限制 (10MB)、SHA-256 二进制校验、9 处 nil-guard 缺陷修复。

**扩展体系**：extmgr↔扩展点桥接 (9 种类型)、5 死扩展点救活、扩展包体系 (pkgmgr + package.json + SCHEMA.md)、ATT&CK build-tag 分离、多算法编排可选化。

**配置与部署**：行业模板完善、deploy 消重、白名单精简单、Root 目录整理、插件 SDK 命名冲突修复 (Plugin→RPCPlugin)、适配器布局文档化。

### ASSCOR v0.2.1 — 2026-07-14 算法独立性发布

**部署与运维：** systemd 服务管控 (systemctl start/stop/reload)、FHS 合规文件系统布局 (/etc/asscor, /var/lib/asscor, /var/log/asscor)、单二进制 --install/--uninstall/--upgrade/--version 命令、Unix socket 远程 CLI (--cli)、SIGHUP 配置热重载、systemd PIDFile 集成。

**SSAM V2.0 公式修正：** 三层加权平均公式 (Intrinsic 50% / Exposure 30% / Threat 20%) 替代旧版乘积公式，新增 OpAdd AST 运算符。

**安全性修复：** 9 处 goroutine 数据竞争修复 (server/interceptor/circuitbreaker/assessor/spc/attck)、5 个插件 Stop 双调 panic 防护、RegisterFormula 功能缺陷修复、CLI 模块 headless 模式内核过早退出修复、SPC 缓存持久化修复 (Stop 阻塞导致丢失)。

**架构补全：** srd_adapters 通过 SRDPlugin wrapper 桥接注册、ATT&CK 9 个死扩展点全部接线、extmgr ExtTypeAdapter 生命周期补全、adapterhub Severity type alias 统一、适配器管线 ExecuteAdapter 统一 ApplyDelegation、CLI 类型断言 bug 修复、引擎 PhasePostReport 钩子阶段添加。

**功能扩展：** CTI OTX/MISP 威胁情报集成、Wazuh SIEM 双向 outbound 推送、备份存档系统 (hourly snapshot + daily tar.gz)、L2 HistoricalStore 趋势分析、Prism IL 贝叶斯推理模型、韧性域 RS-013~016 四项新检查、Prism ScoreFloor 0.15 优化 + Policy 预防性隔离。

**配置文件：** 6 行业模板补齐 [prism]/[attck]/[spc.cnnvd]/[spc.cnvd] 节 + 适配器路径 + 权重 key、config.ini 新增 data_dir/console_report。

### ASSCOR v0.1.3-mvp ATT&CK V19 模块扩展记录

#### ATT&CK V19 四大核心子模块

- **检测与分析子模块** — 实现检测规则引擎（注册/评估/删除/列表）、异常事件记录与查询、告警关联分析（同主机告警按战术-技术关联）、检测摘要统计
- **威胁情报子模块** — 实现 IOC 管理（增删查搜/过期清理）、威胁行为体画像（CRUD/技术匹配）、TTP 追踪（按行为体/技术查询）、告警情报富化
- **对手仿真与红队子模块** — 实现仿真场景管理（CRUD/按组织筛选）、从 APT 组织自动生成仿真场景、安全模式仿真执行、仿真结果记录
- **评估与工程子模块** — 实现差距分析（按主机评估防御覆盖率）、安全控制映射（技术→缓解措施）、缓解建议生成、持续改进追踪（进度计算/动作状态更新）

#### APT 攻击分析与检测增强

- **攻击链重构引擎** — 基于告警、异常、IOC 多源证据，按 ATT&CK 战术顺序（初始访问→执行→持久化→…→命令控制）自动重构多阶段攻击链，支持多主机关联
- **攻击链因果推理** — 20 条 ATT&CK 技术间因果规则构建有向图，提升时序排序精度和阶段置信度（最高 +0.2 加成）
- **行为检测引擎** — 行为指标注册与评估（阈值比较/窗口检测）、主机行为基线管理（指标更新/偏差检测）、C2 信标检测（网络连接时间序列间隔抖动分析，jitter<0.3 评分≥0.7）
- **群体基线** — 按角色聚合同类主机基线均值，缓解首次部署冷启动误报
- **APT 归因引擎** — 多源证据融合算法（TTP 重叠权重 60% + IOC 匹配权重 40%），APT 组织匹配置信度评分，行业对齐加成，替代行为体排序
- **贝叶斯归因网络** — 4 节点贝叶斯网络（TTP重叠/IOC匹配/行业对齐/杀伤链一致性）→ 归因概率分布推理
- **信标信誉库过滤** — 内置 12 条信誉规则（NTP/DNS/OS更新/开发工具），过滤合法低抖动服务误报
- **YARA/Sigma 规则引擎** — 支持规则加载、关键词匹配和结果输出，增强狩猎自动化
- **跨主机网络流量分析** — 按源主机聚合异常连接，计算横向移动评分，建立横向移动证据
- **威胁狩猎框架** — 狩猎假设 CRUD、基于攻击技术转移矩阵自动生成假设（告警驱动+异常驱动+信标驱动）、假设执行与确认、狩猎结果存储

#### SPC 模块增强

- **InstalledCPEs 自动生成** — Agent 端通过包名-版本解析和 vendor-product 映射表，将软件包信息转换为标准 CPE 2.3 格式字符串
- **CPE 精确版本匹配** — 实现 MatchExactVersion（精确版本比对）和 MatchVersionRange（版本范围比对），优先精确匹配
- **NVD API 并发分片请求** — 无 API Key 时 4 并发×30 天窗口，有 API Key 时 2 并发×60 天窗口，指数退避重试
- **CNNVD/CNVD 数据源接入** — 新增 CNNVDConfig/CNVDConfig 配置结构体，实现 FetchFromCNNVD/FetchFromCNVD 方法，支持中文严重等级映射
- **SPC 文件拆分** — 按功能边界将 spc.go 拆分为 spc.go（核心）、spc_fetch.go（数据拉取）、spc_match.go（CPE 匹配）、spc_persist.go（持久化）四个模块
- **SPC 缓存增量更新** — AddCVE/AddCVEs/MergeCVEs 支持 upsert 语义，已存在的 CVE 自动合并更新（EPSS 分数变化、KEV 状态更新等），避免全量替换开销

### ASSCOR v0.1.3-mvp 修复记录

#### 第一批修复（基础设施与协议层）

- **Agent 反复重连修复** — Client 层改用 `bufio.Reader.ReadBytes('\n')` 按行读取 TCP 响应，解决半包导致的 JSON 解析失败；心跳循环改用 `time.Timer` 替代 `time.Ticker`，防止 `runChecks()` 耗时导致的心跳堆积触发连续错误重连。
- **SPC 后台定时同步修复** — `fetchLoop()` 在启动时立即执行首次同步（而非等待首个 Ticker 间隔），确保内核启动后即可获得最新漏洞情报。
- **SPC CVE 缓存磁盘持久化** — 新增 `loadCacheFromDisk()` / `saveCacheToDisk()` 方法，CVE 缓存在启动时从磁盘 JSON 加载、退出时保存，避免服务重启后缓存丢失。
- **适配器结果纳入评分** — `Assessor.AssessFromResults()` 和 `Assess()` 中新增 `runAdapterPipeline()` 调用，21 个外部适配器的 Finding 通过 `NormalizedFinding.ToCheckResult()` 转换后注入评分流程，与内置检查项合并计算。
- **gRPC 原生协议实现** — 基于 `google.golang.org/grpc` 实现原生 gRPC 服务端/客户端，支持 TLS/mTLS 配置，定义 `KernelService`/`AgentService` 接口及 Protobuf 消息类型，与 JSONRPC 兼容层形成双协议栈。
- **权重热加载** — `Assessor.ReloadWeights()` 支持运行时动态更新四域权重，配合 `ConfigWatcher` 模块监控配置文件变化自动触发重载，无需重启服务。
- **AdapterIntegrationModule 注册修复** — 将 `AdapterIntegrationModule` 加入 Kernel 插件注册列表，使后台定时同步（每6小时）、事件总线发布 `adapter.findings`、按需拉取 `CollectFindings()` 功能生效。
- **行业配置文件体系** — 新增 `configs/` 目录，提供政府(config.gov.ini)、金融(config.fin.ini)、医疗(config.hospital.ini)、教育(config.edu.ini)、企业(config.enterprise.ini) 等八套行业专用配置模板。

#### 第二批修复（全项目代码审计 — 2026-05-22）

**高风险（H）— 可被直接利用的安全漏洞或导致服务崩溃的缺陷：**

| 编号 | 模块 | 问题 | 修复 |
|------|------|------|------|
| H-01 | `api/v1/grpc.go` | Protobuf 结构体 `String()` 方法使用 `fmt.Sprintf("%+v", m)` 导致无限递归，`go vet` 报错 | 改为 `fmt.Sprintf("%+v", *m)` 解引用指针，共修改 13 处 |
| H-02 | `internal/engine/assessor.go` | `computeDynamicFinalScore` 因 `FillFromLegacy` 未填充所有域和 `ActiveFactors()` 将 0.0 视为活跃，导致加权和恒为 0 | 修复 `FillFromLegacy` 填充所有域；`ActiveFactors()` 增加 `>0` 判断 |
| H-03 | `internal/kernel/commander.go` | HMAC 签名仅包含 `cmdID` 和 `action`，未包含 `params`，存在参数篡改风险 | 修改 `sign` 方法按 key 排序后加入所有参数，Agent 端同步更新验证逻辑 |
| H-04 | `internal/kernel/assessor.go` | `Assess()` 使用本地主机名作为 `HostID`，`Evaluate` 事后覆盖导致内部计算不一致 | 修改 `Assess` 接受 `hostID` 参数，`Evaluate` 直接传递而非覆盖 |
| H-05 | `internal/kernel/bus.go` | `assessor.result`、`policy.action` 等关键消息使用异步 `Publish`，可能导致消息丢失或处理顺序问题 | 改为 `PublishSync` 同步发布，并记录发布错误 |
| H-06 | `internal/kernel/config_watcher.go` | 裸类型断言 `p.(*AssessorModule)` 在类型不匹配时直接 panic | 改为安全形式 `am, ok2 := p.(*AssessorModule)`，不匹配时记录警告 |

**中风险（M）— 逻辑错误或安全加固不足：**

| 编号 | 模块 | 问题 | 修复 |
|------|------|------|------|
| M-01 | `internal/kernel/cti.go` | `ReportThreat` 未区分威胁严重级别，仅递增计数 | 新增 `severityWeight` 函数，按级别（critical=4, high=3, medium=2, low=1）加权计算 |
| M-02 | `internal/kernel/policy.go` | 阈值逻辑重叠：外层 switch 设为 `HostIsolated` 后，内层 switch 又覆盖为 `HostWarning` | 合并为单一互斥 switch，按分数区间依次判断 |
| M-03 | `internal/kernel/ratelimit.go` | `Stop()` 多次调用重复关闭 `stopCleanup` channel 导致 panic | 添加 `stopped` 标志，确保 `close` 只调用一次 |
| M-04 | `internal/kernel/workerpool.go` | 任务超时后启动的排空 goroutine 未加入 WaitGroup，导致 `Shutdown()` 无法等待 | 排空 goroutine 调用 `p.wg.Add(1)` 和 `defer p.wg.Done()`，绑定 `p.ctx.Done()` |
| M-05 | `internal/extmgr/extension_executor.go` | 环境变量键名含 `=` 或值含换行可导致注入攻击 | 新增 `sanitizeEnvKey` 和 `buildEnv` 函数验证键名和值 |
| M-06 | `internal/common/exec.go` | 未检查命令参数中的 shell 元字符，存在注入风险 | 新增 `containsShellMetachar` 函数，执行前检查所有参数 |
| M-07 | `internal/kernel/spc.go` | 使用 CVE ID 匹配包名（如 CVE-2023-1234 匹配"2023"包），且短包名易误匹配 | 移除 CVE ID 匹配，仅用 Description；过滤长度 <2 的包名 |
| M-08 | `internal/kernel/services.go` | SessionID 随机后缀仅 4 字节（32 位熵），易被猜测 | 增至 16 字节（128 位熵） |

**低风险（L）— 防御性编程与健壮性增强：**

| 编号 | 模块 | 问题 | 修复 |
|------|------|------|------|
| L-01 | `internal/kernel/collector.go` | `entry.Message` 含换行可注入日志结构 | 新增 `sanitizeLogField` 过滤 `\n` 和 `\r` |
| L-02 | `internal/kernel/collector.go` | 写入日志后未调用 `Sync()`，崩溃可能丢失数据 | 写入成功后调用 `m.writer.Sync()` |
| L-03 | `internal/kernel/services.go` | 未验证 `CommandId` 和 `HostId` 为空，可伪造命令确认 | 添加空值校验，返回错误 |
| L-04 | `internal/kernel/services.go` | `rand.Read` 错误被忽略 `_, _ = rand.Read(b)` | 检查错误并记录，降级为确定性填充 |
| L-05 | `internal/kernel/spc.go` | EPSS 因子线性缩放（`EPSS*10`）无法准确反映利用概率影响 | 改为对数缩放 `-log(1-EPSS)/5` |

**新增功能（CLI Agent 管理模块）：**

- **Agent 生命周期管理** — 实现 `agent start/stop/restart/status` 命令，通过 `CommanderModule` 下发控制指令
- **多实例管理** — 支持 `--host <hostID>` 单实例操作、`--all` 批量操作、`--filter <expr>` 过滤
- **日志查看与导出** — `agent logs` 命令支持按主机 ID、级别过滤，JSON/CSV 格式导出
- **权限验证机制** — 引入 `PermissionLevel`（PermRead/PermWrite/PermAdmin/PermSuper），命令执行前验证权限
- **格式化输出** — 统一支持文本表格和 JSON 两种输出格式，通过 `--json` 参数切换
- **HMAC 密钥管理** — 密钥元数据（创建时间/过期时间/哈希）、自动轮换（90 天）、文件权限 `0600`

> **说明：** SSAM（系统安全可接受性模型）是核心算法，当前版本 2.0，已独立为 [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam) 纯函数式库。ASSCOR 是实现 SSAM 的开源平台框架，当前版本 v0.2.3。两者版本号独立演进。

#### 第三批修复（SSAM 解耦与二次审计 — 2026-05-22）

**架构重构 — SSAM 算法与 ASSCOR 框架解耦：**

- **SSAM 独立模块** — 将 SSAM 核心算法抽取为独立包 `internal/ssam`，包含接口定义（`Provider` 四子接口）、数据结构（`AssessmentInput`/`AssessmentOutput` DTO）、算法实现（`Engine`）、配置适配（`adapter.go`）、默认值（`defaults.go`）、输入验证（`errors.go`）
- **依赖注入集成** — 在 `AssessorModule.Init` 中将 SSAM Engine 实例注册到 DI 容器（`Bind((*ssam.ScoringProvider)(nil), engine)`），框架通过接口消费 SSAM 能力
- **边缘因子级联机制** — 支持 `CascadeTo`/`CascadeValue`/`CascadeOnly` 配置，实现因子间级联关系（如 3FA 未满足时级联修改 2FA 因子值）
- **钩子机制** — 提供 `HookPhase`（pre_score/post_score/pre_edge/post_edge）和 `AssessmentHook` 接口，支持在评分过程各阶段插入自定义逻辑
- **编译时接口检查** — 添加 `var _ Provider = (*Engine)(nil)` 确保 Engine 始终满足 Provider 接口

**基础设施增强：**

- **熔断器 (Circuit Breaker)** — 实现基于滑动窗口的熔断器，支持 Closed/Open/Half-Open 三态切换，可配置失败率阈值、超时时间、窗口大小
- **消息总线 (Bus)** — 基于发布-订阅模式的事件总线，支持同步/异步发布、goroutine 并发控制（信号量 + maxGoroutines）、防泄漏机制
- **拦截器链 (Interceptor Chain)** — 可组合的请求拦截器，内置速率限制、熔断器、审计日志拦截器
- **确定性依赖注入** — 对 DI 容器绑定类型排序，消除 map 迭代顺序随机导致的匹配不确定性
- **gRPC 启动检测** — 改进 gRPC 服务器启动检测机制，超时增至 5 秒并优化日志

**二次审计修复（#11-#13）：**

| 编号 | 模块 | 问题 | 修复 |
|------|------|------|------|
| #11 | `services.go` GetSnapshot | 未映射边缘因子到 gRPC 响应 | 补全 6 项边缘因子映射 |
| #12 | `persistence.go` AssessmentRecord | 仅持久化 TwoFactorFail，其他 5 项丢失 | 新增 SYNCookieDis/SELinuxDis/AppArmorDis/NoSIEM/NoIDS 字段 |
| #13 | `persistence.go` DashboardReport | 边缘因子映射不完整 | 补全 6 项边缘因子映射 |

**废弃代码清理：**

- 移除 `engine/assessor.go` 中未实现的 `ScoringBackend` 接口
- 移除 `engine/assessor.go` 中无调用点的 `checkPassed()` 方法
- 移除 `model/edge_factor_chain.go` 中无调用点的 `EdgeFactorChain.Apply()` 方法和 `ResetEdgeFactorsForTesting()` 函数
- 清理 `model/edge_factor_chain.go` 中不再使用的 `math` 导入

#### 第四批修复（Prism 三层架构补全 + 管理适配器测试 — 2026-06-09）

**Prism 风险动力学引擎 — Semantic Layer 与 Inference Layer 实现：**

- **Semantic Layer (`prism-lib/semantic.go`)** — 实现四态模糊隶属度映射函数（`ComputeStateMembership`），将 Core Layer 的 PrismScore 映射为 [μ_Stable, μ_Degraded, μ_Untrusted, μ_Collapse] 四态向量，使用梯形隶属度函数（trapezoidUp/trapezoidDown/triangular），阈值可通过 PrismConfig 配置。
- **Inference Layer (`prism-lib/inference.go`)** — 实现基于马尔可夫链的状态预测（`PredictFuture`），使用 4×4 状态转移矩阵（专家先验），支持 N 步预测（默认 30 天），输出趋势判断（improving/stable/degrading/collapsing）；塌缩检测（collapsing 趋势→触发 collapseProb 计算）。
- **债务衰减修正 (`computeCollapseModifier`)** — CollapseModifier 仅当失败检查项数量 ≥ 2 时触发生效（单失败项不启动塌缩），引入 nFactor（√nFailures）调整分母。
- **趋势判断重构 (`determineTrend`)** — 优先判断塌缩概率（当前 >0.3 且未来 >0.3 → collapsing；未来-当前 >0.1 → collapsing），再依次判断 improving/degrading/stable。

**管理类适配器测试覆盖：**

- **management_test.go** — 新增 35 项测试用例，覆盖全部 10 个管理类适配器的属性验证、解析逻辑、状态判断、注册检查、Validate 统一性。P0 适配器 11 项（Ansible/NetBox/Snipe-IT）、P1 适配器 10 项（FreeIPA/Keycloak/WazuhSIEM/Rundeck）、P2 适配器 6 项（Jira/Terraform/OpenTofu）。

**文档更新：**

- **版本升级** — SSAM 算法版本 1.3 → 2.0，ASSCOR 项目版本 v0.1.3-mvp → v0.1.4-mvp
- **README.md** — 新增 §12.2 Prism 项目拆分说明、更新项目结构（prism-lib/internal/prism/internal/srd）、核心能力表新增 Prism 引擎条目
- **白皮书** — 工程实现白皮书新增 Prism/SRD 三层架构集成章节；SSAM 与 SRD 可移植性白皮书更新 prism-lib 文件统计（5→7，新增 semantic.go/inference.go，标准库依赖 2→3 个包）；外部接入源完整清单更新实施状态与完成度

---

## 16. 许可证与社区模式

ASSCOR 采用 **[Apache License 2.0](LICENSE)** —— 宽松许可证，允许任何人对本项目：

- **二次开发**（修改、增强、派生）
- **分发**（原始或修改版本，含商业分发）
- **闭源**（修改后可保持私有，无需公开源码）

唯一要求：保留 Apache 2.0 版权声明与许可声明（详见 [LICENSE](LICENSE) 全文）。

### 社区模式

**主仓库与 `main` 分支由项目维护者单人开发与合入**，采用"上游谨慎、下游自由"的模式：

| 角色 | 路径 |
|------|------|
| **贡献者** | Fork → 修改 → Pull Request → 维护者 review 后合入 `main` |
| **独立开发者** | 直接 Fork 后自由分支发展，可独立分发/商业化，无需等待上游合入 |
| **维护者** | 保持 `main` 分支稳定，控制上游演进节奏 |

`main` 分支始终为可构建、可测试、可发布状态（CI 全绿）；任何实验性方向（如 `docs/v0.3.0/` 研究提案）不进 `main`，以可选模块/扩展包形式存在。
