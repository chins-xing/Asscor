# SSAM 1.3 — 系统安全可接受性模型

> **ASSCOR 项目** 实现了 SSAM（系统安全可接受性模型）核心算法。
>
> ASSCOR——**ASS**ess + **COR**e（评估 + 内核）。SSAM 是评估算法内核，ASSCOR 是承载它的框架内核：双核一体，算法与架构同构。全视、警惕、永不闭目——持续监控每一台主机的安全状态，不放过任何一个弱点。

**算法版本：** SSAM 1.3 | **项目版本：** ASSCOR v0.1.2-MVP  
**日期：** 2026-05-25  
**状态：** 发布

## 摘要

系统安全可接受性模型（System Security Acceptability Model，SSAM）1.3 是一种多维度、可计算、可演进的安全评估框架。它通过四个互不重叠的核心能力域——攻击面管理、业务连续性、操作可信度、韧性——与独立边缘修正因子、动态威胁系数及安全态势计算相结合，将系统安全状态量化为一个 0–100 的分数。本白皮书系统阐述 SSAM 1.3 的理论基础、核心规则、评估方法，并重点介绍韧性维度的增强：可接受沦陷指标（Acceptable Compromise Index，ACI），以及新引入的安全态势计算模块（Security Posture Calculator，SPC），通过全局漏洞情报与本地资产清单的交叉比对，实现个体化的风险评估。所有参数均可由管理员按场景自定义，实现"定义权归模型，决策权归人"的安全度量实践。

ASSCOR 不替代漏洞扫描器、SIEM 或渗透测试，而是作为上述系统的"安全可接受性"聚合判断层，提供面向业务风险的统一视图。同时，SSAM 1.3 已实现与中国等级保护制度（GB/T 22239-2019）的双向映射，可作为等保合规效果的持续性量化验证工具。

## 1. 引言

安全评估长期面临两大困境：合规清单无法应对高级威胁，而红队演练又难以重复度量。ASSCOR 项目旨在提供一种可计算、可演进、可配置的中间道路，让系统管理员像查看健康仪表盘一样，快速掌握当前的安全可接受程度。

SSAM 1.3 的核心创新包括：

- 四核心域互斥设计，消除重复评分
- 边缘因子以乘法修正方式反映高级防护缺失
- 动态威胁系数结合实时情报使评估结果随威胁环境变化
- 管理员完全自定义，权重、阈值、检查项均可按需调整
- 韧性维度强化，新增可接受沦陷指标（ACI），量化"部分失陷后的生存能力"
- 安全态势计算模块（SPC），将全局漏洞情报本地化，为每台主机生成独立的态势修正
- 等级保护制度接入，实现合规要求与安全能力的双向映射

## 2. 核心架构

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

> **SSAM 1.3 变更：** 供应链校验、自动封禁、资源紧张等项已移入对应核心域检查项（OT-004、RS-003、BC-003），以消除双重扣分。SYN Cookie 仍保留为边缘因子（因其在网络层全局生效）。

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

## 3. 评估公式

SSAM 1.3 的最终评估值由核心域加权得分、边缘因子修正、威胁态势系数及安全态势计算修正共同决定。SPC 1.3 采用平方和开方（√∑Penalty²）替代线性求和，防止大量低危 CVE 过早触底。

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

## 4. 韧性指标增强：可接受沦陷指标（ACI）

传统的韧性评估关注系统抵御攻击的能力，但现实中"完全不被攻破"难以保证。SSAM 1.3 在韧性核心域中引入可接受沦陷指标（ACI），用于衡量：当系统的某一部分已被攻破时，能否将损害控制在可接受范围内，并维持核心业务的运行。

ACI 与抗打击韧性指标互为补充：前者衡量"破防后"，后者衡量"破防前"。两者不重叠、不重复扣分。

### 4.1 ACI 的设计目标

- **隔离能力**：受影响组件能否被快速隔离，阻止横向移动
- **最小权限有效性**：攻击者获得的权限是否被限制在极小的范围内
- **数据保护**：敏感数据是否加密、备份是否离线且不可篡改
- **恢复能力**：从检测到沦陷到恢复正常服务的时间（MTTR）
- **监控留存**：攻击者能否轻易清除入侵痕迹

### 4.2 ACI 的评估假设

ACI 评估默认假设攻击者已获得目标组件的基础访问权限（如 Web 服务用户、低权账户），并以此为前提衡量损害扩散范围。该假设提供了可比较的工程化基线。

### 4.3 ACI 评估项与计分

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

## 5. 安全态势计算模块（SPC）

### 5.1 设计目标

SSAM 1.3 引入安全态势计算模块（Security Posture Calculator，SPC），解决"全局漏洞情报"与"单台主机实际风险"之间的鸿沟。SPC 通过持续追踪全球权威漏洞库，结合本地资产清单，为每台受管主机输出个体化的态势修正向量。

### 5.2 数据源体系

- **一级数据源**：NVD、CNNVD、CNVD 等全球漏洞库
- **二级数据源**：EPSS（漏洞利用预测）、CISA KEV（已知在野利用目录）
- **三级数据源**：Agent 采集的本地软件清单、服务、端口、拓扑

### 5.3 态势修正向量

SPC 为每台主机输出修正向量 $\vec{P_h} = (P_{score}, P_{weight}, P_{action})$：

- $P_{score}$：态势分数修正因子（0.60–1.00），作为乘数进入最终公式
- $P_{weight}$：核心域权重临时偏移（总和为 0）
- $P_{action}$：建议响应动作（如 isolate_host、notify_admin）

### 5.4 计算公式

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

## 6. 等级保护制度接入

SSAM 1.3 已与 GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》（等保 2.0）建立映射关系。四个核心域覆盖等保"安全通信网络"、"安全区域边界"、"安全计算环境"和"安全管理中心"中可自动化评估的部分，物理安全、人员管理等人工审查项不在此列。

### 6.1 等保等级与 SSAM 阈值联动

| 等保等级 | 推荐 SSAM 阈值 | 适用场景 |
|----------|----------------|----------|
| 二级 | 65 | 一般信息系统 |
| 三级 | 80（默认） | 重要系统 |
| 四级及以上 | 90 | 关键基础设施 |

### 6.2 等保控制点映射原则

以等保三级安全计算环境为例，从身份鉴别、访问控制、安全审计、入侵防范、恶意代码防范、数据保护、备份恢复、剩余信息保护等方面推导出 53 项 SSAM 检查项，每一项均可追溯到具体的等保标准条款。所有映射详情请见第二篇章：等保检查项映射手册。

### 6.3 双向验证

ASSCOR 项目评估结果可与等保测评报告交叉验证：若等保三级通过而 SSAM < 80，可能存在配置漂移或防护未持续生效；反之若 SSAM ≥ 80 而等保未通过，则说明部分人工审查项需重点整改。

## 7. 动态扩展与社区驱动

ASSCOR 内置攻击向量插件槽（AVD），每个 AVD 定义为 {ID, 域, 检测逻辑, 分值, 紧急标记}。管理员或社区可编写 AVD 注册到引擎，使模型随威胁演进持续扩展。

## 8. 配置与管理员自定义

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

## 9. 项目结构

```
ASSCOR/
├── cmd/
│   ├── kernel/        # 微内核服务端入口（gRPC + JSONRPC 双协议栈）
│   ├── agent/         # Agent 客户端入口（gRPC + JSONRPC）
│   └── ASSCOR/         # 独立评估工具入口
├── internal/
│   ├── kernel/        # 内核核心模块（assessor, policy, spc, cti,
│   │                   #  adapter_integration, config_watcher,
│   │                   #  di, bus, circuitbreaker, interceptor,
│   │                   #  attck, attck_detection, attck_ti,
│   │                   #  attck_emulation, attck_assessment,
│   │                   #  attck_apt_chain, attck_apt_detect,
│   │                   #  attck_apt_attribution, attck_apt_hunt 等）
│   ├── ssam/          # SSAM 独立算法模块（engine, interfaces, adapter,
│   │                   #  defaults, errors — 可脱离 ASSCOR 独立使用）
│   ├── agent/         # Agent 核心模块（collector, executor）
│   ├── engine/        # ASSCOR 评估引擎（含适配器流水线集成，内部调用 ssam 包）
│   ├── adapter/       # 外部工具适配器框架（21 个适配器：11 探测器 + 10 管理类）
│   │   ├── scanner/   #   探测器适配器（Trivy, Nuclei, Lynis, OpenSCAP 等）
│   │   └── management/#   管理类适配器（Ansible, NetBox, FreeIPA, Jira 等）
│   ├── checks/        # 检查项库（Linux/Windows，等保映射 53+9 项）
│   ├── model/         # 数据模型定义
│   ├── config/        # 配置解析器（INI 格式，支持行业模板覆盖）
│   └── version/       # 版本信息
├── api/v1/            # gRPC 服务接口定义与消息类型
├── config/            # 行业专用配置文件（政府、金融、医疗、教育等）
├── certs/             # TLS/mTLS 证书目录（已排除于版本控制）
├── docs/              # 技术文档与白皮书
├── build/             # 编译产物（Linux/Windows，已排除于版本控制）
├── config.ini         # 内核默认配置文件
└── agent.ini          # Agent 默认配置文件
```

## 10. 快速开始

### 10.1 单机评估模式

```bash
# 使用独立评估工具
./ASSCOR-linux-amd64-v0.1.2-MVP

# 输出 JSON 格式报告
./ASSCOR-linux-amd64-v0.1.2-MVP -json

# 指定默认配置文件
./ASSCOR-linux-amd64-v0.1.2-MVP -config config.ini

# 使用行业专用配置（政府/金融/医疗等）
./ASSCOR-linux-amd64-v0.1.2-MVP -config config/config.gov.ini
```

### 10.2 分布式模式

**启动 Kernel（Windows/Linux）：**
```bash
# Windows（JSONRPC 默认端口 50051，gRPC 默认端口 50052）
ASSCOR-kernel.exe -listen 0.0.0.0:50051 -no-mtls

# Linux（使用行业配置）
./ASSCOR-kernel-linux-amd64-v0.1.2-MVP -listen 0.0.0.0:50051 -no-mtls -config config/config.fin.ini

# 启用 mTLS（自动生成自签名证书）
./ASSCOR-kernel-linux-amd64-v0.1.2-MVP -listen 0.0.0.0:50051
```

**启动 Agent（Linux）：**
```bash
# 使用命令行参数
./ASSCOR-agent-linux-amd64 -kernel 192.168.1.100:50051 -host-id server01

# 或使用配置文件
./ASSCOR-agent-linux-amd64 -config agent.ini
```

Agent 配置文件 `agent.ini` 支持心跳间隔、重连策略、mTLS 等参数自定义，详见文件内注释。

## 11. 与 ASSCOR μKernel 的联动

ASSCOR μKernel 是风险评估与指令分发中心，采用微内核 + Agent 架构，通过 **gRPC 原生协议 + JSONRPC 兼容层** 双协议栈通信，均支持 mTLS 加密。Agent 负责本地检查执行与状态上报，内核汇聚计算并自动下发修复指令，实现"评估→诊断→修复"闭环。

### 核心能力

| 模块 | 功能 |
|------|------|
| **SSAM 算法引擎 (internal/ssam)** | 独立算法模块，实现 SSAM 1.3 评分公式、域评分、边缘因子计算、钩子机制；可脱离 ASSCOR 框架独立使用 |
| **评估引擎 (Assessor)** | 加载检查项并发评估，通过 SSAM 模块计算四域得分 + 边缘因子 + SPC 修正 |
| **依赖注入容器 (DI Container)** | 基于反射的 IoC 容器，支持接口绑定、命名绑定、结构体字段注入（`inject` tag）、确定性匹配 |
| **消息总线 (Bus)** | 发布-订阅模式事件总线，支持同步/异步发布、goroutine 并发控制、信号量防泄漏 |
| **熔断器 (Circuit Breaker)** | 基于滑动窗口的熔断器（Closed→Open→Half-Open），防止服务雪崩 |
| **拦截器链 (Interceptor)** | 可组合的请求拦截器，内置速率限制、熔断器、审计日志拦截器 |
| **适配器集成 (AdapterIntegration)** | 周期性执行 21 个外部工具适配器（Fetch→Parse→Map→Validate 四阶段流水线），结果注入评分流程 |
| **安全态势计算器 (SPC)** | 从 NVD/EPSS/CISA KEV/CNNVD/CNVD 拉取漏洞情报，CVE 缓存磁盘持久化（启动加载/退出保存），CPE 精确版本匹配，输出个体化 P_score |
| **配置监听器 (ConfigWatcher)** | 监控配置文件变化，支持权重热加载（`Assessor.ReloadWeights()`）和 SIGHUP 信号 |
| **策略管理器 (Policy Manager)** | 根据分数区间生成自动化动作（notify_admin / isolate_host 等） |
| **指令下发器 (Commander)** | HMAC-SHA256 签名命令下发，Agent 白名单执行 |
| **ATT&CK V19 模块 (ATTACK)** | MITRE ATT&CK V19 框架集成，四大子模块（检测分析/威胁情报/对手仿真/评估工程）+ APT 增强层（攻击链重构/行为检测/归因引擎/威胁狩猎） |

### 行业配置模板

`config/` 目录提供按行业定制的配置文件，覆盖权重、阈值、适配器开关：

| 文件 | 适用场景 | 特点 |
|------|----------|------|
| `config.gov.ini` | 政府机构 | 高操作可信度权重(30)，等保三级+ |
| `config.fin.ini` | 金融行业 | 高韧性权重(20)，等保四级阈值(90) |
| `config.med.ini` | 医疗健康 | 业务连续性优先，HIPAA 对齐 |
| `config.edu.ini` | 教育科研 | 开放端口容忍度高，侧重基础防护 |
| `config.ent.ini` | 企业通用 | 均衡权重，等保三级默认 |

### 双协议栈架构

```
Agent ──gRPC/mTLS──▶ Kernel gRPC Server (:50052)
   │                    │
   │                    ├─ KernelService (Register, Heartbeat, GetSnapshot)
   │                    └─ AgentService (ExecuteCommand, StreamLogs)
   │
   └──JSONRPC/mTLS──▶ Kernel JSONRPC Server (:50051)
                        │
                        ├─ Register / Heartbeat / GetSnapshot
                        └─ ExecuteCommand / StreamLogs
```

## 12. 总结

SSAM 1.3 提供了一套严谨且可进化的安全可接受性度量标准。四个核心域与边缘因子、威胁系数、SPC 态势修正共同形成完整的风险评估体系。引入等保映射后，ASSCOR 项目既是对抗高级威胁的战术工具，也是衡量合规持续有效性的战略仪表盘。它不仅回答"系统安全吗"，更回答"在当下威胁中，我们的安全程度是否可以被接受"。

## 12.1 SSAM 与 ASSCOR 框架解耦架构

自 v0.1.1-MVP 起，SSAM 算法已从 ASSCOR 框架中完全解耦为独立模块 `internal/ssam`，两者通过标准化接口松耦合协作：

```
┌─────────────────────────────────────────────────┐
│                  ASSCOR Kernel                    │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Assessor │─▶│ DI       │─▶│ SSAM Engine   │  │
│  │ Module   │  │ Container│  │ (internal/ssam)│  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│       │              ▲              │            │
│       ▼              │              ▼            │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Adapter  │  │ Config   │  │ Adapter       │  │
│  │ Pipeline │  │ Adapter  │  │ (model↔ssam)  │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
└─────────────────────────────────────────────────┘
```

**关键设计原则：**

- **接口隔离**：SSAM 通过 `Provider` 聚合接口暴露能力（`ScoringProvider` + `DomainProvider` + `EdgeFactorProvider` + `HookProvider`）
- **依赖注入**：ASSCOR 通过 DI 容器绑定 `ssam.ScoringProvider` → `Engine` 实例，框架不直接依赖 Engine 具体类型
- **数据格式标准化**：`AssessmentInput` / `AssessmentOutput` 作为 DTO，`adapter.go` 负责 ASSCOR model ↔ SSAM 格式转换
- **独立可用**：`internal/ssam` 无外部依赖（仅 `config`、`model`、`logger`），可直接 `go get` 引入第三方项目

详细接口规范与接入指南请参阅 [docs/SSAM接口规范与接入指南.md](docs/SSAM接口规范与接入指南.md)。

## 13. ATT&CK V19 威胁分析模块

ASSCOR v0.1.2-MVP 集成 MITRE ATT&CK V19 框架，构建了从检测、情报、仿真到评估的完整威胁分析能力链，并在此基础上扩展 APT 攻击分析与检测增强子模块。该模块作为 μKernel 插件（`attck`，优先级 80，版本 2.0.0）运行，通过 DI 容器与 SSAM 评估引擎、SPC 态势计算器、CTI 威胁情报管理器深度集成。

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
ATTACKModule (Plugin v2.0.0)
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

## 14. 已知局限与后续工作

- ACI 基于假设攻击者已获基础权限，未覆盖所有攻陷场景
- SPC 精度依赖本地资产清单完整性和情报源质量
- 模型不评估物理安全、社会工程学等非技术向量
- 大规模环境下的检查项互斥验证和性能优化尚待持续完善

## 版本历史

- **SSAM 1.0** — 六维度原始模型
- **SSAM 1.1** — 四核心域 + 独立属性，消除维度重叠
- **SSAM 1.2** — 引入 ACI、SPC、等保映射、AVD 扩展机制、μKernel 联动
- **SSAM 1.3** — 移除4项重叠边缘因子（SYN Cookie/供应链/自动封禁/资源紧张），SPC 引入平方和衰减，增加边缘因子合规等级覆盖，内置冲突检测

### ASSCOR v0.1.2-MVP ATT&CK V19 模块扩展记录

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

### ASSCOR v0.1.2-MVP 修复记录

#### 第一批修复（基础设施与协议层）

- **Agent 反复重连修复** — Client 层改用 `bufio.Reader.ReadBytes('\n')` 按行读取 TCP 响应，解决半包导致的 JSON 解析失败；心跳循环改用 `time.Timer` 替代 `time.Ticker`，防止 `runChecks()` 耗时导致的心跳堆积触发连续错误重连。
- **SPC 后台定时同步修复** — `fetchLoop()` 在启动时立即执行首次同步（而非等待首个 Ticker 间隔），确保内核启动后即可获得最新漏洞情报。
- **SPC CVE 缓存磁盘持久化** — 新增 `loadCacheFromDisk()` / `saveCacheToDisk()` 方法，CVE 缓存在启动时从磁盘 JSON 加载、退出时保存，避免服务重启后缓存丢失。
- **适配器结果纳入评分** — `Assessor.AssessFromResults()` 和 `Assess()` 中新增 `runAdapterPipeline()` 调用，21 个外部适配器的 Finding 通过 `NormalizedFinding.ToCheckResult()` 转换后注入评分流程，与内置检查项合并计算。
- **gRPC 原生协议实现** — 基于 `google.golang.org/grpc` 实现原生 gRPC 服务端/客户端，支持 TLS/mTLS 配置，定义 `KernelService`/`AgentService` 接口及 Protobuf 消息类型，与 JSONRPC 兼容层形成双协议栈。
- **权重热加载** — `Assessor.ReloadWeights()` 支持运行时动态更新四域权重，配合 `ConfigWatcher` 模块监控配置文件变化自动触发重载，无需重启服务。
- **AdapterIntegrationModule 注册修复** — 将 `AdapterIntegrationModule` 加入 Kernel 插件注册列表，使后台定时同步（每6小时）、事件总线发布 `adapter.findings`、按需拉取 `CollectFindings()` 功能生效。
- **行业配置文件体系** — 新增 `config/` 目录，提供政府(config.gov.ini)、金融(config.fin.ini)、医疗(config.med.ini)、教育(config.edu.ini)、企业通用(config.ent.ini) 五套行业专用配置模板。

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

> **说明：** SSAM（系统安全可接受性模型）是核心算法，当前版本 1.3。ASSCOR 是实现 SSAM 的开源项目框架，当前版本 v0.1.2-MVP。两者版本号独立演进。

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
