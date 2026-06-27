# ASSCOR 深度架构分析

**分析日期**: 2026-06-05 | **代码库规模**: ~135个Go文件 | **版本**: ASSCOR v0.2.0 / SSAM 2.0

---

## 目录

1. [整体架构层次](#1-整体架构层次)
2. [插件系统 (Plugin System)](#2-插件系统)
3. [依赖注入容器 (DI Container)](#3-依赖注入容器)
4. [事件总线 (Event Bus)](#4-事件总线)
5. [SSAM V2.0 评分引擎](#5-ssam-v20-评分引擎)
6. [安全态势计算 (SPC)](#6-安全态势计算-spc)
7. [ATT&CK V19 威胁分析模块](#7-attck-v19-威胁分析模块)
8. [适配器框架 (Adapter Framework)](#8-适配器框架)
9. [扩展管理器 (Extension Manager)](#9-扩展管理器)
10. [评估引擎 (Assessor)](#10-评估引擎)
11. [数据流与模块交互](#11-数据流与模块交互)
12. [gRPC / JSONRPC 双协议栈](#12-grpc--jsonrpc-双协议栈)
13. [Prism 传播风险引擎](#13-prism-传播风险引擎)

---

## 1. 整体架构层次

```
┌─────────────────────────────────────────────────────────┐
│  cmd/                   入口层 (3 入口)                   │
│  kernel/ agent/ asscor/                                   │
├─────────────────────────────────────────────────────────┤
│  internal/cli/    internal/webui/   外部界面层             │
├─────────────────────────────────────────────────────────┤
│  internal/kernel/  ─── 微内核核心 (47 文件, 15000+ 行)     │
│  ┌──────────┬─────────┬──────────┬─────────┬──────────┐ │
│  │ Plugin   │ DI Cont.│ Bus      │  SPC    │ ATT&CK   │ │
│  │ System   │ (反射)   │ (PubSub) │ (CVE)   │ V19 (4+4)│ │
│  ├──────────┼─────────┼──────────┼─────────┼──────────┤ │
│  │ Assessor │ Policy  │ Commander│ CTI     │ Adapter  │ │
│  │ExtMgr    │ Config  │ Heartbeat│ Persist │ SrcMgr   │ │
│  └──────────┴─────────┴──────────┴─────────┴──────────┘ │
├─────────────────────────────────────────────────────────┤
│  internal/engine/   评估引擎    internal/ssam/ 评分适配   │
│  internal/adapter/  21适配器   internal/checks/ 检查项    │
│  internal/srd/      风险判定   internal/prism/ 传播引擎   │
│  internal/adapterhub/ 统一适配器管理                      │
│  internal/extmgr/   扩展管理器                            │
├─────────────────────────────────────────────────────────┤
│  internal/model/  config/  logger/  common/  version/   │
├─────────────────────────────────────────────────────────┤
│  ssam-lib/  prism-lib/  独立纯函数库 (零内部依赖)          │
│  github.com/chins-xing/ssam                               │
│  github.com/chins-xing/prism                              │
└─────────────────────────────────────────────────────────┘
```

**外部依赖**: 仅 `google.golang.org/grpc` + 两个自维护的 ssam/prism 库。Go 1.26 标准库满足其余需求。

---

## 2. 插件系统

### 2.1 核心接口 (`internal/kernel/plugin.go`)

```go
type Plugin interface {
    Info() PluginInfo                          // 元数据
    Dependencies() []PluginDependency          // 依赖声明
    Init(ctx context.Context, kc KernelContext) error   // 初始化
    Start(ctx context.Context) error           // 启动异步工作
    Stop(ctx context.Context) error            // 优雅关闭
    State() PluginState                        // 生命周期状态
}

type PriorityPlugin interface { Plugin; Priority() int }        // 启动/关闭顺序
type HealthCheckable interface { HealthCheck(ctx) error }       // 健康检查
type ConfigurablePlugin interface { Plugin; Configure(map) error }  // 配置注入
```

### 2.2 生命周期状态机

```
PluginUnregistered → RegisterPlugin → PluginRegistered
                                        │
                                   Bootstrap()
                                        │
                                   ┌─ Init(ctx, kernel)
                                   │    │ success
                                   │    ▼
                                   │ PluginInitialized
                                   │    │
                                   │ Start(ctx)
                                   │    │
                                   ▼    ▼
                              PluginStarted
                                   │
                              Stop(ctx)
                                   │
                                   ▼
                              PluginStopped
```

### 2.3 Bootstrap 完整流程 (`kernel.go:199-267`)

1. **快照所有插件** → 2. **按优先级排序** (升序: P1→P2→...→P90，无名则按字母序) → 3. **执行 `kernel.pre_init` 扩展点** → 4. **逐个插件**: `Configure()` (如果实现) → 依赖检查 (仅警告) → `Init(ctx, kernel)` (失败则中止) → 5. **`kernel.post_init`** → 6. **`kernel.pre_start`** → 7. **逐个插件**: `Start(ctx)` → 8. **`kernel.post_start`**

**Shutdown 反向顺序**: 高优先级先停止 (P90→P1)，取消上下文，关闭总线，执行 `kernel.post_stop`。

### 2.4 优先级表 (实际加载顺序)

| 优先级 | 插件 | 功能 | Init 顺序 | Stop 顺序 |
|--------|------|------|-----------|-----------|
| P=1 | `config_watcher` | 配置文件热加载 | 1st | last |
| P=2 | `concurrency` | WorkerPool 并发控制 | 2nd | 2nd-last |
| P=3 | `persistence` | 评估结果持久化 | 3rd | 3rd-last |
| P=5 | `heartbeat` | Agent 心跳监控 | 4th | … |
| P=10 | `cti` | 威胁情报系数 | 5th | … |
| P=20 | `spc` | 安全态势计算 | 6th | … |
| P=21 | `attck` | ATT&CK V19 | 7th | … |
| P=35 | `scoring_engine` | SSAM 评分引擎 | 8th | … |
| P=40 | `assessor` | 核心评估器 | 9th | … |
| P=45 | `adapter_integration` | 适配器集成 | 10th | … |
| P=50 | `policy` | 策略管理 | 11th | … |
| P=55 | `source_manager` | 外部源管理 | 12th | … |
| P=60 | `commander` | 指令下发 | 13th | … |
| P=70 | `log_collector` | 日志采集 | 14th | … |
| P=90 | `cli` | 交互式命令行 | 15th | 2nd |

### 2.5 扩展点系统 (`internal/kernel/extensions.go`)

```
ExtensionRegistry {
    extensions map[string][]registeredExtension    // 扩展点 → 处理器列表
    points     map[string]ExtensionPoint           // 注册的扩展点定义
}
```

两种执行模式:
- **`Execute(pointName, data)`**: 按优先级顺序执行所有处理器，收集错误
- **`ExecuteUntilFirst(pointName, data)`**: 执行直到第一个成功的处理器

内置扩展点: `kernel.pre_init`, `kernel.post_init`, `kernel.pre_start`, `kernel.post_start`, `kernel.pre_stop`, `kernel.post_stop`

插件定义的扩展点示例:
- `assessor.pre_evaluate` / `assessor.post_evaluate` — 评估前后
- `spc.pre_calculate` / `spc.post_calculate` / `spc.cve_updated` — SPC 计算前后
- `cli.command.register` — CLI 命令注册
- `attck.coverage.complete` / `attck.apt.matched` / `attck.detection.alert` 等 13 个 — ATT&CK 事件

---

## 3. 依赖注入容器

### 3.1 实现 (`internal/kernel/di.go`)

```go
type Container struct {
    mu       sync.RWMutex
    bindings map[reflect.Type]interface{}    // 类型 → 实现
    aliases  map[string]reflect.Type         // 命名别名 → 类型
}
```

基于反射的类型索引容器，无第三方依赖。

**三种解析模式**:
- `Bind(iface, impl)` — 类型绑定: 键 = `reflect.TypeOf(iface).Elem()`
- `BindNamed(name, iface, impl)` — 命名绑定: 同时存入 `bindings` 和 `aliases`
- `Inject(target)` — struct tag 注入 (实现完整但**从未使用**)

### 3.2 绑定清单 (17 项)

| 绑定 | 提供方 | 模式 |
|------|--------|------|
| `*config.Config` (命名"config") | main.go 预绑定 | 命名绑定 |
| `*ScoringEngineProvider` | main.go 预绑定 | 类型绑定 |
| `*PersistenceInterface` | PersistenceModule.Init (P=3) | 自注册 |
| `*HeartbeatInterface` | HeartbeatModule.Init (P=5) | 自注册 |
| `*CTIInterface` | CTIModule.Init (P=10) | 自注册 |
| `*SPCInterface` | SPCModule.Init (P=20) | 自注册 |
| `*ATTACKInterface` | ATTACKModule.Init (P=21) | 自注册 |
| `*ssam.ScoringProvider` | AssessorModule.Init (P=40) | 子对象绑定 |
| `*AssessorInterface` | AssessorModule.Init (P=40) | 自注册 |
| `*AdapterIntegrationInterface` | AdapterIntegrationModule (P=45) | 自注册 |
| `*PolicyInterface` | PolicyModule.Init (P=50) | 自注册 |
| `*SourceManagerInterface` | SourceManagerModule (P=55) | 自注册 |
| `*CommanderInterface` | CommanderModule.Init (P=60) | 自注册 |
| `*LogCollectorInterface` | LogCollectorModule (P=70) | 自注册 |
| `*ConcurrencyInterface` | ConcurrencyModule (P=2) | 自注册 |
| `*WorkerPoolInterface` | ConcurrencyModule (P=2) | 子对象绑定 |
| `*CLIInterface` | CLIModule.Init (P=90) | 自注册 |

### 3.3 预绑定时序 (main.go)

```
k := kernel.NewKernel()
k.SetConfigObj(cfg)                           // → container.BindNamed("config", ...)
k.Container().Bind((*ScoringEngineProvider)(nil), scoringEngine)  // → 预注入
k.Bootstrap()                                  // → 触发所有插件的 Init/Start
```

依赖检查是**建议性的**——缺失依赖仅记录警告。硬性要求在插件的 `Init()` 中自行检查。

---

## 4. 事件总线

### 4.1 双层信号量架构 (`internal/kernel/bus.go`)

```
Publish(msg) ──► subscribers (RWMutex保护)
                   │ for each subscriber
                   ▼
         ┌─────────────────────┐
         │ Tier 1: maxGoroutines │ (cap=1024, 非阻塞)
         │  满 → 丢弃 + 记录     │
         └─────────┬───────────┘
                   │ acquired
                   ▼
         go func(sub) {                  ← 新 goroutine
             defer release maxGoroutines
         ┌─────────────────────┐
         │ Tier 2: dispatchSem   │ (cap=256, 非阻塞)
         │  满 → 丢弃 + 记录     │
         └─────────┬───────────┘
                   │ acquired
                   ▼
             ctx 检查 → handler()
             release dispatchSem
         }
```

**设计特点**:
- 无界 goroutine 防护: 硬上限 1024
- 非阻塞发布: 调用方永不等待
- Panic 隔离: 每个订阅 goroutine 独立 recover
- 原子指标: `atomic.Int64` 锁定无关的消息/错误/panic 计数
- `PublishSync`: 同步变体，直接调用处理器

**优雅排空** (Phase 2 修复后):
```go
func (b *Bus) Stop() {
    atomic.StoreInt32(&b.stopped, 1)
    b.subscribers = make(map[string][]subscriber)   // 清除订阅
    // 等待在途分发完成 (10秒超时)
    done := make(chan struct{})
    go func() { b.wg.Wait(); close(done) }()
    select { case <-done: ... case <-time.After(10s): ... }
}
```

---

## 5. SSAM V2.0 评分引擎

### 5.1 架构定位

```
┌─────────────────────────────────────┐
│        ASSCOR Platform               │
│  ┌──────────┐  ┌──────────────────┐ │
│  │ Assessor │─▶│ ssam Adapter     │ │
│  │ Module   │  │ (internal/ssam/) │ │
│  └──────────┘  └────────┬─────────┘ │
│                         │           │
│                         ▼           │
│              ┌──────────────────┐   │
│              │   ssam-lib       │   │
│              │ (独立 Go module)  │   │
│              │ 零依赖, 纯函数    │   │
│              └──────────────────┘   │
└─────────────────────────────────────┘
```

### 5.2 评分算法演进: V1 → V2.0

| 维度 | V1.x | V2.0 |
|------|------|------|
| **风险模型** | 二维平面: `ThreatCoeff`, `SPCScore` | 三层语义: `Intrinsic`, `Exposure`, `Threat` |
| **公式** | `weightedSum × threat × spc × ∏edgeFactors` | `weightedSum × ∏edgeFactors × max(exposure,0.60) × max(threat,0.60)` |
| **边缘因子位置** | 全局后乘数 | 归入 **Intrinsic** 层 (系统固有防护) |
| **输出** | 裸 `float64` | 结构化 `FinalScore{Total, Layers{RiskLayerDetail}}` |
| **可追溯性** | 无 | 逐层 `Coeff + Contributors` |
| **AST表示** | `multiply(multiply(multiply(weighted_sum, ref("threat")), ref("exposure")), product_chain)` | `multiply(multiply(multiply(weighted_sum, product_chain), max(ref("exposure"), 0.60)), max(ref("threat"), 0.60))` |

### 5.3 四核心域评分

```
AttackSurface:   权重 35  → 端口/服务/认证最小化 (AS-001~017)
BusinessContinuity: 权重 25 → 服务可达性/备份/资源 (BC-005~007)
OperationTrust:  权重 25  → 配置/审计/供应链完整性 (OT-001~022)
Resilience:      权重 15  → 抗压/沦陷指标ACI/降级 (RS-001~012)
KernelSecurity:  扩展权重 10 → 内核参数/模块签名 (KS-001~012)
```

每个检查项互斥，归属唯一域名。域得分 = 100 − Σ(未通过检查的Delta)，最低 0。

### 5.4 边缘因子链

| 因子 | 默认值 | 触发条件 | 级联 |
|------|--------|----------|------|
| EF-002FA | ×0.85 | EF-001 (2FA未配置) | — |
| EF-SYNCOOKIE | ×0.75 | RS-005 (SYN Cookie) | — |
| EF-SELINUX | ×0.80 | OT-005 (SELinux) | — |
| EF-APPARMOR | ×0.82 | OT-005 (AppArmor) | — |
| EF-NO-SIEM | ×0.90 | RS-007 (SIEM) | — |
| EF-NO-IDS | ×0.88 | RS-006 (IDS/IPS) | — |
| EF-3FA | ×0.82 | EF-002 级联 | CascadeTo: EF-002FA |

因子仅在对应检查失败时激活 (factor < 1.0)。

### 5.5 Formula DSL / AST (`ssam-lib/ast.go`)

支持运行时动态构造评分公式的领域特定语言:

```
运算符: weighted_sum | multiply | divide | min | max | product_chain | ref | const
引用:  "exposure" | "threat" | "intrinsic" | "domain_score:<name>" | "weight:<name>"
```

编译流水线: `FormulaAST` → `compileAST()` → `[]compiledOp` → `ASTToFormula()` 闭包执行。

V2 AST 编码的完整公式:
```
multiply(multiply(multiply(weighted_sum, product_chain),
       max(ref("exposure"), const(0.60))),
       max(ref("threat"), const(0.60)))
```

### 5.6 SSAM IR (`ssam-lib/ir.go`)

`SSAMIR` 是机器可读的 JSON 中间表示，包含完整评估快照:
- `Meta`: 版本, 公式ID, 时间戳
- `Input`: 主机ID, 检查项, RiskContext, 权重, 边缘因子
- `Output`: FinalScore, 可接受性, 域得分, RiskLayers

---

## 6. 安全态势计算 (SPC)

### 6.1 数据源体系

| 级别 | 数据源 | 同步间隔 | 用途 |
|------|--------|----------|------|
| **一级** | NVD (美国) | 6h | CVSS评分, CPE 2.3 匹配 |
| **一级** | CNNVD (中国) | 24h | 中文严重等级 |
| **一级** | CNVD (中国) | 24h | 国内漏洞 |
| **二级** | EPSS | 24h | 漏洞利用预测 (对数缩放) |
| **二级** | CISA KEV | 24h | 已知在野利用目录 |
| **三级** | Agent 采集 | 实时 (心跳) | 本地软件包清单, CPE |

### 6.2 计算公式

```
P_score(h) = max(0.60, 1.00 − √Σ Penalty_i²)

Penalty_i = Impact(CVE_i) × LocalFactor(CVE_i, h) × TimeWindow(CVE_i)

Impact = 0.20·f_cvss + 0.50·f_epss + 0.30·f_kev
  f_cvss = min(1.0, CVSS/10)
  f_epss = min(1.0, −ln(1−EPSS)/5)
  f_kev = 1.0 if InKEV, else 0.3 if HasPoC

LocalFactor = MatchType.Factor × ExposureLevel.Factor × ControlLevel.Factor
  MatchType: ExactVersion=1.0, VersionRange=0.7, CPEProduct=0.3, CPEVendor=0.15

TimeWindow = max(0.3, 1.0 − days/90)
```

### 6.3 缓存策略

- **容量**: 100,000 CVE (可配置)
- **驱逐**: 1年时间窗口 + KEV永不过期 (Phase 2 修复后增加了优先级驱逐)
- **持久化**: 磁盘 JSON 启动加载/退出保存
- **增量更新**: AddCVE/AddCVEs/MergeCVEs 支持 upsert 语义

### 6.4 复杂度

O(N × P × A) — N=CVE数量(100k), P=软件包数(50k), A=受影响CPE数(数百)。通过 `installedCPESet` 短路优化常见路径。

---

## 7. ATT&CK V19 威胁分析模块

### 7.1 模块结构 (Plugin Priority 21)

```
ATTACKModule (29 字段, 56 方法接口)
├── 核心子模块 (4)
│   ├── 检测与分析 (attck_detection.go)
│   ├── 威胁情报   (attck_ti.go)
│   ├── 对手仿真   (attck_emulation.go)
│   └── 评估工程   (attck_assessment.go)
├── APT 增强层 (4)
│   ├── 攻击链重构 (attck_apt_chain.go) — 多源证据 + MITRE 战术排序
│   ├── 因果推理   (attck_apt_causal.go) — 20条规则有向图
│   ├── 行为检测   (attck_apt_detect.go) — 8个指标 + EMA基线 + jitter分析
│   └── 归因引擎   (attck_apt_attribution.go) — TTP 60% + IOC 40% 融合
├── 高级检测 (2)
│   ├── 贝叶斯网络 (attck_apt_enhanced.go) — 4输入64行CPT
│   └── YARA/Sigma  (attck_apt_enhanced.go) — 模式匹配规则引擎
├── 威胁狩猎 (attck_apt_hunt.go)
│   └── 假设 CRUD + 转移矩阵自动生成 + 执行确认
└── 横向移动 (attck_apt_enhanced.go)
    └── 跨主机连接分析 + 评分
```

### 7.2 SSAM 评分双向增强闭环

```
 Assessor.Evaluate()
      │
      ├── applyATTACK (同步, DI 直调)
      │   ├── CalculateCoverage → result.ATTACKCoverage
      │   ├── AssessKillChain   → result.ATTACKKillChain
      │   ├── MatchAPTGroup     → result.ATTACKAPTMatches
      │   └── PredictRisk       → result.ATTACKPredictedRisk
      │
      └── PublishSync TopicAssessorResult
            │
            └── ATTACKModule.onAssessmentResult (异步)
                  ├── CalculateCoverage  → attck.coverage.complete
                  ├── triggerAlerts     → attck.detection.alert
                  ├── ReconstructChain  → attck.apt.chain_detected
                  ├── PerformAttribution → attck.apt.attribution
                  ├── PerformGapAnalysis → attck.assessment.complete
                  └── PredictRisk       → attck.threat.enhanced
```

**双路径架构**: 同步路径直接将 ATT&CK 数据注入 `AssessmentResult`(WEB UI 和策略模块可见)；异步路径触发全量分析流水线和13个扩展点。

### 7.3 关键算法

**C2 信标检测**: 10+ 网络事件 → 平均间隔 + 标准差 → jitter = std/mean → jitter < 0.1 → score 0.95。信誉库过滤 NTP/DNS/Windows更新误报。

**归因融合**: `TTP重叠(权重60%) × IOC匹配(权重40%) → 行业对齐加成 → 贝叶斯归一化`。

**攻击链重构**: 告警 + 异常 + IOC 多源证据 → 按 MITRE 战术顺序排列 → 因果推理置信度加成 (+0.15×avgCausalStrength, max +0.20)。

---

## 8. 适配器框架

### 8.1 双适配器架构

```
AdapterHub (统一管理)                Native Adapter Layer (底层扫描)
┌─────────────────────┐            ┌──────────────────────┐
│ Manager             │            │ Pipeline.RunAll()     │
│ ├─ SSAMAdapter ─────┼─ wraps ──▶│ adapter.ExecuteAdapter│
│ ├─ SRDAdapter       │            │  ├─ Fetch (exec/API)  │
│ └─ SimpleAdapter    │            │  ├─ Parse (JSON/XML)  │
│                     │            │  ├─ Map (enrich)      │
│ RuleEngine.ApplyAll │            │  └─ Validate          │
│  ├─ Transform       │            │                      │
│  ├─ Severity        │            │ Delegation.Apply()    │
│  ├─ Domain          │            │  → CheckID + Domain   │
│  ├─ Delta           │            │                      │
│  └─ Filter          │            │ ToCheckResult()       │
└─────────────────────┘            └──────────────────────┘
```

### 8.2 适配器清单 (21个)

**探测器 (11)**: Trivy, Nuclei, Lynis, OpenSCAP, Wazuh Agent, Suricata, Falco, ClamAV, OSV-Scanner, AIDE, Nikto

**管理类 (10)**: Ansible, NetBox, Snipe-IT, FreeIPA, Keycloak, Wazuh SIEM, Rundeck, Jira, Terraform, OpenTofu

### 8.3 规范化发现 → 评估引擎桥接

```
adapter.NormalizedFinding
    │ .ToCheckResult()
    ▼
model.CheckResult (CheckID, Domain, Delta=severityToDelta())
    │
    ▼
engine.Assessor → SSAM评分 → model.AssessmentResult
```

`DelegationRule` 自动将工具发现路由到正确的 SSAM 检查ID和域 (如 Trivy → AS-099-T attack_surface)。

---

## 9. 扩展管理器

### 9.1 扩展类型与注册

| 类型 | 注册动作 |
|------|----------|
| `check_module` | 扫描 `checks/` 子目录 → `checks.Register()` |
| `domain` | `model.RegisterDomain()` — 注册新 SSAM 域 |
| `edge_factor` | `model.RegisterEdgeFactor()` — 创建新边缘因子 |
| `hook` | `assessor.RegisterHook()` — 注册评估钩子 |
| `adapter` | 通过 AdapterHub 注册 |
| `scoring_plugin` | 自定义公式注入 ssam 引擎 |

### 9.2 安全执行模型

- **执行策略**: allowed / whitelist (默认) / sandboxed / disabled
- **命令解析硬化**: 基名检查 → 完整路径 → symlink 解析 → 绝对路径比对
- **路径遍历防护**: 所有解压和脚本执行检查 `filepath.Clean(targetPath)` 以安装目录为前缀
- **校验和验证**: SHA-256 下载完整性检查

---

## 10. 评估引擎

### 10.1 评估流水线

```
Assess(hostID)
  ├─ PhasePreCheck 钩子
  ├─ runAdapterPipeline() — 120s超时, 所有适配器并发
  ├─ checks.GetAll() → ShouldActivateCheck → SortByPriority
  ├─ runChecksConcurrently() — 信号量10, WaitGroup
  ├─ PhasePostCheck 钩子
  ├─ computeSPCScore() — CVE→资产匹配 + P_score计算
  ├─ PhasePreScore 钩子
  ├─ ssamEngine.ComputeScore() — SSAM V2.0评分
  ├─ applyATTACK() — 同步 ATT&CK 注入
  ├─ PhasePostScore / PhasePreReport 钩子
  └─ 返回 result
```

### 10.2 钩子阶段 (8阶段)

```
pre_check → post_check → pre_score → post_score → pre_edge → post_edge → pre_report → post_report
```

### 10.3 结果缓存

`sync.Map` — 5分钟 TTL 缓存，基于 `cacheKey = hostID + checkCount + checkHash`

---

## 11. 数据流与模块交互

### 11.1 Agent 心跳 → Kernel 完整数据流

```
Agent.runChecks()                     [agent.go:1153]
  │ 信号量10, 200检查并发
  ▼
model.CheckResult[] ──gRPC──▶
  │
KernelServiceImpl.Heartbeat()         [services.go:90]
  ├── HeartbeatModule.RecordHeartbeat()
  ├── SPCModule.UpsertAsset() (包/CPE更新)
  ├── AssessorModule.EvaluateFromResults()  [goroutine异步 — Phase 2/3修复]
  │     ├── ssamEngine.ComputeScore()
  │     ├── computeSPCScore()
  │     └── applyATTACK()
  ├── CommanderModule.DequeueCommands()
  └── 返回 HeartbeatResponse (Ok, ThreatCoeff, PendingCommands)
```

### 11.2 评估结果传播

```
AssessorModule.Evaluate() / EvaluateFromResults()
  │
  ├── PublishSync TopicAssessorResult
  │     ├── ATTACKModule.onAssessmentResult     [异步分析]
  │     ├── PolicyModule.onAssessmentResult     [策略判定]
  │     ├── PersistenceModule.onAssessmentResult [持久化]
  │     └── WebUIModule.onAssessmentResult      [仪表盘推送]
  │
  └── 返回 result
```

### 11.3 策略动作流

```
PolicyModule (policy.go)
  │ 消费 TopicAssessorResult
  ├── 分数 ≥ 80  → HostOK
  ├── 分数 60-80 → HostWarning → notify_admin
  ├── 分数 40-60 → HostCritical → increase_assessment + notify_admin
  └── 分数 < 40  → HostIsolated → isolate_host + notify_admin
```

---

## 12. gRPC / JSONRPC 双协议栈

```
Agent ──gRPC/mTLS──▶ Kernel gRPC Server (:50052)
   │                    │
   │                    ├─ KernelService (Register, Heartbeat)
   │                    └─ AgentService (GetSnapshot, StreamLogs)
   │
   └──JSONRPC/mTLS──▶ Kernel JSONRPC Server (:50051)
                         │
                         ├─ Register / Heartbeat / GetSnapshot
                         └─ ExecuteCommand / StreamLogs
```

**gRPC 拦截器链**: RateLimit → CircuitBreaker → AuditLog → Handler

**HMAC 签名指令**: `sign(cmdID, action, params...)` → Agent 白名单执行

---

## 13. Prism 传播风险引擎

### 13.1 架构

```
internal/prism/engine.go → github.com/chins-xing/prism
internal/srd/ → 外部评估报告 → Prism NodeState → DynamicScore
```

### 13.2 能力

- `ComputeDynamicScore`: 拓扑感知的动态风险传播计算
- `FindPropagationPaths`: 节点间风险传播路径发现
- SRD (Security Risk Determination): 接收外部评估报告 (Lynis/OpenSCAP JSON) → Prism 管道 → 动态评分

---

## 14. 关键架构决策总结

| 决策 | 理由 | 影响 |
|------|------|------|
| **微内核 + 插件** | 模块可独立开发/测试/替换 | 47文件的内核包是上帝包 |
| **DI 容器 (反射)** | 解耦模块间直接依赖 | 字段注入死代码, 手动构造与DI并存 |
| **事件总线 (双层信号量)** | 防止 goroutine 爆炸 | 优雅排空为后期修复 |
| **适配器 init() 自注册** | 零配置添加新工具 | 单例全局注册表 |
| **SSAM 纯函数式库** | 可被任意项目独立引用 | 零依赖, 无锁, 无副作用 |
| **V2.0 三层语义模型** | 语义清晰, 可追溯 | V1→V2 向后兼容桥接 |
| **同步+异步双路径 ATT&CK** | 同时满足实时性和完整性 | 增加复杂度但消除耦合 |
| **SPC 多数据源融合** | 全球漏洞情报本地化 | O(N*P*A) 计算瓶颈 |
| **HMAC 签名指令** | Agent 命令防篡改 | 90天自动密钥轮换 |
| **mTLS 双协议栈** | 安全传输 + 兼容性 | 自签名证书, 启动时5s检测 |
