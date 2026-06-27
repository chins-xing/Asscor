# ASSCOR Code Wiki

> **项目版本**: ASSCOR v0.1.2-MVP | **算法版本**: SSAM 1.3  
> **文档更新**: 2026-05-26

## 目录

1. [项目概述](#1-项目概述)
2. [系统架构](#2-系统架构)
3. [核心模块详解](#3-核心模块详解)
4. [关键类与函数](#4-关键类与函数)
5. [依赖关系](#5-依赖关系)
6. [配置管理](#6-配置管理)
7. [运行方式](#7-运行方式)
8. [扩展机制](#8-扩展机制)
9. [安全机制](#9-安全机制)
10. [API 接口](#10-api-接口)

---

## 1. 项目概述

### 1.1 项目简介

ASSCOR（ASSess + CORe，评估 + 内核）是一个开源的分布式安全可接受性评估系统，实现了 **SSAM（系统安全可接受性模型）1.3** 核心算法。项目采用 **μKernel + Agent** 架构，通过 gRPC 和 JSONRPC 双协议栈通信，支持 mTLS 加密。

**核心能力**：
- 四核心域互斥评估（攻击面、业务连续性、操作可信度、韧性）
- 边缘因子乘法修正
- 动态威胁系数（CTI 集成）
- 安全态势计算（SPC 模块）
- ATT&CK V19 威胁分析
- 等保 2.0 合规映射

### 1.2 技术栈

| 组件 | 技术选型 |
|------|----------|
| 语言 | Go 1.26 |
| 通信协议 | gRPC + JSONRPC + mTLS |
| 架构模式 | μKernel 微内核 + Agent |
| 配置格式 | INI 格式 |
| 并发控制 | Goroutine + Channel + WorkerPool |
| 缓存 | 内存缓存（sync.RWMutex 保护） |
| 日志 | log/slog（JSON 格式） |

### 1.3 项目结构

```
ASSCOR/
├── cmd/
│   ├── kernel/          # 微内核服务端入口
│   ├── agent/           # Agent 客户端入口
│   └── ASSCOR/          # 独立评估工具入口
├── internal/
│   ├── kernel/          # 内核核心模块（15+ 插件）
│   ├── ssam/            # SSAM 评分核心（可独立使用）
│   ├── agent/           # Agent 核心逻辑
│   ├── engine/          # 评估引擎
│   ├── adapter/         # 外部工具适配器框架
│   ├── checks/linux/    # Linux 检查项（53+ 项）
│   ├── model/           # 数据模型定义
│   ├── config/          # 配置解析器
│   ├── extmgr/          # 扩展管理器
│   ├── logger/          # 日志封装
│   ├── common/          # 公共工具（命令白名单）
│   └── cli/             # CLI 命令框架
├── api/v1/              # gRPC 接口定义
├── config/              # 行业专用配置
├── config.ini           # 内核默认配置
└── agent.ini            # Agent 默认配置
```

---

## 2. 系统架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        ASSCOR Kernel                             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                     Plugin Container                        │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │ │
│  │  │Assessor  │ │ Policy   │ │ SPC      │ │ ATTACK Module   │ │ │
│  │  │(评估引擎)│ │(策略管理)│ │(态势计算)│ │ (ATT&CK V19)    │ │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │ │
│  │  │ CTI      │ │ Commander│ │ Heartbeat│ │ AdapterIntegration│ │ │
│  │  │(威胁情报)│ │(指令下发)│ │(心跳监控)│ │ (适配器集成)     │ │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐ │
│  │ DI Container  │  │ Event Bus     │  │ Extension Registry    │ │
│  │ (依赖注入)     │  │ (事件总线)    │  │ (扩展点注册)          │ │
│  └───────────────┘  └───────────────┘  └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         ↕ gRPC/mTLS                      ↕ gRPC/mTLS
┌─────────────────────────────────────────────────────────────────┐
│                      ASSCOR Agent                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ Check Runner │  │ CPE Collector│  │ Command Executor        │ │
│  │ (检查执行)    │  │ (CPE 采集)   │  │ (命令执行)              │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Checks (53+ 项) - AS/OT/RS/BC/AC/EF/KS                      │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 插件生命周期

所有内核模块实现 `Plugin` 接口（[plugin.go](f:\Argus\internal\kernel\plugin.go)）：

```go
type Plugin interface {
    Info() PluginInfo
    Dependencies() []PluginDependency
    Init(ctx context.Context, kc KernelContext) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    State() PluginState
}
```

**插件启动顺序**（按优先级）：

| 优先级 | 插件 | 职责 |
|--------|------|------|
| 2 | ConcurrencyModule | WorkerPool + 信号量并发控制 |
| 5 | HeartbeatModule | Agent 心跳监控（60s 超时） |
| 10 | CTIModule | 网络威胁情报系数 μ |
| 20 | SPCModule | 安全态势计算 |
| 30 | ConfigWatcherModule | 配置热加载 |
| 40 | AssessorModule | SSAM 评分计算 |
| 50 | PolicyModule | 策略引擎 |
| 60 | CommanderModule | 命令分发 |
| 70 | LogCollectorModule | 日志收集 |

### 2.3 双协议栈架构

```
Agent ──gRPC/mTLS──▶ Kernel gRPC Server (:50052)
   │
   └──JSONRPC/mTLS──▶ Kernel JSONRPC Server (:50051)
```

---

## 3. 核心模块详解

### 3.1 SSAM 算法引擎 (`internal/ssam/`)

SSAM 是独立算法模块，可脱离 ASSCOR 框架单独使用。

**核心文件**：
- [engine.go](f:\Argus\internal\ssam\engine.go) - SSAM 1.3 评分引擎
- [interfaces.go](f:\Argus\internal\ssam\interfaces.go) - 接口定义
- [defaults.go](f:\Argus\internal\ssam\defaults.go) - 默认配置
- [adapter.go](f:\Argus\internal\ssam\adapter.go) - 格式适配器

**评分公式**：
```
SSAM_final = (Σ(S_i × W_i) / ΣW_i) × ΠM_j × μ × P_score
```

- `S_i`：核心域得分（0-100）
- `W_i`：域权重（默认：攻击面35、业务连续性25、操作可信度25、韧性15）
- `M_j`：边缘因子乘数（0.0-1.0）
- `μ`：威胁态势系数（0.6-1.0）
- `P_score`：SPC 修正因子（0.60-1.00）

**关键接口**：
```go
type Provider interface {
    ScoringProvider    // ComputeScore, ComputeDomainScores
    DomainProvider      // ListDomains, GetDomainLabel
    EdgeFactorProvider  // ListEdgeFactors, EvaluateEdgeFactors
    HookProvider        // RegisterHook, UnregisterHook
}
```

### 3.2 评估模块 (`internal/kernel/assessor.go`)

`AssessorModule` 是评估引擎核心，负责：
1. 加载检查项
2. 调用 SSAM Engine 计算域得分
3. 集成 SPC 态势修正
4. 集成 CTI 威胁系数
5. 集成 ATT&CK 分析

**核心方法**：
```go
func (m *AssessorModule) Evaluate(hostID string) *model.AssessmentResult
func (m *AssessorModule) EvaluateFromResults(hostID, hostname string, checks []model.CheckResult) *model.AssessmentResult
func (m *AssessorModule) ReloadConfig(cfg *config.Config)  // 权重热加载
```

### 3.3 SPC 模块 (`internal/kernel/spc.go`)

安全态势计算模块，从多数据源拉取漏洞情报并与本地资产交叉比对。

**数据源体系**：
| 数据源 | 方法 | 配置段 |
|--------|------|--------|
| NVD | FetchFromNVD | [spc.nvd] |
| EPSS | FetchFromEPSS | [spc.epss] |
| CISA KEV | FetchFromCISAKEV | [spc.cisa_kev] |
| CNNVD | FetchFromCNNVD | [spc.cnnvd] |
| CNVD | FetchFromCNVD | [spc.cnvd] |
| MISP | FetchFromMISP | [spc.misp] |

**CPE 匹配层级**：
1. `MatchExactVersion` - 精确版本匹配
2. `MatchVersionRange` - 版本范围匹配
3. `MatchCPEProduct` - 产品名匹配
4. `MatchCPEVendor` - 厂商名匹配

**P_score 计算**：
```
P_score = max(0.60, 1.00 - √ΣPenalty²)
Penalty = Impact × LocalFactor × TimeWindow
Impact = 0.20 × f_cvss + 0.50 × f_epss + 0.30 × f_kev
```

### 3.4 ATT&CK 模块 (`internal/kernel/attck_*.go`)

集成 MITRE ATT&CK V19 框架，提供四大子模块：

| 子模块 | 文件 | 能力 |
|--------|------|------|
| 检测与分析 | attck_detection.go | 检测规则引擎、告警关联 |
| 威胁情报 | attck_ti.go | IOC 管理、TTP 追踪 |
| 对手仿真 | attck_emulation.go | 仿真场景、安全模式执行 |
| 评估工程 | attck_assessment.go | 差距分析、控制映射 |

**APT 增强层**：
- [attck_apt_chain.go](f:\Argus\internal\kernel\attck_apt_chain.go) - 攻击链重构
- [attck_apt_detect.go](f:\Argus\internal\kernel\attck_apt_detect.go) - 行为检测、C2 信标
- [attck_apt_attribution.go](f:\Argus\internal\kernel\attck_apt_attribution.go) - APT 归因引擎
- [attck_apt_hunt.go](f:\Argus\internal\kernel\attck_apt_hunt.go) - 威胁狩猎框架

### 3.5 依赖注入容器 (`internal/kernel/di.go`)

基于反射的 IoC 容器，支持：
- 接口绑定：`Bind(接口, 实现)`
- 命名绑定：`BindNamed(名称, 接口, 实现)`
- 结构体注入：使用 `inject` tag

```go
func (c *Container) Bind(iface interface{}, impl interface{})
func (c *Container) BindNamed(name string, iface interface{}, impl interface{})
func (c *Container) Resolve(iface interface{}) (interface{}, bool)
func (c *Container) Inject(target interface{}) error
```

### 3.6 事件总线 (`internal/kernel/bus.go`)

发布-订阅模式的事件总线，支持同步/异步发布。

**特性**：
- Goroutine 并发控制（信号量 + maxGoroutines）
- Panic recovery 机制
- 消息指标统计

**主题常量**（[plugin.go:L83-92](f:\Argus\internal\kernel\plugin.go#L83-L92)）：
```go
const (
    TopicAssessorResult  = "assessor.result"
    TopicPolicyAction    = "policy.action"
    TopicAgentRegistered = "agent.registered"
    TopicSPCUpdated      = "spc.updated"
    TopicCTIUpdated      = "cti.updated"
    // ...
)
```

---

## 4. 关键类与函数

### 4.1 数据模型 (`internal/model/model.go`)

**核心结构体**：

```go
// 检查项定义
type CheckItem struct {
    ID            string
    Domain        string      // attack_surface/business_continuity/...
    Name          string
    Delta         float64     // 扣分值
    ComplianceRef string      // 等保条款编号
    Platform      string      // linux/windows
    Check         CheckFunc   // func() (bool, string)
}

// 检查结果
type CheckResult struct {
    CheckID       string
    Domain        string
    Passed        bool
    Delta         float64
    Detail        string
}

// 评估结果
type AssessmentResult struct {
    HostID             string
    FinalScore         float64
    Acceptable         bool
    DomainScores       DomainScores
    EdgeFactors        EdgeFactors
    ThreatCoeff        float64
    SPCScore           float64
    SPCCVEs            []SPCCVEInfo
    ATTACKCoverage     []ATTACKCoverageInfo
    Checks             []CheckResult
}

// 核心域得分
type DomainScores struct {
    AttackSurface      float64
    BusinessContinuity float64
    OperationTrust     float64
    Resilience         float64
    KernelSecurity     float64
}

// 边缘因子
type EdgeFactors struct {
    TwoFactorFailure   float64  // ×0.85
    SYNCookieDisabled  float64  // ×0.75
    SELinuxDisabled    float64  // ×0.80
    AppArmorDisabled   float64  // ×0.82
    NoSIEM             float64  // ×0.90
    NoIDS              float64  // ×0.88
}
```

### 4.2 检查项定义 (`internal/checks/linux/checks.go`)

**检查项编号体系**：

| 前缀 | 域 | 范围 | 示例 |
|------|-----|------|------|
| AS- | 攻击面管理 | 001-017 | AS-001（无用服务） |
| OT- | 操作可信度 | 001-022 | OT-001（文件权限） |
| RS- | 韧性 | 001-012 | RS-001（自动封禁） |
| BC- | 业务连续性 | 005-007 | BC-005（服务状态） |
| AC- | 可接受沦陷指标 | 001-008 | AC-001（网络分段） |
| EF- | 边缘因子 | 001-002 | EF-001（SYN Cookie） |
| KS- | 内核安全（扩展） | 001-012 | KS-001（内核参数） |

**检查函数签名**：
```go
func CheckFunc() (passed bool, detail string)
```

**示例**（[checks.go:L87-110](f:\Argus\internal\checks\linux\checks.go#L87-L110)）：
```go
func as001() model.CheckItem {
    return model.CheckItem{
        ID:            "AS-001",
        Domain:        model.DomainAttackSurface,
        Name:          "无用服务关闭",
        Delta:         -8,
        ComplianceRef: "L3-CE-21",
        Check: func() (bool, string) {
            dangerous := []string{"telnet", "rsh", "rexec"}
            // 检查逻辑...
        },
    }
}
```

### 4.3 适配器框架 (`internal/adapter/adapter.go`)

外部工具适配器接口定义：

```go
type Adapter interface {
    ID() string
    Name() string
    Fetch(ctx context.Context, config map[string]string) ([]byte, error)
    Parse(raw []byte) ([]*NormalizedFinding, error)
    Map(findings []*NormalizedFinding) []*NormalizedFinding
    Validate(findings []*NormalizedFinding) ([]*NormalizedFinding, []error)
    IsEnabled(config map[string]string) bool
}

type NormalizedFinding struct {
    ID          string
    Source      string
    ToolName    string
    Severity    Severity    // critical/high/medium/low/info
    FindingType FindingType // vulnerability/misconfiguration/compliance
    CheckID     string
    Domain      string
    Passed      bool
    Delta       float64
    // ...
}
```

**适配器分类**（[adapter/scanner/](f:\Argus\internal\adapter\scanner/) 和 [adapter/management/](f:\Argus\internal\adapter\management/)）：
- 扫描器适配器：Trivy, Nuclei, Lynis, OpenSCAP 等
- 管理类适配器：Ansible, NetBox, FreeIPA, Jira 等

### 4.4 Agent 核心 (`internal/agent/agent.go`)

**关键结构体**：

```go
type Agent struct {
    cfg              AgentConfig
    client           *Client
    checkers         []model.CheckItem
    pendingCmd       []*apiv1.Command
    hmacKeyConfigured bool
    cachedPackages   []string
}

type AgentConfig struct {
    KernelAddr       string  // 默认：localhost:50051
    HostID           string  // 默认：主机名
    HeartbeatSec     int     // 默认：2
    CheckIntervalSec int     // 默认：3600
    TLSEnabled       bool    // 默认：false
    HMACKey          string
}
```

**核心流程**：
1. `connect()` - 建立 TLS/mTLS 连接
2. `register()` - 向 Kernel 注册
3. `heartbeatCycle()` - 心跳循环
   - 执行待处理命令
   - 运行检查项
   - 上报结果和 CPE

### 4.5 gRPC 接口 (`api/v1/grpc.go`)

**服务定义**：

```go
type KernelServiceServer interface {
    Register(ctx context.Context, req *PBRegisterRequest) (*PBRegisterResponse, error)
    Heartbeat(ctx context.Context, req *PBHeartbeatRequest) (*PBHeartbeatResponse, error)
}

type AgentServiceServer interface {
    GetSnapshot(ctx context.Context, req *PBSnapshotRequest) (*PBSnapshotResponse, error)
    ExecuteCommand(ctx context.Context, req *PBCommandRequest) (*PBCommandResponse, error)
    StreamLogs(stream AgentService_StreamLogsServer) error
}
```

**消息类型**：
- `PBRegisterRequest/Response` - Agent 注册
- `PBHeartbeatRequest/Response` - 心跳（含检查结果和待执行命令）
- `PBCommand` - HMAC 签名命令
- `PBAssessmentResult` - 评估结果快照

---

## 5. 依赖关系

### 5.1 模块依赖图

```
┌─────────────────────────────────────────────────────────┐
│                      Kernel Main                         │
└─────────────────────┬───────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐
│DI Container│  │Event Bus  │  │Extension  │
│  (依赖注入) │  │ (事件总线) │  │Registry   │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │             │             │
      └─────────────┼─────────────┘
                    ▼
        ┌───────────────────────┐
        │   Plugin Container     │
        │  ┌─────────────────┐  │
        │  │ AssessorModule  │◄─┼──┐
        │  │ (评估引擎)      │  │  │
        │  └────────┬────────┘  │  │
        │           │           │  │
        │  ┌────────▼────────┐  │  │
        │  │ SSAM Engine     │◄─┼──┼──┐
        │  │ (评分算法)      │  │  │  │
        │  └─────────────────┘  │  │  │
        │                      │  │  │
        │  ┌─────────────────┐ │  │  │
        │  │ SPCModule      │◄─┼──┼──┼──┐
        │  │ (态势计算)      │  │  │  │  │
        │  └─────────────────┘  │  │  │  │
        │                       │  │  │  │
        │  ┌─────────────────┐  │  │  │  │
        │  │ CTIModule      │◄─┼──┼──┼──┼──┐
        │  │ (威胁情报)      │  │  │  │  │  │
        │  └─────────────────┘  │  │  │  │  │
        │                       │  │  │  │  │
        │  ┌─────────────────┐  │  │  │  │  │
        │  │ ATTACKModule    │◄─┼──┼──┼──┼──┼──┐
        │  │ (ATT&CK分析)    │  │  │  │  │  │  │
        │  └─────────────────┘  │  │  │  │  │  │
        └───────────────────────┼──┼──┼──┼──┼──┼──┘
                                │  │  │  │  │
                                ▼  ▼  ▼  ▼  ▼
                    ┌─────────────────────────┐
                    │   Config (配置解析)     │
                    │   Model (数据模型)       │
                    │   Logger (日志)         │
                    └─────────────────────────┘
```

### 5.2 接口依赖注入

**AssessorModule 初始化**（[assessor.go:L48-84](f:\Argus\internal\kernel\assessor.go#L48-L84)）：
```go
func (m *AssessorModule) Init(ctx context.Context, kc KernelContext) error {
    m.engine = engine.NewAssessor(m.cfg)
    
    // 绑定 SSAM Engine
    kc.Container().Bind((*ssam.ScoringProvider)(nil), m.engine.SSAMEngine())
    
    // 绑定 Assessor Module
    kc.Container().Bind((*AssessorInterface)(nil), m)
    
    // 注册扩展点
    kc.Extensions().RegisterPoint(ExtensionPoint{
        Name: "assessor.pre_evaluate",
        // ...
    })
    return nil
}
```

---

## 6. 配置管理

### 6.1 配置结构 (`internal/config/config.go`)

```go
type Config struct {
    Weights      model.Weights           // 四域权重
    Threshold    float64                  // 可接受阈值（默认：80）
    EdgeFactors  model.EdgeFactors        // 边缘因子
    ThreatCoeff  float64                  // 威胁系数（默认：1.0）
    SPCEnabled   bool                     // 是否启用 SPC
    
    CheckDeltas map[string]float64       // 检查项扣分表
    SPC        model.SPCConfig           // SPC 配置
    ATTACK     model.ATTACKConfig        // ATT&CK 配置
    
    AdapterConfig map[string]string      // 适配器配置
    ExtMgrCfg   ExtMgrConfig             // 扩展管理器配置
    
    HotloadEnabled   bool                 // 是否启用配置热加载
    HotloadIntervalS int                 // 热加载间隔（秒）
}
```

### 6.2 默认配置 (`config.ini`)

**权重配置**：
```ini
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15
```

**边缘因子**：
```ini
[edge_factors]
two_factor_failure = 0.85      # 双因素认证缺失
syn_cookie_disabled = 0.75     # SYN Cookie 未开启
selinux_disabled = 0.80        # SELinux 未启用
apparmor_disabled = 0.82       # AppArmor 未启用
no_siem = 0.90                 # 无 SIEM
no_ids = 0.88                  # 无 IDS/IPS
```

**SPC 配置**：
```ini
[spc]
enabled = true
min_pscore = 0.60
cache_retention_days = 365
fetch_interval_h = 1

[spc.nvd]
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
api_key =              # 从环境变量 NVD_API_KEY 读取
sync_interval_h = 6
```

### 6.3 Agent 配置 (`agent.ini`)

```ini
[agent]
kernel_addr = 127.0.0.1:50051
host_id =
heartbeat_sec = 2
check_interval_sec = 3600
check_timeout_sec = 10
max_retries = 3
reconnect_sec = 5
tls_enabled = false
cert_dir = certs
hmac_key =              # 从环境变量 ASSCOR_HMAC_KEY 读取
```

### 6.4 环境变量覆盖

| 配置项 | 环境变量 |
|--------|----------|
| NVD API Key | `NVD_API_KEY` |
| CNNVD API Key | `CNNVD_API_KEY` |
| MISP API Key | `MISP_API_KEY` |
| HMAC 密钥 | `ASSCOR_HMAC_KEY` |

---

## 7. 运行方式

### 7.1 编译项目

```bash
# 克隆项目
git clone https://github.com/asscor/asscor.git
cd ASSCOR

# 编译所有组件
go build -o ASSCOR-kernel ./cmd/kernel
go build -o ASSCOR-agent ./cmd/agent

# 或使用 Makefile
make build
```

### 7.2 启动 Kernel

```bash
# 基本启动（JSONRPC，默认端口 50051）
./ASSCOR-kernel -config config.ini

# 指定监听地址
./ASSCOR-kernel -listen 0.0.0.0:50051

# 禁用 mTLS（仅开发环境）
./ASSCOR-kernel -listen 0.0.0.0:50051 -no-mtls

# 启用 gRPC（端口 50052）
./ASSCOR-kernel -config config.ini

# 行业配置模板
./ASSCOR-kernel -config config/config.gov.ini  # 政府
./ASSCOR-kernel -config config/config.fin.ini   # 金融

# 守护进程模式
./ASSCOR-kernel -daemon -pid-file /var/run/asscor.pid

# 强制重新生成 TLS 证书
./ASSCOR-kernel -force-regen-certs

# 验证 TLS 证书
./ASSCOR-kernel -verify-certs

# 日志配置
./ASSCOR-kernel -log-format text -log-level debug
```

### 7.3 启动 Agent

```bash
# 基本启动
./ASSCOR-agent -kernel 127.0.0.1:50051

# 使用配置文件
./ASSCOR-agent -config agent.ini

# 指定主机 ID
./ASSCOR-agent -kernel 192.168.1.100:50051 -host-id server01

# 启用 TLS
./ASSCOR-agent -tls -cert-dir /path/to/certs

# 开发环境（跳过证书验证）
./ASSCOR-agent -tls -tls-skip-verify

# 日志配置
./ASSCOR-agent -log-format text -log-level debug
```

### 7.4 独立评估模式

```bash
# 本地评估（无需 Kernel）
./ASSCOR -config config.ini

# JSON 格式输出
./ASSCOR -json

# 使用行业配置
./ASSCOR -config config/config.gov.ini -json
```

### 7.5 Docker 部署

```bash
# 构建镜像
docker build -t asscor:latest .

# 运行 Kernel
docker run -d -p 50051:50051 -p 50052:50052 \
  -v $(pwd)/config.ini:/app/config.ini \
  -v $(pwd)/certs:/app/certs \
  asscor:latest kernel

# 运行 Agent
docker run -d \
  -e ASSCOR_HMAC_KEY=your-secret-key \
  asscor:latest agent -kernel kernel:50051
```

---

## 8. 扩展机制

### 8.1 扩展点系统 (`internal/kernel/extensions.go`)

扩展点允许在评估流程各阶段插入自定义逻辑：

```go
type ExtensionPoint struct {
    Name        string
    Description string
    Version     string
}

// 内置扩展点
const (
    "kernel.pre_init"      // 所有插件初始化前
    "kernel.post_init"     // 所有插件初始化后
    "kernel.pre_start"     // 所有插件启动前
    "kernel.post_start"    // 所有插件启动后
    "assessor.pre_evaluate"  // 每次评估前
    "assessor.post_evaluate" // 每次评估后
)
```

### 8.2 SSAM 钩子机制

在评分过程各阶段插入自定义逻辑：

```go
type HookPhase string

const (
    HookPreScore  HookPhase = "pre_score"   // 计算域得分前
    HookPostScore HookPhase = "post_score"  // 计算域得分后
    HookPreEdge   HookPhase = "pre_edge"    // 应用边缘因子前
    HookPostEdge  HookPhase = "post_edge"   // 应用边缘因子后
)

type AssessmentHook func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error
```

### 8.3 扩展管理器 (`internal/extmgr/`)

支持动态加载外部扩展：

```go
type ExtensionSpec struct {
    ID          string
    Name        string
    Version     string    // SemVer
    Description string
    Commands    []string  // 白名单命令
    Checks      []string  // 自定义检查项 ID
}

// 配置
[extension_manager]
enabled = true
extensions_dir = ./extensions
state_dir = ./extensions/state
auto_enable = false
execution_timeout_s = 30
```

### 8.4 自定义检查项

1. 实现 `CheckFunc`：
```go
func myCustomCheck() (bool, string) {
    // 检查逻辑
    passed := checkSomething()
    detail := "检查详情"
    return passed, detail
}
```

2. 封装为 `CheckItem`：
```go
model.CheckItem{
    ID:            "MY-001",
    Domain:        model.DomainOperationTrust,
    Name:          "自定义检查",
    Delta:         -10,
    ComplianceRef: "Custom-001",
    Platform:      "linux",
    Check:         myCustomCheck,
}
```

3. 注册到检查项列表：
```go
// internal/checks/linux/checks.go
func All() []model.CheckItem {
    items := []model.CheckItem{
        // ... 现有检查项
        myCustomCheckItem(),
    }
    return items
}
```

---

## 9. 安全机制

### 9.1 命令执行白名单 (`internal/common/exec.go`)

**白名单命令**：
```go
allowedCommands = map[string]bool{
    "systemctl": true,
    "ss":        true,
    "sysctl":    true,
    "iptables":  true,
    "ip":        true,
    "ufw":       true,
    "firewall-cmd": true,
    // ... 共 24 个
}
```

**Shell 命令白名单**：
```go
allowedShellCommands = map[string]bool{
    "systemctl":   true,
    "service":     true,
    "chkconfig":   true,
    "journalctl":  true,
    // ... 共 15 个
}
```

**安全检查**：
```go
func containsShellMetachar(s string) bool {
    // 检查 shell 元字符：| & ; $ < > ` \ " '
}
```

### 9.2 HMAC 命令签名

Commander 模块使用 HMAC-SHA256 签名命令：
- 签名内容：`cmdID:command:key1=value1:key2=value2...`（参数按键排序）
- 密钥轮换：90 天自动轮换
- Agent 端验证签名后才执行

```go
// Commander 配置
[commander]
hmac_key = your-256-bit-secret
key_rotation_days = 90
```

### 9.3 mTLS 双向认证

**证书体系**：
- CA 证书：签名所有服务端/客户端证书
- Server 证书：服务端身份验证
- Agent 证书：客户端身份验证

**自动证书管理**：
- 启动时自动生成自签名证书
- 支持强制重新生成：`--force-regen-certs`
- 验证证书一致性：`--verify-certs`

### 9.4 并发安全

- 所有共享状态使用 `sync.RWMutex` 保护
- 信号量控制最大并发（WorkerPool 默认 10）
- Bus 消息分发有 goroutine 上限（1024）
- Panic recovery 机制防止崩溃传播

---

## 10. API 接口

### 10.1 gRPC 服务定义

**KernelService**：

```protobuf
service KernelService {
    rpc Register(RegisterRequest) returns (RegisterResponse);
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}

message RegisterRequest {
    string host_id = 1;
    string hostname = 2;
    string version = 3;
}

message HeartbeatRequest {
    string host_id = 1;
    string session_id = 2;
    AssessmentResult result = 3;
    repeated string packages = 5;
    repeated string installed_cpes = 6;
}
```

**AgentService**：

```protobuf
service AgentService {
    rpc GetSnapshot(SnapshotRequest) returns (SnapshotResponse);
    rpc ExecuteCommand(CommandRequest) returns (CommandResponse);
    rpc StreamLogs(stream LogEntry) returns (Ack);
}
```

### 10.2 JSONRPC 接口

**请求格式**：
```json
{
    "jsonrpc": "2.0",
    "method": "Register",
    "params": {
        "host_id": "server01",
        "hostname": "server01.example.com",
        "version": "v0.1.2-MVP"
    },
    "id": 1
}
```

**响应格式**：
```json
{
    "jsonrpc": "2.0",
    "result": {
        "accepted": true,
        "session_id": "sess-abc123"
    },
    "id": 1
}
```

### 10.3 RESTful 端点（扩展）

部分功能支持 REST API（通过 API 网关）：

```
GET  /api/v1/hosts                    # 列出所有主机
GET  /api/v1/hosts/{id}              # 获取主机详情
GET  /api/v1/hosts/{id}/assessment   # 获取最新评估结果
GET  /api/v1/snapshot                # 获取全局快照
POST /api/v1/commands                # 下发命令
```

---

## 11. 源代码深度分析

### 11.1 SSAM Engine 实现细节

#### 11.1.1 核心评分流程

SSAM Engine 是独立算法模块，可脱离 ASSCOR 框架使用。核心评分流程如下：

```go
// internal/ssam/engine.go - 伪代码
func (e *Engine) ComputeScore(input *AssessmentInput) *AssessmentOutput {
    // 1. 钩子执行：pre_score
    if err := e.runHooks(HookPreScore, input, nil); err != nil {
        return nil
    }
    
    // 2. 计算域得分
    domainScores := e.computeDomainScores(input)
    
    // 3. 钩子执行：post_score
    output := &AssessmentOutput{DomainScores: domainScores}
    if err := e.runHooks(HookPostScore, input, output); err != nil {
        return nil
    }
    
    // 4. 应用边缘因子
    edgeMultiplier := e.evaluateEdgeFactors(input)
    
    // 5. 计算最终分数
    finalScore := computeFinalScore(domainScores, edgeMultiplier, input)
    
    return output
}
```

#### 11.1.2 加权平均计算

```go
// 正确的加权平均（Σ(S_i × W_i) / ΣW_i）
func computeWeightedAverage(scores DomainScores, weights Weights) float64 {
    totalScore := 0.0
    totalWeight := 0.0
    
    if scores.AttackSurface > 0 {
        totalScore += scores.AttackSurface * weights.AttackSurface
        totalWeight += weights.AttackSurface
    }
    if scores.BusinessContinuity > 0 {
        totalScore += scores.BusinessContinuity * weights.BusinessContinuity
        totalWeight += weights.BusinessContinuity
    }
    if scores.OperationTrust > 0 {
        totalScore += scores.OperationTrust * weights.OperationTrust
        totalWeight += weights.OperationTrust
    }
    if scores.Resilience > 0 {
        totalScore += scores.Resilience * weights.Resilience
        totalWeight += weights.Resilience
    }
    
    if totalWeight == 0 {
        return 0
    }
    return totalScore / totalWeight  // 注意：不是 /100
}
```

#### 11.1.3 边缘因子乘法

边缘因子仅对 `Active && Factor ∈ (0,1)` 的项执行乘法：

```go
func evaluateEdgeFactors(factors EdgeFactors, active EdgeFactorActive) float64 {
    multiplier := 1.0
    
    if active.TwoFactorFailure && factors.TwoFactorFailure > 0 && factors.TwoFactorFailure < 1 {
        multiplier *= factors.TwoFactorFailure  // ×0.85
    }
    if active.SYNCookieDisabled && factors.SYNCookieDisabled > 0 && factors.SYNCookieDisabled < 1 {
        multiplier *= factors.SYNCookieDisabled  // ×0.75
    }
    // ... 其他边缘因子
    
    return multiplier
}
```

---

### 11.2 SPC 模块实现细节

#### 11.2.1 数据获取策略

SPC 模块采用多数据源并发拉取策略（[spc_fetch.go](f:\Argus\internal\kernel\spc_fetch.go)）：

```go
func (m *SPCModule) FetchFromAllSources() []SPCFetchResult {
    results := make([]SPCFetchResult, 0)
    
    // 1. NVD API 获取（必须）
    result := m.FetchFromNVD()
    results = append(results, result)
    
    // 2. EPSS 数据（可选）
    if m.epssConfig.Enabled {
        resultEPSS := m.FetchFromEPSS()
        results = append(results, resultEPSS)
    }
    
    // 3. CISA KEV（可选）
    if m.kevConfig.Enabled {
        resultKEV := m.FetchFromCISAKEV()
        results = append(results, resultKEV)
    }
    
    // 4. MISP（可选）
    result2 := m.FetchFromMISP()
    
    // 5. CNNVD/CNVD（可选）
    // ...
    
    return results
}
```

#### 11.2.2 NVD API 并发策略

```go
// internal/kernel/spc_fetch.go:L310-415
func (m *SPCModule) fetchNVDAPI(...) ([]SPCCVEScore, error) {
    // 根据是否有 API Key 决定并发度
    concurrency := 1
    chunkDays := 120
    if apiKey == "" && totalDays > 30 {
        chunkDays = 30
        concurrency = 4  // 无 Key：4 并发
    } else if apiKey != "" && totalDays > 60 {
        chunkDays = 60
        concurrency = 2  // 有 Key：2 并发
    }
    
    // 窗口式并发拉取
    sem := make(chan struct{}, concurrency)
    var wg sync.WaitGroup
    
    for i, w := range windows {
        wg.Add(1)
        sem <- struct{}{}
        go func(idx int, start, end time.Time) {
            defer wg.Done()
            defer func() { <-sem }()
            
            cves, err := m.fetchNVDWindow(client, baseURL, apiKey, start, end, ...)
            results[idx] = windowResult{cves: cves, err: err, idx: idx}
        }(i, w.start, w.end)
    }
    wg.Wait()
    
    return allCVEs, nil
}
```

#### 11.2.3 CPE 匹配算法

CPE 匹配采用分层优先级（[spc_match.go](f:\Argus\internal\kernel\spc_match.go)）：

```go
type MatchType int

const (
    MatchNone MatchType = iota
    MatchCPEVendor           // 厂商匹配（优先级最低）
    MatchCPEProduct          // 产品匹配
    MatchVersionRange        // 版本范围匹配
    MatchExactVersion        // 精确版本匹配（优先级最高）
)

func (m *SPCModule) compareCPE(installed, vuln string) MatchType {
    // 1. 解析版本范围
    cpePart, versionRange := parseCPEParts(vuln)
    
    // 2. 比较 CPE 各字段
    matchCount := compareCPEParts(installed, cpePart)
    
    // 3. 根据匹配字段数判断匹配类型
    if matchCount >= 5 && versionRange == "" && exactVersionMatch(installed, vuln) {
        return MatchExactVersion  // 最高优先级
    }
    if matchCount >= 5 {
        return MatchVersionRange
    }
    if matchCount >= 4 && versionInRange(installedVersion, versionRange) {
        return MatchVersionRange
    }
    if matchCount >= 3 {
        return MatchCPEProduct
    }
    if matchCount >= 2 {
        return MatchCPEVendor
    }
    return MatchNone
}
```

#### 11.2.4 P_score 计算公式

```
P_score = max(0.60, 1.00 - √ΣPenalty²)
Penalty = Impact × LocalFactor × TimeWindow
Impact = 0.20 × f_cvss + 0.50 × f_epss + 0.30 × f_kev
```

```go
func (m *SPCModule) CalculatePScore(localCPEs []string, packages []string) float64 {
    var totalPenalty float64
    
    for _, cpe := range localCPEs {
        for _, cve := range m.cveCache {
            matchType := m.compareCPE(cpe, cve.AffectedCPEs...)
            if matchType == MatchNone {
                continue
            }
            
            // 计算影响因子
            f_cvss := cve.CVSS / 10.0
            f_epss := cve.EPSS
            f_kev := 0.0
            if cve.InKEV {
                f_kev = 1.0
            }
            impact := 0.20*f_cvss + 0.50*f_epss + 0.30*f_kev
            
            // 局部因子（本地匹配类型）
            localFactor := float64(matchType) / float64(MatchExactVersion)
            
            // 时间窗口因子
            daysSincePublished := time.Since(cve.DatePublished).Hours() / 24
            timeWindow := math.Max(0.5, 1.0-daysSincePublished/365.0)
            
            penalty := impact * localFactor * timeWindow
            totalPenalty += penalty * penalty  // 平方累计
        }
    }
    
    pScore := 1.0 - math.Sqrt(totalPenalty)
    return math.Max(0.60, pScore)
}
```

---

### 11.3 检查项实现细节

#### 11.3.1 检查项注册机制

检查项通过 `All()` 函数统一注册（[checks.go:L16-85](f:\Argus\internal\checks\linux\checks.go#L16-L85)）：

```go
func All() []model.CheckItem {
    items := []model.CheckItem{
        // 攻击面管理（AS-001 至 AS-017）
        as001(), as002(), as003(), // ...
        
        // 操作可信度（OT-001 至 OT-022）
        ot001(), ot002(), ot003(), // ...
        
        // 韧性（RS-001 至 RS-012）
        rs001(), rs002(), rs003(), // ...
        
        // 业务连续性（BC-005 至 BC-007）
        bc005(), bc006(), bc007(),
        
        // 可接受沦陷指标（AC-001 至 AC-008）
        ac001(), ac002(), ac003(), // ...
        
        // 边缘因子（EF-001, EF-002）
        ef001(), ef002(),
    }
    // 追加内核安全扩展域
    items = append(items, ksAll()...)
    return items
}
```

#### 11.3.2 检查函数实现模式

```go
// 典型检查函数签名
func as001() model.CheckItem {
    return model.CheckItem{
        ID:            "AS-001",
        Domain:        model.DomainAttackSurface,
        Name:          "无用服务关闭",
        Delta:         -8,
        ComplianceRef: "L3-CE-21",  // 等保三级条款
        Platform:      "linux",
        Check: func() (bool, string) {
            dangerous := []string{"telnet", "rsh", "rexec", "chargen", "echo"}
            var active []string
            
            for _, svc := range dangerous {
                // 使用白名单命令执行
                out, ok := common.RunCmdQuiet("systemctl", "is-active", svc)
                if ok && strings.TrimSpace(out) == "active" {
                    active = append(active, svc)
                }
            }
            
            if len(active) == 0 {
                return true, "所有高风险服务均已禁用"
            }
            return false, fmt.Sprintf("发现 %d 个高风险服务: %s", len(active), strings.Join(active, ", "))
        },
    }
}
```

#### 11.3.3 命令执行白名单

所有检查项必须使用白名单命令（[common/exec.go](f:\Argus\internal\common\exec.go)）：

```go
var allowedCommands = map[string]bool{
    "systemctl":    true,
    "ss":           true,
    "sysctl":       true,
    "iptables":     true,
    "firewall-cmd": true,
    "uname":        true,
    "dmesg":        true,
    "lsmod":        true,
    "sestatus":     true,
    "aa-status":    true,
    "getenforce":   true,
    // ... 共 24 个
}

var allowedShellCommands = map[string]bool{
    "systemctl status":                  true,
    "ss -tlnp":                         true,
    "sysctl net.ipv4.tcp_syncookies":   true,
    "iptables -L -n":                    true,
    // ... 共 15 个
}

// 安全检查：防止 shell 元字符注入
func containsShellMetachar(s string) bool {
    return strings.ContainsAny(s, "|;&`$()<>{}\n\r")
}
```

---

### 11.4 并发安全实现

#### 11.4.1 WorkerPool 实现

WorkerPool 提供受控的并发任务执行（[workerpool.go](f:\Argus\internal\kernel\workerpool.go)）：

```go
func (p *WorkerPool) SubmitWithTimeout(task func() error, timeout time.Duration) {
    p.wg.Add(1)
    go func() {
        defer p.wg.Done()
        
        // 1. 获取信号量（限制并发数）
        select {
        case p.semaphore <- struct{}{}:
            defer func() { <-p.semaphore }()
            
            // 2. 设置任务超时
            taskCtx, taskCancel := context.WithTimeout(context.Background(), timeout)
            defer taskCancel()
            
            // 3. 执行任务（带 panic recovery）
            done := make(chan error, 1)
            go func() {
                defer func() {
                    if r := recover(); r != nil {
                        done <- fmt.Errorf("panic: %v", r)
                    }
                }()
                done <- task()
            }()
            
            select {
            case err := <-done:
                // 更新指标
            case <-taskCtx.Done():
                // 超时处理
            }
        case <-p.ctx.Done():
            return  // 池已关闭
        }
    }()
}
```

#### 11.4.2 事件总线并发控制

事件总线使用信号量限制分发并发（[bus.go](f:\Argus\internal\kernel\bus.go)）：

```go
type EventBus struct {
    mu            sync.RWMutex
    subscribers   map[string][]*Subscriber
    dispatchSem   chan struct{}      // 信号量限制
    maxGoroutines int                // goroutine 上限
}

func (b *EventBus) dispatch(sub *Subscriber, msg Message) {
    b.dispatchSem <- struct{}{}  // 获取信号量
    go func() {
        defer func() { <-b.dispatchSem }()  // 释放信号量
        
        defer func() {
            if r := recover(); r != nil {
                logger.WithComponent("bus").Error("subscriber panic", "panic", r)
            }
        }()
        
        sub.handler(msg)
    }()
}
```

---

### 11.5 HMAC 命令签名机制

Commander 模块实现安全的命令分发（[commander.go](f:\Argus\internal\kernel\commander.go)）：

#### 11.5.1 密钥管理

```go
func (m *CommanderModule) generateAndPersistKey(keyPath, metaPath string) {
    key := randomHex(32)  // 生成 256 位密钥
    m.hmacKey = []byte(key)
    m.keyMeta = keyMetadata{
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(90 * 24 * time.Hour),  // 90 天轮换
        KeyHash:   sha256Hex([]byte(key)),
    }
    
    // 持久化到文件
    os.WriteFile(keyPath, []byte(key), 0600)
}

func (m *CommanderModule) rotateKey(keyPath, metaPath string) {
    m.prevHMACKey = make([]byte, len(m.hmacKey))
    copy(m.prevHMACKey, m.hmacKey)  // 保留旧密钥用于验证
    m.keyRotatedAt = time.Now()
    
    // 生成新密钥
    newKey := randomHex(32)
    m.hmacKey = []byte(newKey)
}
```

#### 11.5.2 命令签名

```go
func signCommand(cmd *apiv1.Command, key []byte) string {
    // 按键排序构造签名内容
    var parts []string
    parts = append(parts, cmd.Id)
    parts = append(parts, cmd.Action)
    
    var keys []string
    for k := range cmd.Params {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    
    for _, k := range keys {
        parts = append(parts, fmt.Sprintf("%s=%s", k, cmd.Params[k]))
    }
    
    // HMAC-SHA256 签名
    content := strings.Join(parts, ":")
    h := hmac.New(sha256.New, key)
    h.Write([]byte(content))
    return hex.EncodeToString(h.Sum(nil))
}

func verifySignature(cmd *apiv1.Command, key []byte) bool {
    expected := signCommand(cmd, key)
    return hmac.Equal([]byte(cmd.Signature), []byte(expected))
}
```

---

### 11.6 ATT&CK 模块实现

#### 11.6.1 检测规则引擎

```go
// internal/kernel/attck_detection.go
func (m *ATTACKModule) EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error) {
    var rule *DetectionRule
    for i := range m.detectionRules {
        if m.detectionRules[i].ID == ruleID {
            rule = &m.detectionRules[i]
            break
        }
    }
    
    // 规则匹配
    matched := m.matchRule(rule, rawLog, fields)
    if !matched {
        return nil, nil
    }
    
    // 生成告警
    alert := DetectionAlert{
        ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
        RuleID:      rule.ID,
        TechniqueID: rule.TechniqueID,
        Severity:    rule.Severity,
        HostID:      hostID,
        Timestamp:   time.Now(),
    }
    
    // 发布到事件总线
    m.kernel.Bus().Publish(m.kernel.Context(), Message{
        Topic:   "attck.detection.alert",
        Payload: alert,
    })
    
    return &alert, nil
}
```

#### 11.6.2 IOC 管理

```go
// internal/kernel/attck_ti.go
func (m *ATTACKModule) AddIOC(entry IOCEntry) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // 检查重复
    for i, existing := range m.iocs {
        if existing.Type == entry.Type && existing.Value == entry.Value {
            m.iocs[i] = entry  // 更新
            return nil
        }
    }
    
    // 添加新 IOC
    m.iocs = append(m.iocs, entry)
    
    // 关联到 ATT&CK 技术
    m.enrichTechniqueFromIOC(entry)
    
    return nil
}
```

---

### 11.7 CTI 威胁情报模块

CTI 模块计算全局威胁系数 μ（[cti.go](f:\Argus\internal\kernel\cti.go)）：

```go
func (m *CTIModule) updateCoefficient() {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // 威胁衰减
    if m.activeThreats > 0 {
        decay := m.activeThreats / 4
        if decay < 1 {
            decay = 1
        }
        m.activeThreats -= decay
    }
    
    // 计算威胁系数
    base := 1.0
    threatPenalty := float64(m.activeThreats) * 0.02
    m.coefficient = math.Max(0.60, base-threatPenalty)  // μ ∈ [0.60, 1.0]
}

func (m *CTIModule) ReportThreat(severity string) {
    weight := severityWeight(severity)  // critical=4, high=3, medium=2, low=1
    
    m.mu.Lock()
    defer m.mu.Unlock()
    m.activeThreats += weight
    
    // 发布威胁事件
    m.kernel.Bus().Publish(m.kernel.Context(), Message{
        Topic:   "cti.threat_detected",
        Payload: map[string]interface{}{"severity": severity, "weight": weight},
    })
}
```

---

### 11.8 策略引擎实现

Policy 模块根据评分触发自动化动作（[policy.go](f:\Argus\internal\kernel\policy.go)）：

```go
func (m *PolicyModule) EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction) {
    threshold := m.cfg.Threshold
    
    switch {
    case score >= threshold:
        return HostOK, nil
    case score >= threshold-10:
        return HostWarning, []PolicyAction{{
            Action:  "notify_admin",
            Message: fmt.Sprintf("host %s score %.2f below threshold %.2f", hostID, score, threshold),
        }}
    case score >= threshold-30:
        return HostCritical, []PolicyAction{
            {Action: "notify_admin", Message: "CRITICAL"},
            {Action: "increase_assessment"},
        }
    default:  // score < threshold-30
        return HostIsolated, []PolicyAction{
            {Action: "isolate_host", Params: map[string]string{"host_id": hostID}},
            {Action: "notify_admin"},
        }
    }
}
```

---

### 11.9 内存安全实现

#### 11.9.1 CVE 缓存大小限制

```go
// internal/kernel/spc.go
const defaultMaxCacheSize = 50000

func (m *SPCModule) AddCVE(cve SPCCVEScore) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    if len(m.cveCache) >= m.maxCacheSize {
        logger.WithComponent("spc").Warn("CVE cache full, dropping oldest",
            "max", m.maxCacheSize)
        // 简单策略：拒绝添加（实际应实现 LRU）
        return
    }
    
    m.cveIndex[cve.CVEID] = len(m.cveCache)
    m.cveCache = append(m.cveCache, cve)
}
```

#### 11.9.2 HTTP 响应体大小限制

```go
const maxHTTPBodySize = 10 * 1024 * 1024  // 10MB

func fetchURL(client *http.Client, url string) ([]byte, error) {
    resp, err := client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // 限制响应体大小，防止内存耗尽
    body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
    if err != nil {
        return nil, err
    }
    
    return body, nil
}
```

---

### 11.10 错误处理模式

#### 11.10.1 错误链式包装

```go
// 使用 %w 包装错误，保留错误链
func (m *SPCModule) FetchFromNVD() error {
    cves, err := m.fetchNVDAPI(baseURL, apiKey, since)
    if err != nil {
        return fmt.Errorf("NVD fetch failed: %w", err)
    }
    
    if err := m.parseAndStoreCVEs(cves); err != nil {
        return fmt.Errorf("CVE storage failed: %w", err)
    }
    
    return nil
}
```

#### 11.10.2 Goroutine 错误传播

```go
// 通过 channel 传播 goroutine 错误
func parallelFetch(sources []string) ([]Result, error) {
    results := make([]Result, len(sources))
    errors := make(chan error, len(sources))
    
    for i, source := range sources {
        go func(idx int, src string) {
            result, err := fetchFromSource(src)
            results[idx] = result
            if err != nil {
                errors <- err
            }
        }(i, source)
    }
    
    // 收集结果（忽略部分错误）
    var err error
    for range sources {
        if e := <-errors; e != nil && err == nil {
            err = e  // 保留第一个错误
        }
    }
    
    return results, err
}
```

---

### 附录

### A. 文件索引

| 文件路径 | 说明 |
|---------|------|
| [kernel.go](f:\Argus\internal\kernel\kernel.go) | μKernel 核心 |
| [plugin.go](f:\Argus\internal\kernel\plugin.go) | 插件接口定义 |
| [assessor.go](f:\Argus\internal\kernel\assessor.go) | 评估引擎 |
| [spc.go](f:\Argus\internal\kernel\spc.go) | 安全态势计算 |
| [cti.go](f:\Argus\internal\kernel\cti.go) | 威胁情报模块 |
| [policy.go](f:\Argus\internal\kernel\policy.go) | 策略引擎 |
| [commander.go](f:\Argus\internal\kernel\commander.go) | 指令下发 |
| [bus.go](f:\Argus\internal\kernel\bus.go) | 事件总线 |
| [di.go](f:\Argus\internal\kernel\di.go) | 依赖注入容器 |
| [engine.go](f:\Argus\internal\ssam\engine.go) | SSAM 评分引擎 |
| [agent.go](f:\Argus\internal\agent\agent.go) | Agent 核心 |
| [checks.go](f:\Argus\internal\checks\linux\checks.go) | Linux 检查项 |
| [adapter.go](f:\Argus\internal\adapter\adapter.go) | 适配器框架 |
| [grpc.go](f:\Argus\api\v1\grpc.go) | gRPC 接口定义 |
| [config.go](f:\Argus\internal\config\config.go) | 配置解析 |

### B. 术语表

| 术语 | 英文 | 说明 |
|------|------|------|
| 系统安全可接受性模型 | SSAM | System Security Acceptability Model |
| 攻击面管理 | AS | Attack Surface |
| 业务连续性 | BC | Business Continuity |
| 操作可信度 | OT | Operation Trust |
| 韧性 | RS | Resilience |
| 可接受沦陷指标 | ACI | Acceptable Compromise Index |
| 安全态势计算 | SPC | Security Posture Calculator |
| 网络威胁情报 | CTI | Cyber Threat Intelligence |
| 通用平台枚举 | CPE | Common Platform Enumeration |
| 漏洞利用预测评分系统 | EPSS | Exploit Prediction Scoring System |
| 已知被利用漏洞目录 | KEV | Known Exploited Vulnerabilities |

### C. 参考链接

- [SSAM 接口规范与接入指南](f:\Argus\docs\SSAM接口规范与接入指南.md)
- [SPC 安全态势计算模块技术白皮书](f:\Argus\docs\SPC安全态势计算模块技术白皮书.md)
- [等级保护检查项映射手册](f:\Argus\docs\等级保护检查项映射手册.md)
- [工程实现白皮书](f:\Argus\docs\工程实现白皮书.md)

---

**文档版本**: 1.0  
**生成时间**: 2026-05-26  
**维护者**: ASSCOR Core Team
