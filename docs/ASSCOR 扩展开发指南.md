# ASSCOR 扩展开发指南

**版本**：v1.2 | **适用**：ASSCOR v0.2.3 / SSAM 2.0 | **日期**：2026-07-14

---

## 摘要

ASSCOR 采用微内核 + 插件架构，提供 **10 种扩展方式**，覆盖从零门槛配置到专业 Go 开发的完整扩展面。本指南面向希望为 ASSCOR 编写自定义扩展的开发者。

---

## 1. 扩展体系总览

### 1.1 十种扩展方式

| 方式 | 门槛 | 注册入口 | 接入方式 |
|------|------|----------|----------|
| `user_check` | ?? 零 | `config.ini [user_check.*]` | 编辑配置文件 |
| `adapter_script` | ?? 极低 | `config.ini [adapter_script.*]` | 脚本 + 配置 |
| `check_module` | ?? 低 | `checks.Register()` | 编译期 init() / 扩展包 |
| `scoring_plugin` | ?? 低 | `Engine.RegisterFormula()` | 运行时 |
| `adapter` | ?? 低 | `adapter.Register()` | 编译期 init() |
| `hook` | ?? 低 | `Assessor.RegisterHook()` | 运行时 |
| `domain` | ?? 低 | `model.RegisterDomain()` | 运行时 / 配置 |
| `edge_factor` | ?? 低 | `model.RegisterEdgeFactor()` | 编译期 init() / 配置 |
| `cli_command` | ?? 低 | `CLIModule.RegisterCommand()` | 扩展点 |
| `custom` | ?? 中 | `kernel.Plugin` 接口 | 插件注册 |
| `web_panel` | ?? 中 | `webui.route.register` 扩展点 | 运行时 |

### 1.2 选择指南

| 需求 | 推荐方式 | 需要写代码 |
|------|----------|-----------|
| 添加一个命令检查 | `user_check` | ? 不需要 |
| 运行自定义脚本 | `adapter_script` | ? Bash/Python |
| 对接新扫描工具 | `adapter` | ? Go |
| 自定义评分算法 | `scoring_plugin` | ? Go |
| 完整子系统 | `Plugin SDK` | ? Go（独立模块） |

扩展代码作为 Go 包编入二进制，通过 `init()` 函数在启动时自动注册。零运行时依赖，保持单二进制部署优势。

**模式 B — 运行时扩展包（ExtensionManager）**

扩展以外部包形式（git/http/本地）分发，由 `ExtensionManager` 下载、校验、解压、注册，支持 `Install → Enable → Disable → Delete` 生命周期。适用于第三方分发的可插拔扩展。

---

## 2. 扩展类型详解

### 2.1 user_check — 配置文件定义检查项（零门槛）

**不需要编写任何代码。** 在 `config.ini` 中添加 `[user_check.<名称>]` 节即可创建检查项。

**编写示例**：

```ini
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
command = systemctl is-active nginx
delta = -8
output_match = active
```

**工作原理**：内核启动时解析 `user_check.*` 键，为每个有效的节创建 `model.CheckItem` 并注册到检查项注册表。支持 `command`（命令检查）和 `file_path + file_regex`（文件内容检查）两种模式。

**要点**：
- 修改后执行 `systemctl reload asscor-kernel`（SIGHUP）即可生效，无需重启
- `command` 模式通过 shell 执行，exit 0 或输出中含 `output_match` 则为通过
- `file_path` 模式检查文件存在性（无正则）或内容正则匹配

### 2.2 adapter_script — 外部脚本适配器（极低门槛）

**编写任意语言的脚本**，其 stdout 输出 JSON 数组即自动成为适配器发现。配置一行即可引入。

**编写示例**（Bash 脚本 `/opt/asscor/scripts/my-monitor.sh`）：

```bash
#!/bin/bash
echo '[{"id":"MON-001","title":"Disk usage","severity":"high","detail":"95% full"}]'
```

**配置**（`config.ini`）：

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

**安全限制**：路径必须在白名单目录下（`/opt/asscor/scripts/` 等），脚本必须 root:root 且非 world-writable，拒绝符号链接，30 秒超时，1MB 输出上限。

**JSON 字段** (`scriptFinding`):

```go
type scriptFinding struct {
    ID          string `json:"id"`
    Title       string `json:"title"`       // 必须
    Severity    string `json:"severity"`    // critical/high/medium/low/info
    Detail      string `json:"detail"`
    Domain      string `json:"domain"`
    CheckID     string `json:"check_id"`
    FindingType string `json:"finding_type"` // vulnerability/misconfig/compliance/alert
}
```

### 2.3 Plugin SDK — 独立模块开发（Go 专业开发）

位于 `pluginsdk/` 的独立 Go 模块。插件通过 **JSON-RPC 2.0 协议** 经 stdin/stdout 与内核通信，**零 ASSCOR 源码依赖**。

**核心接口**：

```go
type Plugin interface {
    Init(config map[string]string) error
    HandleRequest(method string, params json.RawMessage) (json.RawMessage, error)
    Shutdown() error
}
```

**开发流程**：

1. 复制 `pluginsdk/cmd/myplugin/` → 你的插件目录
2. 实现 `HandleRequest()` 方法
3. `go build -o yourplugin`
4. 编写 `extension.json` 或 `package.json` manifest
5. `asscor> source deploy yourplugin`

**架构**（低耦合）：插件作为独立进程运行，通过 stdin/stdout JSON-RPC 2.0 通信，零共享内存。安全上实现进程隔离、SHA-256 校验和、systemd scoping 资源限制。

### 2.4 check_module — 安全检查项

检查项是 ASSCOR 最常见的扩展。每个检查项归属一个评估域，输出通过/失败与扣分。

**核心结构** (`internal/model/model.go`)：

```go
type CheckFunc func() (passed bool, detail string)

type PrivilegeLevel int
const (
    PrivNormal PrivilegeLevel = iota  // 普通权限
    PrivRoot                          // 需要 root
)

type CheckItem struct {
    ID            string          // 唯一标识，如 "KS-001"
    Domain        string          // 归属域，如 model.DomainKernelSecurity
    Name          string
    Description   string
    Delta         float64         // 失败时扣分（负值）
    ComplianceRef string          // 合规引用，如 "GB/T 22239-2019"
    Platform      string          // "" = 全平台, "linux", "windows"
    Check         CheckFunc
    Privilege     PrivilegeLevel  // 非 root 运行时 PrivRoot 检查自动跳过
}
```

**编写示例**：

```go
package mychecks

import (
    "os"
    "github.com/asscor/asscor/internal/checks"
    "github.com/asscor/asscor/internal/model"
)

func init() {
    checks.Register(model.CheckItem{
        ID:            "CU-001",
        Domain:        model.DomainOperationTrust,
        Name:          "自定义配置检查",
        Description:   "检查 /etc/myapp/secure.conf 是否存在且权限正确",
        Delta:         -8,
        ComplianceRef: "GB/T 22239-2019 8.1.3",
        Platform:      "linux",
        Privilege:     model.PrivNormal,
        Check: func() (bool, string) {
            info, err := os.Stat("/etc/myapp/secure.conf")
            if err != nil {
                return false, "配置文件不存在"
            }
            if info.Mode().Perm() != 0600 {
                return false, "配置文件权限过宽（应为 0600）"
            }
            return true, "配置文件权限正确"
        },
    })
}
```

**要点**：
- `Check` 函数由内核在独立 goroutine 中调用，内置 panic 恢复
- 需要 root 的检查设 `Privilege: model.PrivRoot`，Agent 非 root 运行时自动跳过并标记
- 命令执行请使用 `common.RunCmd`（内置 shell 元字符防护）

### 2.2 scoring_plugin — 自定义评分公式

评分公式将域得分、威胁系数、SPC 分数、边缘因子聚合为最终分数。

**函数类型** (`ssam-lib/types.go`)：

```go
type ScoringFormula func(
    domainScores []DomainScore,      // 各域得分
    weights      []WeightConfig,     // 各域权重
    threatCoeff  float64,            // 威胁系数 μ (0.60-1.0)
    spcScore     float64,            // SPC 态势分数 (0.60-1.0)
    edgeFactors  []EdgeFactorResult, // 边缘因子
) float64
```

**编写示例**：

```go
engine.RegisterFormula("my-strict-v1", func(
    ds []ssam.DomainScore, w []ssam.WeightConfig,
    threat, spc float64, ef []ssam.EdgeFactorResult) float64 {

    var sum, wsum float64
    for _, d := range ds {
        for _, cfg := range w {
            if cfg.Domain == d.Domain {
                sum += d.Score * cfg.Weight
                wsum += cfg.Weight
            }
        }
    }
    base := sum / wsum
    for _, f := range ef {
        if f.Active {
            base *= f.Factor  // 边缘因子乘法修正
        }
    }
    // 严格模式：威胁与态势直接相乘
    return base * threat * spc
})
```

**要点**：
- 通过 `RegisterFormula(id, fn)` 注册后，该 ID 自动成为活跃公式
- 自定义公式**优先于**内置 SSAM V2.0 三层加权平均公式
- 内置默认公式为 `ssam_v2.0`（三层加权平均：Intrinsic 50% / Exposure 30% / Threat 20%）

### 2.3 adapter — 外部工具适配器

适配器将外部安全工具（扫描器、资产管理系统）的输出规范化为 ASSCOR 检查结果。

**接口** (`internal/adapter/adapter.go`)：

```go
type Adapter interface {
    ID() string
    Name() string
    Category() string    // "vulnerability" / "asset" / ...
    Priority() string    // "high" / "medium" / "low"
    Version() string
    Fetch(ctx context.Context, config map[string]string) ([]byte, error)
    Parse(raw []byte) ([]*NormalizedFinding, error)
    Map(findings []*NormalizedFinding) []*NormalizedFinding
    Validate(findings []*NormalizedFinding) ([]*NormalizedFinding, []error)
    IsEnabled(config map[string]string) bool
}
```

**四阶段流水线**：`Fetch`（采集）→ `Parse`（解析）→ `Map`（富化/映射）→ `Validate`（校验）。`ExecuteAdapter` 在 Parse 后自动调用 `ApplyDelegation` 路由到检查 ID。

**编写示例（嵌入 BaseAdapter 省去样板）**：

```go
package myadapters

import (
    "context"
    "encoding/json"
    "github.com/asscor/asscor/internal/adapter"
)

type MyScanner struct {
    adapter.BaseAdapter
}

func NewMyScanner() *MyScanner {
    return &MyScanner{adapter.NewBaseAdapter(
        "myscan", "My Scanner", "vulnerability", "high", "1.0.0")}
}

func (a *MyScanner) Fetch(ctx context.Context, cfg map[string]string) ([]byte, error) {
    path := cfg["myscan.path"]
    if path == "" {
        path = "/usr/bin/myscan"
    }
    return adapter.RunTool(ctx, path, "--json")
}

func (a *MyScanner) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
    var report struct {
        Vulns []struct {
            ID, Severity, Title string
        } `json:"vulnerabilities"`
    }
    if err := json.Unmarshal(raw, &report); err != nil {
        return nil, err
    }
    var findings []*adapter.NormalizedFinding
    for _, v := range report.Vulns {
        findings = append(findings, &adapter.NormalizedFinding{
            ID:          v.ID,
            Source:      "myscan",
            ToolName:    "My Scanner",
            FindingType: adapter.FindingVulnerability,
            Severity:    adapter.Severity(v.Severity),
            Title:       v.Title,
        })
    }
    return findings, nil
}

func (a *MyScanner) Map(f []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
    return adapter.DefaultMap(f)
}

func (a *MyScanner) Validate(f []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
    return adapter.DefaultValidate(f)
}

func init() {
    adapter.Register(NewMyScanner())
}
```

**Severity → Delta 映射**：critical(-20) / high(-15) / medium(-10) / low(-5) / info(-2) / none(0)。

**委托路由**：在 `internal/adapter/delegation.go` 中为适配器添加 `DelegationRule`，将发现映射到实际检查 ID 和域。

### 2.4 hook — 评估流程钩子

钩子在评估流程的 8 个阶段插入自定义逻辑。

**阶段与类型** (`internal/engine/extensibility.go`)：

```go
type AssessmentPhase string
const (
    PhasePreCheck   AssessmentPhase = "pre_check"
    PhasePostCheck  AssessmentPhase = "post_check"
    PhasePreScore   AssessmentPhase = "pre_score"
    PhasePostScore  AssessmentPhase = "post_score"
    PhasePreEdge    AssessmentPhase = "pre_edge"
    PhasePostEdge   AssessmentPhase = "post_edge"
    PhasePreReport  AssessmentPhase = "pre_report"
    PhasePostReport AssessmentPhase = "post_report"
)

type AssessmentHook func(ctx context.Context, result *model.AssessmentResult) error
```

**编写示例**：

```go
assessor.RegisterHook("enrich-metadata", engine.PhasePostScore,
    func(ctx context.Context, result *model.AssessmentResult) error {
        // 评分后为高风险主机附加元数据
        if result.FinalScore < 60 {
            result.Metadata["alert_level"] = "high"
        }
        return nil
    }, 50)  // priority：数字越小越先执行
```

### 2.5 domain — 新增评估域

评估域是检查项的逻辑分组，拥有独立权重。

**结构** (`internal/model/domain_registry.go`)：

```go
type DomainMeta struct {
    ID            string
    Label         string
    Description   string
    Category      DomainCategory  // CategoryCore / CategoryExtension
    DefaultWeight float64
}
```

**编写示例**：

```go
model.RegisterDomain(model.DomainMeta{
    ID:            "container_security",
    Label:         "容器安全",
    Description:   "Docker/K8s 加固态势",
    Category:      model.CategoryExtension,
    DefaultWeight: 10,
})
```

注册后即可在 check_module 中将检查项的 `Domain` 设为 `"container_security"`。权重可在 `config.ini` 的 `[weights]` 节覆盖。

### 2.6 edge_factor — 边缘修正因子

边缘因子是跨域的全局乘法修正项，缺失关键防护时降低总分。

**结构** (`internal/model/edge_factor_chain.go`)：

```go
type EdgeFactor struct {
    ID          string
    Name        string
    Description string
    Factor      float64  // < 1.0 = 惩罚乘数
    Active      bool
    Priority    int      // 越小越先应用
}
```

**编写示例**：

```go
func init() {
    model.RegisterEdgeFactor(model.EdgeFactor{
        ID:          "EF-NO-MFA",
        Name:        "MFA 缺失",
        Description: "未强制多因素认证",
        Factor:      0.85,
        Active:      false,
        Priority:    10,
    })
}
```

激活值可在 `config.ini` 的 `[edge_factors.custom]` / `[edge_factors.custom_triggers]` 节配置。

### 2.7 cli_command — CLI 命令

为交互式 CLI 添加自定义命令。

**编写示例（BaseCommand）**：

```go
cmd := cli.NewBaseCommand(
    cli.CommandInfo{
        Name:        "myscan",
        Description: "运行自定义扫描",
        Category:    "custom",
        Usage:       "myscan [--target host]",
        Options: []cli.CommandOption{
            {Name: "target", Description: "目标主机"},
        },
    },
    func(ctx *cli.CommandContext) *cli.CommandResult {
        target := ctx.Options["target"]
        return &cli.CommandResult{
            ExitCode: cli.ExitOK,
            Output:   "扫描完成: " + target + "\n",
        }
    },
)

cliModule.RegisterCommand(cmd)
```

**通过扩展点注册**（插件方式）：

```go
kc.Extensions().RegisterExtension("myplugin", "cli.command.register",
    func(ctx context.Context, data interface{}) error {
        cliMod := data.(cli.CLIInterface)
        return cliMod.RegisterCommand(cmd)
    }, 50)
```

### 2.8 custom — 完整内核插件

最灵活的扩展形式，实现完整的 `kernel.Plugin` 接口，拥有生命周期、DI 容器访问、事件总线、扩展点注册能力。

**接口** (`internal/kernel/plugin.go`)：

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

**编写示例**：

```go
type MyPlugin struct {
    state kernel.PluginState
}

func (p *MyPlugin) Info() kernel.PluginInfo {
    return kernel.PluginInfo{
        Name: "myplugin", Version: "1.0.0",
        Description: "自定义扩展", Author: "Me",
    }
}
func (p *MyPlugin) Dependencies() []kernel.PluginDependency { return nil }

func (p *MyPlugin) Init(ctx context.Context, kc kernel.KernelContext) error {
    // 订阅已有的扩展点（v0.2.2: 扩展点由平台层集中定义，插件不可注册新点）
    kc.Extensions().RegisterExtension("myplugin", "assessor.post_evaluate",
        func(ctx context.Context, data interface{}) error {
            result := data.(*model.AssessmentResult)
            return p.handleResult(ctx, result)
        }, 10)
    // 订阅事件总线
    kc.Bus().Subscribe(kernel.TopicAssessorResult, "myplugin", p.onResult)
    // 从 DI 容器解析其他模块
    if impl, ok := kc.Container().Resolve((*kernel.SPCInterface)(nil)); ok {
        _ = impl.(kernel.SPCInterface)
    }
    p.state = kernel.PluginInitialized
    return nil
}

func (p *MyPlugin) Start(ctx context.Context) error {
    p.state = kernel.PluginStarted
    return nil
}
func (p *MyPlugin) Stop(ctx context.Context) error {
    p.state = kernel.PluginStopped
    return nil
}
func (p *MyPlugin) State() kernel.PluginState { return p.state }

func (p *MyPlugin) onResult(ctx context.Context, msg kernel.Message) error {
    // 处理评估结果事件
    return nil
}
```

内核插件通过 `PriorityPlugin` 接口可指定优先级（决定 Init/Start 顺序），通过 `HealthCheckable` 接口可提供健康检查。

---

## 3. 运行时扩展包（ExtensionManager）

对于第三方分发的扩展，使用 `ExtensionManager` 进行生命周期管理。

### 3.1 扩展清单（manifest）

编写 `extension.json`：

```json
{
  "id": "container-security-pack",
  "name": "Container Security Domain",
  "version": "1.2.0",
  "type": "check_module",
  "description": "Docker/K8s 加固检查项集合",
  "author": "Security Team",
  "license": "Apache-2.0",
  "homepage": "https://github.com/example/container-security",
  "dependencies": [
    {"extension_id": "base-checks", "constraint": ">=1.0.0"}
  ],
  "source": {
    "url": "https://github.com/example/container-security.git",
    "type": "git",
    "branch": "main",
    "checksum": "sha256:abc123..."
  },
  "custom_config": {
    "category": "custom"
  }
}
```

### 3.2 安装与管理

```bash
# CLI 命令
asscor> source deploy container-security-pack --version 1.2.0
asscor> source enable container-security-pack
asscor> source disable container-security-pack
asscor> source uninstall container-security-pack
```

或通过配置文件 `config.ini`：

```ini
[extension_manager]
enabled = true
extensions_dir = /var/lib/asscor/extensions
state_dir = /var/lib/asscor/extensions/state
auto_enable = false
allow_prerelease = false
execution_policy = whitelist
execution_timeout_s = 30

[extension_manager.repositories]
repo_1 = https://extensions.example.dev/index.json

[extension_manager.whitelist]
cmd_1 = python3
cmd_2 = bash
```

### 3.3 生命周期

```
Install → Validate(SemVer+校验和+依赖) → Download(git/http/local)
        → Extract(tar.gz/zip, Zip-Slip 防护) → Register
        → [AutoEnable] → onExtensionInstalled(类型分发)
Enable  → 激活扩展（如边缘因子生效）
Disable → 注销检查项/域/边缘因子恢复
Delete  → Disable + 删除文件
```

---

## 4. 安全控制

ASSCOR 扩展系统内置多层安全防护：

| 控制 | 机制 |
|------|------|
| **版本门控** | SemVer 比对，拒绝安装同版本或旧版本 |
| **完整性校验** | SHA-256 校验和验证（`sha256:<hex>`） |
| **Zip-Slip 防护** | 解压时校验目标路径不逃逸安装目录 |
| **命令白名单** | 仅允许白名单命令执行，含 symlink 解析防绕过 |
| **环境变量净化** | 拒绝含 `=`/换行的键名、含换行的值 |
| **脚本路径防护** | 脚本执行路径必须位于安装目录内 |
| **执行策略** | allowed / whitelist（默认） / sandboxed / disabled 四级 |
| **执行超时** | 默认 30 秒硬超时 |

---

## 5. 打包与分发

### 5.1 编译期扩展（单二进制）

将扩展包加入 import，通过 `init()` 自注册，重新编译内核：

```go
// cmd/kernel/main.go 或专用 imports 文件
import (
    _ "github.com/yourorg/asscor-ext/mychecks"    // check_module
    _ "github.com/yourorg/asscor-ext/myadapters"  // adapter
)
```

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ASSCOR-kernel ./cmd/kernel/
```

**优势**：零运行时依赖，保持单二进制部署，类型安全，编译期检查。

### 5.2 运行时扩展包

打包为 tar.gz/zip，包含 `extension.json` + 可执行脚本 + 资源，通过 git/http 仓库或本地路径分发，由 ExtensionManager 管理。

**优势**：无需重新编译内核，支持热插拔，独立版本演进。

---

## 6. 扩展类型选择指南

| 需求 | 推荐类型 | 模式 |
|------|----------|------|
| 新增一个安全检查 | `check_module` | 编译期 |
| 对接一个新扫描工具 | `adapter` | 编译期 |
| 自定义评分算法 | `scoring_plugin` | 运行时 |
| 新增一个评估维度 | `domain` + `check_module` | 编译期/配置 |
| 全局防护缺失惩罚 | `edge_factor` | 编译期/配置 |
| 评估流程注入逻辑 | `hook` | 运行时 |
| 新增运维命令 | `cli_command` | 扩展点 |
| 复杂有状态子系统 | `custom`（Plugin） | 插件注册 |
| 第三方可插拔分发 | 任意类型 + ExtensionManager | 运行时包 |

---

## 7. 完整示例：容器安全扩展

以下展示一个完整的容器安全扩展，组合 domain + check_module + edge_factor：

```go
package containersec

import (
    "os"
    "github.com/asscor/asscor/internal/checks"
    "github.com/asscor/asscor/internal/model"
)

func init() {
    // 1. 注册新域
    model.RegisterDomain(model.DomainMeta{
        ID:            "container_security",
        Label:         "容器安全",
        Category:      model.CategoryExtension,
        DefaultWeight: 10,
    })

    // 2. 注册边缘因子
    model.RegisterEdgeFactor(model.EdgeFactor{
        ID:       "EF-NO-SECCOMP",
        Name:     "Seccomp 缺失",
        Factor:   0.90,
        Priority: 20,
    })

    // 3. 注册检查项
    checks.Register(
        model.CheckItem{
            ID:       "CS-001",
            Domain:   "container_security",
            Name:     "Docker daemon 安全配置",
            Delta:    -10,
            Platform: "linux",
            Check:    checkDockerDaemon,
        },
        model.CheckItem{
            ID:       "CS-002",
            Domain:   "container_security",
            Name:     "容器镜像签名验证",
            Delta:    -8,
            Platform: "linux",
            Check:    checkImageSigning,
        },
    )
}

func checkDockerDaemon() (bool, string) {
    data, err := os.ReadFile("/etc/docker/daemon.json")
    if err != nil {
        return true, "未检测到 Docker"
    }
    // ...解析并检查安全选项...
    _ = data
    return true, "Docker 安全配置合规"
}

func checkImageSigning() (bool, string) {
    // ...检查 cosign/notary 配置...
    return false, "未启用镜像签名验证"
}
```

在 `config.ini` 中启用：

```ini
[weights]
container_security = 10

[extensions]
container_security = on
```

---

## 8. 外部扩展模块与扩展包（v0.2.2+）

### 8.1 概述

与内核集成式扩展 (ExtensionManager + extension.json) 互补，ASSCOR v0.2.2 引入**外部编译时扩展体系**。外部扩展位于 `optional/` 目录，不修改内核代码，通过 Go import + Extension Point 系统挂载。

### 8.2 两种扩展形式

| 形式 | 路径 | 接入 | 适用 |
|------|------|------|------|
| **单模块** | `optional/<category>/modules/<name>/` | direct `import` → `Register()` | 独立功能 |
| **扩展包** | `optional/<category>/packages/<name>/` | `package.json` + `asscor-pkg install` | 多模块组合 / 含外部 git 依赖 |

### 8.3 扩展包清单 (package.json)

每个扩展包含一个 `package.json`，声明模块列表、外部 git 仓库引用、依赖和冲突：

```json
{
  "name": "my-pack",
  "version": "1.0.0",
  "compatibility": { "asscor_version": ">=0.2.1" },
  "modules": [{ "id": "my-module", "path": "../../modules/my-module" }],
  "external_sources": [{ "repo": "https://github.com/user/repo", "ref": "main", "target": "modules/ext" }],
  "dependencies": [{ "package": "base-pack", "version": ">=1.0.0" }]
}
```

完整规范见 `optional/SCHEMA.md`。

### 8.4 扩展包管理工具 (asscor-pkg)

```bash
cd optional/pkgmgr && go build -o asscor-pkg .
./asscor-pkg resolve          # 解析依赖图
./asscor-pkg install --force  # 克隆外部仓库
./asscor-pkg list             # 列出所有扩展包
./asscor-pkg info my-pack     # 查看扩展包详情
```

### 8.5 多算法编排器开发示例

```go
// 在 optional/algorithms/modules/my-algo/orchestrator.go
import "github.com/asscor/asscor/internal/kernel"

type MyOrchestrator struct { ... }

func (o *MyOrchestrator) Register(ext kernel.ModuleExtensions) {
    ext.RegisterExtension("my-algo", "assessor.pre_score", func(ctx context.Context, data interface{}) error {
        result := data.(*model.AssessmentResult)
        // 调用多个评分引擎，取最低分
        scores := []float64{runSSAM(result), runLegacy(result), runCustom(result)}
        result.FinalScore = min(scores...)
        return nil
    }, 45)
}
```

```go
// 在 cmd/kernel/main.go 中启用
import myalgo "github.com/asscor/asscor-optional-my-algo"

orch := myalgo.NewOrchestrator(cfg)
orch.Register(k.PlatformExtensionRegistry())
```

## 9. 参考

- 检查项库：`internal/checks/linux/checks.go`（80 个内置检查项参考实现）
- 适配器示例：`internal/adapter/scanner/`（11 个探测器）、`internal/adapter/management/`（10 个管理类）
- 内核插件示例：`internal/<模块名>/`（全部功能模块均已剥离为 build-tag 可选插件：heartbeat/commander/policy/cti/assessor/attck_ext/spc/collector/sourcemanager/persistence/srdwrapper/webui/integrity/resilience/comms/checks/adapter/engine；常编译包仅 historicalstore/topology/oscal 纯工具 + kernel 核心），契约接口见 `internal/kernel/*_interface.go`、`internal/kernel/engine_types.go`
- 扩展管理器：`internal/extmgr/`
- 外部扩展模块：`optional/algorithms/modules/multi-algo-orchestrator/`
- 扩展包示例：`optional/algorithms/packages/example-pack/package.json`
- SSAM 接口规范：`docs/SSAM接口规范与接入指南.md`
