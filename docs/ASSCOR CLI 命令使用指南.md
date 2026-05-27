# ASSCOR CLI 命令使用指南

> 版本：v0.2.0 | SSAM 2.0 | 最后更新：2026-05-28

---

## 目录

1. [CLI 概述](#1-cli-概述)
2. [通用选项](#2-通用选项)
3. [核心命令](#3-核心命令)
4. [评估命令](#4-评估命令)
5. [SPC 命令](#5-spc-命令)
6. [Agent 管理命令](#6-agent-管理命令)
7. [ATT&CK 命令](#7-attck-命令)
8. [插件管理命令](#8-插件管理命令)
9. [外部源管理命令](#9-外部源管理命令)
10. [系统命令](#10-系统命令)
11. [调试命令](#11-调试命令)
12. [命令注册与扩展](#12-命令注册与扩展)
13. [交互式终端功能](#13-交互式终端功能)

---

## 1. CLI 概述

ASSCOR Kernel 内置交互式 CLI 终端，Kernel 启动后自动进入。CLI 提供命令注册、自动补全、历史记录和插件扩展能力。

### 进入 CLI

Kernel 启动后，日志自动重定向到 `ASSCOR-kernel.log`，终端进入交互模式：

```
ASSCOR μKernel
  Framework: v0.2.0   SSAM: 2.0
  Listen:   :50051 (mTLS: true)
  ...
  CLI active: logs redirected to ASSCOR-kernel.log

ASSCOR>
```

### 命令语法

```
command <subcommand|param> [options]
```

- 命令和参数以空格分隔
- 选项使用 `--name=value` 或 `--name value` 格式
- 布尔选项使用 `--flag` 开启，无需值
- 短选项使用 `-X` 格式

### 退出 CLI

输入 `Ctrl+D` 或 `Ctrl+C` 退出交互式终端，Kernel 随之关闭。

---

## 2. 通用选项

以下选项适用于所有命令：

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--verbose` | `-v` | 显示详细输出 |
| `--json` | `-j` | 以 JSON 格式输出 |
| `--quiet` | `-q` | 抑制非必要输出 |
| `--help` | `-h` | 显示命令帮助 |

---

## 3. 核心命令

### 3.1 help — 帮助信息

显示命令帮助或列出所有可用命令。

**用法**：

```
help [command]
```

**参数**：

| 参数 | 必需 | 说明 |
|------|------|------|
| `command` | 否 | 要查看帮助的命令名 |

**示例**：

```
ASSCOR> help
  Core:
    help              Show help information
    version           Show version information
    status            Show kernel status

  Assessment:
    assess            Run assessment

  SPC:
    spc               Security Posture Calculator

  ...

ASSCOR> help spc
  spc — Security Posture Calculator
  Usage: spc <summary|cve|kev|score|fetch>
  ...
```

### 3.2 version — 版本信息

显示 ASSCOR 框架版本和 SSAM 模型版本。

**用法**：

```
version
```

**示例**：

```
ASSCOR> version
  ASSCOR Framework: v0.2.0
  SSAM Model:      2.0
```

### 3.3 status — 内核状态

显示当前 Kernel 状态，包括插件状态、运行时间和资源使用。

**用法**：

```
status [options]
```

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--format` | `-f` | `text` | 输出格式：`text`、`json` |

**示例**：

```
ASSCOR> status

  Kernel Status
  ─────────────────────────────────────────
  Plugins:   14 loaded
  Healthy:   14
  Unhealthy: 0

ASSCOR> status --json
```

---

## 4. 评估命令

### 4.1 assess — 执行安全评估

触发对指定主机的安全可接受性评估。

**用法**：

```
assess [host] [options]
```

**参数**：

| 参数 | 必需 | 说明 |
|------|------|------|
| `host` | 否 | 目标主机 ID（默认：`local`） |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--format` | `-f` | `text` | 输出格式：`text`、`json` |
| `--domain` | `-d` | — | 仅评估指定核心域 |

**domain 可选值**：

| 值 | 核心域 |
|----|--------|
| `attack_surface` | 攻击面管理 |
| `business_continuity` | 业务连续性 |
| `operation_trust` | 操作可信度 |
| `resilience` | 韧性 |

**示例**：

```
ASSCOR> assess
  Assessment Result
  ─────────────────────────────────────────
  Host:    local
  Result:  ...

ASSCOR> assess web-server-01
ASSCOR> assess --domain=attack_surface
ASSCOR> assess --json
```

---

## 5. SPC 命令

### 5.1 spc — 安全态势计算器

查询 SPC 模块的 CVE 缓存、P-score、KEV 数量和修正数据。

**用法**：

```
spc <action> [options]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `summary` | SPC 模块概览（CVE 数量、KEV 数量、缓存状态） |
| `cve` | 查询 CVE 缓存 |
| `kev` | 查询 CISA KEV 目录 |
| `score` | 计算指定主机的 P-score |
| `fetch` | 手动触发数据源同步 |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--limit` | `-n` | `20` | 结果数量限制 |
| `--cvss-min` | — | — | 最低 CVSS 分数过滤 |
| `--kev-only` | — | — | 仅显示 KEV 条目 |

**示例**：

```
ASSCOR> spc summary

  SPC Summary
  ─────────────────────────────────────────
  total_cve           1234
  kev_count           56
  last_fetch          2026-05-24T18:30:00Z
  cache_size_mb       12.5

ASSCOR> spc cve --cvss-min=9.0
ASSCOR> spc cve --cvss-min=9.0 --kev-only
ASSCOR> spc kev
ASSCOR> spc score --host=web-server-01
ASSCOR> spc fetch
ASSCOR> spc summary --json
```

---

## 6. Agent 管理命令

### 6.1 agent — Agent 生命周期管理

管理已注册的 Agent，包括查看状态、启停和配置。

**用法**：

```
agent <action> [options]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `list` | 列出所有已注册 Agent |
| `status` | 查看指定 Agent 详细状态 |
| `start` | 启动指定 Agent |
| `stop` | 停止指定 Agent |
| `restart` | 重启指定 Agent |
| `config` | 查看/修改 Agent 配置 |
| `command` | 向 Agent 发送命令 |

**选项**：

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--host` | `-H` | 目标 Agent 主机 ID |
| `--all` | `-a` | 应用到所有 Agent |
| `--filter` | `-f` | 按 key=value 过滤 |
| `--limit` | `-n` | 结果数量限制（默认 50） |
| `--watch` | `-w` | 持续刷新模式 |

**示例**：

```
ASSCOR> agent list
ASSCOR> agent list --filter=active=true
ASSCOR> agent list --limit=10
ASSCOR> agent status --host=web-server-01
ASSCOR> agent stop --host=db-master-01
ASSCOR> agent restart --all
ASSCOR> agent config --host=web-01 --set threshold=80
ASSCOR> agent command --host=web-01 --action=scan
```

### 6.2 log — Agent 日志查看

查看、过滤和导出 Agent 运行日志。

**用法**：

```
log <action> [options]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `show` | 显示日志条目 |
| `export` | 导出日志到文件 |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--host` | `-H` | — | 按 Agent 主机 ID 过滤 |
| `--level` | `-l` | — | 按日志级别过滤：`debug`、`info`、`warn`、`error` |
| `--limit` | `-n` | `50` | 显示条目数 |
| `--format` | `-f` | `json` | 导出格式：`json`、`csv` |
| `--output` | `-o` | — | 导出文件路径 |

**示例**：

```
ASSCOR> log show
ASSCOR> log show --host=web-01 --level=error
ASSCOR> log show --limit=100
ASSCOR> log export --host=db-01 --format=csv --output=logs.csv
ASSCOR> log export --format=json --output=logs.json
```

---

## 7. ATT&CK 命令

### 7.1 attck — MITRE ATT&CK V19 威胁分析

操作 ATT&CK V19 模块，包括检测规则管理、IOC 管理、差距分析、攻击链重构、APT 归因和威胁狩猎。

**用法**：

```
attck <action> [options]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `summary` | ATT&CK 模块概览（规则数、告警数、IOC 数、覆盖率） |
| `rule` | 检测规则管理 |
| `alert` | 告警查询与确认 |
| `anomaly` | 异常事件查询 |
| `ioc` | IOC 指标管理 |
| `actor` | 威胁行为体画像 |
| `gap` | 防御差距分析 |
| `control` | 安全控制映射 |
| `chain` | 攻击链重构 |
| `attribute` | APT 归因分析 |
| `hunt` | 威胁狩猎框架 |
| `emulate` | 对手仿真执行 |
| `improve` | 持续改进追踪 |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--host` | `-H` | — | 目标主机 ID |
| `--severity` | `-s` | — | 按严重等级过滤：`critical`、`high`、`medium`、`low` |
| `--technique` | `-t` | — | 按 ATT&CK 技术 ID 过滤 |
| `--limit` | `-n` | `20` | 结果数量限制 |
| `--format` | `-f` | `text` | 输出格式：`text`、`json` |

### 7.2 attck summary — 模块概览

**示例**：

```
ASSCOR> attck summary

  ATT&CK V19 Module Summary
  ─────────────────────────────────────────
  detection_rules    15
  active_alerts      3
  ioc_entries        128
  threat_actors      12
  coverage_pct       67.3%
  chains_detected    1
  hunt_hypotheses    4
```

### 7.3 attck rule — 检测规则管理

| 子动作 | 说明 |
|--------|------|
| `add` | 注册检测规则 |
| `list` | 列出所有规则 |
| `delete` | 删除规则 |
| `evaluate` | 对指定主机评估规则 |

**示例**：

```
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high
ASSCOR> attck rule list
ASSCOR> attck rule evaluate --rule=<ruleID> --host=web-server-01
ASSCOR> attck rule delete --rule=<ruleID>
```

### 7.4 attck alert — 告警管理

| 子动作 | 说明 |
|--------|------|
| `list` | 列出告警 |
| `ack` | 确认告警 |

**示例**：

```
ASSCOR> attck alert list --severity=high
ASSCOR> attck alert list --host=web-server-01
ASSCOR> attck alert ack --alert=<alertID>
```

### 7.5 attck ioc — IOC 管理

| 子动作 | 说明 |
|--------|------|
| `add` | 添加 IOC |
| `list` | 列出 IOC |
| `search` | 搜索 IOC |
| `delete` | 删除 IOC |
| `expire` | 清理过期 IOC |

**示例**：

```
ASSCOR> attck ioc add --type=ip --value=10.0.0.1 --confidence=0.8 --technique=T1071
ASSCOR> attck ioc list --type=domain
ASSCOR> attck ioc search --value=10.0.0
ASSCOR> attck ioc delete --id=<iocID>
ASSCOR> attck ioc expire
```

### 7.6 attck gap — 防御差距分析

对指定主机执行 ATT&CK 覆盖率差距分析，输出防御缺口和缓解建议。

**示例**：

```
ASSCOR> attck gap --host=web-server-01

  Gap Analysis: web-server-01
  ─────────────────────────────────────────
  coverage_pct       67.3%
  gaps_found         8
  critical_gaps      2

  Critical Gaps:
    TA0001/T1566  Initial Access / Phishing
    TA0006/T1003  Credential Access / OS Credential Dumping
```

### 7.7 attck chain — 攻击链重构

基于告警、异常、IOC 多源证据，按 ATT&CK 战术顺序自动重构多阶段攻击链。

**示例**：

```
ASSCOR> attck chain --host=web-server-01

  Attack Chain: CHAIN-20260525-001
  ─────────────────────────────────────────
  stages: 5
  severity: critical
  status: active

  Stage 1: TA0001/T1566  Phishing          confidence: 0.85
  Stage 2: TA0002/T1059  PowerShell         confidence: 0.90
  Stage 3: TA0006/T1003  Credential Dump    confidence: 0.75
  Stage 4: TA0008/T1021  Lateral Movement   confidence: 0.60
  Stage 5: TA0011/T1071  C2 Communication   confidence: 0.80
```

### 7.8 attck attribute — APT 归因

对已检测的攻击链执行 APT 归因分析，基于 TTP 重叠和 IOC 匹配计算置信度。

**示例**：

```
ASSCOR> attck attribute --chain=CHAIN-20260525-001

  Attribution Result
  ─────────────────────────────────────────
  primary_actor      APT28
  confidence         0.82
  ttp_overlap        0.78 (7/9 techniques match)
  ioc_match          0.88 (3 IOC matches)
  industry_align     +0.05 (Government sector)
```

### 7.9 attck hunt — 威胁狩猎

| 子动作 | 说明 |
|--------|------|
| `generate` | 自动生成狩猎假设 |
| `list` | 列出狩猎假设 |
| `execute` | 执行狩猎假设 |
| `confirm` | 确认狩猎结果 |

**示例**：

```
ASSCOR> attck hunt generate --host=web-server-01
ASSCOR> attck hunt list
ASSCOR> attck hunt execute --id=<hypothesisID> --host=web-server-01
ASSCOR> attck hunt confirm --id=<hypothesisID> --status=confirmed
```

### 7.10 attck emulate — 对手仿真

| 子动作 | 说明 |
|--------|------|
| `create` | 创建仿真场景 |
| `generate` | 从 APT 组织自动生成场景 |
| `run` | 执行仿真 |
| `results` | 查看仿真结果 |

**示例**：

```
ASSCOR> attck emulate generate --actor=APT29
ASSCOR> attck emulate run --scenario=<scenarioID> --host=web-server-01 --safe
ASSCOR> attck emulate results --scenario=<scenarioID>
```

### 7.11 attck improve — 持续改进追踪

| 子动作 | 说明 |
|--------|------|
| `create` | 创建改进追踪 |
| `list` | 列出改进追踪 |
| `update` | 更新改进动作状态 |
| `progress` | 查看改进进度 |

**示例**：

```
ASSCOR> attck improve create --name=" Harden credential policy"
ASSCOR> attck improve list
ASSCOR> attck improve update --track=<trackID> --action=<actionID> --status=completed
ASSCOR> attck improve progress --track=<trackID>
```

---

## 8. 插件管理命令

### 8.1 plugin — 插件管理

列出、查看和管理 Kernel 插件。

**用法**：

```
plugin <action> [name]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `list` | 列出所有已注册插件 |
| `info` | 查看插件详细信息 |
| `health` | 对所有插件执行健康检查 |

**参数**：

| 参数 | 必需 | 说明 |
|------|------|------|
| `name` | 否 | 插件名（`info` 动作需要） |

**示例**：

```
ASSCOR> plugin list

  Plugin List
  ─────────────────────────────────────────
  heartbeat         v1.0.0  Agent heartbeat tracking
  spc               v1.0.0  Security Posture Calculator
  cti               v1.0.0  Cyber Threat Intelligence
  assessor          v1.0.0  SSAM security assessment engine
  policy            v1.0.0  Policy enforcement and compliance
  commander         v1.0.0  Agent command dispatch
  log_collector     v1.0.0  Agent log collection
  persistence       v1.0.0  Data persistence layer
  concurrency       v1.0.0  Concurrency control
  attck             v2.0.0  MITRE ATT&CK V19 threat analysis
  config_watcher    v1.0.0  Configuration hot-reload
  adapter_integration v1.0.0 External adapter integration
  source_manager    v1.0.0  External source management
  cli               v1.0.0  Command-line interface

ASSCOR> plugin info spc
ASSCOR> plugin health
```

---

## 9. 外部源管理命令

### 9.1 source — 外部源管理

部署、配置、启停和审计外部集成源。

**用法**：

```
source <action> [name] [options]
```

**子命令**：

| 动作 | 说明 |
|------|------|
| `list` | 列出已注册的外部源 |
| `info` | 查看外部源详细信息 |
| `deploy` | 部署外部源 |
| `enable` | 启用外部源 |
| `disable` | 禁用外部源 |
| `update` | 更新外部源版本 |
| `uninstall` | 卸载外部源 |
| `run` | 手动运行外部源 |
| `config` | 查看/修改外部源配置 |
| `audit` | 查看外部源审计日志 |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--category` | `-c` | — | 按类别过滤：`scanner`、`management` |
| `--version` | `-v` | — | 版本号（用于 deploy/update） |
| `--force` | `-f` | — | 强制操作 |
| `--limit` | `-l` | `50` | 结果数量限制 |

**示例**：

```
ASSCOR> source list
ASSCOR> source list --category scanner
ASSCOR> source info trivy
ASSCOR> source enable trivy
ASSCOR> source disable trivy
ASSCOR> source update trivy --version 0.50.0
ASSCOR> source uninstall trivy --force
ASSCOR> source run trivy
ASSCOR> source config trivy
ASSCOR> source audit trivy --limit 20
```

---

## 10. 系统命令

### 10.1 config — 配置查看

查看当前 Kernel 配置。

**用法**：

```
config [key] [options]
```

**参数**：

| 参数 | 必需 | 说明 |
|------|------|------|
| `key` | 否 | 配置键名（点分路径） |

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--format` | `-f` | `text` | 输出格式：`text`、`json` |

**示例**：

```
ASSCOR> config
ASSCOR> config threshold
ASSCOR> config --json
```

### 10.2 health — 健康检查

对所有 Kernel 插件执行健康检查。

**用法**：

```
health [options]
```

**示例**：

```
ASSCOR> health

  Health Check Results
  ─────────────────────────────────────────
  ✓ heartbeat         OK
  ✓ spc               OK
  ✓ cti               OK
  ✗ assessor          SPC data not available
  ✓ policy            OK
  ...

ASSCOR> health --json
```

---

## 11. 调试命令

### 11.1 history — 命令历史

查看命令执行历史记录。

**用法**：

```
history [count] [options]
```

**参数**：

| 参数 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `count` | 否 | `20` | 显示最近 N 条记录 |

**选项**：

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--failed` | `-f` | 仅显示失败的命令 |
| `--clear` | — | 清除历史记录 |

**示例**：

```
ASSCOR> history

  Command History
  ──────────────────────────────────────────────────────────────────────
  #     EXIT   DURATION     COMMAND
  ──────────────────────────────────────────────────────────────────────
  1     OK     2ms          status
  2     OK     15ms         spc summary
  3     1      3ms          assess unknown-host

ASSCOR> history 50
ASSCOR> history --failed
ASSCOR> history --clear
```

---

## 12. 命令注册与扩展

### 12.1 命令分类

| 分类 | 标识 | 包含命令 |
|------|------|----------|
| Core | `core` | help, version, status |
| Assessment | `assess` | assess |
| SPC | `spc` | spc |
| ATT&CK | `attck` | attck |
| Plugin | `plugin` | plugin |
| Agent | `agent` | agent, log |
| Source | `source` | source |
| System | `system` | config, health |
| Debug | `debug` | history |

### 12.2 权限级别

| 级别 | 标识 | 说明 |
|------|------|------|
| Read | `PermRead` | 只读操作，如查看状态、查询数据 |
| Write | `PermWrite` | 修改操作，如更新配置、启停 Agent |
| Admin | `PermAdmin` | 管理操作，如部署外部源、强制操作 |

### 12.3 插件注册自定义命令

插件可通过 `cli.command.register` 扩展点注册自定义命令：

```go
cliPlugin, ok := k.Container().Resolve((*cli.CLIInterface)(nil))
if ok {
    cliMod := cliPlugin.(cli.CLIInterface)
    cliMod.RegisterCommand(cli.NewBaseCommand(
        cli.CommandInfo{
            Name:        "mycmd",
            Short:       "My custom command",
            Description: "Does something custom",
            Usage:       "mycmd [args]",
            Category:    cli.CategoryPlugin,
        },
        func(ctx *cli.CommandContext) *cli.CommandResult {
            return &cli.CommandResult{
                ExitCode: cli.ExitOK,
                Output:   "Custom command executed\n",
            }
        },
    ))
}
```

### 12.4 命令接口规范

```go
type Command interface {
    Info() CommandInfo
    Execute(ctx *CommandContext) *CommandResult
    Completions(ctx *CommandContext, partial string) []string
}
```

| 方法 | 说明 |
|------|------|
| `Info()` | 返回命令元信息（名称、描述、参数、选项） |
| `Execute()` | 执行命令，返回结果 |
| `Completions()` | 返回自动补全候选列表 |

---

## 13. 交互式终端功能

### 13.1 自动补全

输入命令时按 `Tab` 键触发自动补全：

- 命令名补全：输入前缀后按 `Tab`
- 子命令补全：输入命令后按 `Tab`
- 选项补全：输入 `--` 后按 `Tab`

### 13.2 命令历史

- 使用 `↑` / `↓` 箭头键浏览历史命令
- 使用 `history` 命令查看完整历史记录

### 13.3 输出格式

所有命令支持 `--json` 选项输出结构化 JSON 数据，便于脚本集成：

```bash
# 在脚本中调用（通过管道）
echo "spc summary --json" | ./ASSCOR-kernel-linux-x86_64
```

### 13.4 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 执行错误 |
| 2 | 用法错误（参数缺失或无效） |
| 130 | 用户取消（Ctrl+C） |
