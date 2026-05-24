# ARGUS CLI 命令使用指南

> 版本：v0.1.2-MVP | SSAM 1.3 | 最后更新：2026-05-24

---

## 目录

1. [CLI 概述](#1-cli-概述)
2. [通用选项](#2-通用选项)
3. [核心命令](#3-核心命令)
4. [评估命令](#4-评估命令)
5. [SPC 命令](#5-spc-命令)
6. [Agent 管理命令](#6-agent-管理命令)
7. [插件管理命令](#7-插件管理命令)
8. [外部源管理命令](#8-外部源管理命令)
9. [系统命令](#9-系统命令)
10. [调试命令](#10-调试命令)
11. [命令注册与扩展](#11-命令注册与扩展)
12. [交互式终端功能](#12-交互式终端功能)

---

## 1. CLI 概述

ARGUS Kernel 内置交互式 CLI 终端，Kernel 启动后自动进入。CLI 提供命令注册、自动补全、历史记录和插件扩展能力。

### 进入 CLI

Kernel 启动后，日志自动重定向到 `argus-kernel.log`，终端进入交互模式：

```
ARGUS μKernel
  Framework: v0.1.2-MVP   SSAM: 1.3
  Listen:   :50051 (mTLS: true)
  ...
  CLI active: logs redirected to argus-kernel.log

argus>
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
argus> help
  Core:
    help              Show help information
    version           Show version information
    status            Show kernel status

  Assessment:
    assess            Run assessment

  SPC:
    spc               Security Posture Calculator

  ...

argus> help spc
  spc — Security Posture Calculator
  Usage: spc <summary|cve|kev|score|fetch>
  ...
```

### 3.2 version — 版本信息

显示 ARGUS 框架版本和 SSAM 模型版本。

**用法**：

```
version
```

**示例**：

```
argus> version
  ARGUS Framework: v0.1.2-MVP
  SSAM Model:      1.3
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
argus> status

  Kernel Status
  ─────────────────────────────────────────
  Plugins:   14 loaded
  Healthy:   14
  Unhealthy: 0

argus> status --json
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
argus> assess
  Assessment Result
  ─────────────────────────────────────────
  Host:    local
  Result:  ...

argus> assess web-server-01
argus> assess --domain=attack_surface
argus> assess --json
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
argus> spc summary

  SPC Summary
  ─────────────────────────────────────────
  total_cve           1234
  kev_count           56
  last_fetch          2026-05-24T18:30:00Z
  cache_size_mb       12.5

argus> spc cve --cvss-min=9.0
argus> spc cve --cvss-min=9.0 --kev-only
argus> spc kev
argus> spc score --host=web-server-01
argus> spc fetch
argus> spc summary --json
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
argus> agent list
argus> agent list --filter=active=true
argus> agent list --limit=10
argus> agent status --host=web-server-01
argus> agent stop --host=db-master-01
argus> agent restart --all
argus> agent config --host=web-01 --set threshold=80
argus> agent command --host=web-01 --action=scan
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
argus> log show
argus> log show --host=web-01 --level=error
argus> log show --limit=100
argus> log export --host=db-01 --format=csv --output=logs.csv
argus> log export --format=json --output=logs.json
```

---

## 7. 插件管理命令

### 7.1 plugin — 插件管理

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
argus> plugin list

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
  attck             v1.0.0  MITRE ATT&CK mapping
  config_watcher    v1.0.0  Configuration hot-reload
  adapter_integration v1.0.0 External adapter integration
  source_manager    v1.0.0  External source management
  cli               v1.0.0  Command-line interface

argus> plugin info spc
argus> plugin health
```

---

## 8. 外部源管理命令

### 8.1 source — 外部源管理

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
argus> source list
argus> source list --category scanner
argus> source info trivy
argus> source enable trivy
argus> source disable trivy
argus> source update trivy --version 0.50.0
argus> source uninstall trivy --force
argus> source run trivy
argus> source config trivy
argus> source audit trivy --limit 20
```

---

## 9. 系统命令

### 9.1 config — 配置查看

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
argus> config
argus> config threshold
argus> config --json
```

### 9.2 health — 健康检查

对所有 Kernel 插件执行健康检查。

**用法**：

```
health [options]
```

**示例**：

```
argus> health

  Health Check Results
  ─────────────────────────────────────────
  ✓ heartbeat         OK
  ✓ spc               OK
  ✓ cti               OK
  ✗ assessor          SPC data not available
  ✓ policy            OK
  ...

argus> health --json
```

---

## 10. 调试命令

### 10.1 history — 命令历史

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
argus> history

  Command History
  ──────────────────────────────────────────────────────────────────────
  #     EXIT   DURATION     COMMAND
  ──────────────────────────────────────────────────────────────────────
  1     OK     2ms          status
  2     OK     15ms         spc summary
  3     1      3ms          assess unknown-host

argus> history 50
argus> history --failed
argus> history --clear
```

---

## 11. 命令注册与扩展

### 11.1 命令分类

| 分类 | 标识 | 包含命令 |
|------|------|----------|
| Core | `core` | help, version, status |
| Assessment | `assess` | assess |
| SPC | `spc` | spc |
| Plugin | `plugin` | plugin |
| Agent | `agent` | agent, log |
| Source | `source` | source |
| System | `system` | config, health |
| Debug | `debug` | history |

### 11.2 权限级别

| 级别 | 标识 | 说明 |
|------|------|------|
| Read | `PermRead` | 只读操作，如查看状态、查询数据 |
| Write | `PermWrite` | 修改操作，如更新配置、启停 Agent |
| Admin | `PermAdmin` | 管理操作，如部署外部源、强制操作 |

### 11.3 插件注册自定义命令

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

### 11.4 命令接口规范

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

## 12. 交互式终端功能

### 12.1 自动补全

输入命令时按 `Tab` 键触发自动补全：

- 命令名补全：输入前缀后按 `Tab`
- 子命令补全：输入命令后按 `Tab`
- 选项补全：输入 `--` 后按 `Tab`

### 12.2 命令历史

- 使用 `↑` / `↓` 箭头键浏览历史命令
- 使用 `history` 命令查看完整历史记录

### 12.3 输出格式

所有命令支持 `--json` 选项输出结构化 JSON 数据，便于脚本集成：

```bash
# 在脚本中调用（通过管道）
echo "spc summary --json" | ./argus-kernel-linux-x86_64
```

### 12.4 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 执行错误 |
| 2 | 用法错误（参数缺失或无效） |
| 130 | 用户取消（Ctrl+C） |
