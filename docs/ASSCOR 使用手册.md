# ASSCOR 使用手册

> 版本：v0.1.2-MVP | SSAM 1.3 | 最后更新：2026-05-25

---

## 目录

1. [概述](#1-概述)
2. [快速开始](#2-快速开始)
3. [部署架构](#3-部署架构)
4. [Kernel 部署](#4-kernel-部署)
5. [Agent 部署](#5-agent-部署)
6. [TLS 证书管理](#6-tls-证书管理)
7. [配置文件详解](#7-配置文件详解)
8. [SPC 安全态势模块](#8-spc-安全态势模块)
9. [等保映射与评分阈值](#9-等保映射与评分阈值)
10. [ATT&CK V19 威胁分析模块](#10-attck-v19-威胁分析模块)
11. [日志管理](#11-日志管理)
12. [守护进程模式](#12-守护进程模式)
13. [离线评估模式](#13-离线评估模式)
14. [环境变量参考](#14-环境变量参考)
15. [故障排查](#15-故障排查)

---

## 1. 概述

ASSCOR 是一个开源的分布式安全可接受性评估系统，实现了系统安全可接受性模型（SSAM）1.3。系统通过四个互斥核心域评估主机安全状态，并集成 MITRE ATT&CK V19 威胁分析框架，提供从安全评估、威胁检测到 APT 攻击分析的完整能力链。

| 核心域 | 权重 | 评估内容 |
|--------|------|----------|
| 攻击面管理 | 35% | 无用服务、开放端口、强认证、SSH 配置 |
| 业务连续性 | 25% | 关键服务运行、备份机制、资源充裕度 |
| 操作可信度 | 25% | 文件权限、审计日志、命令历史防篡改、供应链完整性、SELinux/AppArmor |
| 韧性 | 15% | 自动封禁精度、SYN Cookie、连接限制、可接受沦陷指标（ACI） |

**附加模块**：

| 模块 | 功能 |
|------|------|
| ATT&CK V19 | MITRE ATT&CK 框架集成，检测分析、威胁情报、对手仿真、评估工程、APT 攻击分析与检测增强 |
| SPC | 安全态势计算，NVD/EPSS/CISA KEV/CNNVD/CNVD 多源漏洞情报与本地资产比对 |
| CTI | 网络威胁情报管理，动态威胁系数 μ 计算 |

**评分公式**：

```
SSAM_final = (Σ(S_i × W_i) / ΣW_i) × ΠM_j × μ × P_score
```

- `S_i`：核心域分数（0–100）
- `W_i`：核心域权重（总和 100）
- `M_j`：边缘因子乘数（仅对 Active 且 Factor ∈ (0,1) 的因子执行连乘）
- `μ`：威胁系数（默认 1.0，由 CTI 模块动态调整）
- `P_score`：SPC 修正因子（0.60–1.00，基于 CVE 匹配结果计算）

---

## 2. 快速开始

### 2.1 前置条件

- 目标主机：Linux（支持 x86_64 / ARM64 / i386）
- Kernel 与 Agent 间网络可达
- （推荐）NVD API Key：从 https://nvd.nist.gov/developers/request-an-api-key 获取

### 2.2 最小部署

```bash
# 1. 部署 Kernel
./ASSCOR-kernel-linux-x86_64 -config config.ini -listen :50051

# 2. 在目标主机部署 Agent
./ASSCOR-agent-linux-x86_64 -kernel 192.168.1.10:50051 -tls

# 3. Kernel 启动后进入交互式 CLI
# 直接在终端输入命令即可操作
```

### 2.3 离线评估（无需 Agent）

```bash
# 单机模式：直接在本地执行评估
./ASSCOR -config config.ini          # 文本报告
./ASSCOR -config config.ini -json    # JSON 报告
```

---

## 3. 部署架构

```
┌─────────────────────────────────────────────────┐
│                  ASSCOR Kernel                    │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ │
│  │Assess│ │Policy│ │ SPC  │ │ CTI  │ │Cmdr  │ │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ │
│  ┌──────┐                                      │
│  │ATT&CK│  MITRE ATT&CK V19 威胁分析           │
│  └──┬───┘  检测/情报/仿真/评估/APT增强          │
│     │        │        │        │        │      │
│  ┌──┴────────┴────────┴────────┴────────┴──┐   │
│  │         μKernel Plugin Bus              │   │
│  └────────────────┬───────────────────────┘   │
│                   │ gRPC + mTLS                │
└───────────────────┼───────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
   ┌────┴────┐ ┌────┴────┐ ┌────┴────┐
   │ Agent A │ │ Agent B │ │ Agent C │
   │(host-01)│ │(host-02)│ │(host-03)│
   └─────────┘ └─────────┘ └─────────┘
```

**组件说明**：

| 组件 | 职责 |
|------|------|
| Kernel | 微内核，管理插件生命周期、gRPC 服务、CLI 交互 |
| Agent | 部署在被评估主机，收集检查项数据并上报 |
| CLI | Kernel 内置交互式终端，提供命令行管理能力 |

---

## 4. Kernel 部署

### 4.1 命令行参数

```
ASSCOR-kernel [选项]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config` | `config.ini` | 配置文件路径 |
| `-listen` | `:50051` | gRPC 监听地址 |
| `-no-mtls` | `false` | 禁用 mTLS（**仅限开发环境**） |
| `-cert-dir` | `certs` | TLS 证书目录 |
| `-verify-certs` | `false` | 验证证书链一致性后退出 |
| `-force-regen-certs` | `false` | 强制重新生成所有 TLS 证书 |
| `-daemon` | `false` | 以守护进程模式运行 |
| `-pid-file` | `ASSCOR-kernel.pid` | PID 文件路径 |
| `-log-format` | `json` | 日志格式：`json`、`text` |
| `-log-level` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `-log-output` | `stderr` | 日志输出：`stderr`、`stdout`、或文件路径 |

### 4.2 启动示例

```bash
# 标准启动（mTLS 启用）
./ASSCOR-kernel-linux-x86_64 -config /etc/ASSCOR/config.ini -listen :50051

# 开发模式（无 mTLS）
./ASSCOR-kernel-linux-x86_64 -no-mtls -log-level debug -log-format text

# 守护进程模式
./ASSCOR-kernel-linux-x86_64 -daemon -pid-file /var/run/ASSCOR-kernel.pid

# 验证证书
./ASSCOR-kernel-linux-x86_64 -verify-certs -cert-dir /etc/ASSCOR/certs

# 重新生成证书
./ASSCOR-kernel-linux-x86_64 -force-regen-certs -cert-dir /etc/ASSCOR/certs
```

### 4.3 启动输出

Kernel 启动后将显示加载状态：

```
ASSCOR μKernel
  Framework: v0.1.2-MVP   SSAM: 1.3

  Listen:   :50051 (mTLS: true)
  Log:      json (info) -> stderr
  Plugins:  14 loaded
    {heartbeat} v1.0.0 — Agent heartbeat tracking
    {spc} v1.0.0 — Security Posture Calculator
    {cti} v1.0.0 — Cyber Threat Intelligence
    {assessor} v1.0.0 — SSAM security assessment engine
    {policy} v1.0.0 — Policy enforcement and compliance
    {commander} v1.0.0 — Agent command dispatch
    {log_collector} v1.0.0 — Agent log collection
    {persistence} v1.0.0 — Data persistence layer
    {concurrency} v1.0.0 — Concurrency control
    {attck} v2.0.0 — MITRE ATT&CK V19 threat analysis
    {config_watcher} v1.0.0 — Configuration hot-reload
    {adapter_integration} v1.0.0 — External adapter integration
    {source_manager} v1.0.0 — External source management
    {cli} v1.0.0 — Command-line interface
```

---

## 5. Agent 部署

### 5.1 命令行参数

```
ASSCOR-agent [选项]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config` | `agent.ini` | Agent 配置文件路径 |
| `-kernel` | `127.0.0.1:50051` | Kernel 地址（host:port） |
| `-host-id` | 主机名 | Agent 主机标识符 |
| `-tls` | `false` | 启用 mTLS 连接 |
| `-tls-skip-verify` | `false` | 跳过 TLS 证书验证（**仅限开发环境**） |
| `-cert-dir` | `certs` | TLS 证书目录 |
| `-log-format` | `json` | 日志格式 |
| `-log-level` | `info` | 日志级别 |
| `-log-output` | `stderr` | 日志输出 |

### 5.2 启动示例

```bash
# 连接远程 Kernel（mTLS）
./ASSCOR-agent-linux-x86_64 -kernel 192.168.1.10:50051 -tls -cert-dir /etc/ASSCOR/certs

# 指定主机 ID
./ASSCOR-agent-linux-x86_64 -kernel 10.0.0.5:50051 -tls -host-id web-server-01

# 开发模式
./ASSCOR-agent-linux-x86_64 -kernel localhost:50051 -tls-skip-verify -log-level debug
```

### 5.3 Agent 配置文件

Agent 支持独立的 INI 配置文件（默认 `agent.ini`），格式如下：

```ini
[agent]
kernel_addr = 192.168.1.10:50051
host_id = web-server-01
tls_enabled = true
cert_dir = /etc/ASSCOR/certs

[logging]
format = json
level = info
output = /var/log/ASSCOR-agent.log
```

命令行参数优先级高于配置文件。

---

## 6. TLS 证书管理

ASSCOR 使用 mTLS（双向 TLS）保障 Kernel 与 Agent 间的通信安全。

### 6.1 自动证书生成

首次启动时，Kernel 自动在证书目录生成以下文件：

```
certs/
├── ca.crt        # CA 证书
├── ca.key        # CA 私钥
├── server.crt    # Kernel 服务端证书
├── server.key    # Kernel 服务端私钥
├── agent.crt     # Agent 客户端证书
└── agent.key     # Agent 客户端私钥
```

### 6.2 证书操作

```bash
# 验证证书链一致性
./ASSCOR-kernel-linux-x86_64 -verify-certs -cert-dir /etc/ASSCOR/certs

# 强制重新生成所有证书（旧证书将被删除）
./ASSCOR-kernel-linux-x86_64 -force-regen-certs -cert-dir /etc/ASSCOR/certs
```

### 6.3 证书分发

将 `ca.crt`、`agent.crt`、`agent.key` 分发到每台 Agent 主机的证书目录。

> **安全提示**：私钥文件（`.key`）权限应设为 0600，仅限 root 用户读取。

---

## 7. 配置文件详解

配置文件采用 INI 格式，默认路径 `config.ini`。

### 7.1 权重配置

```ini
[weights]
attack_surface = 35        # 攻击面管理权重
business_continuity = 25   # 业务连续性权重
operation_trust = 25       # 操作可信度权重
resilience = 15            # 韧性权重
```

> 四项权重总和必须为 100。

### 7.2 可接受性阈值

```ini
[acceptability]
threshold = 80.0                       # SSAM 评分阈值
compliance_framework = GB/T 22239-2019 Level 3  # 合规框架
```

阈值与等保等级联动：

| 等保等级 | SSAM 阈值 |
|----------|-----------|
| 二级 | ≥ 65 |
| 三级（默认） | ≥ 80 |
| 四级 | ≥ 90 |

### 7.3 边缘因子

```ini
[edge_factors]
two_factor_failure = 0.85    # 双因素认证缺失时乘数

[edge_factors.level4_override]
two_factor_failure = 0.70    # 等保四级三因素认证缺失时乘数
```

边缘因子仅在对应条件触发时参与连乘，取值范围 (0, 1)。

### 7.4 威胁配置

```ini
[threat]
coefficient = 1.0     # 威胁系数 μ（默认 1.0，由 CTI 模块动态调整）
spc_enabled = true    # 是否启用 SPC 修正
```

### 7.5 检查项 Delta 值

```ini
[check_deltas]
AS-001 = -8      # 攻击面检查项
OT-001 = -10     # 操作可信度检查项
RS-001 = -10     # 韧性检查项
BC-005 = -10     # 业务连续性检查项
AC-001 = -15     # 等保四级增强检查项
EF-001 = 0       # 边缘因子检查项
```

Delta 值为负数表示检查未通过时的扣分，正数表示补偿加分。每个检查项 ID 遵循 `XX-NNN` 编号体系：

- `AS`：攻击面（Attack Surface）
- `OT`：操作可信度（Operation Trust）
- `RS`：韧性（Resilience）
- `BC`：业务连续性（Business Continuity）
- `AC`：等保四级增强（Additional Control）
- `EF`：边缘因子（Edge Factor）
- `KS`：内核安全扩展（Kernel Security）

### 7.6 扩展配置

```ini
[extensions]
kernel_security = on        # 启用内核安全扩展域

[extension_weights]
kernel_security = 10        # 内核安全扩展权重
```

---

## 8. SPC 安全态势模块

SPC 模块通过 NVD/EPSS/CISA KEV/CNNVD/CNVD 等外部漏洞数据源与本地资产比对，输出个体化修正因子 P_score（0.60–1.00）。

### 8.1 基本配置

```ini
[spc]
enabled = true              # 是否启用
min_pscore = 0.60           # P_score 下限
cache_retention_days = 365  # CVE 缓存保留天数
fetch_interval_h = 1        # 自动刷新间隔（小时）
```

### 8.2 NVD 数据源

```ini
[spc.nvd]
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
api_key =                   # 留空则从环境变量 NVD_API_KEY 读取
sync_interval_h = 6         # 同步间隔
use_last_mod = true         # 增量同步模式
no_rejected = true          # 过滤已拒绝的 CVE
```

**API Key 说明**：

- 无 Key：请求速率限制 5 次/30秒，系统自动采用 4 并发分片策略
- 有 Key：请求速率限制 50 次/30秒，系统自动采用 2 并发分片策略
- 获取地址：https://nvd.nist.gov/developers/request-an-api-key

### 8.3 EPSS 数据源

```ini
[spc.epss]
enabled = true
data_url = https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
sync_interval_h = 24
```

### 8.4 CISA KEV 数据源

```ini
[spc.cisa_kev]
enabled = true
catalog_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
sync_interval_h = 24
```

### 8.5 CNNVD 数据源

```ini
[spc.cnnvd]
enabled = false
base_url = https://www.cnnvd.org.cn/home/data
api_key =                   # 留空则从环境变量 CNNVD_API_KEY 读取
sync_interval_h = 24
```

### 8.6 CNVD 数据源

```ini
[spc.cnvd]
enabled = false
base_url = https://www.cnvd.org.cn/shareData
sync_interval_h = 24
```

### 8.7 MISP 数据源

```ini
[spc.misp]
base_url =                  # MISP 服务器地址
api_key =                   # 留空则从环境变量 MISP_API_KEY 读取
verify_tls = true
sync_interval_h = 1
tlp_filter = white          # TLP 标签过滤
```

### 8.8 OSCAL 导入

```ini
[spc.oscal]
enabled = false
input_format = json         # json / yaml / xml
results_path = ./oscal_results/
plan_path = ./oscal_plan/
```

### 8.9 CPE 匹配机制

Agent 自动将已安装软件包转换为 CPE 2.3 格式（`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`），SPC 模块按以下优先级匹配：

1. **精确版本匹配**（MatchExactVersion）：vendor、product、version 完全一致
2. **版本范围匹配**（MatchVersionRange）：vendor、product 一致，version 在受影响范围内
3. **产品匹配**（MatchProduct）：vendor、product 一致，无版本信息
4. **厂商匹配**（MatchVendor）：仅 vendor 一致
5. **描述匹配**（MatchDescription）：包名出现在 CVE 描述中

---

## 9. 等保映射与评分阈值

### 9.1 检查项覆盖

| 等保等级 | 自动化检查项数 |
|----------|----------------|
| 三级 | 53 项 |
| 四级 | 53 + 9 = 62 项 |

### 9.2 核心域检查项分布

| 核心域 | 检查项前缀 | 数量（三级） |
|--------|------------|--------------|
| 攻击面管理 | AS-001 ~ AS-017 | 17 |
| 操作可信度 | OT-001 ~ OT-022 | 22 |
| 韧性 | RS-001 ~ RS-012 | 12 |
| 业务连续性 | BC-005 ~ BC-007 | 3 |
| 等保四级增强 | AC-001 ~ AC-008 | 8（仅四级） |
| 边缘因子 | EF-001 ~ EF-002 | 2 |

### 9.3 评分阈值联动

修改 `[acceptability] threshold` 值即可切换等保等级对应的阈值：

```ini
# 等保二级
threshold = 65.0

# 等保三级（默认）
threshold = 80.0

# 等保四级
threshold = 90.0
```

---

## 10. ATT&CK V19 威胁分析模块

ASSCOR v0.1.2-MVP 集成 MITRE ATT&CK V19 框架，作为 μKernel 插件（`attck`，优先级 80，版本 2.0.0）运行。模块提供从检测、情报、仿真到评估的完整威胁分析能力链，并在此基础上扩展 APT 攻击分析与检测增强子模块。

### 10.1 四大核心子模块

| 子模块 | 核心能力 |
|--------|----------|
| **检测与分析** | 检测规则引擎（注册/评估/删除）、异常事件记录与查询、告警关联分析、检测摘要统计 |
| **威胁情报** | IOC 管理（增删查搜/过期清理）、威胁行为体画像、TTP 追踪、告警情报富化 |
| **对手仿真与红队** | 仿真场景管理、从 APT 组织自动生成场景、安全模式仿真执行、仿真结果记录 |
| **评估与工程** | 差距分析（防御覆盖率）、安全控制映射、缓解建议生成、持续改进追踪 |

### 10.2 APT 攻击分析与检测增强

在四大子模块基础上，APT 增强层提供高级威胁分析能力：

| 功能 | 描述 |
|------|------|
| **攻击链重构** | 基于告警、异常、IOC 多源证据，按 ATT&CK 战术顺序自动重构多阶段攻击链 |
| **行为检测** | 行为指标注册与评估、主机行为基线管理、C2 信标检测（间隔抖动分析） |
| **APT 归因引擎** | 多源证据融合（TTP 重叠 60% + IOC 匹配 40%），APT 组织匹配置信度评分 |
| **威胁狩猎框架** | 狩猎假设 CRUD、基于攻击转移矩阵自动生成假设、假设执行与确认 |

### 10.3 与 SSAM 评估体系的协同

ATT&CK 模块与 SSAM 评估体系形成双向增强闭环：

- **韧性域增强**：APT 攻击链检测结果通过事件总线注入策略管理器，影响主机安全状态判定
- **SPC 联动**：APT 归因引擎输出的威胁行为体信息可与 SPC 漏洞情报交叉验证，动态调整 P_score
- **CTI 协同**：CTI 模块的威胁系数 μ 与 ATT&CK 威胁情报子模块共享数据源
- **策略联动**：APT 检测告警触发策略管理器自动响应动作

### 10.4 ATT&CK 配置

```ini
[attck]
enabled = true                  # 是否启用 ATT&CK 模块
version = v19                   # ATT&CK 框架版本
auto_hunt = false               # 是否自动生成狩猎假设
beacon_threshold = 0.7          # 信标检测评分阈值
attribution_threshold = 0.6     # APT 归因置信度阈值
safe_emulation = true           # 仿真是否默认安全模式
```

### 10.5 CLI 操作

通过 Kernel 交互式 CLI 可操作 ATT&CK 模块：

```
# 查看检测摘要
ASSCOR> attck summary

# 注册检测规则
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high

# 查看 IOC 列表
ASSCOR> attck ioc list --type ip

# 执行差距分析
ASSCOR> attck gap --host=web-server-01

# 重构攻击链
ASSCOR> attck chain --host=web-server-01

# 执行 APT 归因
ASSCOR> attck attribute --chain=<chainID>

# 生成狩猎假设
ASSCOR> attck hunt generate --host=web-server-01

# 执行对手仿真
ASSCOR> attck emulate --scenario=<scenarioID> --host=web-server-01 --safe
```

---

## 11. 日志管理

### 11.1 日志配置

```bash
# JSON 格式（默认，适合日志采集系统）
-log-format json -log-level info -log-output /var/log/ASSCOR-kernel.log

# 文本格式（适合人工阅读）
-log-format text -log-level debug -log-output stderr
```

### 11.2 日志级别

| 级别 | 用途 |
|------|------|
| `debug` | 详细调试信息，包含请求/响应细节 |
| `info` | 正常运行信息（推荐生产环境） |
| `warn` | 警告信息，如配置缺失、降级运行 |
| `error` | 错误信息，需要关注处理 |

### 11.3 日志组件前缀

每条日志包含组件前缀，便于过滤：

```
{"time":"...","level":"info","component":"spc","msg":"CVE cache loaded","count":1234}
{"time":"...","level":"warn","component":"kernel","msg":"NVD API key not configured"}
```

常见组件前缀：`kernel`、`spc`、`cti`、`assessor`、`policy`、`commander`、`heartbeat`、`cli`、`tls`

---

## 12. 守护进程模式

```bash
# 启动守护进程
./ASSCOR-kernel-linux-x86_64 -daemon -pid-file /var/run/ASSCOR-kernel.pid

# 停止守护进程
kill $(cat /var/run/ASSCOR-kernel.pid)
```

守护进程模式下，日志自动重定向到 `ASSCOR-kernel.log`。

---

## 13. 离线评估模式

`ASSCOR` 命令提供单机离线评估，无需部署 Kernel 和 Agent：

```bash
# 文本报告
./ASSCOR -config config.ini

# JSON 报告
./ASSCOR -config config.ini -json
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config` | `config.ini` | 配置文件路径 |
| `-json` | `false` | 以 JSON 格式输出 |

离线评估模式下 SPC 模块仍可工作（如已配置数据源），但无 Agent 上报数据。

---

## 14. 环境变量参考

| 环境变量 | 用途 | 优先级 |
|----------|------|--------|
| `NVD_API_KEY` | NVD API 密钥 | 高于 config.ini 中的 `api_key` |
| `MISP_API_KEY` | MISP API 密钥 | 高于 config.ini 中的 `api_key` |
| `CNNVD_API_KEY` | CNNVD API 密钥 | 高于 config.ini 中的 `api_key` |

> **安全提示**：API Key 应通过环境变量传递，禁止硬编码到配置文件或命令行参数中。

---

## 15. 故障排查

### 15.1 Kernel 启动失败

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| `FATAL: kernel bootstrap failed` | 插件初始化失败 | 检查日志输出，确认配置文件格式正确 |
| `WARN: server start failed` | 端口被占用 | 更换 `-listen` 地址或释放端口 |
| 证书错误 | 证书文件损坏或不匹配 | 使用 `-force-regen-certs` 重新生成 |

### 15.2 Agent 连接失败

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| `connection refused` | Kernel 未启动或地址错误 | 确认 Kernel 地址和端口 |
| `certificate verify failed` | 证书不匹配 | 重新分发证书，确认 `cert_dir` 路径 |
| `agent: fatal` | 配置错误 | 使用 `-log-level debug` 查看详细错误 |

### 15.3 SPC 数据同步问题

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| `CVE cache is empty` | 首次同步未完成 | 等待后台同步完成（约 1–5 分钟） |
| `NVD API rate limited` | 无 API Key 或请求过频 | 配置 `NVD_API_KEY` 环境变量 |
| `SPC cannot calculate risk` | 缓存为空 | 检查网络连接，确认数据源可访问 |

### 15.4 评分异常

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| 评分始终为 100 | 所有检查项通过 | 正常现象，表示系统安全状态良好 |
| 评分异常偏低 | 检查项 Delta 值过大 | 检查 `[check_deltas]` 配置是否合理 |
| P_score 为 0.60 | 存在高危 CVE 匹配 | 使用 `spc cve` 命令查看匹配的 CVE 详情 |
