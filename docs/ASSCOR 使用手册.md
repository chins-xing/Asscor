# ASSCOR 使用手册

> 版本：v0.2.0 | SSAM 2.0 | 最后更新：2026-07-07

> ⚠️ ASSCOR 输出的分数是一个**数学模型的计算结果，不是绝对的安全真值。**
> 请将评分作为决策参考而非决策替代。模型能捕获已知的可量化维度，但安全的
> 完整图景远超任何公式的覆盖范围。

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

ASSCOR 是一个开源的分布式安全可接受性评估系统，实现了系统安全可接受性模型（SSAM）2.0。系统通过四个互斥核心域评估主机安全状态，并集成 MITRE ATT&CK V19 威胁分析框架，提供从安全评估、威胁检测到 APT 攻击分析的完整能力链。

SSAM V2.0 引入三层语义模型（本征 Intrinsic / 暴露 Exposure / 威胁 Threat），以三个独立风险层加权平均取代旧版 ThreatCoeff/SPCScore 双重罚分机制，提升评分的可解释性与公正性。核心算法库已独立为 [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam)（`ssam-lib/`），零外部依赖、纯函数式设计。ASSCOR 平台通过 `internal/ssam/` 薄适配层委托调用。

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

### 2.2 最小部署（生产，推荐）

```bash
# 1. 安装并启动 Kernel（一条命令完成 systemd + FHS + PATH）
sudo ./ASSCOR-kernel-v0.2.0-linux-amd64 --install
sudo systemctl start asscor-kernel

# 2. 安装并启动 Agent（目标主机）
sudo ./ASSCOR-agent-v0.2.0-linux-amd64 --install
sudo systemctl start asscor-agent

# 3. 连接 CLI 管理
asscor-cli               # status / plugins / history / exit
```

### 2.3 离线评估（无需 Kernel/Agent）

```bash
# 单机模式：直接在本地执行评估，结果打印到终端
./ASSCOR-v0.2.0-linux-amd64 --config=/etc/asscor/config.ini          # 文本报告
./ASSCOR-v0.2.0-linux-amd64 --config=/etc/asscor/config.ini -json    # JSON 报告
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
| `--config` | `config.ini` | 配置文件路径 |
| `--listen` | `:50051` | gRPC 监听地址 |
| `--webui-port` | `8087` | Web 仪表盘端口（0 禁用） |
| `--no-mtls` | `false` | 禁用 mTLS（**仅限开发环境**） |
| `--cert-dir` | `certs` | TLS 证书目录 |
| `--verify-certs` | `false` | 验证证书链一致性后退出 |
| `--force-regen-certs` | `false` | 强制重新生成所有 TLS 证书 |
| `--daemon` | `false` | 以守护进程模式运行 |
| `--pid-file` | `ASSCOR-kernel.pid` | PID 文件路径 |
| `--version` | — | 显示版本并退出 |
| `--install` | — | 安装为 systemd 服务（需 root） |
| `--uninstall` | — | 卸载 systemd 服务（需 root） |
| `--upgrade` | — | 原地升级已安装版本（需 root） |
| `--check-install` | — | 校验安装完整性后退出 |
| `--cli <socket>` | — | 连接到运行中内核的 CLI（Unix socket） |
| `--log-format` | `json` | 日志格式：`json`、`text` |
| `--log-level` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `--log-output` | `stderr` | 日志输出：`stderr`、`stdout`、或文件路径 |

### 4.2 生产部署（systemd + FHS，推荐）

单二进制自带安装能力，一条命令完成 systemd 服务注册、FHS 目录布局、PATH 符号链接、用户创建：

```bash
# 安装（需 root）
sudo ./ASSCOR-kernel-v0.2.0-linux-amd64 --install

# 启动 + 开机自启
sudo systemctl start asscor-kernel
sudo systemctl enable asscor-kernel

# 安装 Agent（同一主机或被评估主机）
sudo ./ASSCOR-agent-v0.2.0-linux-amd64 --install
sudo systemctl start asscor-agent
```

**FHS 文件系统布局**：

```
/etc/asscor/config.ini              # 内核配置
/etc/asscor/agent.ini               # Agent 配置
/etc/asscor/config/                 # 6 行业模板
/opt/asscor/ASSCOR-kernel           # 内核二进制
/opt/asscor/agent/ASSCOR-agent      # Agent 二进制
/opt/asscor/asscor-cli.sock         # CLI Unix socket
/var/lib/asscor/                    # 数据（CVE 缓存、评估记录、备份）
/var/lib/asscor/latest-assessment.json      # 最新评估报告
/var/lib/asscor/assessments-<date>.jsonl     # 历史评估记录
/var/log/asscor/kernel.log          # 内核日志
/usr/bin/asscor                     # 全局命令（符号链接）
/usr/bin/asscor-cli                 # CLI 便捷包装脚本
```

安装后 `asscor` 与 `asscor-cli` 在任意路径（含 `sudo`）可用。

### 4.3 systemctl 管控

| 命令 | 效果 |
|------|------|
| `systemctl start asscor-kernel` | 启动服务 |
| `systemctl stop asscor-kernel` | 停止（SIGTERM → 优雅关闭，保存 CVE 缓存） |
| `systemctl reload asscor-kernel` | SIGHUP → 热重载 config.ini（权重/阈值/Prism/边缘因子） |
| `systemctl status asscor-kernel` | 查看状态 |
| `journalctl -u asscor-kernel -f` | 实时跟踪日志 |

### 4.4 版本升级

```bash
# 原地升级（自动停止→备份→替换→启动，失败自动回滚）
sudo ./ASSCOR-kernel-v0.2.1-linux-amd64 --upgrade
asscor --version         # 确认版本
```

升级会自动补建 PATH 符号链接并保留旧二进制于 `.bak`。

### 4.5 远程 CLI

内核以 systemd 服务运行时（无交互终端），通过 Unix socket 连接 CLI：

```bash
asscor-cli               # 便捷方式（自动连接 socket）
# 或
asscor --cli /opt/asscor/asscor-cli.sock

asscor> status           # 查看内核状态
asscor> plugins          # 插件列表
asscor> exit             # 断开（内核继续运行）
```

> `exit`/`quit` 仅断开当前 CLI 会话，内核持续运行。只有 `systemctl stop` 才会完整退出内核。

### 4.6 命令行参数（手动运行）

```bash
ASSCOR-kernel [选项]
```

### 4.7 启动示例

```bash
# 标准启动（mTLS 启用）
./ASSCOR-kernel-v0.2.0-linux-amd64 --config=/etc/asscor/config.ini --listen=:50051

# 开发模式（无 mTLS）
./ASSCOR-kernel-v0.2.0-linux-amd64 --no-mtls --log-level=debug --log-format=text

# 守护进程模式
./ASSCOR-kernel-v0.2.0-linux-amd64 --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# 验证证书
./ASSCOR-kernel-v0.2.0-linux-amd64 --verify-certs --cert-dir=/etc/asscor/certs

# 重新生成证书
./ASSCOR-kernel-v0.2.0-linux-amd64 --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 4.3 启动输出

Kernel 启动后将显示加载状态：

```
ASSCOR μKernel
  Framework: v0.2.0   SSAM: 2.0

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
    {attck} v1.0.0 — MITRE ATT&CK V19 threat analysis
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
| `--config` | `agent.ini` | Agent 配置文件路径 |
| `--kernel` | `127.0.0.1:50051` | Kernel 地址（host:port） |
| `--host-id` | 主机名 | Agent 主机标识符 |
| `--tls` | `false` | 启用 mTLS 连接 |
| `--tls-skip-verify` | `false` | 跳过 TLS 证书验证（**仅限开发环境**） |
| `--cert-dir` | `certs` | TLS 证书目录 |
| `--install` | — | 安装为 systemd 服务（需 root） |
| `--uninstall` | — | 卸载 systemd 服务（需 root） |
| `--upgrade` | — | 原地升级（需 root） |
| `--version` | — | 显示版本并退出 |
| `--log-format` | `json` | 日志格式 |
| `--log-level` | `info` | 日志级别 |
| `--log-output` | `stderr` | 日志输出 |

### 5.2 部署示例

```bash
# 生产安装（systemd）
sudo ./ASSCOR-agent-v0.2.0-linux-amd64 --install
sudo systemctl start asscor-agent

# 手动运行：连接远程 Kernel（mTLS）
./ASSCOR-agent-v0.2.0-linux-amd64 --kernel=192.168.1.10:50051 --tls --cert-dir=/etc/asscor/certs

# 指定主机 ID
./ASSCOR-agent-v0.2.0-linux-amd64 --kernel=10.0.0.5:50051 --tls --host-id=web-server-01

# 开发模式
./ASSCOR-agent-v0.2.0-linux-amd64 --kernel=localhost:50051 --tls-skip-verify --log-level=debug
```

> Agent 需 root 运行以执行系统级检查（读取 `/etc/shadow`、`iptables` 等）。非 root 运行时需要 root 权限的检查项自动跳过并标记。

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
./ASSCOR-kernel-v0.2.0-linux-amd64 --verify-certs --cert-dir=/etc/asscor/certs

# 强制重新生成所有证书（旧证书将被删除）
./ASSCOR-kernel-v0.2.0-linux-amd64 --force-regen-certs --cert-dir=/etc/asscor/certs
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

> ⚠️ **评估方法声明（已知局限性）**：SPC 的验证逻辑基于 CPE 字符串匹配——将已安装软件包名称/版本与 CVE 数据库中的受影响产品版本进行交叉比对。它**不执行**漏洞利用验证、运行时可达性分析、二进制分析、或替代缓解措施验证。匹配结果可能产生假阳性（已通过 WAF/虚拟补丁缓解但未更新版本号的漏洞）和假阴性（版本号匹配但存在定制变种）。SPC 定位为"漏洞情报聚合与版本比对引擎"，而非"漏洞利用验证器"，目前暂无计划引入深度验证能力。

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

ASSCOR v0.2.0 集成 MITRE ATT&CK V19 框架，作为 μKernel 插件（`attck`，优先级 21，版本 1.0.0）运行。模块提供从检测、情报、仿真到评估的完整威胁分析能力链，并在此基础上扩展 APT 攻击分析与检测增强子模块。

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
./ASSCOR-kernel-v0.2.0-linux-amd64 --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# 停止守护进程
kill $(cat /var/run/ASSCOR-kernel.pid)
```

守护进程模式下，日志自动重定向到 `ASSCOR-kernel.log`。

---

## 13. 离线评估模式

`ASSCOR` 命令提供单机离线评估，无需部署 Kernel 和 Agent，即时输出到终端：

```bash
# 文本报告（直接打印到终端）
./ASSCOR-v0.2.0-linux-amd64 --config=/etc/asscor/config.ini

# JSON 报告（可重定向到文件）
./ASSCOR-v0.2.0-linux-amd64 --config=/etc/asscor/config.ini -json > report.json
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--config` | `config.ini` | 配置文件路径 |
| `--json` | `false` | 以 JSON 格式输出 |

单机模式的完整能力：

- **核心检查**：76+ 项本地安全检查（含 KS 内核安全域）
- **SPC 态势计算**：如已配置数据源则自动拉取 NVD/EPSS/KEV 并计算
- **ATT&CK 分析**：覆盖度、Kill Chain、APT 归因、风险预测
- **外部适配器外派**：config.ini `[adapters]` 中启用的工具（Trivy/Lynis/Suricata/ClamAV/AIDE 等）自动执行并将发现外派到对应检查项
- **SRD/Prism 三层分析**：Core（动态评分）→ Semantic（模糊状态）→ Inference（趋势预测）

> **报告位置说明**：单机模式的报告**仅输出到终端/stdout**，不写入磁盘。若需持久化历史报告，请使用 Kernel + Agent 模式（报告自动写入 `/var/lib/asscor/`，见 §4.2）。

### 13.1 报告位置对照

| 模式 | 报告位置 |
|------|----------|
| 单机 `ASSCOR` | 终端 stdout（`-json > file` 可保存） |
| Kernel 服务模式 | `/var/lib/asscor/latest-assessment.json`（最新）<br>`/var/lib/asscor/assessments-<date>.jsonl`（历史）<br>WebUI `http://<host>:8087` |

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

---

## 16. CLI 命令参考

### 16.1 CLI 概述

ASSCOR Kernel 内置交互式 CLI 终端，Kernel 启动后自动进入。CLI 提供命令注册、自动补全、历史记录和插件扩展能力。

**进入 CLI**：Kernel 启动后，日志自动重定向到 `ASSCOR-kernel.log`，终端进入交互模式：

```
ASSCOR μKernel
  Framework: v0.2.0   SSAM: 2.0
  Listen:   :50051 (mTLS: true)
  CLI active: logs redirected to ASSCOR-kernel.log

ASSCOR>
```

**命令语法**：`command <subcommand|param> [options]`。选项使用 `--name=value` 或 `--name value` 格式，布尔选项使用 `--flag` 开启。输入 `Ctrl+D` 或 `Ctrl+C` 退出。

### 16.2 通用选项

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--verbose` | `-v` | 显示详细输出 |
| `--json` | `-j` | 以 JSON 格式输出 |
| `--quiet` | `-q` | 抑制非必要输出 |
| `--help` | `-h` | 显示命令帮助 |

### 16.3 核心命令

**help** — 显示命令帮助或列出所有可用命令：`help [command]`

**version** — 显示 ASSCOR 框架版本和 SSAM 模型版本：`version`

**status** — 显示当前 Kernel 状态，包括插件状态、运行时间和资源使用：`status [--format=json]`

### 16.4 评估命令

**assess** — 触发对指定主机的安全可接受性评估。

```
用法：assess [host] [options]
参数：host — 目标主机 ID（默认 local）
选项：--format=json, --domain=attack_surface|business_continuity|operation_trust|resilience
```

### 16.5 SPC 命令

**spc** — 查询 SPC 模块的 CVE 缓存、P-score、KEV 数量和修正数据。

```
用法：spc <summary|cve|kev|score|fetch> [options]
选项：--limit=N（默认20）, --cvss-min=N, --kev-only, --host=HOST
示例：
  ASSCOR> spc summary
  ASSCOR> spc cve --cvss-min=9.0 --kev-only
  ASSCOR> spc score --host=web-server-01
  ASSCOR> spc fetch
```

### 16.6 Agent 管理命令

**agent** — 管理已注册的 Agent。

```
用法：agent <list|status|start|stop|restart|config|command> [options]
选项：--host=HOST, --all, --filter=key=value, --limit=N（默认50）, --watch
示例：
  ASSCOR> agent list --filter=active=true
  ASSCOR> agent status --host=web-server-01
  ASSCOR> agent stop --host=db-master-01
  ASSCOR> agent command --host=web-01 --action=scan
```

**log** — 查看、过滤和导出 Agent 运行日志。

```
用法：log <show|export> [options]
选项：--host=HOST, --level=debug|info|warn|error, --limit=N（默认50）, --format=json|csv, --output=PATH
```

### 16.7 ATT&CK 命令

**attck** — 操作 ATT&CK V19 模块，包括检测规则管理、IOC 管理、差距分析、攻击链重构、APT 归因和威胁狩猎。

```
用法：attck <summary|rule|alert|anomaly|ioc|actor|gap|control|chain|attribute|hunt|emulate|improve> [options]
选项：--host=HOST, --severity=critical|high|medium|low, --technique=T1234, --limit=N（默认20）, --format=json
```

核心子命令示例：

```
ASSCOR> attck summary                                      # 模块概览
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high
ASSCOR> attck ioc add --type=ip --value=10.0.0.1 --confidence=0.8 --technique=T1071
ASSCOR> attck gap --host=web-server-01                     # 防御差距分析
ASSCOR> attck chain --host=web-server-01                   # 攻击链重构
ASSCOR> attck attribute --chain=CHAIN-20260525-001         # APT 归因
ASSCOR> attck hunt generate --host=web-server-01           # 生成狩猎假设
ASSCOR> attck emulate generate --actor=APT29               # 生成对手仿真
ASSCOR> attck improve create --name="Harden credential policy"  # 持续改进追踪
```

### 16.8 插件管理命令

**plugin** — 列出、查看和管理 Kernel 插件。

```
用法：plugin <list|info|health> [name]
示例：
  ASSCOR> plugin list
  ASSCOR> plugin info spc
  ASSCOR> plugin health
```

### 16.9 外部源管理命令

**source** — 部署、配置、启停和审计外部集成源。

```
用法：source <list|info|deploy|enable|disable|update|uninstall|run|config|audit> [name] [options]
选项：--category=scanner|management, --version=VERSION, --force, --limit=N（默认50）
```

### 16.10 系统命令

**config** — 查看当前 Kernel 配置：`config [key] [--format=json]`

**health** — 对所有 Kernel 插件执行健康检查：`health [--json]`

### 16.11 调试命令

**history** — 查看命令执行历史记录：`history [count] [--failed] [--clear]`

### 16.12 交互式终端功能

- **自动补全**：输入命令后按 `Tab` 键触发（命令名、子命令、选项均可补全）
- **命令历史**：使用 `↑`/`↓` 箭头键浏览历史命令
- **脚本集成**：所有命令支持 `--json` 选项输出结构化 JSON：`echo "spc summary --json" | asscor-cli`
- **退出码**：0=成功，1=执行错误，2=用法错误，130=用户取消

### 16.13 插件注册自定义命令

```go
cliPlugin, ok := k.Container().Resolve((*cli.CLIInterface)(nil))
if ok {
    cliMod := cliPlugin.(cli.CLIInterface)
    cliMod.RegisterCommand(cli.NewBaseCommand(
        cli.CommandInfo{
            Name: "mycmd", Short: "My custom command",
            Usage: "mycmd [args]", Category: cli.CategoryPlugin,
        },
        func(ctx *cli.CommandContext) *cli.CommandResult {
            return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "Custom command executed\n"}
        },
    ))
}

---

## 15. 自定义扩展（无需编写 Go 代码）

ASSCOR 支持三类无需编写 Go 代码的扩展方式，从零门槛到专业开发逐级递进。

### 15.1 配置文件定义检查项 (`[user_check]`)

在 `config.ini` 中直接添加安全检查，无需任何编程：

```ini
# 命令检查：执行 shell 命令，exit 0 或输出匹配字符串 = 通过
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
description = Check if nginx is running
command = systemctl is-active nginx
delta = -8
output_match = active

# 文件内容检查：检查文件是否存在、内容是否匹配正则
[user_check.auditd]
id = CU-002
domain = operation_trust
name = Auditd rules
description = Verify auditd has shadow watch rules
file_path = /etc/audit/audit.rules
file_regex = -w /etc/shadow -p wa
delta = -10
```

支持的字段：

| 字段 | 必须 | 说明 |
|------|------|------|
| `id` | ✅ | 唯一检查 ID，如 `CU-001` |
| `domain` | ✅ | 归属域（attack_surface / business_continuity / operation_trust / resilience / kernel_security） |
| `name` | ✅ | 检查名称 |
| `command` | * | shell 命令（exit 0 = 通过） |
| `output_match` | 否 | 输出中出现此字符串 = 通过 |
| `file_path` | * | 要检查的文件路径 |
| `file_regex` | 否 | 文件内容匹配此正则 = 通过 |
| `delta` | 否 | 失败扣分（默认 -10） |

> *: `command` 和 `file_path` 至少提供一个。修改后执行 `systemctl reload asscor-kernel` 即可生效。

### 15.2 外部脚本适配器 (`[adapter_script]`)

运行任何语言编写的脚本（Bash/Python/任何），其 JSON stdout 自动成为适配器发现：

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

脚本 stdout 格式（JSON 数组）：

```json
[
  {
    "id": "MON-001",
    "title": "Disk usage warning",
    "severity": "high",
    "detail": "/dev/sda1 is 95% full",
    "domain": "business_continuity",
    "finding_type": "alert"
  }
]
```

**安全限制**:
- 脚本路径必须在 `/opt/asscor/scripts/` `/etc/asscor/scripts/` `/var/lib/asscor/scripts/`
- 脚本必须 root:root 且非 world-writable
- 拒绝符号链接
- 30 秒执行超时
- 1MB 输出上限

### 15.3 Plugin SDK（独立 Go 模块，专业开发）

`pluginsdk/` 提供独立 Go 模块模板，插件通过 JSON-RPC (stdin/stdout) 与内核通信，**零 ASSCOR 源码依赖**：

```
pluginsdk/
├── go.mod           # 独立模块定义
├── sdk.go           # Plugin 接口 + JSON-RPC 循环
├── cmd/myplugin/    # 完整示例插件
│   ├── main.go
│   └── extension.json
└── README.md
```

开发流程：复制模板 → 实现 `HandleRequest()` → `go build` → `asscor> source deploy`。

---

## 16. 算法防护配置 (`[integrity]`)

控制 ASSCOR 对 SSAM/Prism 核心算法的完整性保护：

```ini
[integrity]
sign_assessment = true    # 评估报告 HMAC-SHA256 签名（防伪造报告）
verify_algo = true        # 启动时校验 SSAM/Prism 常量完整性
anti_debug = false        # Linux 反调试检测（需显式开启）
```

| 模式 | 场景 |
|------|------|
| `sign=false, verify=false` | 单二进制轻量部署 |
| `sign=true, verify=true` | 防护评估报告伪造 + 算法校验（推荐） |
| `anti_debug=true` | 敏感环境附加反调试 |

---

## 版本历史

| 版本 | 日期 | 主要变更 |
|------|------|----------|
| v0.2.0 | 2026-07-07 | 单二进制安装(--install/--uninstall/--upgrade/--version)；FHS布局(/etc/asscor,/var/lib/asscor,/var/log/asscor)；systemctl管控+SIGHUP热重载；远程CLI(Unix socket, asscor-cli)；PATH符号链接(/usr/bin/asscor)；单机模式支持适配器外派+SRD三层分析；SSAM V2加权平均评分；persistence路径修复；agent心跳频率优化；config定义检查项([user_check])；外部脚本适配器([adapter_script])；Plugin SDK(pluginsdk/)；算法防护配置([integrity])；CLI diag/policy运维命令 |
| v0.2.0 | 2026-06-28 | CLI spc子命令(score/kev/fetch)实现；kernel控制台评估报告(config.ini console_report)；agent日志格式可配置(agent.ini log_format)；source deploy命令；ATT&CK版本/优先级修正；config热重载默认开启；管理适配器Parse升级；系统d service + Dockerfile |
| v0.1.4-mvp | 2026-06-09 | SSAM V2.0三层语义模型；ATT&CK V19模块；SPC多数据源(CNNVD/CNVD/MISP)；扩展管理器；Prism SRD引擎 |
| v0.1.3-mvp | 2026-05-25 | gRPC/JSONRPC双协议栈；权重热加载；SPC磁盘持久化；适配器集成模块 |
| v0.1.2 | 2026-05-22 | HMAC签名修复；关键消息PublishSync；策略管理器互斥switch；CTI严重级别加权 |
| v0.1.1 | 2026-05-16 | Agent心跳机制；编译产物统一build/目录 |
| v0.1.0 | 2026-05-13 | 初始发布 |
```
