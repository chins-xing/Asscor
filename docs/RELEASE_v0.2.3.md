# ASSCOR v0.2.3 发布说明

**发布日期**: 2026-08-16 | **版本**: v0.2.3 (SSAM 2.0) | **上一版本**: v0.2.2

---

## 概述

ASSCOR v0.2.3 是一次**安全加固与可加入性发布**：完成攻击面管理的专项审计与闭环修复（Web UI 整体移除、user_check 命令白名单化、CLI socket 收紧、mTLS 生产强制、检查命令白名单内核下发）、Agent 检查体系的配置化与强制隔离（user_check/check_deltas 内核同步、Source 标记、CU- 前缀命名空间）、以及大量测试补齐与贡献者基础设施。同时修复了安全与性能审计发现的全部缺陷。

### 关键指标

| 指标 | v0.2.2 | v0.2.3 | 变化 |
|------|:---:|:---:|:---:|
| 提交数 | — | **108** | 本周期新增 |
| 变更行 | — | **+21,354 / −11,019** | 330 文件 |
| 功能模块 | 18 | **17** | Web UI 移除 |
| 网络监听面 | 5 | **4** | 8087 无认证端口删除 |
| 测试文件 | 51 | **58** | +7 |
| agent 测试覆盖 | 0% | **26.2%** | 首次引入 |
| checks/linux 覆盖 | 0% | **11.2%** | 首次引入 |
| gofmt 债务 | 162 文件 | **0** | 全仓库清零 |
| 攻击面审计闭环 | — | **5/5 项修复** | P0×2 + P1×2 + P2 |

---

## 核心变更

### 一、攻击面管理专项审计与闭环修复（安全加固主线）

专项审计（`docs/audits/ATTACK_SURFACE_MANAGEMENT_AUDIT_2026-08-15.md`）盘点 19 个攻击面，二次审计（`SECOND_AUDIT_2026-08-15.md`）验证修复并发现绕过，全部闭环：

| 审计项 | 修复 | 效果 |
|--------|------|------|
| **P0-1 Web UI (8087) 无认证** | 整体删除 `internal/webui` + 全部接线/部署/文档 | 无认证 HTTP 端口彻底消失 |
| **P0-2 user_check 命令失控** | 首词白名单 → 二次审计发现 shell 绕过 → **重设计为无 shell 直接 exec**（含 `; & \| $()` 反引号等元字符构造时拒绝） | `sh -c` 注入面彻底移除 |
| **P1 CLI socket 0660** | 0600 + Linux SO_PEERCRED 连接校验（root/内核自身） | 本地管理通道 peer 校验 |
| **P1 mTLS 生产未强制** | `[comms] require_mtls`（默认 true）拒绝 `--no-mtls` 启动 | 生产强制加密 |
| **P2 检查白名单 agent 硬编码** | `[commands] extra_whitelist` 内核同步下发（内置 25 命令基线不可删） | 命令白名单内核集中管控 |

### 二、Agent 检查体系配置化与强制隔离

- **user_check 修复**：kernel 侧注册失效 bug 修复（`[user_check.<name>]` 子节此前完全无法注册）+ agent 侧配置化（agent.ini `[user_check.*]`）
- **内核→agent 配置同步**：`HeartbeatResponse.CheckConfig` 携带 user_check/check_deltas/命令白名单（内容指纹版本化），config.ini 成为检查定义唯一事实源
- **强制隔离**：`CheckItem.Source` 标记（builtin/user）、`CU-` 保留前缀（非法 ID 拒绝注册）、注册表防重复覆盖（内置检查不可被自定义遮蔽）
- **报告可辨识**：agent 报告 `[user]` 标记、CLI 统计 user-defined 检查数
- **`[check_deltas]` 扩展到 agent**：按检查 ID 覆盖 Delta（与 kernel 行为一致）

### 三、Agent 配置安全化

- agent.ini/config.ini **0640 root:asscor**、`/etc/asscor` **0750 root:asscor**——agent 进程（asscor 用户）可读不可写自身配置
- 配置主源从"直接编辑 agent.ini"转变为"内核 config.ini 同步下发"（agent.ini 降级为最小引导文件）

### 四、微内核剥离完成（v0.2.2 延续）

- 通信服务/完整性/韧性/检查项/适配器/评估引擎全部 build-tag 剥离（17 模块），契约类型上移 `internal/kernel/engine_types.go`
- 单 build-tag 独立编译修复（assessor/attck 剥离 engine 实现包依赖）
- agent 主进程 + 特权进程（root）权限拆分

### 五、测试补齐

| 包 | 覆盖 | 内容 |
|------|:---:|------|
| internal/agent | 0 → **26.2%** | HMAC 命令签名 8 用例（防重放/防篡改）、CPE 生成、检查器（超时配置化+字段补全）等 40+ 用例 |
| internal/checks/linux | 0 → **11.2%** | matchSSHConfig/parseCrypttab/权限辅助/80 检查项元数据一致性等 24 用例 |
| internal/config | — | user_check 解析/白名单/`[comms]`/`[commands]` 节 20+ 用例 |
| internal/comms | — | CheckConfig 提取/版本指纹/CLI peer 校验 10+ 用例 |

### 六、可加入性基础设施

- **gofmt 全仓库规范化**（162 文件 → 0）
- **GitHub Actions CI**：gofmt/vet/最小与全 tag 构建/无 tag 与全 tag 测试自动执行
- **CONTRIBUTING.md**：构建/测试/模块依赖矩阵/代码约定/贡献流程
- **Apache License 2.0 社区模式**：主仓库单人开发、下游自由 fork/二次开发/分发/闭源
- 构建链修复（build.sh/Dockerfile `configs/` 路径）

### 七、稳定性与性能修复

- 命令输出日志脱敏（512 字节截断，SEC01）
- SPC 评估热路径优化（CPE 小写缓存、日志降级，PERF01/02/03）
- persistence flush 错误检查、pluginsdk/bus 双层 panic 恢复（S01-S05）

---

## 已知问题

| ID | 问题 | 等级 | 计划 |
|:--:|------|:---:|------|
| P2-残余 | user_check 管道类命令不再支持（无 shell 收紧的有意取舍） | P2 | 如需管道走整串显式白名单 |
| M01 | 升级不自动更新 systemd unit（v0.2.3 移除 `--webui-port`/`--no-mtls` 后旧 unit 需手动更新） | P1 | 改进升级流程 |
| — | `splitPkgNameVersion` 裸 `rpm -qa` 多破折号包名拆分不完善 | P2 | 后续修复 |

---

## 安装

```bash
# 下载二进制
wget https://github.com/asscor/asscor/releases/download/v0.2.3/ASSCOR-kernel-linux-amd64
wget https://github.com/asscor/asscor/releases/download/v0.2.3/ASSCOR-agent-linux-amd64

# 安装
sudo ./ASSCOR-kernel-linux-amd64 --install
sudo ./ASSCOR-agent-linux-amd64 --install

# 启动
sudo systemctl start asscor-kernel
sudo systemctl start asscor-agent

# 验证
/opt/asscor/ASSCOR-kernel --version
```

## 升级（自 v0.2.2）

```bash
# 1. 更新二进制
sudo ./ASSCOR-kernel-linux-amd64 --upgrade
sudo systemctl restart asscor-agent

# 2. ⚠️ 更新 systemd unit（v0.2.3 移除了 --webui-port/--no-mtls flag）：
#    编辑 /etc/systemd/system/asscor-kernel.service，从 ExecStart 移除
#    "--no-mtls --webui-port=8087"，然后：
sudo systemctl daemon-reload
sudo systemctl restart asscor-kernel

# 3. 同步配置（可选，启用新能力）
#    config.ini: [comms] require_mtls=true（生产强制 mTLS）、[user_check.<name>] 自定义检查
```

---

## 统计

| 指标 | 数值 |
|------|:---:|
| 提交数 | 108 |
| 修改文件 | 330 |
| 新增行 | 21,354 |
| 删除行 | 11,019 |
| 新增测试文件 | 7 |
| 审计报告 | 6 份（攻击面管理 + 二次审计 + 安全/稳定性/代码质量） |
| 新增命令/配置 | `[comms]` `[commands]` `[user_check]` `[check_deltas]` 同步机制 |

---

*ASSCOR v0.2.3 — 攻击面收敛与可加入性发布。*
