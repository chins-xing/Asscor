# ASSCOR v0.2.2 发布说明

**发布日期**: 2026-08-02 | **版本**: v0.2.2 (SSAM 2.0) | **上一版本**: v0.2.1

---

## 概述

ASSCOR v0.2.2 是一次**全面代码审查与重构发布**，聚焦于技术债务清偿、内核架构解耦、扩展体系激活和测试基础设施建设。本版本不引入新功能，而是在 v0.2.1 基础上进行了深度的质量加固和架构优化。

### 关键指标

| 指标 | v0.2.1 | v0.2.2 | 变化 |
|------|:---:|:---:|:---:|
| 技术债务项 | 87 | **7** | -92% |
| P0 缺陷 | 19 | **0** | 全部清零 |
| 内核测试用例 | ~50 | **222** | +344% |
| 基准测试 | 0 | **5** | 首次引入 |
| 内核文件数 | 66 | **83** | +17 拆分文件 |
| 扩展点 | 65 | **70** | +5 新扩展点 |
| 接口/类型文件 | 0 | **17** | 首次提取 |

---

## 核心变更

### 一、内核架构解耦

**17 个接口/类型文件从单体 kernel 包中提取**，消除 God Package 模式：

| 文件 | 类型 | 行数 |
|------|------|:---:|
| `spc_interface.go` | SPCInterface + 4 子接口 | 42 |
| `cti_interface.go` | CTIInterface | 5 |
| `commander_interface.go` | CommanderInterface | 6 |
| `persistence_interface.go` | PersistenceInterface | 14 |
| `assessor_interface.go` | AssessorInterface | 8 |
| `collector_interface.go` | LogCollectorInterface | 5 |
| `workerpool_interface.go` | ConcurrencyInterface + WorkerPoolInterface | 16 |
| `adapter_integration_interface.go` | AdapterIntegrationInterface | 5 |
| `source_manager_interface.go` | SourceManagerInterface | 16 |
| `policy_types.go` | HostStatus + PolicyAction + PolicyInterface | 37 |
| `crypto_types.go` | CertConfig + CertPair | 12 |
| `crypto_defaults.go` | DefaultCA/Server/AgentConfig | 23 |
| `heartbeat_types.go` | AgentRecord + HeartbeatInterface | 18 |
| `kernel_lifecycle.go` | Bootstrap/Shutdown/Run/Wait/IsRunning | 149 |

同时将 **SPC fetch 模块** 从单一 1,912 行文件拆分为 7 个按数据源命名的文件：
`spc_fetch_nvd.go`, `spc_fetch_epss.go`, `spc_fetch_kev.go`, `spc_fetch_misp.go`, `spc_fetch_cn.go`, `spc_fetch_oscal.go`

### 二、扩展体系激活

**从"66 个扩展点零订阅者"到"9 种扩展类型可通过 extmgr 桥接订阅全部扩展点"**：

- extmgr ↔ Extension Point 桥接建立 (`SetKernelExtensions` + `onExtensionInstalled`)
- 9 种扩展类型全部通过内核扩展点或 `model.Register*` 激活
- 5 个死扩展点救活: `log.entry_received`, `agent.log_uploaded`, `siem.post_push`, `commander.key_rotated`, `srd.result_processed`
- 扩展体系 E2E 集成测试 (3 用例) + extmgr 桥接验证 (5 用例)
- `extension.config_changed` 生命周期扩展点注册 + 热重载触发

### 三、引擎钩子 ↔ 内核扩展点桥接

消除两套独立钩子系统（引擎 `HookRegistry` vs 内核 `ExtensionRegistry`）：

```
engine.HookRegistry (8 phases)        kernel.ExtensionRegistry
  ├── pre_check  ─────────────────→  engine.pre_check   ✅
  ├── post_check ─────────────────→  engine.post_check  ✅
  ├── pre_score  ─────────────────→  engine.pre_score   ✅
  ├── post_score ─────────────────→  engine.post_score  ✅
  ├── pre_edge   ─────────────────→  engine.pre_edge    ✅
  ├── post_edge  ─────────────────→  engine.post_edge   ✅
  ├── pre_report ─────────────────→  engine.pre_report  ✅
  └── post_report ────────────────→  engine.post_report ✅
```

8 阶段全部接线，双重路径触发（`Evaluate` + `EvaluateFromResults`）。

### 四、测试基础设施建设

**222 个内核测试用例** (从 ~50 启动)，**5 个全项目首批基准测试**：

| 新增模块 | 用例 | 说明 |
|------|:---:|------|
| bus.go | 5 | Publish/PublishSync/Subscribe/Unsubscribe/PanicRecovery |
| circuitbreaker.go | 8 | 三态状态机全路径 |
| collector.go | 6 | Append/AppendBatch/NilWriter/Sanitize |
| common/exec.go | 6 | 命令白名单 + Shell 注入防护 |
| services.go | 8 | DTO 转换 5 类型 |
| di.go | 6 | Bind/Resolve/BindNamed/Inject |
| plugin.go | 4 | StateString/Lifecycle/Info |
| interceptor.go | 7 | 拦截器链全路径 |
| ratelimit.go | 7 | 令牌桶限流器全路径 |
| heartbeat.go | 4 | RegisterAgent/GetAgent/ListAgents |
| policy.go | 5 | 四阈值状态机 |
| extensions.go | 8 | 扩展注册表核心 API |
| kernel.go | 6 | 内核访问器 |
| commander.go | 5 | 命令队列 |
| cti.go | 4 | 威胁系数 |
| crypto.go | 6 | 证书生成与验证链 |
| auditlog.go | 4 | 审计日志拦截器 |
| config_watcher.go | 6 | 配置监听器 |
| server.go | 5 | TCP 服务器配置 |

**P0 全部清零 (19/19)**。

### 五、代码质量

| 修复类型 | 数量 | 说明 |
|------|:---:|------|
| nil-guard | 10+ | Bus/Publish/ExtensionsExecute 增补 `m.kernel != nil` 保护 |
| 重复代码消除 | 4 | setupTLS (writeCertFile)、parseInt (common.ParseInt)、CopyFile (copySelfTo)、SemVer (internal/semver/) |
| 死代码标注 | 6 | ATT&CK 零调用者方法标记 `0 callers — reserved` |
| 配置完善 | 6 模板 | 行业模板 console_report 补全 + 重复 INI 段删除 |
| 部署消重 | 2 文件 | 删除静态 systemd 服务文件，Go 代码为单源 |

### 六、SemVer 统一

新建 `internal/semver/` 共享包，统一 extmgr 和 pkgmgr 的版本约束解析：

- 支持 8 种约束语法: `>=`, `>`, `<=`, `<`, `^`, `~`, `1.x`, `1.0 - 2.0`
- pkgmgr 删除 95 行重复代码
- pkgmgr go.mod 移除，并入主模块

### 七、其他变更

- 引擎适配器归位: `srd/prism/ssam` → `internal/engine/srd/prism/ssam/`
- ATT&CK 模块 build-tag 分离: 13 文件添加 `//go:build attck_ext`
- 多算法编排器从引擎内嵌改为可选扩展包 (`optional/algorithms/modules/`)
- 扩展包管理体系: `pkgmgr` + `package.json` + `SCHEMA.md`
- 根目录清理: 删除 6 份过时白皮书副本
- 所有白皮书 v0.2.1→v0.2.2 版本同步

---

## 已知问题

| ID | 问题 | 等级 | 计划 |
|:--:|------|:---:|------|
| E05 | extmgr 不含 PluginSDK 进程启动代码 | P1 | v0.3.0 |
| E06 | pkgmgr 不处理传递依赖 | P1 | v0.3.0 |
| M01 | kernel/ 单体 83 文件/17 插件 (已拆分 17 类型文件) | P1 | v0.3.0 |
| T32 | FHS 路径参数化 (环境变量覆盖) | P2 | v0.3.0 |

---

## 安装

```bash
# 下载二进制
wget https://github.com/asscor/asscor/releases/download/v0.2.2/ASSCOR-kernel-linux
wget https://github.com/asscor/asscor/releases/download/v0.2.2/ASSCOR-agent-linux

# 安装
sudo ./ASSCOR-kernel-linux --install
sudo ./ASSCOR-agent-linux --install

# 启动
sudo systemctl start asscor-kernel
sudo systemctl start asscor-agent

# 验证
/opt/asscor/ASSCOR-kernel --version
curl http://localhost:8087/api/health
```

## 升级

```bash
sudo ./ASSCOR-kernel-v0.2.2-linux-amd64 --upgrade
sudo systemctl restart asscor-agent
```

---

## 统计

| 指标 | 数值 |
|------|:---:|
| 提交数 | 60+ |
| 修改文件 | 66 |
| 新增行 | 3,784 |
| 删除行 | 796 |
| 新增测试文件 | 25 |
| 内核测试用例 | 222 |
| 审计/规划文档 | 9 份 |

---
*ASSCOR v0.2.2 — 可靠性加固与架构优化发布。*
