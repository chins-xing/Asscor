# ASSCOR 内部耦合审计（内核/Agent/模块）

- **日期**：2026-09-03
- **分支**：ASSCOR-Research-Core（main 与 ARC 内核/模块结构同构，结论两分支适用；ARC 额外含 securemode）
- **方法**：`go list -json/-f` 配置矩阵 + `go/parser` 源码全量扫描构建 union 依赖图 + 19 种单 tag 隔离构建 + `nm` 二进制符号验证 + 人工抽查（工具与产物在 `build/coupcheck/`）
- **性质**：审计 + 归档（不修改代码）

---

## 一、总体结论

**架构基调健康，无包级 import 环；但存在 2 个 Important 结构性耦合与若干行为性静默降级点。**

- **全图（所有 tag 组合 union，含 cmd/api）无任何 SCC>1、无自环**——无包级循环依赖。
- **微内核 SPI 成立**：`internal/kernel` 声明契约接口（`*_interface.go`/`*_types.go`）、模块实现各自独立包、`cmd/kernel/main.go` 作组合根经 DI 注入。kernel 不 import 任何可选模块的实现（见下方 C2 修正）。
- 默认构建 kernel 依赖 14 个内部包：adapter / checks / cli / common / config / extmgr / integrity / kernel / logger / model / resilience / securemode / topology / version。

## 二、发现分级表

| # | 级别 | 位置 | 问题 | 影响 |
|---|------|------|------|------|
| **C1** | Important | `cmd/agent → internal/cli → internal/kernel` | agent 不直接 import kernel，但经 internal/cli（102 处 `kernel.*`，kernel 默认插件包）传递依赖：**cmd/agent 编译图含与 kernel 几乎相同的 14 个内部包** | agent 只用 cli 的 3 个 systemd 安装函数（纯文件操作，不引用 kernel），却拖入整个 kernel 契约面；nm 显示链接期 DCE 良好（仅剩 kernel.init+inittask），但编译期耦合 + init 副作用仍在，违背"agent 轻量受管端"定位 |
| **C2** | Important | `internal/kernel/adapter_integration.go`（无 tag 常编译） | 微内核核心直接调用 `adapter.List()/NewPipeline/ExecuteAdapter`——**adapter 模块实现被 kernel 包内常编译的 AdapterIntegrationModule 引用**（子代理将其计入 kernel 依赖的 {adapter,…} 之一） | 内核默认构建携带 adapter 模块实现，模块门控对该链路失效；AdapterIntegrationModule 属"应 tag 化但滞留 kernel"的组件 |
| **F2** | Important | `internal/srdwrapper`（build-tag srdwrapper） | **硬依赖 engine tag**：单 `-tags srdwrapper` 构建 cmd/kernel 失败（engine/srd 全文件 `//go:build engine`，无 engine 时零文件）；其余 17 个模块单 tag 全部 OK | tag 间无依赖表达，组合构建易碎；建议 guard 改 `srdwrapper && engine` 或归入 engine 族 |
| **F3** | Important | 模块→模块直依赖（靠 `!tag` no-op stub 保编译） | assessor→integrity/checks、comms→resilience/securemode/topology、persistence→historicalstore、sourcemanager→adapter、adapter→resilience、engine/ssam→engine、engine/srd→engine/prism、srdwrapper→engine/srd | **静默降级**：enable assessor 忘开 integrity → 结果无签名（GetSigner no-op）；enable comms 忘开 resilience → 无熔断。无 fail-fast / 告警 |
| F4 | Minor | `internal/comms` | 对 resilience.GuardGo / topology.RecordTopology / securemode.Controller 是**直接函数调用**；而对 heartbeat/collector/commander/assessor 走 kernel 声明接口注入——风格不统一 | 同一模块内两种消费方式，削弱"经 kernel SPI"的一致性；securemode 包实际全时编译（tag 只在 cmd 装配层），非严格模块门控 |
| F5 | Minor | 孤儿/私撑包 | `internal/oscal`、`internal/semver`、`internal/adapterhub` 全仓 0 import 方；`internal/historicalstore` 默认-on（无 tag）但仅被 persistence（tag）引用 | 归属不清；宜下沉（如并入调用方）或加 tag / 移入 optional |
| F6 | Minor | 共享地基 | api/v1、model、logger 纯净 leaf；common→logger；**config 反向依赖 checks**（默认-on registry，user_check_registry.go）；kernel fan-in=17、config=11、common=8、api/v1=5 | config→checks 使"地基"层向上依赖检查注册表，违背分层直觉（checks 无 tag 时 registry 也在） |
| F7 | 提示 | `attackerstate/predictor/engagement/defensecycle`（ACL 四包） | 默认-on 无 tag，仅被 expr/tracecheck 工具 cmd 引用 | 与"可选/扩展模块"叙述不一致；cli 既是 kernel 默认插件又是 agent 辅助库——C1 根因 |

## 三、验证过的正面项（防误报）

- **securemode**：仅依赖 stdlib + `golang.org/x/crypto/argon2`，零 kernel/模块依赖——模块解耦的正面范例（agent 与 kernel 各自消费其 API）。
- **internal/engine/ssam|srd|prism**：无 kernel 依赖（纯 SSAM/SRD 适配）——引擎与框架解耦干净。
- **模块间交叉依赖**（spc→attck、policy→cti 等）不存在。
- 无包级 import 环（union 图 SCC 均 = 1）。

## 四、收敛建议（最小攻击面，按优先级）

1. **拆 `internal/cli` 为 leaf 安装库 + kernel CLI 引擎**（C1）：把 `agent_linux.go` 的 Install/Uninstall/Upgrade 移入独立小包（如 `internal/install`，纯文件/systemd 操作），cmd/agent 改依赖之 → agent 编译图立即脱离 kernel；cli 保留 kernel 插件职责。改动小、纯新增包 + 改 import。
2. **kernel 内 AdapterIntegrationModule tag 化**（C2）：将 adapter_integration.go 拆出或加 `//go:build adapter`（与 internal/adapter 对齐），消除 kernel 默认对 adapter 实现的硬依赖。
3. **srdwrapper guard 修复合取**（F2）：`//go:build srdwrapper && engine`，或把 srdwrapper 归入 engine 依赖族并在装配层联合启用。
4. **模块半启用告警**（F3）：cmd/kernel 启动时校验"已启用模块的硬依赖模块 tag 是否也在"（如 assessor→integrity、comms→resilience），缺失则 log.Warn/fail-fast，消除静默降级。
5. **长期**：oscal/semver/adapterhub 归属归档（F5）；config→checks 依赖显式化（F6）；ACL 四包加 tag 与 optional 叙述对齐（F7）。

## 五、审计边界

- 基于静态依赖图 + 构建矩阵 + 符号验证，未做运行时行为探针；"静默降级"影响经代码路径（no-op stub）推断。
- 全部发现仅归档，不修改代码；若需执行 C1–F2 修复，建议按上文优先级逐个进行并配测试。
