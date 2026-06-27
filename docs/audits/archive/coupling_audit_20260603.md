# ASSCOR 项目耦合度专项审计报告

## 基本信息
- 审计范围：`internal/` 目录下所有包
- 审计时间：2026-06-03
- 审计类型：耦合度专项审计

---

## 审计结论

**[有条件通过 ⚠️]** — 发现多处循环依赖和高耦合问题，需要逐步重构解耦

---

## 发现项

### [C-1] 循环依赖 — Critical

**位置**：`kernel` ↔ `engine` ↔ `adapter` ↔ `ssam` 形成环形依赖

**问题描述**：
```
kernel/adapter_integration.go → imports adapter, engine
kernel/assessor.go → imports engine, ssam, model
engine/assessor.go → imports adapter, ssam, model
adapter/adapter.go → imports model
ssam/engine.go → imports external ssam library (github.com/chins-xing/ssam)
```

**风险**：
1. 编译顺序敏感，任何一个包的变更可能触发级联编译错误
2. 无法独立测试各模块
3. 模块边界模糊，职责不清

**修复建议**：
- 方案 A（推荐）：引入接口抽象层，所有跨包调用通过 `*Interface` 接口进行
- 方案 B：将 `kernel` 与 `engine/adapter/ssam` 的公共部分提取到新包 `kernelcontracts`
- 方案 C：使用插件化架构，将 engine/adapter/ssam 改造为真正的外部插件

---

### [C-2] `model` 包过度中心化 — High

**位置**：30+ 个包直接导入 `internal/model`

**问题描述**：
`model` 包被以下包直接导入：
- kernel (9 处)
- engine (3 处)
- adapter (5 处)
- ssam (1 处)
- checks (2 处)
- agent (1 处)
- webui (2 处)
- config (1 处)
- extmgr (2 处)
- adapterhub (1 处)

**风险**：
1. `model` 包变更影响整个项目
2. 无法独立演进 model 和业务逻辑
3. 违反"稳定依赖原则"（Stable Dependencies Principle）

**修复建议**：
- 方案 A：提取 `model` 包为独立模块 `asscor/model`，定义清晰的接口
- 方案 B：按领域拆分 model（如 `assessmentmodel`、`scoringmodel`、`cvemodel`）
- 方案 C：使用 `wire` 或 `dig` 等编译时 DI 工具减少运行时耦合

---

### [C-3] `kernel` 包职责过重 — High

**位置**：`kernel/` 目录 60+ 文件

**问题描述**：
kernel 包承担了过多职责：
- 插件生命周期管理
- 事件总线（Bus）
- DI 容器
- gRPC 服务
- SPC CVE 数据
- ATT&CK 评估
- 持久化
- 配置监听
- 心跳检测
- 适配器集成

**风险**：
1. 违反单一职责原则
2. 无法独立测试和部署各子模块
3. 编译时间过长

**修复建议**：
- 方案 A：拆分为 `kernel/` + `kernel/bus/` + `kernel/di/` + `kernel/plugins/`
- 方案 B：将 SPC、ATT&CK、AdapterIntegration 移出 kernel，改造为独立插件
- 方案 C：引入插件化架构，kernel 只保留核心调度功能

---

### [C-4] 适配器直接依赖具体实现 — Medium

**位置**：`engine/adapter_import.go`

**问题描述**：
```go
import (
    _ "github.com/asscor/asscor/internal/adapter/management"
    _ "github.com/asscor/asscor/internal/adapter/scanner"
)
```
使用空白导入触发 `init()` 函数注册适配器，但 engine 包对 adapter 包的注册机制没有控制权。

**风险**：
1. 无法动态控制适配器加载
2. 无法独立测试单个适配器
3. 适配器故障可能影响 engine 启动

**修复建议**：
- 方案 A：通过配置驱动适配器加载，不使用空白导入
- 方案 B：使用 `plugin` 包实现真正的动态加载
- 方案 C：将适配器注册移到 kernel 的插件注册阶段

---

### [C-5] DI 容器反射注入风险 — Medium

**位置**：`kernel/di.go:78-143`

**问题描述**：
```go
func (c *Container) Inject(target interface{}) error {
    // 使用反射动态注入，运行时错误风险
    fieldVal.Set(reflect.ValueOf(impl))
}
```

**风险**：
1. 运行时错误而非编译时错误
2. 无法被 IDE/工具提前检测
3. 性能开销

**修复建议**：
- 方案 A（推荐）：使用编译时 DI 工具如 `wire`
- 方案 B：改为显式构造函数注入
- 方案 C：仅在测试代码中使用反射注入，生产代码使用显式注入

---

### [C-6] SSAM/Prism 外部库耦合 — Low

**位置**：`ssam/engine.go:9` 和 `prism/engine.go:6`

**问题描述**：
```go
ssam "github.com/chins-xing/ssam"
prismlib "github.com/chins-xing/prism"
```

**风险**：
1. 外部库变更直接影响系统行为
2. 无法在本地替换实现
3. 违反依赖倒置原则

**修复建议**：
- 方案 A：定义内部接口，将外部库包装为实现
- 方案 B：使用 `go mod replace` 指向本地 fork
- 方案 C：将 ssam/prism 源码直接引入项目作为子模块

---

## 统计

| 指标 | 数值 |
|------|------|
| 检测到的循环依赖路径 | 6 条 |
| model 包被导入次数 | 30+ |
| kernel 包文件数 | 60+ |
| DI 容器反射使用 | 1 处 |
| 外部库直接依赖 | 2 处 |

---

## 耦合度评分

| 维度 | 评分 (1-10) | 说明 |
|------|-------------|------|
| 循环依赖 | 3 | 存在 6 条循环依赖路径 |
| 中心化程度 | 4 | model 包过于中心化 |
| 接口抽象 | 6 | 部分使用接口但不够彻底 |
| 模块独立性 | 3 | kernel 过于臃肿 |
| 依赖方向 | 5 | 存在双向依赖 |

**综合评分：4.2 / 10** — 需要重构

---

## 建议优先级

| 优先级 | 问题 | 修复成本 |
|--------|------|---------|
| P0 | kernel ↔ engine ↔ adapter ↔ ssam 循环依赖 | 高 |
| P1 | model 包中心化 | 中 |
| P2 | kernel 职责过重 | 高 |
| P3 | 适配器直接导入 | 低 |
| P4 | DI 反射注入 | 中 |

---

## 最佳实践建议

1. **接口隔离**：所有跨包调用必须通过 `*Interface` 接口
2. **依赖单向**：确保依赖方向是单向的，不存在循环
3. **稳定依赖原则**：被依赖的包应该更稳定（更多接口，更少具体实现）
4. **插件化**：将非核心功能（adapter、spc、attck）改造为插件
5. **编译时 DI**：考虑使用 wire 等编译时 DI 工具
