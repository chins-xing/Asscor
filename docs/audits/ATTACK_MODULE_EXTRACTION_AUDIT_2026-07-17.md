# ATT&CK 模块分离为扩展包可行性审计

**日期**: 2026-07-17 | **版本**: v0.2.1 | **审计范围**: `internal/kernel/attck*.go` (13 文件, 7,115 LOC)

---

## 执行摘要

| 维度 | 评级 | 关键因素 |
|------|:----:|---------|
| **整体难度** | **中等** | 代码耦合极低，但 Go `internal/` 可见性规则是最大障碍 |
| **同模块策略** | **低-中** | 文件物理移动 + 管线接口适配 + build tag 注册 (~2-3天) |
| **独立模块策略** | **高** | 需要创建公共 SDK 层重导 11 个内部包类型 (~1-2周) |

---

## 一、代码耦合分析

### 1.1 导入依赖 (零外部库)

| 内部依赖 | 使用文件数 | 用途 |
|----------|:---------:|------|
| `internal/logger` | 10/12 | 日志 |
| `internal/model` | 1/12 | `model.AssessmentResult` (`attck.go:423`) |
| `internal/config` | 1/12 | `config.Config` (`attck.go:213`) |

**关键发现**: ATT&CK 模块的 7,115 行代码仅引用 3 个内部包，其他 9 个文件完全自包含。零外部库依赖。

### 1.2 内核服务使用 (31 处，全部通过接口)

| 服务 | 使用次数 | 接口类型 |
|------|:-------:|---------|
| Event Bus Publish | 11 | `m.kernel.Bus()` — 已有接口 |
| Event Bus Subscribe | 2 | `m.kernel.Bus()` |
| 扩展点 Execute | 17 | `m.kernel.Extensions()` — 已有接口 |
| DI 容器 | 2 | `m.kernel.Container()` |
| Config | 2 | `kc.GetConfigObj()` |
| Context | 多处 | `m.kernel.Context()` |

所有访问通过 `KernelContext` 接口 — 无具体 `*Kernel` 引用。

### 1.3 下游消费方

| 消费方 | 文件 | 使用方式 | 解耦难度 |
|--------|------|---------|:----:|
| **评估管线** | `assessor.go:589-711` | `applyATTACK()` — 覆盖率/杀伤链/APT/风险预测 | 中 |
| **CLI 命令** | `commands.go:834-1058` | `attck` 命令 — 6 个子命令 | 低 |
| **内核注册** | `main.go:238,244` | 插件列表静态注册 | 低 |
| **独立 CLI** | `cmd/asscor/main.go:79-163` | `attackAdapter` 适配器 | 低 |
| **gRPC 服务** | `services.go:237-241` | `model.ATTACK*Info` DTO 转换 | 不需要改 |

### 1.4 数据模型耦合

`attck_model.go` (36 类型) 中 **仅 4 个** 被非 ATT&CK 代码使用：
- `ATTACKCoverage` — 评估管线和 CLI
- `KillChainAssessment` — 评估管线和 CLI
- `APTGroupProfile` — CLI
- `DetectionSummary` — CLI

其余 32+ 类型完全模块内部使用。

### 1.5 接口提取可行性

`ATTACKInterface` (~90 方法, 8 个子接口) 中仅约 **10 个方法** 跨越模块边界。`engine.ATTACKProvider` (5 方法) 已提供引擎层抽象的前例。

### 1.6 扩展点与事件总线

13 个扩展点 + 11 个总线话题。全部可保留在核心框架中（字符串契约），模块移除后 `Execute` 无订阅者为空操作。

---

## 二、Go `internal/` 规则影响

这是**唯一的高难度因素**。

| 策略 | Go module 边界 | 复杂度 | 说明 |
|------|:---:|:---:|------|
| **同模块** | 无独立 go.mod | 低 | 文件移至 `optional/` 但保留在 `github.com/asscor/asscor` 模块下 — `internal/*` 可正常 import |
| **独立模块** | 独立 go.mod | 高 | 需创建 `pkg/sdk/` 公共层导出 `KernelContext`/`Bus`/`Message`/`ModuleExtensions`/`Plugin`/`PluginState` + logger facade + config 类型 (~400-600 LOC 新代码) |

**推荐同模块策略**: 与现有 `multi-algo-orchestrator` 一样保留在同一个 Go module 中，通过 build tag 或运行时注册控制启用。

---

## 三、推荐提取路线

### Phase 0: 合约硬化 (1 天, 不移动任何文件)

1. `engine.ATTACKProvider` 新增 `IsEnabled()` 方法, 补齐为 6 方法接口
2. 重写 `assessor.go:589-711` 的 `applyATTACK()` — 通过 DI 容器 Resolve `engine.ATTACKProvider` 而非直接 cast `ATTCKCore`
3. CLI 处理函数 (`commands.go:901/928/956/991`) 将具体类型返回改为 DTO/map
4. 验证内核在 ATT&CK 未注册时正常降级 (已有降级路径)

### Phase 1: 物理移动 (1 天)

1. 13 个 `attck*.go` 文件移至 `optional/algorithms/packages/attck-ext-pack/` (同模块, 无独立 go.mod)
2. 包名设为 `attckext`
3. 创建 `package.json` 声明模块和 13 个扩展点钩子
4. 在 `cmd/kernel/main.go` 中通过 `cfg.ATTACK.Enabled` 或 build tag `//go:build attck_ext` 控制注册
5. 迁移 1,004 行测试文件

### Phase 2 (可选, 后续): 独立模块隔离

仅在需要外部分发时执行: 创建 `pkg/sdk` 公共层, 重新导出内核类型, 给扩展包独立 go.mod。当前**不推荐**, 投入产出比低。

---

## 四、难度矩阵

| 变更 | 复杂度 | 文件数 | 估时 |
|------|:---:|:---:|:---:|
| 文件物理移动 (13 文件) | 低 | 13 移动 | 0.5h |
| package.json + README | 低 | 2 新建 | 0.5h |
| 移除静态注册, 改为 build tag/条件注册 | 低 | 1 修改 | 0.5h |
| `engine.ATTACKProvider` 补齐 `IsEnabled()` | 低 | 1 修改 | 0.3h |
| 评估管线 `applyATTACK` 改为接口注入 | 中 | 1 修改 (~120行) | 2h |
| CLI 处理器类型解耦 | 中 | 1 修改 (~60行) | 1.5h |
| `attackAdapter` 移至扩展包 | 中 | 1 移动 (~90行) | 0.5h |
| test 文件迁移 + 回归验证 | 中 | 1 移动 | 1h |
| **同模块策略合计** | **整体中等** | **~22 文件** | **~2-3 天** |
| 公共 SDK 层创建 (独立模块附加成本) | **高** | 8-10 新建 (~500行) | **+1周** |

---

## 五、不变量保护

以下内容在分离后保持不变（字符串/DTO 契约）:

- 13 个扩展点名称 (`platform_extensions.go:33-80`)
- 13 个总线话题常量 (`attck.analysis.complete`, `apt.threat.matched`, ...)
- `TopicAssessorResult` 订阅合约
- `[attack]` 配置段 (`config.go:502-516`)
- `model.ATTACK*Info` DTO (`services.go:237-241` 仍使用)

---

## 六、审计结论

ATT&CK 模块是 ASSCOR 内核中**最适合分离为扩展包的模块**:

1. **代码耦合极低**: 仅依赖 3 个内部包, 0 个外部库
2. **接口已抽象**: `engine.ATTACKProvider` 和 `SPCProvider` 前例已证明引擎层解耦可行
3. **降级路径已存在**: 评估管线和 CLI 都已有 graceful degradation
4. **合同已解耦**: 扩展点名称和总线话题是字符串契约, 与模块位置无关
5. **唯一障碍**: Go `internal/` 规则在独立 module 场景下需要 SDK 层

推荐 Phase 0 + Phase 1 同模块策略, 2-3 天完成。独立 module 的 SDK 层推迟到有外部分发需求时再实施。

---
*审计完成于 2026-07-17T03:00+08:00。仅审计，不立即修复。*
