# ATT&CK 模块分离为扩展包 — 实施计划

**日期**: 2026-07-17 | **版本**: v0.2.1 | **基于**: `docs/audits/ATTACK_MODULE_EXTRACTION_AUDIT_2026-07-17.md`

---

## 目标

将 ATT&CK 模块（7,115 LOC，13 文件）从 `internal/kernel/` 移至 `optional/algorithms/packages/attck-ext-pack/`，作为可选编译扩展包。核心框架在模块缺失时保持正常降级运行。

---

## 策略

采用**同模块 + build tag** 策略：
- ATT&CK 文件保留在 `github.com/asscor/asscor` 模块下（无独立 go.mod）
- 通过 `//go:build attck_ext` 编译标签控制是否包含
- `package.json` 声明扩展包元信息
- 核心框架通过 `engine.ATTACKProvider` 接口注入（已存在，需补齐）

---

## Phase 0: 合约硬化（1 天）

本阶段不移动任何文件，只修改核心框架使其准备好接受 ATT&CK 作为可注入组件。

### 任务 0.1: 补齐 `engine.ATTACKProvider` 接口

**文件**: `internal/engine/assessor.go`

当前 `ATTACKProvider` 仅有 5 个方法，缺少 `IsEnabled()` 和能力查询：

```go
// 在 line 42 后追加:
type ATTACKProvider interface {
    // existing:
    CalculateCoverage(checkResults map[string]bool) []ATTACKCoverageResult
    AssessKillChain(hostID string, checkResults map[string]bool) ATTACKKillChainResult
    MatchAPTGroup(detectedTechniques []string) []ATTACKAPTMatch
    PredictRisk(hostID string, detectedTechniques []string, maxDepth int) ATTACKPredictedRisk
    GetAllTactics() []ATTACKTacticInfo
    // new (v0.2.1+):
    IsEnabled() bool   // allows runtime check before invoking pipeline methods
    Version() string   // identifies the loaded ATT&CK module version
}
```

**影响**: 低 — 新增 2 个方法签名，所有现有 ATT&CK 模块实现都已有 `IsEnabled()` 和 `Version()`。

### 任务 0.2: 重写 `kernel/assessor.go` 的 `applyATTACK`

**文件**: `internal/kernel/assessor.go` (lines 589-711)

当前通过 DI 容器解析 `ATTACKInterface` → cast `ATTCKCore`。需改为通过 `engine.ATTACKProvider` 接口注入：

```go
// 替换 line 590-598:
// OLD: impl, ok := m.kernel.Container().Resolve((*ATTACKInterface)(nil))
//      attck, ok2 := impl.(ATTCKCore)
// NEW:
attck := m.attackProvider  // ← 新增字段，通过 SetATTACKProvider() 注入
if attck == nil || !attck.IsEnabled() {
    return
}
```

将 lines 607/624/653/675/693 的 ATT&CK 方法调用从：
- `attck.CalculateCoverage(...)` → 返回 `[]ATTACKCoverage` (kernel 包类型)
- `attck.AssessKillChain(...)` → 返回 `KillChainAssessment` (kernel 包类型)

改为返回 engine 包的中性 DTO：
- `attck.CalculateCoverage(...)` → 返回 `[]engine.ATTACKCoverageResult`
- `attck.AssessKillChain(...)` → 返回 `engine.ATTACKKillChainResult`

**影响**: 中 — 移除 DI cast，改用全注入接口。120 行适配。`assessor.go` 不再 import ATT&CK 具体类型。

### 任务 0.3: 解耦 CLI 指令处理器

**文件**: `internal/cli/commands.go` (lines 834-1058)

当前通过 `GetPlugin("attck")` 获取插件后用 duck-type 接口断言，接口签名引用 `kernel.*` 类型。需将 4 个 kernel 类型引用替换为 engine DTO：

| 行 | 当前类型 | 替换为 |
|----|---------|--------|
| 901 | `[]kernel.ATTACKCoverage` | `[]engine.ATTACKCoverageResult` |
| 928 | `kernel.KillChainAssessment` | `engine.ATTACKKillChainResult` |
| 956 | `*kernel.APTGroupProfile` | `engine.ATTACKAPTMatch` (聚合) |
| 991 | `kernel.DetectionSummary` | 保留 `map[string]interface{}` 返回 |

**影响**: 低 — 局部接口签名变更，60 行适配。CLI 不再 import ATT&CK 具体 kernel 类型。

### 任务 0.4: 确保降级路径完整

验证:
1. `assessor.go:591-592` 的 `return` 降级 — 当 ATT&CK 未注入或 `IsEnabled()==false` 时正常跳过
2. `commands.go:845-847` 的 CLI 降级 — 当 `GetPlugin("attck")` 返回 nil 时提示 "ATT&CK module is not loaded"
3. `cmd/asscor/main.go:186` 的 `cfg.ATTACK.Enabled` 条件 — standalone 评估时可选启用

---

## Phase 1: 物理移动（1 天）

### 任务 1.1: 创建扩展包目录结构

```
optional/algorithms/packages/attck-ext-pack/
├── package.json              # 扩展包清单
├── README.md                 # 使用文档
├── attck.go                  # 核心模块 (1651 → 1349 行，默认数据已提取)
├── attck_model.go            # 36 个数据模型类型
├── attck_defaults.go         # 默认矩阵 + APT 配置 (300 行)
├── attck_detection.go        # 检测子模块
├── attck_ti.go               # 威胁情报子模块
├── attck_emulation.go        # 对手仿真子模块
├── attck_assessment.go       # 评估子模块
├── attck_apt_chain.go        # APT 攻击链重构
├── attck_apt_detect.go       # APT 行为检测
├── attck_apt_attribution.go  # APT 归因引擎
├── attck_apt_hunt.go         # APT 威胁狩猎
├── attck_apt_enhanced.go     # APT 增强分析
├── attck_apt_causal.go       # APT 因果推断
├── attck_test.go             # 1004 行测试 (迁移)
└── adapters/
    └── attack_adapter.go     # attackAdapter (从 cmd/asscor/main.go 移入)
```

### 任务 1.2: 修改包名

将 12 个源文件（不含测试）的 `package kernel` 改为 `package attckext`。需要在每个文件头部替换。

### 任务 1.3: 调整 imports

移入 `internal/kernel` 中需要的类型:
- `Plugin` interface
- `PluginInfo`, `PluginDependency`, `PluginState`
- `KernelContext`
- `Message`, `TopicAssessorResult` 等总线常量
- 扩展点注册

移除不再需要的 import: `internal/config` → 通过 `KernelContext.GetConfigObj()` 已可获取

### 任务 1.4: 注册与启用控制

**方式 A: build tag (推荐)**

```go
//go:build attck_ext

package attckext
```

在 `cmd/kernel/main.go` 中:
```go
//go:build attck_ext
import "github.com/asscor/asscor/optional/algorithms/packages/attck-ext-pack"

func registerATTACK(plugins []kernel.Plugin) []kernel.Plugin {
    attck := attckext.NewATTACKModule()
    // ... configure ...
    return append(plugins, attck)
}
```

编译时添加: `go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/`

**方式 B: 配置驱动**

在 `config.ini` 中:
```ini
[optional.attck_ext]
enabled = true
```

在 `cmd/kernel/main.go` 中运行时判断 `cfg.OptionalModules["attck_ext"]`。

### 任务 1.5: 创建 package.json

```json
{
  "name": "attck-ext-pack",
  "version": "1.0.0",
  "description": "ATT&CK V19 威胁分析扩展包 - 检测分析/威胁情报/对手仿真/评估工程/APT归因/威胁狩猎",
  "author": "ASSCOR Core Team",
  "compatibility": { "asscor_version": ">=0.2.1", "go_version": ">=1.26", "platform": ["linux"] },
  "modules": [
    { "id": "attck-ext-pack", "path": ".", "type": "pack" }
  ],
  "hooks": {
    "assessor.pre_score": "attck-ext-pack"
  },
  "compatibility": {
    "asscor_version": ">=0.2.1",
    "go_version": ">=1.26"
  }
}
```

### 任务 1.6: 清理核心框架

从 `internal/kernel/` 中删除 13 个 attck*.go 文件，从 `cmd/kernel/main.go` 中移除 `kernel.NewATTACKModule()` 静态注册。

**保留在 kernel 中的内容**:
- 13 个扩展点名称注册 (`platform_extensions.go:33-80`) — 字符串合同
- 11 个总线话题常量 (`plugin.go`) — 字符串合同
- `TopicAssessorResult` 订阅合约 — 字符串合同
- `[attack]` 配置段解析 (`config.go:502-516`) — 配置驱动扩展包启用
- `model.ATTACK*Info` DTO (5 类型) — 持久化输出格式

### 任务 1.7: 迁移测试

将 `attck_test.go` (1004 行) 移入扩展包，调整包名和 import。验证:
- `go test ./optional/algorithms/packages/attck-ext-pack/` 通过
- `go test ./internal/kernel/ -run "TestHeartbeat|TestAssessor"` 通过 (核心评估管线)

### 任务 1.8: 回归验证

```bash
# 普通编译 (不包含 ATT&CK)
go build -o ASSCOR-kernel-linux ./cmd/kernel/
# → 应成功编译，评估管线降级

# 带 ATT&CK 编译
go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/
# → 应成功编译，评估管线使用 ATT&CK 分析

# 全量测试
go test ./internal/kernel/ ./internal/engine/ ./internal/cli/ ./optional/.../
# → 全部通过
```

---

## Phase 2: 运行验证 (预留, 0.5 天)

1. 在开发环境启动无 ATT&CK 的内核，验证 CLI `attck` 命令提示 "module not loaded"
2. 发起一次 Agent 心跳评估，验证评分不受影响 (ATT&CK 覆盖率/杀伤链字段为空)
3. 以 build tag 重新编译后启动，验证 ATT&CK 分析正常
4. 验证 WebUI 仪表盘正常展示

---

## 工作量估算

| 阶段 | 任务 | 文件 | 估时 |
|------|------|:---:|:---:|
| Phase 0.1 | 补齐 `ATTACKProvider.IsEnabled/Version` | 1 修改 | 0.3h |
| Phase 0.2 | 重写 kernel `applyATTACK` | 1 修改 (~120行) | 2h |
| Phase 0.3 | 解耦 CLI | 1 修改 (~60行) | 1.5h |
| Phase 1.1 | 创建目录 + package.json + README | 3 新建 | 0.5h |
| Phase 1.2 | 修改包名 (12 文件) | 12 修改 | 0.3h |
| Phase 1.3 | 调整 imports | 12 修改 | 1h |
| Phase 1.4 | build tag 注册 | 2 修改 | 0.5h |
| Phase 1.5 | package.json 创建 | 1 新建 | 0.1h |
| Phase 1.6 | 清理核心框架 | 13 删除 + 1 修改 | 0.3h |
| Phase 1.7 | 迁移测试 + 回归 | 1 移动 + 2 测试 | 1.5h |
| Phase 2 | 运行验证 | — | 0.5h |
| **合计** | | **~35 文件** | **~8.5h (1.5 天)** |

---

## 风险与回滚

| 风险 | 概率 | 缓解措施 |
|------|:---:|---------|
| `assessor.go` DI 解耦引入 bug | 低 | Phase 0 在前，不移动文件即可独立测试 |
| CLI duck-type 接口遗漏 | 中 | Phase 0.3 在移动前完成，通过编译检查确保不遗漏 |
| build tag 配置错误 | 低 | CI 测试矩阵：`go test -tags attck_ext` + `go test` 双线 |
| 扩展点名称拼错 | 低 | 字符串批量替换，不改名称 |
| 测试回归失败 | 低-中 | Phase 1.8 运行全量测试 |
| 紧急回滚 | — | `git revert` 一键恢复 |