# ASSCOR 多算法并行评估与多方式并行探测能力专项审计

**日期**: 2026-07-17 | **版本**: v0.2.1 | **审计范围**: engine/assessor, kernel/assessor, checks/linux, adapter, model

---

## 执行摘要

对 ASSCOR 的两项核心并行能力进行了完整代码级审计。结论：两个维度均**不架构级支持并行执行**。

| 能力 | 现状 | 设计模式 | 并行度 |
|------|------|----------|--------|
| 多算法并行评估 | ❌ 不支持 | 串行回退（either/or） | 0 |
| 同检查项多方式探测 | ❌ 不支持 | 替代模型（adapter→built-in） | 1→1 |

---

## 一、多算法并行评估能力

### 1.1 当前架构

```
Assess() 执行流:
  runAdapterPipeline → runChecksConcurrently → computeSPCScore
  → tryPluginScore()
      ├─ 成功 → return (legacy 永不执行)
      └─ 失败/nil → runLegacyScoring()
  → applyATTACK → 返回 FinalScore

并行 Prism（旁路）:
  applyPrismToResult() → AssessmentResult.PrismScore (独立字段，永不合并)
```

### 1.2 核心分发逻辑 (`engine/assessor.go:770`)

```go
func (a *Assessor) tryPluginScore(ctx, result) bool {
    if a.pluginEngine == nil { return false }
    if err := a.pluginEngine.ComputeScore(ctx, result); err != nil {
        return false   // ← SSAM 失败 → 静默回退至 legacy
    }
    return true        // ← SSAM 成功 → legacy 完全跳过
}
```

**关键发现**：
- 只有一个 `pluginEngine` 字段（`SetPluginEngine()` 只能设置一个实现）
- `tryPluginScore()` 返回 `bool`，不是比较两个结果
- 不存在 goroutine 级别的并行调度
- 不存在 `FinalScore = max(SSAM, legacy)` 之类的择优逻辑
- `trySSAMScore()` 在全代码库中**不存在** — SSAM 通过通用的 `tryPluginScore()` 机制挂载

### 1.3 评分引擎选择

| 场景 | 引擎 | 触发条件 |
|------|------|---------|
| `config.ini` 中 `scoring_engine = "legacy"` (或空) | 内置 legacy | `pluginEngine == nil` |
| `config.ini` 中未指定 `scoring_engine` | SSAM 2.0 | `SetPluginEngine(ssamAdapter)` |
| SSAM 运行时错误 | 内置 legacy | `ComputeScore()` 返回 error → fallthrough |

`cmd/kernel/main.go:217` 在启动时一次性决定，不支持运行时热切换：
```go
if cfg.ScoringEngine != "legacy" {
    ssamAdapter := ssam.NewEngineAdapter(cfg)
    scoringEngine.SetPluginEngine(ssamAdapter)
}
```

### 1.4 Prism 的"并行"地位

Prism 引擎被调用在 `applyPrismToResult()` 中（`kernel/assessor.go`），产生独立的 `PrismScore` 字段：
```
result.FinalScore  ← SSAM 或 legacy（二选一）
result.PrismScore  ← Prism（始终计算，独立字段）
```

两者从不合并。日志同时输出："ssam_score" 和 "prism_score"。Prism 是一个**正交覆盖层**，不是竞争算法。

### 1.5 能力评估

| 维度 | 现状 | 差距 |
|------|------|------|
| 单次评估多引擎并行 | ❌ | 需要 goroutine fan-out + 聚合器 |
| 多引擎结果择优 | ❌ | 需要比较器 + 置信度权重 |
| 引擎热切换 | ❌ | `SetPluginEngine` 在 `Init` 时调用一次 |
| SSAM 禁用回退 | ✅ | legacy fallback 工作正常 |
| Prism 并行覆盖 | ⚠️ | 并行但独立，不参与 FinalScore |

---

## 二、同检查项多方式并行探测能力

### 2.1 当前架构

```
┌─ Adapter Pipeline ──► findings[] ──► 委托规则(CheckID) ──► delegatedIDs set
│                                                                   │
│                                                    ┌──────────────┘
│                                                    ▼ (替换，非合并)
├─ checks.GetAll() ──► filter(delegatedIDs) ──► runChecksConcurrently()
│      (内置)                                           │
│                                                       ▼
└─ [user_check.*] ──► Register(CheckItem) ──► 并入 checks.GetAll()
                                                       │
                                                       ▼
                                              result.Checks[] (flat list)
```

### 2.2 数据模型限制 (`model/model.go:19,38`)

```go
type CheckFunc func() (passed bool, detail string)  // 单个闭包，单一结果

type CheckItem struct {
    Check     CheckFunc     // 只有一个函数——不能声明多个探测策略
    Privilege PrivilegeLevel // 已定义但引擎层从未使用（PrivRoot 检查只在 Agent 端生效）
}
```

**根本限制**：`CheckItem` 只持有一个 `CheckFunc`，框架不支持声明式多策略。

### 2.3 适配器→内置检查的替代模型

委托规则 (`adapter/delegation.go`) 定义了明确的**替换关系**：

| 适配器 | 替代的内置 CheckID |
|--------|-------------------|
| trivy | KS-001, AS-005 |
| nuclei | AS-006, AS-005 |
| lynis | OT-001, KS-001, OT-099 |
| openscap | OT-001 |
| suricata | RS-006, AS-006 |

`buildDelegatedSet()` 在评估前收集所有适配器的委托 CheckID，然后在执行内置检查时**跳过**这些 ID。同一个 CheckID 从不出现在两个来源中。

### 2.4 用户检查的互斥限制 (`config/user_check_registry.go:88-124`)

```go
if e.command != "" {
    // 命令方式
} else if e.filePath != "" {
    // 文件方式
}
// else if 强制互斥 — 不能同时使用
```

一个用户检查只能使用**命令模式**或**文件模式**，不可兼得。

### 2.5 内置检查中的 ad-hoc 多方式组合

约 30% 的 Linux 内置检查**在单个闭包内**组合多种探测方法，但完全是手工序列化的：

| Check ID | 组合方式 | 合并策略 |
|----------|---------|---------|
| AS-004 | `iptables -L` → 失败 → `firewall-cmd --state` | 短路：首个成功即通过 |
| AS-006 | `systemctl is-active` + `ss -tlnp` | 并行收集 issue，列表去重 |
| AS-007 | `systemctl` + `os.ReadFile`(PAM配置) | 所有路径并行检查 |
| OT-005 | `getenforce` → 失败 → `aa-status` | SELinux/AppArmor 互斥回退 |
| RS-006 | `systemctl is-active` → `ps -eo comm` | 多工具方法盲检测 |
| OT-014 | `lsblk` + `mount` + `/etc/crypttab` | 三方式合成加密状态 |

所有结果最终坍塌为 `(bool, string)` —— 无结构化 per-method 证据、无置信度、无冲突日志。

### 2.6 多适配器未去重的潜在风险

当多个适配器将 findings 映射到同一 CheckID 时（如 trivy 和 lynis 都委托 KS-001），两者都会在 `result.Checks` 中产生独立的 `CheckResult` 条目。每个条目的 `Delta` 独立累加到领域总分中。这意味着**同一个概念性检查可能被多次扣分**——目前没有去重或调和机制。

### 2.7 能力评估

| 维度 | 现状 | 差距 |
|------|------|------|
| 单 CheckItem 多 CheckFunc | ❌ | 需改为 `[]CheckFunc` 或策略列表 |
| 适配器+内置检查合并 | ❌ | 需将"替换"模型改为"增强"模型 |
| 用户检查命令+文件组合 | ❌ | `else if` 需改为独立条件 |
| 闭包内 ad-hoc 多方式 | ⚠️ | 可用但不规范，无框架支持 |
| 多适配器同 CheckID 去重 | ❌ | 缺乏调和逻辑 |
| 结构化多源证据 | ❌ | `CheckResult` 无双源字段 |

---

## 三、架构建议（不立即修复）

以下为可选的架构演进方向，供后续设计参考：

### 3.1 多算法并行评估

- `pluginEngine` 改为 `[]AssessorEngine`，支持注册多个评分引擎
- `tryPluginScore()` 改为 `runPluginScores()`，goroutine 并发执行所有引擎
- 新增 `ScoreAggregator` 接口：`Aggregate(scores []EngineScore) FinalScore`
- Prism 可与 SSAM 一同注入 `pluginEngines` 列表，参与统一比较
- 保留 `--scoring-engine=legacy` 回退路径

### 3.2 多方式并行探测

- `CheckItem.Check` 从 `CheckFunc` 改为 `[]CheckFunc`，每个策略独立执行
- 每个 `CheckFunc` 包装为 `CheckMethod{Name, Func}`，输出携带来源标记
- `CheckResult` 新增 `Methods []MethodResult` 字段，存储 per-method 证据
- 委托规则添加 `mode: replace | augment`，`augment` 模式下适配器不抑制内置检查
- 用户检查配置语法支持 `command` + `file_path` 同时声明

### 3.3 最小改动切入点

- **低风险**：将 `PrivilegeLevel` 用于引擎层预过滤（当前仅在 Agent 端生效）
- **低风险**：添加 `assessor.engine_selected` 扩展点，暴露当前使用的引擎信息
- **中风险**：在 `buildDelegatedSet` 中添加去重，防止同 CheckID 多适配器累加扣分
- **中风险**：用户检查 `else if` 改为两个独立 `if` 块，允许命令+文件共存

---

## 四、审计结论

ASSCOR 当前在"多算法"和"多方式"两个维度均采用**序列化单一胜者**模型：

- **评分引擎**：SSAM 或 legacy 二选一，失败回退，无比较无合并
- **探测方法**：适配器**替换**内置检查，而非增强；同检查项不支持多源证据合并

这两项能力在框架层面是**有意为之的单路设计**，而非实现缺陷。对于绝大多数合规评估场景，单一评分引擎和单一探测方式已足够。如需并行多路能力，建议按 §3 的架构方向进行语义层重构。

---
*审计完成于 2026-07-17T01:11+08:00。仅审计，不立即修复。*
