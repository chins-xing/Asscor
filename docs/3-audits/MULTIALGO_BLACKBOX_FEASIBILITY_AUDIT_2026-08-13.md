# 多算法编排器 + 外挂黑盒模型 最小化白盒破坏 可行性审计

**日期**: 2026-08-13 | **版本**: v0.2.3 | **对象**: `optional/algorithms/modules/multi-algo-orchestrator/`

---

## 一、核心结论

**方案可行，但当前编排器存在一个关键缺陷：`RoleAdvisory` 角色已定义，但合并逻辑从未区分角色，导致黑盒模型挂载后必然破坏白盒属性。**

要实现"最小化破坏"，需新增 **`MergeWhiteboxFirst` 合并策略 + 置信度门控 + 角色感知合并** 三处改造。

---

## 二、关键发现：RoleAdvisory 是"死角色"

### 2.1 已定义但未使用

| 代码位置 | 现状 | 问题 |
|------|------|------|
| `orchestrator.go:48` | `RoleAdvisory` 已定义 | 本应表示"参考算法（黑盒）" |
| `orchestrator.go:325-344` | 合并逻辑把 primary/secondary/advisory **一视同仁**加入 scores | 黑盒分数污染白盒合并 |
| `orchestrator.go:367-399` | 5 种合并策略无一种区分角色 | 黑盒输出直接进入决策 |

### 2.2 破坏路径（逐策略评估）

| 合并策略 | 黑盒挂载后破坏程度 | 破坏机制 |
|------|:---:|------|
| `MergeBestOf` | 🟡 中 | 黑盒异常高分被取（高分通常安全，但虚高） |
| `MergeWorstOf` | 🔴 **大** | 黑盒异常低分直接拉低分数 → 破坏确定性 |
| `MergeWeightedAverage` | 🟡 中 | 黑盒 confidence 权重污染白盒加权 |
| `MergePrimaryOnly` | 🟢 零 | 只取白盒主算法，但丧失"多白盒合并" |
| `MergeConsensus` | 🔴 **大** | 离散度 >5 取最低 → 黑盒异常低分破坏 |

**关键矛盾**：`MergeWorstOf`（消除木桶效应的核心策略）在黑盒挂载后变成**最大的白盒破坏源**。

---

## 三、最小化破坏方案

### 3.1 新增 `MergeWhiteboxFirst` 策略

```go
// 语义: 只在白盒算法(primary/secondary)之间合并;
//       黑盒算法(advisory)完全不进入最终分数, 仅作为参考元数据
const MergeWhiteboxFirst MergeStrategy = "whitebox_first"
```

合并逻辑改造（`buildOrchestrationResult`）：
```
1. 分离白盒(primary/secondary)与黑盒(advisory)
2. 白盒之间按选定策略合并(WorstOf/Consensus/BestOf)
3. 黑盒输出仅记录在 OrchestrationResult.AdvisoryResults
4. 最终分数 = 白盒合并结果（黑盒零影响）
```

### 3.2 置信度门控

```go
// 黑盒输出必须附带 confidence, 低于阈值丢弃
type AlgorithmProfile struct {
    ...
    MinConfidence float64  // 黑盒输出的最低置信度门槛, 默认 0
}
```

黑盒输出 confidence < MinConfidence → 丢弃，不进入参考层。

### 3.3 角色感知合并

`buildOrchestrationResult` 需按 `ar.Role` 分类：
- `RolePrimary` + `RoleSecondary` → 白盒池，参与合并
- `RoleAdvisory` → 黑盒池，仅参考

---

## 四、对白盒属性的破坏面积评估

### 4.1 方案落地后的破坏面积

| 白盒属性 | 现状破坏面积 | 落地后破坏面积 |
|------|:---:|:---:|
| SSAM/Prism 确定性评分 | 🔴 大（黑盒污染合并） | 🟢 **零**（黑盒隔离到参考层） |
| 策略引擎确定性响应 | 🔴 大（分数被拉低→误判） | 🟢 零 |
| 审计可追溯性 | 🟡 中 | 🟢 零（黑盒仅附注） |
| HMAC 审计一致性 | 🟡 中 | 🟢 零 |

### 4.2 保留的能力

| 能力 | 是否保留 |
|------|:---:|
| 多白盒算法并行合并（消除木桶效应） | ✅ 保留（白盒池内仍可用 WorstOf） |
| 黑盒感知增强（预测/异常/拓扑） | ✅ 保留（作为 advisory 参考） |
| 单白盒退化路径 | ✅ 保留（无黑盒时退化为现有多白盒） |

---

## 五、可行性裁定

**可行，且是"最小化破坏"的最优解。**

| 维度 | 结论 |
|------|------|
| 可行性 | ✅ 编排器已有 Role 概念，只需补全角色感知合并 |
| 破坏面积 | 🟢 零（黑盒完全隔离到参考层，不进入决策链） |
| 改造量 | 🟢 小（~50 行：1 常量 + 1 合并分支 + 角色过滤） |
| 风险 | 🟡 需守住"黑盒永不进入 scores 列表"这条实现红线 |

### 改造清单

| # | 改造 | 位置 | 行数 |
|:--:|------|------|:---:|
| 1 | 新增 `MergeWhiteboxFirst` 常量 | orchestrator.go:64 | 1 |
| 2 | `buildOrchestrationResult` 角色过滤 | orchestrator.go:325 | ~20 |
| 3 | 新增 `MergeWhiteboxFirst` 合并分支 | orchestrator.go:397 | ~10 |
| 4 | `AlgorithmProfile.MinConfidence` 字段 | orchestrator.go:80 | 1 |
| 5 | 置信度门控过滤 | orchestrator.go:325 | ~5 |

---

## 六、与上一轮混合架构审计的关系

上一轮审计结论是"守住黑盒不直接驱动决策的红线"。本审计确认：**多算法编排器的 `RoleAdvisory` + 新增 `MergeWhiteboxFirst` 正是这条红线的工程实现**。

- 黑盒 = `RoleAdvisory` 角色 + 低置信度门控
- 白盒 = `RolePrimary`/`RoleSecondary` 角色 + 现有合并策略
- 仲裁 = `MergeWhiteboxFirst`（黑盒永不进入决策）

三者结合，实现了"黑盒作感知参考、白盒作决策主体"的最小破坏架构。

---
*审计完成于 2026-08-13T00:15+08:00。仅审计，不立即修复。*
