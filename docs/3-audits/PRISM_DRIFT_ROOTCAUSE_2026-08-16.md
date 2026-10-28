# PRISM 自变根因分析 — 同一评估快照为何 PRISM 分数变化

**日期**: 2026-08-16 | **版本**: v0.2.3 | **性质**: 根因定位（E1 确定性实验的深入调查）

## 一、现象

E1 实验（Assessment 正确性）发现：同一主机、同一检查项结果（SSAM 分数恒 58.27），连续评估时 **PRISM 分数单调漂移**（43.55 → 43.45）。

## 二、根因

### 机制链

PRISM Core 层债务模型（`prism-lib/core.go` `computeDebtRaw`）：

```
debtRaw      = Σ |delta| × ((nowUnix − fail_at) / 86400)^1.2
debtPenalty  = min(0.3, debtRaw / 1500)
prismScore   = SSAM × (1−propPenalty) × (1−debtPenalty) × (1−collapseMod)
```

- **`fail_at` = 检查项首次失败时间**（`internal/assessor/assessor.go` `updateFailTracker`：首次失败记录 `nowUnix`，PASS 才清除；存于 kernel 内存 map `failTracker[hostID][checkID]`）
- **`nowUnix` = 每次评估时刻**（`applyPrismToResult` 传入）

→ 时间每推进，`elapsedDays` 增长 → `debtRaw` 以 **^1.2 非线性增长** → 债务惩罚增长 → PRISM 分数单调下降。

### 实测验证（host1，同一快照，SSAM 恒 58.27）

| 评估时刻 | prism_score | debt_raw | debt_penalty | fail_at |
|---|---|---|---|---|
| 04:41:26 | 58.27 | 0 | 0 | 1786855286 |
| 04:42:31 | 43.70 | 0.08 | 0.0001 | 1786855286 |
| 04:45:35 | 43.69 | 0.40 | 0.0003 | 1786855286 |
| 04:54:30 | 43.66 | 1.57 | 0.001 | 1786855286 |
| 04:59:30 | 43.63 | 2.32 | 0.0015 | 1786855286 |

`fail_at` 恒定、`debt_raw` 单调增、`prism` 单调降——完全对应。

## 三、判定

**设计行为，非随机/非错误**：债务 = 失败检查 × 失败持续时长——"长期未修复的失败比刚发生的更危险"，时间衰减是 PRISM 的有意语义（`debt_norm_days=1500` 归一化）。

**三个副作用**（"快照自变"的来源）：

| # | 副作用 | 说明 |
|:-:|--------|------|
| 1 | 非纯函数 | PRISM 依赖（快照 + fail_at 历史 + 评估时刻 + 拓扑累积），同一快照不同时刻结果不同 |
| 2 | kernel 重启跳变 | `failTracker` 为内存态，重启清空 → fail_at 重置 → debt 归零 → PRISM 分数跳变（重启前后不一致） |
| 3 | 风险记忆不持久化 | fail_at 历史丢失，与身份绑定/评估 jsonl 的持久化设计不一致 |

## 四、改进方向（按产品意图取舍）

| 方案 | 效果 | 代价 |
|------|------|------|
| **a. failTracker 持久化**（推荐） | 重启保持债务历史，消除跳变；保留时间衰减语义 | 新增 `<data_dir>/fail_tracker.json` 持久化（0600，temp+rename，同 identity 模式） |
| b. 快照时间戳计算 debt | 同快照同结果（纯函数） | 失去"失败持续时长"风险语义 |
| c. 维持现状 | 保留债务模型 | 快照确定性不成立，需文档明确 |

**推荐 a**：与 ASSCOR 现有持久化一致性设计（身份绑定、评估 jsonl 均已持久化）对齐；保留 PRISM 时间衰减的安全语义；消除"同一快照 PRISM 自变"的观测困惑（重启场景）。

## 五、与拓扑审计的关系

PRISM 分数还受**传播惩罚**影响（`propPenalty = min(0.25, propagatedRisk)`）——传播边由拓扑注册顺序累积（T11 发现：edges 0→7 时 PRISM 58.27→43.7）。M1 已修复拓扑生命周期（超时注销）与网段过滤，传播边稳定性改善后，PRISM 漂移的主要剩余来源即本文档的债务时间衰减。
