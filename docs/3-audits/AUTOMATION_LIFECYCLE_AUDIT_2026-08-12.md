# ASSCOR 自动化全链路审计 — 新生命周期模型映射

**日期**: 2026-08-12 | **版本**: v0.2.3 | **范围**: 自动化安全运营全链路

---

## 一、新生命周期模型

用户定义的目标生命周期（10 阶段，含循环）：

```
探测 → 定位 → 响应 → 报告 → 阻断 → 修复 → 验证 → 定位 → 归档
  ↑                                                              │
  └──────── 重复（定位中仍存在攻击者活动信息）←──────────────────┘
```

对比旧模型（探测→响应→报告→修复→验证→归档），新增：
- **定位** (Locate) — 攻击者定位，出现在"响应前"与"验证后"两处
- **阻断** (Block) — 主动阻断（比"响应"更强，是隔离/封禁的执行层）
- **重复循环** — 攻击者活动持续时，从"定位"重新进入循环

---

## 二、总体结论

**当前代码是事件驱动，非显式状态机**。整条链由 `assessor.result` 一条总线消息驱动，无独立的"定位/阻断/重定位/循环"编排层。

| 生命周期阶段 | 自动化状态 | 扩展点 | 关键缺口 |
|------|:---:|:---:|------|
| 1. 探测 | ✅ 完整 | assessor.*/spc.*/engine.* | — |
| 2. 定位 | ⚠️ 部分 | attck.apt.* (归因/链重构/狩猎) | 无攻击者"位置"追踪 |
| 3. 响应 | ✅ 完整 | policy.action_decided/notify | — |
| 4. 报告 | ✅ 完整 | assessor.report_generated/siem.* | — |
| 5. 阻断 | ❌ **缺失** | 无 block.* | 调度断裂 + 动作不可执行 |
| 6. 修复 | ⚠️ 部分 | remediation.* | 动作是自由字符串 |
| 7. 验证 | ⚠️ 部分 | verify.* | 非独立阶段，嵌入评估 |
| 8. 定位(再次) | ❌ 缺失 | 无 | 靠下次心跳隐式重跑 |
| 9. 归档 | ✅ 完整 | archive.*/persistence.* | — |
| 循环 | ❌ **缺失** | 无 lifecycle.repeat | 无状态机 |

---

## 三、关键发现

### 3.1 定位 (Locate) — 是"归因"而非"定位"

| 能力 | 位置 | 说明 |
|------|------|------|
| 攻击链重构 | `attck_apt_chain.go:21` | 按战术排序 + 因果推理 |
| APT 归因 | `attck_apt_attribution.go:14` | TTP(60%) + IOC(40%) + 行业对齐 |
| 威胁狩猎 | `attck_apt_hunt.go:113` | 假设确认 |
| 行为/信标检测 | `attck_apt_detect.go:111/215` | 抖动分析、基线偏离 |

**限制**:
- 全部被 `//go:build attck_ext` 编译标签门控（非默认构建）
- 回答"是**谁**（哪个 APT）"，不回答"在**哪**（攻击者占据哪台主机/哪条路径）"
- 无攻击者网络位置追踪能力

### 3.2 阻断 (Block) — 双重硬伤

| 缺陷 | 位置 | 详情 |
|------|------|------|
| **调度断裂** | `commander.go:388-398` | `policy.go:153` 发布 `PolicyAction` 结构体，但 commander 断言 `map[string]interface{}` → 断言必失败 → 空命令 |
| **动作不可执行** | `common/exec.go:14-56` | `"isolate_host"` 不在 allowlist；无隔离原语 (iptables/firewall-cmd) |

### 3.3 重复循环 — 完全缺失

- `AcknowledgeAlert` (attck_detection.go:192) 和 `chain.Status: "active"` (attck_apt_chain.go:70) 字段存在
- 但**无任何代码读取这些状态来驱动循环**
- 唯一循环是心跳驱动的隐式重评估，无"活动持续→重复全链"逻辑

---

## 四、扩展点 → 新生命周期映射表

| 阶段 | 现有扩展点 | 状态 |
|------|------|:---:|
| 探测 | assessor.pre_evaluate/pre_score/post_evaluate/outbound, spc.*, engine.* | ✅ |
| 定位 | attck.coverage/detection.*/behavioral.*/apt.matched/chain_detected/attribution/hunt_confirmed | ⚠️ 缺 locate.completed |
| 响应 | policy.action_decided/notify/status_changed | ✅ |
| 报告 | assessor.report_generated, siem.*, engine.pre/post_report, attck.apt.report_generated | ✅ |
| 阻断 | — | ❌ 无 block.* |
| 修复 | remediation.pre_apply/post_apply/action_resolved | ⚠️ |
| 验证 | verify.pre_check/post_check/status_changed | ⚠️ 嵌入评估 |
| 定位(再次) | — | ❌ |
| 归档 | archive.pre_write/post_write/rotation, persistence.record_written | ✅ |
| 循环 | — | ❌ 无 lifecycle.repeat |

---

## 五、修复建议（按优先级）

| 优先级 | 修复 | 影响 |
|:---:|------|------|
| 1 | **阻断调度断裂** — `commander.go:388-398` 载荷断言改为 `PolicyAction` | 阻断/修复命令能真正下发 |
| 2 | **隔离原语** — Agent 为 `isolate_host` 添加 iptables/firewall-cmd 专用处理器 | 阻断可执行 |
| 3 | **循环编排层** — 新增状态机 + `lifecycle.phase_entered`/`lifecycle.repeat` 扩展点 | 实现重复循环 |
| 4 | **verify 抽离** — 修复 ack 后显式触发验证，而非依赖下次心跳 | 验证独立化 |
| 5 | **新增 block.*/locate.* 扩展点** | 与 remediation.*/attck.apt.* 对齐 |
| 6 | **定位默认开启** — 去掉 attck_ext 门控或提供默认定位子集 | 定位可用 |

---

## 六、结论

当前 ASSCOR 自动化链路**覆盖了新生命周期的 5/10 阶段**（探测/响应/报告/归档完整，定位/修复/验证部分），**缺失 3 个关键阶段**（阻断、定位再次、重复循环）。

核心架构问题：**缺少显式编排状态机**。整条链路靠 `assessor.result` 一条消息的事件副作用串联，而非一个可重复、可条件跳转的生命周期引擎。

要完整支撑新生命周期，需引入：
1. 生命周期状态机（Lifecycle Engine）
2. 攻击者活动状态追踪（读 chain.Status / alert ack 状态）
3. 循环条件判断（"定位中仍存在攻击者活动 → 重复"）

---
*审计完成于 2026-08-12T23:40+08:00。仅审计，不立即修复。*
