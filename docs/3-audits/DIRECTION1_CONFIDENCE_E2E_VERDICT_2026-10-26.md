# 方向①（情报可信度原生变量）端到端验收：结论与证据（2026-10-26）

> 目的：回答三个问题 —— 方向①**是否完全落地**、**是否进入评分模型**、**是否可用**。
> 环境：`dl360gen9`（PVE，46 GiB 可用内存 / 36 核）。拓扑按要求：**kernel 在 VM（910）**、**agent 在 CT（911）**。
> 结论先行：**策略层已完全落地并进入评分；规则表层发现 1 处未接线（legacy 路径），已修并红绿验证；整体可用。**

## 1. 评分链路（代码事实）

```
config.ini [confidence]            → internal/config/confidence.go（解析 + 校验 + 规则表）
  ├─ enabled / default / floor / accept_by_lower_bound   → ConfidencePolicy
  └─ [confidence.check] / [confidence.checkrx] / [confidence.source] / [confidence.domain] → Resolve(...)
        ↓
每条检查的 Confidence（CheckResult.Confidence，0 = 未指定）
        ↓
ssam-lib：E = Σ|delta|·c ／ U = Σ|delta|²·c·(1−c) ／ score = max(0,100−E) ／ σ = √U
        ↓
ConfidenceInterval（95% 区间；只夹**下界**） + AcceptanceDecision（可选按区间下界判可接受）
        ↓
报告字段：final_score / score_lower95 / score_upper95 / evidence_confidence / acceptable
```

两条执行路径**都必须**消费同一份规则表：

| 路径 | 入口 | 规则表接线 |
|---|---|---|
| 插件路径 | `internal/engine/ssam/adapter_engine.go` 的 `ComputeScore` | ✅ 早已接线（调用 `ssam.ResolveCheckConfidence`） |
| **legacy 路径** | `cmd/asscor` → `internal/engine` 的 `legacyCheckInputs` | ❌ **修复前未接线**（本次发现并修复） |

修复前 `ssam.ResolveCheckConfidence` 的注释写着"两条路径消费同一份规则表"，但代码里只有插件路径调用 —— **注释与代码不一致**，这是审计口径上的确凿缺陷。

## 2. 实测（同一台 VM、同一批 80 条检查、同一份配置，只改 `[confidence]`）

命令（VM 内，root）：

```bash
sudo ./bin/asscor --config etc/config.ini      -json > out/a-disabled.json
sudo ./bin/asscor --config etc/config-conf.ini -json > out/b-rules.json
sudo ./bin/asscor --config etc/config-def05.ini -json > out/c-def05.json
```

| 口径 | point | lower95 | upper95 | evidence_confidence |
|---|---|---|---|---|
| **A：`enabled = false`**（历史） | **63.79** | 63.790 | 63.790 | **1.0** |
| **B：`enabled = true` + `[confidence.check]` 6 条 = 0.50** | **65.03** | 63.238 | 66.822 | **0.959** |
| **C：`enabled = true` + `default = 0.5`（无规则表）** | **76.54** | 70.708 | 82.372 | **0.5** |

三条结论：

1. **策略字段真的进入评分**：C 只改 `default`，分数从 63.79 → **76.54**、σ 从 0 变成有宽度（CI ±5.83）、`evidence_confidence` = 0.5。
2. **规则表也真的进入评分**（修复后）：B 只给 6 条失败检查打 0.50，分数 63.79 → **65.03**、CI 由退化区间变成 **[63.24, 66.82]**、`evidence_confidence` = **0.959**（其余 74 条按 default=1.0）。
3. **关闭时与历史逐位一致**：A 的 CI 退化为点值、`evidence_confidence = 1` —— "不开 = 老行为"这条兼容承诺成立。

## 2.1 规则优先级端到端（五级同时给不同值）

配置（VM 上 `etc/config-chain.ini`，同一批 80 条检查）：

```ini
[confidence]
enabled = true
default = 0.55
floor = 0.05

[confidence.check]
OT-008 = 0.11          ; 精确检查 ID

[confidence.checkrx]
^ot-0 = 0.22           ; 正则（小写匹配）

[confidence.source]
nuclei = 0.33          ; 来源（builtin 没有规则 ⇒ 落到域）

[confidence.domain]
operation_trust = 0.44
resilience = 0.66
```

实测 **80/80 条全部落在预期的层级**（`check > checkrx > source > domain > default`）：

| 检查 | 域 | 实际拿到的 confidence | 命中层级 |
|---|---|---|---|
| `OT-008` | operation_trust | **0.11** | `[confidence.check]` |
| `OT-007/009/011/012/…` | operation_trust | **0.22** | `[confidence.checkrx]` |
| `RS-016` 等 | resilience | **0.66** | `[confidence.domain]`（source 无规则） |
| `AS-*` 等 | attack_surface | **0.55** | `default` |

> **source 层级：端到端已成立（修掉一处装配缺口后）**。修前 `asscor` 只空白导入 checks、
> **从不注册 `[user_check.*]`**（kernel 侧在组合根做这一步），于是自定义检查被解析却从不执行。
> **合法配置 + 修前/修后两个二进制**的对照：修前仍是 **80 条**（`CU-*` 一条不出现）；
> 修后 **83 条** —— `CU-PROBE-OK`（passed）/`CU-PROBE-MISSING`（failed）/`CU-001` 三条全部
> `source=user`、`confidence=0.33`（来自 `[confidence.source] user = 0.33`）
> ⇒ source 层级在真实评分链路上被命中并生效。
> 引擎级单测（`internal/engine/confidence_rules_test.go`）保留五级断言作快速回归。
>
> ⚠️ 教训：首次验证时我给的 `user_check` 配置**缺 `id`/`domain`（必填）**，`ParseUserChecks` 返回空，
> 差点把"配置写错"记成"代码没消费"。上面的 80→83 是**用合法配置重做**的对照。

## 2.2 总分公式逐项复核（证明"真的进了评分模型"，不是只写进报告）

反算链路（与 `internal/engine/assessor.go` 的 `computeDynamicFinalScore` 一致）：

```
域分 score_d = 100 − Σ|delta|·c        （只算失败且 delta<0 的检查）
intrinsic    = (Σ w_d·score_d / Σ w_d) / 100 × Π(活跃边因子)
Total        = (intrinsic×50 + SPC×30 + threat×20) / 100 × 100
```

实测（`config-chain.ini`）：

- **逐域分 5/5 完全一致**（`attack_surface` 79.10、`business_continuity` 78.00、
  `kernel_security` 74.70、`operation_trust` 79.65、`resilience` 0.00 —— 与报告的 `domain_scores` 逐项相等）；
- `Σ w·score/Σw = 67.7886`，活跃边因子 `two_factor_failure = 0.82`（其余为 1）
  ⇒ `intrinsicCoeff = 0.555867`；
- 三层反算 **77.7933**，报告 **77.7900**，差 **0.0033**（四舍五入量级）。

⇒ 置信度确实参与了每一个域分的计算，而不只是被写进输出字段。

## 2.3 `accept_by_lower_bound` 的端到端效果

同一份数据、同一阈值（`[acceptability] threshold = 75.0`，介于 CI 下界 72.35 与点估计 77.79 之间）：

| `accept_by_lower_bound` | point | lower95 | threshold | acceptable |
|---|---|---|---|---|
| `false`（默认，点估计判定） | 77.79 | 72.35 | 75.0 | **true** |
| `true`（保守：用 95% 下界判定） | 77.79 | 72.35 | 75.0 | **false** |

⇒ 这个开关是**真的**改变接受性结论的（不是只解析不消费）。

## 2.4 `floor` 夹取：发现一处"显示值 ≠ 计算值"（已修）

配置 `[confidence.check] OT-008 = 0.01` + `floor = 0.05`：

- **修前**：报告里 `OT-008` 的 `confidence` 仍是 **0.01**，而评分时 `NormalizeConfidence` 按 **0.05** 计算
  ⇒ 同一字段两种含义（报告值低于 floor，与"floor = 下限"的语义矛盾）；
- **根因**：`(*ConfidenceConfig).Resolve` 只做规则匹配、**不应用 floor/上限**；
- **修法**：`Resolve` 返回**生效值**（`resolveRaw` 匹配 → `clampConfidence` 夹到 `[floor,1]`），
  与 `NormalizeConfidence` 同一套默认（floor 非法 ⇒ 0.05）；
- **修后**：`OT-008` 的 `confidence = 0.05`（期望值），优先级链 **80/80 不变**、`point` 不变；
- 回归：`internal/config/confidence_floor_test.go`（先红后绿：修前 `want 0.05, got 0.01`）。

## 3. 修复与回归（本次提交）

- `internal/engine/assessor.go`：`legacyCheckInputs` 在映射前调用 `a.cfg.ResolveChecks(result.Checks)`，
  与插件路径共用 `(*config.Config).ResolveChecks` 同一实现。
- `internal/engine/confidence_rules_test.go`（新增）：钉住
  ① `[confidence.check]` 命中 → `Confidence=0.50`；
  ② 未命中时按 `[confidence.source] builtin=0.80`；
  ③ `enabled=false` 时 **不写** Confidence（保持 0 = 未指定，库按 1.0 处理）。
- **先红后绿**：把修复 `git stash` 掉只留测试 ⇒ 两条断言失败（`got 0`）；恢复后 **PASS**。

## 4. 架构侧（kernel=VM / agent=CT）

| 项 | 实测 |
|---|---|
| kernel | VM **910** `asc-kernel-vm`，Debian 12.15，8 GiB / 4 核，mTLS 启用，监听 `:50051`（systemd `asscor-kernel.service`，`enabled`） |
| agent | CT **911** `asc-agent-ct`，Debian 12，`192.168.30.51` |
| 连接 | agent 日志：`TLS configured … connected to kernel 192.168.30.50:50051 mtls=true` → **`registered session_id=sess-asc-agent-ct-…`** |
| kernel 侧 | `ss` 显示两条 ESTAB（agent → kernel）；kernel 日志列出 `heartbeat` / `commander` / `cti` / `assessor` 模块 |

⇒ 方向① 的"证据可信度"由 kernel 侧 assessor 计算；agent 负责在目标节点采集/执行。**agent 上报的 findings 若显式带 Confidence，会被保留；未带的由 kernel 的规则表/默认值补齐。**

## 5. 未落地 / 限制（诚实登记）

| 项 | 状态 |
|---|---|
| `[confidence.algorithm]` / `prior_strength`（beta_bayes） | **未实现**（配置里是 reserved，写别的取值会加载失败）；当前只有 `weighted_evidence` |
| `[confidence.checkrx]`（正则选择器） | ✅ **已端到端实测**（见 §2.1：`^ot-0 = 0.22` 命中 80 条中的 OT 组，且被精确 ID 规则正确压过） |
| 适配器来源置信度 | 依赖 adapter 侧 findings 携带 `Source`/`Confidence`（`internal/adapter`）；本机 80 条里大部分是**内置检查**，所以实际控制手段是 `[confidence.check]` + `default` |
| `[user_check.*]` 在 legacy 路径 | ✅ **已修（2026-10-26）**：`asscor` 此前只空白导入 checks、从不装配 `[user_check.*]`；现补 `registerUserChecks`（与 kernel 组合根同一步）。修前 80 条 → 修后 **83 条**（`CU-*` 三条 `source=user`、`confidence=0.33`）|
| 标定 | **从未标定**。`user=0.90` / `adapter=0.80` 是**先验**，不是实测标定值 —— 任何"已标定"的说法都不成立 |
| 报告的 `confidence` 字段口径 | 已统一为**生效值**（`Resolve` 内夹 floor/上限）；`NormalizeConfidence` 在评分时再夹一次（幂等） |

## 6. 复跑步骤（可重复）

见 `docs/1-current/guides/ASSCOR_KERNEL_VM_ASSET_2026-10-26.md` 的"复用步骤"；一句话：
VM 910 上 `sudo systemctl start asscor-kernel`，CT 911 上起 `asc-agent`，再在 VM 上跑三份配置的 `asscor` 对比。
