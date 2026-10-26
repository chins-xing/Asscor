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
| `[confidence.checkrx]`（正则选择器） | 已实现，但**未做按正则的端到端实测**（规则表命中顺序在单测里覆盖） |
| 适配器来源置信度 | 依赖 adapter 侧 findings 携带 `Source`/`Confidence`（`internal/adapter`）；本机 80 条里大部分是**内置检查**，所以实际控制手段是 `[confidence.check]` + `default` |
| 标定 | **从未标定**。`user=0.90` / `adapter=0.80` 是**先验**，不是实测标定值 —— 任何"已标定"的说法都不成立 |

## 6. 复跑步骤（可重复）

见 `docs/1-current/guides/ASSCOR_KERNEL_VM_ASSET_2026-10-26.md` 的"复用步骤"；一句话：
VM 910 上 `sudo systemctl start asscor-kernel`，CT 911 上起 `asc-agent`，再在 VM 上跑三份配置的 `asscor` 对比。
