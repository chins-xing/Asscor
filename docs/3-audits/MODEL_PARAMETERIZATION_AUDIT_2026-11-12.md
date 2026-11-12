# 模型参数变量化审计（2026-11-12）

> 问题：模型参数（评分权重、阈值、边因子、Prism/SRD 参数、SPC/ATT&CK、研究引擎）是否已经"配置驱动"？
> 方法：静态代码追踪 + 运行时探针（加载 `config.ini`，再用一份改值配置对比生效值）。

## 1. 结论摘要

**已落实（随配置生效）**

- 内核评分：`[weights]`、`[acceptability] threshold`、`[spc]`、`[attck]`、`[threat]`、`[check_deltas]`、`[extension_weights]`、`[confidence]`。
- 边因子：SSAM 路径的 6 个内置因子读 `[edge_factors]`。
- Prism：**13 个参数全部**经 `ConfigFromMap` 生效（含 `aggregation`）。
- SRD：`layered_graph`、`horizon_days`、`max_path_depth`、`path_decay`、`prop_cap`、`aggregation`、`transmission`、`debt_alpha/debt_cap/debt_norm_days`、`score_floor`、`collapse_beta`、`stable/degraded/untrusted_threshold` 均被 `loadConfig` 读取。

**未落实 / 半落实（按优先级）**

| 级别 | 问题 | 位置 |
|---|---|---|
| P1 | `[edge_factors] two_factor_failure` 被 `[edge_factors.level4_override]` **无条件覆盖**：配置写 0.85，实际永远 0.70 | `internal/config/config.go:275-307` |
| P1 | **legacy 评分路径**的 5 个因子硬编码（0.75/0.80/0.82/0.90/0.88），不读 `[edge_factors]`（代码注释明确"刻意保留"） | `internal/engine/assessor.go:562-570` |
| P1 | `[resilience] aci_*` 7 个权重被解析，但**全仓没有消费点**（死配置） | `internal/config/config.go:38-44,111-117,326-346` |
| P2 | SSAM 路径 `EF-3FA` 因子硬编码 0.82（含 CascadeValue） | `internal/engine/ssam/adapter.go:69` |
| P2 | ATT&CK 15 技术转移矩阵硬编码（专家先验），无配置入口 | `internal/attck/attck.go:987+` |
| P2 | SPC 影响公式权重硬编码：`0.20*cvss + 0.50*epss + 0.30*kev`、APT `×1.2`、子技术 `×1.1`、PoC `0.3` | `internal/spc/spc.go:535-544` |
| P2 | CTI 系数 `1.0`、更新间隔 `15m` 硬编码；只配了 OTX/MISP 凭据 | `internal/cti/cti.go:70-71` |
| P2 | 研究引擎默认参数硬编码：predictor 动作收益表、engagement `1.0/0.8/0.6/1.2`、attackerstate `0.1/0.15` 增量（RC-M4） | `internal/predictor/predictor.go:71`、`internal/engagement/engagement.go:62`、`internal/attackerstate/state.go:106,132` |
| P3 | `[resilience.circuit]` 未解析；熔断默认值 5 次/5 分钟/1 分钟硬编码 | `internal/resilience/circuit.go:71` |

## 2. 运行时探针（实测）

命令：`go run -tags engine ./build/paramprobe`（临时探针，未入库）。基准 `config.ini` 与"追加同名段覆盖"的改值配置对比：

| 参数 | base | altered | 结论 |
|---|---|---|---|
| `acceptability.threshold` | 80.00 | **42.00** | ✅ |
| `weights.attack_surface` | 35.000 | **12.162**（归一化后） | ✅ |
| `spc.min_pscore` | 0.60 | **0.99** | ✅ |
| `attck.beacon_threshold` | 0.70 | **0.99** | ✅ |
| `edge_factors.two_factor_failure` | 0.700 | **0.700**（应为 0.55） | ❌ 被 level4 覆盖 |
| `prism.debt_alpha` | 1.200 | **1.770** | ✅ |
| `prism.prop_cap` | 0.250 | **0.110** | ✅ |
| `prism.debt_cap` | 0.300 | **0.220** | ✅ |
| `prism.debt_norm_days` | 1500 | **999** | ✅ |
| `prism.path_decay` | 0.800 | **0.660** | ✅ |
| `prism.max_path_depth` | 5 | **8** | ✅ |
| `prism.score_floor` | 0.150 | **0.220** | ✅ |
| `prism.collapse_beta` | 1.500 | **1.900** | ✅ |
| `prism.aggregation` | rss | **max** | ✅ |
| `prism.stable_threshold` | 0.90 | **0.95** | ✅ |
| `prism.degraded_threshold` | 0.70 | **0.75** | ✅ |
| `prism.untrusted_threshold` | 0.50 | **0.55** | ✅ |
| `prism.horizon_days` | 7 | **11** | ✅ |
| `prism.default_transmission` | 0.30 | **0.77** | ✅ |
| `srd.layered_graph` | true | **false** | ✅ |
| `srd.horizon_days` | 空 | **13** | ✅ |
| `srd.max_path_depth` | 空 | **7** | ✅ |
| `srd.path_decay` | 空 | **0.55** | ✅ |
| `srd.aggregation` | 空 | **max** | ✅ |
| `srd.transmission` | 空 | **0.66** | ✅ |

SSAM 路径实际边因子（探针输出）：

```text
EF-002FA     0.700    ← 来自 level4_override，[edge_factors] 的 0.85 被覆盖
EF-SYNCOOKIE 0.750
EF-SELINUX   0.800
EF-APPARMOR  0.820
EF-NO-SIEM   0.900
EF-NO-IDS    0.880
EF-3FA       0.820    ← 硬编码
ef-002fa     0.850    ← [edge_factors.custom] 的同名小写项，作为额外因子另计
```

## 3. 为什么 `two_factor_failure` 不生效

`config.Parse` 的固定顺序：

1. 先读 `[edge_factors]`：`cfg.EdgeFactors.TwoFactorFailure = 0.85`（`config.go:275-301`）；
2. 再读 `[edge_factors.level4_override]`：无条件覆盖为 `0.70`（`config.go:303-307`）。

"level4" 只存在于键名/文案里，**解析与评分时没有任何合规等级判定**，所以它实际上是"永远覆盖"。要么按 `compliance_framework`/等级 gate，要么把该键改成普通覆盖项并在文档里删掉 `[edge_factors]` 的同名写法。


**修复（2026-11-13，`d635197`）**：`[edge_factors.level4_override]` 现在只在
`[acceptability] compliance_framework` 判定为 Level 4（含 "Level 4"/"等保四级"）时应用；
默认 Level 3 下 `[edge_factors] two_factor_failure = 0.85` 生效。回归测试
`TestEdgeFactorLevel4OverrideOnlyForLevel4` 锁定 Level 3/Level 4/空值三种行为。

## 4. 建议

**P0（配置正确性）**
- 修 `level4_override` 语义：只有等保四级场景才覆盖；否则移除该键或改名。补一个配置回归测试（0.85 在非 level4 下生效）。

**P1（口径一致性）**
- `[resilience] aci_*`：接入 ACI 评分（SPC/assessor）或从配置/文档删除，避免"配了没用"。
- legacy 路径：明确是否废弃。若保留，`legacyDefaultCustomFactors` 应读 `cfg.EdgeFactors`；若不保留，文档标注 legacy 仅作对照、参数固定。
- `EF-3FA` 0.82 参数化（或明确写死为模型常量）。

**P2（研究/实验参数）**
- RC-M4：给 predictor/engagement/attackerstate 加 `PlannerParams` 类注入（实验侧配置），默认值可保留。
- ATT&CK 转移矩阵、SPC 影响权重、CTI 系数/间隔：若近期要做参数敏感性实验，先加只读配置/实验注入；否则在文档中明确标为"模型常量"。

## 5. 复现

```bash
# 静态：看解析与消费
grep -n "level4_override" internal/config/config.go
grep -n "legacyDefaultCustomFactors" -A12 internal/engine/assessor.go
grep -rn "ACINetworkSegmentation" internal cmd

# 运行时：基准 vs 改值
go run -tags engine ./build/paramprobe
```

> 探针与原始输出在 `build/paramprobe`、`build/paramprobe.out`（本地临时，`build/` 不入库）。
