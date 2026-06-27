# ASSCOR 白皮书 vs 实际代码 — 技术一致性审计报告

**审计日期**: 2026-06-28 | **范围**: 14份白皮书 vs 135+ Go源文件 | **检查项**: 88项技术声明

---

## 总览

| 领域 | 检查项 | MATCH | MISMATCH | PARTIAL | 准确率 |
|------|--------|-------|----------|---------|--------|
| SSAM V2.0 公式与类型 | 20 | 10 | 9 | 1 | **50%** |
| SPC 态势计算 | 18 | 15 | 1 | 1 | **83%** |
| ATT&CK V19 | 17 | 13 | 4 | 0 | **76%** |
| 内核架构 (Plugin/DI/Bus/Adapter) | 21 | 18 | 3 | 0 | **86%** |
| Prism/ExtMgr/Config/Crypto | 12 | 11 | 1 | 0 | **92%** |
| **总计** | **88** | **67** | **18** | **2** | **76%** |

---

## 一、SSAM V2.0 — 50% (最薄弱)

### 匹配项 (10)
| 声明 | 代码 |
|------|------|
| Intrinsic = weightedSum × ∏edgeFactors | `formulas_v2.go:33-38` ✅ |
| Exposure floor 0.60 | `formulas_v2.go:44-50` ✅ |
| Threat floor 0.60 | `formulas_v2.go:52-58` ✅ |
| Domain weights AS=35/BC=25/OT=25/RS=15 | `defaults.go:3-8` ✅ |
| Edge factors 乘积链 | `formulas.go:24-27` ✅ |
| Edge factor 值 (2FA=0.85等) | `defaults.go:10-18` ✅ |
| V1.x 向后兼容 (ssam_v1.2) | `formulas.go:59-63` ✅ |
| Formula DSL/AST 支持 | `ast.go` ✅ |
| 域评分逻辑 | `ssam.go` ✅ |
| SPCScore→Exposure (V1 fallthrough) | `ssam.go:58-63` ✅ |

### 不匹配项 (10)

| # | 白皮书声明 | 实际代码 | 严重度 |
|---|-----------|---------|--------|
| **1** | **三层加权平均**: `Σ(layer×weight)/Σweight` (50/30/20) | **乘积**: `intrinsic × exposure × threat × 100` | 🔴 核心公式偏差 |
| **2** | `RiskContext` 含6字段 (CVEContext等) | 仅3字段 (Intrinsic/Exposure/Threat) | 🟡 接口文档过时 |
| **3** | `RiskLayerDetail` 含 Score/Weight/Description | 仅 Coeff/Contributors | 🟡 接口文档过时 |
| **4** | `FinalScore` 含 Acceptable/Threshold/Metadata | 仅 Total/Layers | 🟡 接口文档过时 |
| **5** | `AssessmentInputV2` 含 Timestamp | 含 Threshold 无 Timestamp | 🟡 接口文档过时 |
| **6** | `AssessmentOutputV2` 含 CalculatedAt | 含 Acceptable/Threshold 无 CalculatedAt | 🟡 接口文档过时 |
| **7** | `ScoringFormulaV2` 是 interface | 是 function type | 🟡 架构变化 |
| **8** | Exposure含 CVE_count/CVE_severity | 单标量 pre-computed | 🟡 简化 |
| **9** | Threat含 KEV_status/ThreatActor | 单标量 pre-computed | 🟡 简化 |
| **10** | V2路径有hooks | hooks仅在V1路径 | 🟡 遗漏 |

**核心发现**: SSAM V2.0 的"三层加权平均"创新——用 50/30/20 权重组合三个语义层——在白皮书中描述为 V2 的核心区别，**但代码中从未实现**。代码使用 `intrinsic × exposure × threat × 100` 乘积，语义上更接近 V1.x 公式。三层分解在显示/调试层有效，但组合方式是乘法而非加权平均。

---

## 二、SPC — 83% (优秀)

### 精确匹配的核心公式
```
    Impact  = 0.20×f_cvss + 0.50×f_epss + 0.30×f_kev        ✅ spc.go:527
    Penalty = impact × LocalFactor × TimeWindow                ✅ spc.go:547
    P_score = max(0.60, 1.00 − √ΣPenalty_i²)                  ✅ spc.go:596-597
    ATT&CK bonus: × (1 + 0.1×nSubTech)                         ✅ spc.go:531
    APT bonus:    × (1 + 0.2×nAptGroups)                       ✅ spc.go:537
```

### 不匹配 (2)

| # | 声明 | 代码 | 差异 |
|---|------|------|------|
| **1** | CPE Vendor 因子 = 0.3 | 实际 = **0.15** | 白皮书1行错误 |
| **2** | 4种MatchType | 6种匹配策略, 但归并到4种MatchType | 文档简化 |

---

## 三、ATT&CK V19 — 76% (良好)

### 不匹配 (4)

| # | 声明 | 实际 | 原因 |
|---|------|------|------|
| **1** | 4+4=8个子系统 | 4+6=**10** | 白皮书§10.1自己列了6个增强 |
| **2** | 12个扩展点 | **13**个 | 白皮书表格也列了13个 |
| **3** | 贝叶斯CPT 64行 | **81**行 (3⁴) | 数学错误: 4父×3状态=81,非64 |
| **4** | YARA/Sigma"规则引擎" | 关键词匹配 | §10.4已自述, 但§10.1标题夸大 |

### 精确匹配 (13): 归因融合 TTP60+IOC40 ✅, 因果推理20条 ✅, 贝叶斯4+1节点 ✅, 信标检测 jitter<0.1 ✅, 信誉库12条 ✅, 所有算法公式 ✅

---

## 四、内核架构 — 86% (良好)

### 不匹配 (3)

| # | 声明 | 实际 |
|---|------|------|
| **1** | dispatchSem=256 | **512** (kernel.go:45) |
| **2** | pre_init在Configure之后 | **在Configure之前** (kernel.go:227) |
| **3** | Plugin优先级表6项错误 | assessor 30→40, attck 80→21, concurrency 40→2, config_watcher 90→1, adapter_integration 35→45 |

### 完全匹配 (18): Plugin生命周期 ✅, DI反射实现 ✅, Bus双层信号量 ✅, Panic隔离 ✅, Adapter四阶段流水线 ✅, init()自注册 ✅, 21个DelegationRules ✅

---

## 五、Prism/ExtMgr/Config/Crypto — 92% (优秀)

唯一不匹配: 文件名 `ir.go` vs 实际 `prismir.go` (文件存在,内容正确,仅路径不同)。

完全匹配: 三层架构 ✅, 4状态向量 ✅, Markov+Bayes ✅, 拓扑传播 ✅, 8扩展类型 ✅, Install/Enable/Disable/Delete ✅, 53+配置节 ✅, 6行业模板 ✅, RSA三证 ✅

---

## 六、优先级修复建议

| 优先级 | 领域 | 问题 | 修复方式 |
|--------|------|------|----------|
| **P0** | SSAM | 三层加权平均 vs 乘积 | 改代码或改白皮书 — 这是**架构决策** |
| **P0** | SSAM | 接口文档类型全面过时 | 更新 `SSAM接口规范与接入指南.md` 或同步 `types_v2.go` |
| **P1** | SPC | CPE Vendor因子 0.15→0.3 | 改代码 (1行) |
| **P1** | ATT&CK | 子系统/扩展点/CPT计数 | 改白皮书 |
| **P1** | Kernel | Plugin优先级表 | 改白皮书 |
| **P2** | Kernel | pre_init顺序 | 改白皮书 |
| **P2** | Bus | dispatchSem值 | 改白皮书 |

---

## 七、结论

**技术准确率: 76%**

- **SPC公式和核心算法** 是忠实实现的 — 15/17项精确匹配
- **ATT&CK算法** 实现精确 — 所有归因/检测/推理公式与代码一致
- **内核基础设施** 设计意图已实现 — Plugin/DI/Bus/Adapter模式正确
- **SSAM V2.0接口文档** 与代码严重脱节 — 三层语义模型准确, 但公式实现、类型定义偏离
- **白皮书作者对V2.0"加权平均"的理解可能与代码实现不一致** — 乘积 vs 加权平均需决策对齐
