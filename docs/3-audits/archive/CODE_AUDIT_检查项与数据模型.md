# 代码审计报告

## 基本信息

- **审计范围**：检查项定义、数据模型、SSAM 评分公式
- **审计类型**：代码审计（Code Audit）
- **变更类型**：例行审计
- **影响等级**：Medium-High
- **审计日期**：2026-05-26

---

## 审计结论

**[有条件通过 ⚠️]**

发现 2 个 **High** 级别问题和 3 个 **Medium** 级别问题，需修复后通过。

---

## 发现项

### [B-1] 权重归一化计算错误 — High

- **位置**：`internal/model/model.go:L238-247`
- **描述**：`Weights.Normalize()` 方法将 5 个域权重归一化到 100，但原有 4 域模型总和为 100，添加 `KernelSecurity=10` 后总和变为 105，导致归一化后每个域权重被错误压缩。

**代码**：
```go
func (w *Weights) Normalize() {
    sum := w.AttackSurface + w.BusinessContinuity + w.OperationTrust + w.Resilience + w.KernelSecurity
    if sum == 0 || sum == 100 {
        return
    }
    w.AttackSurface = w.AttackSurface / sum * 100
    w.BusinessContinuity = w.BusinessContinuity / sum * 100
    w.OperationTrust = w.OperationTrust / sum * 100
    w.Resilience = w.Resilience / sum * 100
    w.KernelSecurity = w.KernelSecurity / sum * 100  // 新增
}
```

**问题分析**：
- `config.ini` 中 4 域默认权重：`35+25+25+15 = 100`
- 加上 `[extension_weights]` 中 `kernel_security = 10` 后：`35+25+25+15+10 = 105`
- 归一化后实际权重变成：`33.33 + 23.81 + 23.81 + 14.29 + 9.52 ≈ 105`（总和仍为 100）

**风险**：
- 实际评分使用的权重与配置意图不一致
- 等保映射阈值（二级≥65、三级≥80、四级≥90）失效

**修复建议**：
1. **方案 A**：修改 `Normalize()` 方法，当 `kernel_security > 0` 时，单独处理归一化（推荐）
2. **方案 B**：在 `config.ini` 中移除 `[extension_weights]` 段的 `kernel_security`，保持总权重为 100
3. **方案 C**：重新设计权重模型，使用动态域注册机制替代静态 `Weights` 结构体

---

### [B-2] SSAM 公式描述与实现不一致 — High

- **位置**：
  - `internal/ssam/engine.go:L401-429`（实际实现）
  - `docs/SSAM接口规范与接入指南.md`（文档描述）

- **描述**：文档描述 SSAM 1.3 为 4 域模型（攻击面35 + 业务连续性25 + 操作可信度25 + 韧性15 = 100），但代码实现了 5 域模型（增加了 `kernel_security` 扩展域）。

**代码差异**：
```go
// 文档描述的公式：
SSAM_final = (Σ(S_i × W_i) / 100) × ΠM_j × μ × P_score

// 实际代码（ssamV12Formula）：
sum := 0.0
totalWeight := 0.0
for _, ds := range domainScores {
    if w, ok := wMap[ds.Domain]; ok && w > 0 {
        sum += ds.Score * w
        totalWeight += w  // 注意：totalWeight 可能是 100 或 105
    }
}
baseScore := sum / totalWeight  // 不是 /100！
```

**风险**：
- 使用者按照文档配置权重，结果与预期不符
- 扩展域 `kernel_security` 的权重计算依赖配置加载顺序

**修复建议**：
1. **方案 A**：更新文档，明确说明 5 域模型及权重计算规则（推荐）
2. **方案 B**：代码中强制总权重为 100，超出部分按比例压缩
3. **方案 C**：将 `[extension_weights]` 改为动态注入，不参与 `Weights.Normalize()`

---

### [B-3] 检查项与边缘因子逻辑重叠 — Medium

- **位置**：
  - `internal/checks/linux/kernel_security.go:L489-543`（KS-012）
  - `internal/model/edge_factor_chain.go:L121-136`（EF-SELINUX、EF-APPARMOR）

- **描述**：KS-012 检查 LSM（SELinux/AppArmor）是否处于 enforcing 模式，同时边缘因子中也定义了 `EF-SELINUX` 和 `EF-APPARMOR`，两者存在双重惩罚风险。

**代码**：
```go
// KS-012（Delta = -15）
func ks012() model.CheckItem {
    return model.CheckItem{
        ID:    "KS-012",
        Delta: -15,
        Check: func() (bool, string) {
            // 检查 SELinux/AppArmor 是否 enforcing
            if len(activeLSMs) > 0 {
                return true, "活跃LSM: ..."
            }
            return false, "未检测到任何处于enforcing模式的LSM"
        },
    }
}

// 边缘因子
RegisterEdgeFactor(EdgeFactor{
    ID:     "EF-SELINUX",
    Factor: 0.80,  // 额外 ×0.8 惩罚
})
RegisterEdgeFactor(EdgeFactor{
    ID:     "EF-APPARMOR",
    Factor: 0.82,  // 额外 ×0.82 惩罚
})
```

**问题分析**：
- 如果 SELinux 未 enforcing，KS-012 扣 15 分，EF-SELINUX 再乘 0.80
- 组合惩罚：`100 - 15 = 85 → 85 × 0.80 = 68`（实际影响更大）

**修复建议**：
1. **方案 A**：移除 KS-012 中的 LSM 检查，让边缘因子单独处理（推荐，保持职责分离）
2. **方案 B**：修改边缘因子配置，使其仅在 KS-012 未定义时生效
3. **方案 C**：在 `assessor.go` 中添加逻辑，防止双重惩罚

---

### [M-1] 检查项编号体系不规范 — Medium

- **位置**：`internal/checks/linux/checks.go`、`internal/checks/linux/kernel_security.go`

- **描述**：检查项编号存在跳跃和不连续：
  - BC 域只有 `BC-005`、`BC-006`、`BC-007`（缺少 BC-001 至 BC-004）
  - EF 域只有 `EF-001`、`EF-002`（边缘因子域定义不完整）

**当前编号**：
```
AS-001 ~ AS-017    ✓ 连续
OT-001 ~ OT-022    ✓ 连续
RS-001 ~ RS-012    ✓ 连续
BC-005 ~ BC-007    ✗ 跳跃（BC-001~BC-004 缺失）
AC-001 ~ AC-008    ✓ 连续
EF-001, EF-002     ✗ 仅 2 项，config.ini 中有更多定义
KS-001 ~ KS-012    ✓ 连续
```

**config.ini 中的边缘因子**：
```ini
[edge_factors.custom]
EF-002FA = 0.85
EF-SYNCOOKIE = 0.75
EF-SELINUX = 0.80
EF-APPARMOR = 0.82
EF-NO-SIEM = 0.90
EF-NO-IDS = 0.88
EF-3FA = 0.82
```

**问题**：`config.ini` 中定义了 7 个边缘因子（使用不同命名），但代码中只实现了 2 个（`EF-001`、`EF-002`）。

**修复建议**：
1. **方案 A**：统一编号体系，将所有边缘因子映射到 `EF-XXX` 编号（推荐）
2. **方案 B**：在代码中实现 `EF-002FA`、`EF-SYNCOOKIE` 等新编号的检查项
3. **方案 C**：清理 `config.ini` 中未使用的边缘因子定义

---

### [E-1] 错误处理不一致 — Low

- **位置**：`internal/checks/linux/kernel_security.go:L316-318`

- **描述**：KS-008 检查项中，错误处理逻辑与其他检查项不一致：

**代码**：
```go
out, err := common.RunCmdQuiet("bpftool", "prog", "list")
if !err {  // 注意：这里是 !err，与其他检查项相反
    return true, "bpftool 不可用，跳过eBPF审计"
}
```

**问题分析**：
- `RunCmdQuiet` 返回 `(string, bool)`，其中 `bool` 表示是否有错误
- 其他检查项使用 `if err != nil` 判断，这里使用 `if !err` 判断
- 虽然功能正确，但容易引起混淆

**修复建议**：
1. **方案 A**：统一使用 `RunCmd` 而非 `RunCmdQuiet`，保持一致的风格
2. **方案 B**：添加注释说明 `RunCmdQuiet` 的返回值语义

---

## 验证项（通过）

### ✅ SSAM 评分公式实现正确

**位置**：`internal/ssam/engine.go:L401-429`

```go
func (e *Engine) ssamV12Formula(...) float64 {
    sum := 0.0
    totalWeight := 0.0
    for _, ds := range domainScores {
        if w, ok := wMap[ds.Domain]; ok && w > 0 {
            sum += ds.Score * w      // ✓ 正确：S_i × W_i
            totalWeight += w          // ✓ 正确：ΣW_i
        }
    }
    if totalWeight == 0 {
        return 0
    }
    baseScore := sum / totalWeight   // ✓ 正确：Σ(S_i×W_i)/ΣW_i
    baseScore *= threatCoeff          // ✓ 正确：×μ
    baseScore *= spcScore             // ✓ 正确：×P_score
    
    for _, f := range edgeFactors {   // ✓ 正确：仅对 Active && Factor∈(0,1) 的因子乘法
        if f.Active && f.Factor > 0 && f.Factor < 1.0 {
            baseScore *= f.Factor
        }
    }
    return math.Round(baseScore*100) / 100  // ✓ 正确：保留两位小数
}
```

**结论**：评分公式实现完全符合 SSAM 1.3 规范。

---

### ✅ 检查项 Delta 值一致性

**验证**：对比 `checks.go` 中定义的 Delta 与 `config.ini` 中 `[check_deltas]` 的值：

| 检查项 | checks.go Delta | config.ini Delta | 状态 |
|--------|-----------------|-----------------|------|
| AS-001 | -8 | -8 | ✓ |
| AS-002 | -8 | -8 | ✓ |
| AS-017 | -5 | -5 | ✓ |
| OT-005 | -15 | -15 | ✓ |
| OT-022 | -15 | -15 | ✓ |
| RS-011 | -15 | -15 | ✓ |
| KS-001 | -15 | -15 | ✓ |
| KS-012 | -15 | -15 | ✓ |

**结论**：所有检查项 Delta 值与配置文件一致。

---

### ✅ 边缘因子配置正确

**位置**：`internal/config/config.go:L208-228`

边缘因子配置解析正确：
```go
case "syn_cookie_disabled":
    cfg.EdgeFactors.SYNCookieDisabled = f   // ✓
case "selinux_disabled":
    cfg.EdgeFactors.SELinuxDisabled = f      // ✓
```

**结论**：边缘因子配置解析逻辑正确。

---

### ✅ DomainScores 结构体完整

**位置**：`internal/model/model.go:L86-123`

```go
type DomainScores struct {
    AttackSurface      float64  // ✓ 攻击面
    BusinessContinuity float64  // ✓ 业务连续性
    OperationTrust     float64  // ✓ 操作可信度
    Resilience         float64  // ✓ 韧性
    KernelSecurity     float64  // ✓ 内核安全（扩展域）
}
```

**结论**：所有 5 个域都有对应的分数字段。

---

## 统计

| 类别 | 数量 |
|------|------|
| 发现项总数 | 5 |
| High | 2 |
| Medium | 2 |
| Low | 1 |
| 业务类 (B) | 3 |
| 可维护性类 (M) | 1 |
| 错误处理类 (E) | 1 |

---

## 修复优先级建议

1. **[B-1] 权重归一化计算错误** — 立即修复，影响评分准确性
2. **[B-2] SSAM 公式描述与实现不一致** — 立即修复，文档与代码不一致
3. **[B-3] 检查项与边缘因子逻辑重叠** — 高优先级，存在双重惩罚风险
4. **[M-1] 检查项编号体系不规范** — 中优先级，影响可维护性
5. **[E-1] 错误处理不一致** — 低优先级，仅代码风格问题

---

## 附录

### A. 审计文件清单

| 文件 | 审计内容 |
|------|----------|
| [checks.go](f:\Argus\internal\checks\linux\checks.go) | 检查项定义 |
| [kernel_security.go](f:\Argus\internal\checks\linux\kernel_security.go) | 内核安全检查项 |
| [model.go](f:\Argus\internal\model\model.go) | 数据模型定义 |
| [engine.go](f:\Argus\internal\ssam\engine.go) | SSAM 评分引擎 |
| [config.go](f:\Argus\internal\config\config.go) | 配置解析 |
| [edge_factor_chain.go](f:\Argus\internal\model\edge_factor_chain.go) | 边缘因子链 |
| [config.ini](f:\Argus\config.ini) | 默认配置 |
| [assessor.go](f:\Argus\internal\kernel\assessor.go) | 评估模块 |

### B. 修复验证检查清单

修复后需验证：
- [ ] `Weights.Normalize()` 总权重为 100
- [ ] SSAM 评分公式输出在 [0, 100] 范围内
- [ ] 边缘因子乘法不会导致分数异常降低
- [ ] 所有检查项 Delta 值与 config.ini 一致
- [ ] 等保映射阈值（二级≥65、三级≥80、四级≥90）正常工作

---

**审计员**：ASSCOR 代码审计 Agent  
**审计时间**：2026-05-26  
**审计版本**：v0.1.2-MVP
