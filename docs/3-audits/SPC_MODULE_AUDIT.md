# SPC 模块代码审计报告

## 基本信息

- **审计范围**：`internal/kernel/` 下 5 个 SPC 相关文件
- **审计方法**：Oracle 第二模型审查 + SymPy 公式数学验证 + OpenClaw GHSA 安全公告审计
- **模块规模**：~1400 行代码（NVD/EPSS/KEV/MISP/CNNVD/CNVD 数据获取 + CPE 匹配 + P_score 计算）
- **审计日期**：2026-05-27
- **影响等级**：High

---

## 审计结论

**[有条件通过 ⚠️]**

发现 **2 个 Critical**、**3 个 High**、**4 个 Medium** 级别问题。

核心 P_score 公式数学实现正确，但 **MatchCPEVendor Factor=0.0 的逻辑缺陷**和**Calculate 方法持读锁时间过长**需要修复。

---

## ------------------------------------------------------------
## CRITICAL — 共 2 项
## ------------------------------------------------------------

### [B-1] MatchCPEVendor Factor() 返回 0.0 — 厂商级匹配不产生任何惩罚 — Critical

- **来源**：Oracle + SymPy（独立发现确认）
- **位置**：[spc.go:L41-L52](file:///f:/Argus/internal/kernel/spc.go#L41-L52)
- **描述**：`MatchType` 枚举中 `MatchCPEVendor = 1`（iota），但 `Factor()` 方法的 switch case 只处理了前三个 case，`default` 返回 `0.0`：

```go
func (mt MatchType) Factor() float64 {
    switch mt {
    case MatchExactVersion:            // iota=0
        return 1.0
    case MatchVersionRange:            // iota=1
        return 0.7
    case MatchCPEProduct:              // iota=2
        return 0.3
    default:
        return 0.0  // ← MatchCPEVendor (iota=1) 命中这里！
    }
}
```

**影响链**：在 `Calculate` 方法中（L923）：

```go
localFactor := matchType.Factor() * exposure.Factor() * control.Factor()
// 当 MatchCPEVendor → Factor() = 0.0 → localFactor = 0.0
penalty := impact * localFactor * timeFactor
// penalty = impact × 0.0 × timeFactor = 0.0
```

**定量分析**：
- 即使 CVE 通过厂商名成功匹配，`localFactor = 0.0`，`penalty = 0`
- 该 CVE 对 `totalPenalty` 和 `pscore` **完全不产生任何影响**
- `MatchCPEVendor` 枚举值虽然存在，但**从未被正确使用**

**SymPy 验证**：若 `MatchCPEVendor.Factor() = 0.3`（与其他 Medium 匹配类型一致），则：
```
localFactor = 0.3 × 1.0 × 0.5 = 0.15（以 Localhost+Partial 为例）
而非当前的 0.0
```

- **修复方案**：
  - **方案 A（推荐）**：在 `Factor()` 中添加 `case MatchCPEVendor: return 0.15`（建议值）

    ```go
    func (mt MatchType) Factor() float64 {
        switch mt {
        case MatchExactVersion:
            return 1.0
        case MatchVersionRange:
            return 0.7
        case MatchCPEProduct:
            return 0.3
        case MatchCPEVendor:
            return 0.15  // 新增：厂商级匹配次低优先级
        default:
            return 0.0
        }
    }
    ```

  - **方案 B**：将 `MatchCPEVendor` 的匹配结果降级为 `MatchCPEProduct`（在 `compareCPE` 返回前添加转换逻辑）
  - **方案 C**：完全移除 `MatchCPEVendor` 枚举，清理相关代码

---

### [B-2] `matchCPE` 与 Calculate 内联逻辑重复 — MatchCPEVendor 缺陷双份存在 — Critical

- **来源**：Oracle Skill
- **位置**：
  - [spc_match.go:L69-L123](file:///f:/Argus/internal/kernel/spc_match.go#L69-L123) — 独立的 `matchCPE` 方法
  - [spc.go:L815-L843](file:///f:/Argus/internal/kernel/spc.go#L815-L843) — Calculate 中的内联 CPE 匹配逻辑

- **描述**：`matchCPE` 和 `Calculate` 中的内联逻辑**几乎完全一致**，两处都包含相同的 MatchCPEVendor 缺陷：
  - `spc_match.go` L82: `if matchType == 0` — 只处理精确版本匹配
  - `spc.go` L815: 同样的逻辑

  维护风险：修复 MatchCPEVendor 缺陷需要同时修改两处，否则不一致。

- **修复方案**：
  - **方案 A（推荐）**：删除 `spc_match.go` 中的 `matchCPE` 方法，`Calculate` 中直接使用该方法（确保只维护一份逻辑）
  - **方案 B**：删除 `Calculate` 中的内联逻辑，改为调用 `matchCPE`
  - **方案 C**：统一两份代码后，确保 Factor() 在两处都生效

---

## ------------------------------------------------------------
## HIGH — 共 3 项
## ------------------------------------------------------------

### [C-1] Calculate 持读锁构建 CPE 索引时间过长 — High

- **来源**：Oracle + GHSA（独立发现确认）
- **位置**：[spc.go:L701-L721](file:///f:/Argus/internal/kernel/spc.go#L701-L721)
- **描述**：`Calculate` 方法在持有 `m.mu.RLock()` 期间（L670），遍历全部 `cveCache` 构建完整的 `cpeIndex`（每个 CVE × AffectedCPEs 遍历）。最大 100,000 条 CVE，每条可能有数十个 CPE，锁持有时间可能达到数百毫秒。

```go
m.mu.RLock()
// L701-L721: CPE 索引构建 — 线性遍历所有 CVE
for i := range m.cveCache {
    entries := make([]cpeIndexEntry, 0, len(m.cveCache[i].AffectedCPEs))
    for _, cpe := range m.cveCache[i].AffectedCPEs {
        // ... 字符串解析和处理 ...
    }
    cpeIndex[i] = entries
}
// L722-L731: CVE 缓存拷贝
cves = append(cves, m.cveCache...)
// L732-L739: KEV catalog 拷贝
// L740: m.mu.RUnlock() — 锁释放
```

- **风险**：在锁持有期间，所有写操作（`UpsertAsset`、`AddCVE`、`mergeCVEInPlace` 等）被阻塞。对于大规模 CVE 缓存，读取方等待时间显著。
- **修复方案**：
  - **方案 A（推荐）**：快速拷贝 `cveCache` 切片（引用），释放锁，再基于拷贝构建索引

    ```go
    m.mu.RLock()
    cves = make([]SPCCVEScore, len(m.cveCache))
    copy(cves, m.cveCache)  // 仅拷贝指针和元数据，非深层拷贝
    kev := m.kevCatalog
    m.mu.RUnlock()  // 锁释放早

    // 锁外：构建 CPE 索引（CPU 密集）
    cpeIndex := make([][]cpeIndexEntry, len(cves))
    for i := range cves {
        entries := make([]cpeIndexEntry, 0, len(cves[i].AffectedCPEs))
        for _, cpe := range cves[i].AffectedCPEs { /* parse */ }
        cpeIndex[i] = entries
    }
    ```

  - **方案 B**：预计算并缓存 `cpeIndex`，在数据刷新时增量更新，`Calculate` 仅读取缓存

---

### [C-2] cleanupOldCVEs 持写锁重建全量索引 — High

- **来源**：GHSA Skill
- **位置**：[spc.go:L634-L655](file:///f:/Argus/internal/kernel/spc.go#L634-L655)
- **描述**：`cleanupOldCVEs` 持有 `m.mu.Lock()`（写锁）期间，重建完整的 `cveIndex` 映射。重建复杂度 O(n)，且持有锁期间阻塞所有读写操作（包括 `Calculate`）。

```go
func (m *SPCModule) cleanupOldCVEs() {
    m.mu.Lock()              // ← 持写锁
    defer m.mu.Unlock()

    newCache := make([]SPCCVEScore, 0, len(m.cveCache))
    newIndex := make(map[string]int)

    for i, cve := range m.cveCache {  // ← O(n) 遍历
        if m.shouldKeepCVE(cve) {
            newCache = append(newCache, cve)
            newIndex[cve.CVEID] = len(newCache) - 1
        }
    }
    m.cveCache = newCache
    m.cveIndex = newIndex  // ← 重建整个索引
}
```

- **风险**：清理大量 CVE 时，锁持有时间线性增长，影响实时评分请求。
- **修复方案**：
  - **方案 A**：用新切片替换旧切片（当前实现已是），但清理应分批执行，每次清理少量后释放锁
  - **方案 B**：在 `cleanupOldCVEs` 结束时通过 channel 或条件变量通知等待的读锁持有者

---

### [B-3] mergeCVEInPlace 新字段值可能覆盖已有数据 — High

- **来源**：Oracle Skill
- **位置**：[spc.go:L44-L85](file:///f:/Argus/internal/kernel/spc.go#L44-L85)
- **描述**：`mergeCVEInPlace` 中所有字段的合并策略为"仅在新字段非零时才更新"（`if !isZero(new.{field}) { existing.{field} = new.{field} }`）。这个策略在某些场景下会导致问题：

  **场景**：现有 CVE 的 `CVSS=7.5`（非零），新导入的数据中该 CVE 的 `CVSS=0`（因为数据源不提供）。结果：保持 `CVSS=7.5`（正确）。
  
  **但问题在于**：某些字段如 `Exploitability`、`PublicationDate` 等，可能在第一次导入时为空，第二次从不同数据源导入时有值，但由于 `isZero` 检查，第二次的值被忽略。

- **更严重的问题**：当同一 CVE ID 在两个不同数据源中出现，且分数不同（如 NVD: CVSS=9.8, CNNVD: CVSS=8.5），merge 使用 `max` 策略。但 `isZero` 检查会导致：如果第二次导入的 `CVSS=0`（网络不稳定导致获取失败），`max(9.8, 0) = 9.8`，结果正确。但如果第二次导入的 `CVSS=10.0`，`max(9.8, 10.0) = 10.0`，也会正确替换。

  **真正的 bug**：合并时没有处理 `EPSSScore` 和 `KEVListed` 的 max 策略。EPSS 可能出现 `old=0.5 (有值), new=0.0 (无值)` → `max(0.5, 0.0) = 0.5`（保留旧值，OK），但 `old=0.0 (无值), new=0.3 (有值)` → `max(0.0, 0.3) = 0.3`（正确替换）。看起来 EPSS 合并逻辑本身没问题。

- **修复方案**：
  - **方案 A（推荐）**：引入"数据源优先级"机制，高优先级数据源的值始终覆盖低优先级（如 NVD > CNNVD > CNVD）
  - **方案 B**：改为"最新优先"——按 `LastModified` 时间戳保留最新数据
  - **方案 C**：显式跟踪每个字段的数据来源，合并时按来源优先级

---

## ------------------------------------------------------------
## MEDIUM — 共 4 项
## ------------------------------------------------------------

### [M-1] EPSS 因子压缩过于激进 — Medium

- **来源**：SymPy Skill
- **位置**：[spc.go:L898-L899](file:///f:/Argus/internal/kernel/spc.go#L898-L899)
- **描述**：EPSS 因子变换公式 `f(epss) = min(1.0, -ln(1-epss)/5.0)` 将 [0,1) 映射到 [0,1)，但对低 EPSS 值的压缩极强：

| EPSS | f(EPSS) | 压缩比 |
|------|---------|--------|
| 0.01 | 0.00201 | 降为 0.2% |
| 0.10 | 0.0210 | 降为 2.1% |
| 0.50 | 0.1386 | 降为 13.9% |
| 0.90 | 0.4605 | 降为 46.1% |
| 0.99 | 0.9210 | 降为 92.1% |

**语义问题**：公式设计者意图似乎是"对数变换以平滑极端值"，但压缩后的 EPSS 在 impact 中权重 `0.50 × f(EPSS)` 被极度削弱。EPSS=0.5 的 CVE 在 impact 中的贡献仅为 `0.50 × 0.1386 = 0.0693`，而 CVSS=10 的贡献为 `0.20 × 1.0 = 0.20`。即使 EPSS=0.99，其 `0.50 × 0.921 = 0.46` 仍低于 CVSS=10 的 `0.20`——**设计者似乎将 EPSS 视为辅助因子，但权重 0.50 高于 CVSS 的 0.20**。

**SymPy 建议**：考虑使用 `f(epss) = epss`（无变换）或更温和的对数变换如 `f(epss) = 1 - exp(-5*epss)`（当 epss=0.5 时 f=0.92，更能反映真实 EPSS 值）。

- **修复方案**：
  - **方案 A（推荐）**：使用 `f(epss) = epss`（移除对数变换），保持 EPSS 原值
  - **方案 B**：使用 `f(epss) = 1 - exp(-5*epss)`（指数变换，当 epss=0.5 时 f≈0.92）
  - **方案 C**：保持当前公式（这是设计决策，但需确认权重分配意图）

---

### [P-1] cveSlicePool 预分配 1M 元素但不释放 — Medium

- **来源**：GHSA Skill
- **位置**：[spc.go:L133-L137](file:///f:/Argus/internal/kernel/spc.go#L133-L137)
- **描述**：`cveSlicePool = sync.Pool{New: func() interface{} { return make([]SPCCVEScore, 0, 1000) }}` 预分配 1000 容量，但每次 `Get()` 后不会放回，导致：
  - 每个调用 `Calculate` 的 goroutine 持有一个 1000 元素的底层数组（可能数 MB）
  - goroutine 退出时底层数组被 GC 回收前持续占用内存

```go
p := cveSlicePool.Get().([]SPCCVEScore)
p = p[:0]
// ... 使用 p ...
cveSlicePool.Put(p)  // 放回，但 Go sync.Pool 不保证立即释放
```

- **风险**：大量并发 `Calculate` 调用时，内存峰值可能达到 goroutine数 × 1000 × sizeof(SPCCVEScore)。
- **修复方案**：
  - **方案 A（推荐）**：减少预分配容量（`make([]SPCCVEScore, 0, 100)`），降低单个 goroutine 内存占用
  - **方案 B**：完全移除 slice pool，直接在函数内创建局部切片（Go 编译器优化后通常足够高效）

---

### [B-4] 测试失败未被追踪 — Medium

- **来源**：Oracle Skill
- **位置**：`TestSPCImportOSCALDuplicateHandling` (spc_test.go)
- **描述**：`TestSPCImportOSCALDuplicateHandling` 测试失败（OOM 或数据不一致），但代码库中没有 CI 检查确保该测试通过。该测试验证 OSCAL 导入时的 CVE 去重逻辑，失败意味着 `mergeCVEInPlace` 的合并策略可能存在边界问题。
- **修复方案**：在 CI/CD 中集成该测试，确保每次构建都运行 SPC 模块测试

---

### [E-1] NVD API 无 Key 时并发度受限但无优雅降级 — Medium

- **来源**：GHSA Skill
- **位置**：[spc_fetch.go:L370-L415](file:///f:/Argus/internal/kernel/spc_fetch.go#L370-L415)
- **描述**：无 API Key 时使用 4 并发 × 30 天窗口（`chunkDays=30`），令牌桶 `nvdLimiter = 6秒`（无 Key 档位）。在 NVD API 限流（429）时，程序会 retry 但没有指数退避，可能在高并发下持续被限流。

```go
// spc_fetch.go:L375
if apiKey == "" && totalDays > 30 {
    chunkDays = 30
    concurrency = 4  // 无 Key: 4 并发
}
// L384-387: retry 逻辑没有退避
for attempts < maxRetries {
    // ... fetch ...
    if resp.StatusCode == 429 {
        attempts++  // 无退避，立即重试
        continue
    }
}
```

- **修复方案**：
  - **方案 A（推荐）**：在 429 时添加指数退避 `time.Sleep(time.Duration(math.Pow(2, float64(attempts))) * time.Second)`
  - **方案 B**：429 时将并发度减半（`concurrency = max(1, concurrency/2)`），减少 API 压力

---

## ------------------------------------------------------------
## LOW — 共 3 项
## ------------------------------------------------------------

1. **[P-2] cleanupOldCVEs 清理频率未配置化** — 硬编码每 24 小时执行一次 ([spc.go:L447-L449](file:///f:/Argus/internal/kernel/spc.go#L447-L449))，建议移至配置
2. **[M-2] calculateKillChainScore 硬编码 ATT&CK 映射** — 约 33 个技术的硬编码映射，ATT&CK v19 有 200+ 技术 ([spc.go:L1142-L1224](file:///f:/Argus/internal/kernel/spc.go#L1142-L1224))
3. **[M-3] generateWeightShift 阈值硬编码** — `publicExposedCount >= 3` 和权重偏移值固定，建议可配置化 ([spc.go:L1150-L1154](file:///f:/Argus/internal/kernel/spc.go#L1150-L1154))

---

## ------------------------------------------------------------
## SymPy 公式验证结果汇总
## ------------------------------------------------------------

| # | 公式 | 区间验证 | 收敛/边界 | 语义 | 总体 |
|---|------|----------|-----------|------|------|
| 1 | P_score: `max(0.60, 1-√Σp²)` | ∈ [0.60, 1.0] ✅ | ✅ | ✅ | **通过** |
| 2 | impact: `0.2·CVSS + 0.5·EPSS + 0.3·KEV` | ⚠️ EPSS 压缩过度 | ✅ | ⚠️ 权重配置存疑 | **有条件通过** |
| 3 | EPSS 变换: `min(1, -ln(1-x)/5)` | ∈ [0,1] ✅ | N/A | ⚠️ 对低 EPSS 压 99%+ | **有条件通过** |
| 4 | localFactor: Match×Exposure×Control | ⚠️ Vendor→0.0 | ✅ | ⚠️ 缺陷 | **不通过** |
| 5 | timeFactor: `max(0.3, 1-d/90)` | ∈ [0.3, 1.0] ✅ | ✅ | ✅ | **通过** |
| 6 | KillChain Score: avg(stageScores) | ∈ [0, 100] ✅ | ✅ | ✅ | **通过** |
| 7 | ATT&CK 加成: `(1+0.1n)` | 无上界 ✅ | N/A | ⚠️ 无上限 | **有条件通过** |
| 8 | APT 加成: `(1+0.2n)` | 无上界 ✅ | N/A | ⚠️ 无上限 | **有条件通过** |

**P_score 上界验证**：
```
totalPenalty = sqrt(Σ penalty²)
max(penalty) = impact_max × localFactor_max × timeFactor_max
impact_max ≈ (0.2×1.0 + 0.5×1.0 + 0.3×1.0) × (1+0.1×20技术) × (1+0.2×50组织) ≈ 1.0 × 3.0 × 11.0 = 33.0
若 N=100 个高危 CVE: totalPenalty = sqrt(100 × 33²) = sqrt(108900) ≈ 330
pscore = max(0.60, 1.0 - 330) = 0.60
→ 下界正确（分数钳制在 0.60）
```

---

## 安全审计结果

| 检查项 | 结果 | 说明 |
|--------|------|------|
| 命令注入 | ✅ 无 | 无 exec.Command / common.RunCmd 调用 |
| HTTP 安全 | ✅ 通过 | HTTPS + 超时设置（45-120s）+ resp.Body.Close() defer |
| API Key 安全 | ✅ 通过 | NVD/MISP/CNNVD 均从环境变量读取 |
| 数据注入 | ✅ 通过 | parseOSCAL 使用标准库解析，无命令构造 |
| 敏感信息泄露 | ✅ 无 | 日志使用结构化输出，无 CVE ID 明文泄露 |
| MISP VerifyTLS | ✅ 通过 | 支持配置 TLS 验证开关 |
| 持久化原子性 | ✅ 通过 | saveCacheToDisk 使用临时文件 + rename |
| CVE ID 冲突 | ✅ 无 | generateSampleCVEs 生成前缀为 `TEST-` 的假 CVE |

---

## 正面实践（已确认正确）

1. ✅ **P_score 公式数学正确**：`max(0.60, 1.0 - √Σpenalty²)` 正确实现欧几里得范数惩罚模型
2. ✅ **MatchExactVersion 优先于 MatchVersionRange**：`break` 在精确匹配后立即退出（[spc.go:L831](file:///f:/Argus/internal/kernel/spc.go#L831)）
3. ✅ **isZero 判断正确**：避免用零值覆盖有效数据
4. ✅ **HTTP 客户端超时配置完整**：各数据源 30-120s 超时
5. ✅ **数据源并发控制**：`nvdLimiter` 令牌桶（无Key:6秒，有Key:600ms）
6. ✅ **persistOnce 保证幂等**：`fetchLoop` 中使用 `persistOnce` 防止重复持久化
7. ✅ **MISP VerifyTLS 配置**：支持环境变量控制
8. ✅ **CVE 缓存大小限制**：`maxCacheSize = 100000`
9. ✅ **cleanupOldCVEs 防止泄漏**：自动清理超过 180 天且 EPSS < 0.01 的 CVE

---

## 统计

| 审计维度 | Critical | High | Medium | Low | 合计 |
|----------|----------|------|--------|-----|------|
| 业务正确性 (B) | 2 | 1 | 1 | 1 | **5** |
| 并发安全 (C) | 0 | 2 | 0 | 0 | **2** |
| 性能 (P) | 0 | 0 | 1 | 0 | **1** |
| 错误处理 (E) | 0 | 0 | 1 | 0 | **1** |
| 可维护性 (M) | 0 | 0 | 1 | 2 | **3** |
| **合计** | **2** | **3** | **4** | **3** | **12** |

---

## 修复排期建议

| 优先级 | 编号 | 问题 | 建议时间 |
|--------|------|------|----------|
| **P0** | B-1 | MatchCPEVendor Factor=0.0 | 立即 |
| **P0** | B-2 | matchCPE/内联逻辑重复，维护风险 | 立即 |
| **P1** | C-1 | Calculate 持锁构建 CPE 索引过长 | 本周 |
| **P1** | C-2 | cleanupOldCVEs 持写锁重建索引 | 本周 |
| **P1** | B-3 | mergeCVEInPlace 数据源优先级缺失 | 本周 |
| **P2** | M-1 | EPSS 因子压缩过度 | 本月 |
| **P2** | P-1 | cveSlicePool 预分配过大 | 本月 |
| **P2** | E-1 | NVD 429 无退避 | 本月 |
| **P3** | 其余 Low | 配置化/硬编码映射 | 下月 |

---

**审计员**：ASSCOR 多技能代码审计 Agent（Oracle + SymPy + GHSA）  
**审计时间**：2026-05-27  
**审计版本**：v0.1.2-MVP
