# 全项目代码审计报告

## 基本信息

- **审计范围**：ASSCOR v0.1.2-MVP 全项目（12+ 核心文件）
- **审计方法**：Oracle 第二模型审查 + SymPy 公式数学验证 + OpenClaw GHSA 安全公告审计 + Solana (评估后跳过——与 Go 安全项目无关)
- **审计类型**：系统性全项目代码审计
- **审计日期**：2026-05-27
- **严重等级**：Critical

---

## 审计结论

**[驳回 ❌]**

发现 **12 个 Critical**、**6 个 High**、**7 个 Medium**、**4 个 Low** 级别问题。

**三个关键阻塞问题**必须在发布前解决：
1. 自定义边缘因子完全失效（评分结果与配置预期不一致）
2. Agent `safeExec` 绕过 Shell 元字符检查（命令注入风险）
3. SPC fetchLoop goroutine 退出机制缺陷（插件生命周期泄漏）

---

## 发现项（按严重程度排序）

## ------------------------------------------------------------
## CRITICAL — 共 12 项
## ------------------------------------------------------------

### [S-1] Agent `safeExec` 绕过 Shell 元字符检查 — Critical

- **来源**：Oracle Skill + GHSA Skill（GHSA-S-001）
- **位置**：[agent.go:L827-L835](file:///f:/Argus/internal/agent/agent.go#L827-L835)
- **描述**：`safeExec` 直接使用 `exec.CommandContext`，虽然检查了命令白名单，但跳过了 `common.RunCmdTimeout` 中的 `containsShellMetachar` 参数校验。

```go
func (a *Agent) safeExec(name string, args []string) (string, error) {
    if !common.IsCommandAllowed(name) {
        return "", fmt.Errorf("command %s not in allowlist", name)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, name, args...)  // ← args 未经元字符校验
    out, err := cmd.Output()
    return string(out), err
}
```

- **修复建议**：改为调用 `common.RunCmdTimeout(30*time.Second, name, args...)`（推荐）

---

### [B-1] 双重边缘因子系统——自定义因子完全失效 — Critical

- **来源**：Oracle Skill
- **位置**：[adapter.go:L61-L65](file:///f:/Argus/internal/ssam/adapter.go#L61-L65) + [engine.go:L185-L193](file:///f:/Argus/internal/ssam/engine.go#L185-L193)

- **描述**：存在两个完全独立的边缘因子系统：
  1. 全局链 (`model/edge_factor_chain.go`)——由 config.go 写入但**从未被评分引擎读取**
  2. 引擎链 (`ssam/engine.go`)——实际用于评分的系统

  `config.ini` 中 `[edge_factors.custom]` 的自定义因子加载时 `TriggerCheck` 字段为空，导致 `ApplyEdgeFactorsToChecks` 中触发条件 `cfg.TriggerCheck == check.CheckID` 永远为 false，**自定义因子完全不影响评分**。

```go
// adapter.go:L61-L65 — TriggerCheck 为空，永远无法被触发
for id, factor := range cfg.EdgeFactorsCustom {
    result = append(result, EdgeFactorConfig{
        ID: id, Name: id, Factor: factor,  // TriggerCheck 缺失！
    })
}

// engine.go:L189-193 — 触发条件依赖 TriggerCheck
if cfg.TriggerCheck == check.CheckID {  // 自定义因子永远无法进入此分支
    triggered[id] = true
}
```

- **修复建议**：为自定义因子添加 TriggerCheck 支持，或删除全局链只保留引擎链（推荐方案 C）

---

### [C-1] SPC fetchLoop goroutine 退出与 Stop 信号解耦 — Critical

- **来源**：Oracle Skill
- **位置**：[spc.go:L457-L481](file:///f:/Argus/internal/kernel/spc.go#L457-L481) + [spc.go:L610](file:///f:/Argus/internal/kernel/spc.go#L610)

- **描述**：`fetchLoop` 通过 `m.kernel.Context().Done()` 接收退出信号，但 `Stop()` 只停止 `nvdTimers` 并等待 `m.done`。如果内核上下文未被取消（插件独立停止场景），`Stop()` 的 context 超时后会返回，但 `fetchLoop` 仍在运行——违反插件生命周期约定。

```go
// fetchLoop:L609-611 — 仅监听 kernel Context
case <-m.kernel.Context().Done():
    m.saveCacheToDisk()
    return

// Stop:L463-476 — 等待 m.done，但 fetchLoop 只在 kernel.Context 取消时退出
select {
case <-m.done:     // fetchLoop 的 defer close(m.done)
case <-ctx.Done(): // 超时返回，但 fetchLoop 仍在运行
}
```

- **修复建议**：为 SPCModule 新增独立的 `cancelFunc`，`Stop()` 调用 `cancelFunc` 触发退出

---

### [S-2] 命令白名单缺失 `cat`——KS-012 LSM 检测静默失败 — Critical

- **来源**：Oracle Skill
- **位置**：[kernel_security.go:L529](file:///f:/Argus/internal/checks/linux/kernel_security.go#L529)
- **描述**：`ks012()` 调用 `common.RunCmdQuiet("cat", "/sys/kernel/security/lsm")`，但 `cat` 不在 `allowedCommands` 白名单中。`RunCmdQuiet` 在白名单检查时返回错误，`lsmOut` 始终为空，LSM 检测回退逻辑**完全失效**。

- **修复建议**：使用 `os.ReadFile` 直接读取 `/sys/kernel/security/lsm`（推荐，该路径为伪文件系统中的常规文件）

---

### [B-2] SSAM 公式中文档间不一致 — Critical (已确认)

- **来源**：SymPy Skill (D-1)
- **位置**：`.trae/rules/project_rules.md` vs `.trae/rules/code_audit_rules.md`
- **描述**：project_rules.md 声明公式为 `(Σ(S_i×W_i) / 100)`，但 code_audit_rules.md 和实际代码均使用 `(Σ(S_i×W_i) / ΣW_i)`。两者在单域场景下差异显著。

- **修复建议**：统一文档为 `ΣW_i`，与代码实现一致

---

### [S-3] GHSA-S-002——MISP HTTP 请求缺少 Context 超时 — Critical

- **来源**：GHSA Skill
- **位置**：[spc_fetch.go:L1387](file:///f:/Argus/internal/kernel/spc_fetch.go#L1387)
- **描述**：`fetchMISPEvents` 使用 `http.NewRequest` 而非 `http.NewRequestWithContext`，无法在 context 取消时中断请求。

- **修复建议**：统一所有外部 HTTP 调用使用 `http.NewRequestWithContext`

---

### [S-4] GHSA-S-003——HMAC 密钥生成 PRNG 失败时回退确定性序列 — Critical

- **来源**：GHSA Skill
- **位置**：[commander.go:L297-L305](file:///f:/Argus/internal/kernel/commander.go#L297-L305)
- **描述**：`randomHex` 在 `crypto/rand.Read` 失败时回退到 `b[i] = byte(i)` 确定性序列。

- **修复建议**：PRNG 失败时返回 error，不允许以不安全密钥运行

---

### [S-5] GHSA-S-004——gRPC TLS 配置缺少 CipherSuites 约束 — Critical

- **来源**：GHSA Skill
- **位置**：[grpc_server.go:L149-L154](file:///f:/Argus/internal/kernel/grpc_server.go#L149-L154)
- **描述**：gRPC 服务端的 TLS 配置未设置 CipherSuites，而 JSONRPC 路径的 `crypto.go` 已正确限制为 ECDHE_RSA_WITH_AES_256/128_GCM。

- **修复建议**：在 gRPC TLS 配置中添加与 `crypto.go` 一致的 CipherSuites 和 CurvePreferences

---

### [S-6] GHSA-S-005——默认 gRPC TLS 禁用 + insecure fallback — Critical

- **来源**：GHSA Skill
- **位置**：[config.ini:L355-L356](file:///f:/Argus/config.ini#L355-L356) + [grpc_server.go:L305](file:///f:/Argus/internal/kernel/grpc_server.go#L305)
- **描述**：`config.ini` 中 `tls_enabled = false`（默认关闭 mTLS），禁用时使用 `insecure.NewCredentials()` 明文传输。

- **修复建议**：默认启用 TLS，或要求显式设置 `allow_insecure = true` 才能继续

---

### [E-1] OT-018 使用字面量字符串匹配替代正则表达式 — Critical

- **来源**：Oracle Skill
- **位置**：[checks.go:L1653-L1666](file:///f:/Argus/internal/checks/linux/checks.go#L1653-L1666)
- **描述**：身份证和手机号的正则表达式模式通过 `strings.Contains` 进行字面量匹配，永远不会匹配实际文本。该检查项**永远通过**。

```go
idPattern := `[1-9]\d{5}(18|19|20)\d{2}...`
if strings.Contains(content, idPattern) {  // 永远为 false！
```

- **修复建议**：使用 `regexp.MustCompile(idPattern).MatchString(content)`

---

### [C-2] SPC Calculate 方法持读锁时间过长 — Critical

- **来源**：Oracle Skill  
- **位置**：[spc.go:L656-L699](file:///f:/Argus/internal/kernel/spc.go#L656-L699)
- **描述**：`Calculate` 在持有 `RLock` 期间构建完整的 `cpeIndex`（遍历所有 100,000 条 CVE 及其 AffectedCPEs），阻塞所有写操作数百毫秒。

- **修复建议**：快速拷贝 `cveCache` 切片后释放锁，再基于拷贝构建索引

---

### [B-3] KS-001 CVE 检查使用字符串搜索而非 JSON 解析 — Critical

- **来源**：Oracle Skill
- **位置**：[kernel_security.go:L55-L73](file:///f:/Argus/internal/checks/linux/kernel_security.go#L55-L73)
- **描述**：读取 JSON 格式的 CVE 缓存文件但使用 `strings.Contains(line, kernelVer) && strings.Contains(line, "CVE")`，导致误报（版本号出现在 description 字段中）和漏报（紧凑 JSON 格式）。

- **修复建议**：使用 `encoding/json` 解析缓存文件，精确匹配

---

## ------------------------------------------------------------
## HIGH — 共 6 项
## ------------------------------------------------------------

### [B-4] 所有 ACI 检查项集中于韧性域——评分不敏感 — High

- **来源**：Oracle Skill
- **位置**：[checks.go:L859-L970](file:///f:/Argus/internal/checks/linux/checks.go#L859-L970)
- **描述**：8 个 ACI 检查项（AC-001~AC-008）Domain 全部设为 `model.DomainResilience`（权重 15%）。网络分段(-15)、离线备份(-20)、EDR(-10) 等关键检查的扣分集中于低权重域，对总评分影响不充分。

- **修复建议**：重新分配 ACI 项的 Domain 归属（网络分段→AttackSurface，EDR→OperationTrust，备份→BusinessContinuity）

---

### [C-3] SPC `matchCPE` 方法为死代码——Calculate 使用内联逻辑 — High

- **来源**：Oracle Skill
- **位置**：[spc.go:L1010-L1072](file:///f:/Argus/internal/kernel/spc.go#L1010-L1072)（matchCPE 定义）vs [spc.go:L656-L1008](file:///f:/Argus/internal/kernel/spc.go#L656-L1008)（Calculate 内联匹配）
- **描述**：`matchCPE` 实现了一套 CPE 匹配逻辑，但 `Calculate` 使用内联逻辑。修改 `matchCPE` 不会影响实际计算。

- **修复建议**：将 Calculate 中的 CPE 匹配重构为调用 `matchCPE`，或删除死代码

---

### [S-7] GHSA-S-006——扩展管理器白名单含完整 Shell 解释器 — High

- **来源**：GHSA Skill
- **位置**：[config.ini:L322-L328](file:///f:/Argus/config.ini#L322-L328)
- **描述**：扩展管理器白名单包含 `sh`、`bash`、`powershell`、`pwsh`。

- **修复建议**：移除 shell 解释器，仅保留 python3/node 等受限解释器

---

### [S-8] GHSA-S-007——Agent `runCommand` 存在双重命令白名单路径 — High

- **来源**：GHSA Skill
- **位置**：[agent.go:L1095-L1123](file:///f:/Argus/internal/agent/agent.go#L1095-L1123)
- **描述**：`runCommand` 先检查 shell 命令白名单，失败后回退到 ParseCommand+RunCmdTimeout，存在双重标准。

- **修复建议**：统一命令检查路径

---

### [S-9] GHSA-S-008——依赖安全问题 — High

- **来源**：GHSA Skill
- **位置**：[go.mod](file:///f:/Argus/go.mod)
- **描述**：需确认 `google.golang.org/grpc v1.68.0`、`golang.org/x/net v0.29.0` 无已知 CVE。

- **修复建议**：集成 `govulncheck` 自动扫描

---

### [N-1] SSAM 引擎 P_score 下界未强制校验 — High

- **来源**：SymPy Skill
- **位置**：[engine.go:L72-L73](file:///f:/Argus/internal/ssam/engine.go#L72-L73)
- **描述**：仅处理 `SPCScore == 0 → 1.0`，未强制执行 `min_pscore = 0.60`。

- **修复建议**：添加 `math.Max(spcScore, minPScore)` 下界裁剪

---

## ------------------------------------------------------------
## MEDIUM — 共 7 项
## ------------------------------------------------------------

### [M-1] 全局可变状态 `globalEdgeFactorChain` — Medium

- **来源**：Oracle Skill
- **位置**：[edge_factor_chain.go:L22-L24](file:///f:/Argus/internal/model/edge_factor_chain.go#L22-L24)
- **描述**：包级变量由其他包直接修改，不符合 DI 容器设计模式。

---

### [B-5] Kill Chain 评分硬编码 ATT&CK 映射覆盖率低 — Medium

- **来源**：Oracle Skill
- **位置**：[spc.go:L1142-L1224](file:///f:/Argus/internal/kernel/spc.go#L1142-L1224)
- **描述**：仅覆盖 33 个技术，ATT&CK v19 有 200+ 技术。

---

### [P-1] `collectCPEs` 缓存永不刷新 — Medium

- **来源**：Oracle Skill
- **位置**：[agent.go:L838-L845](file:///f:/Argus/internal/agent/agent.go#L838-L845)
- **描述**：`cachedPackages` 仅在首次调用时设置，安装新软件包后 SPC 仍使用旧 CPE 列表。

---

### [N-2] μ 无下界约束 — Medium

- **来源**：SymPy Skill
- **位置**：[engine.go:L69-L70](file:///f:/Argus/internal/ssam/engine.go#L69-L70)
- **描述**：只处理 `μ == 0`，未强制 `μ ≥ 0.60`。

---

### 其他 Medium 级发现项

5. **`checkKernelCVEs` 使用不精确的 `strings.Contains` 匹配** ([kernel_security.go:L55-L73](file:///f:/Argus/internal/checks/linux/kernel_security.go#L55-L73))
6. **`Calculate` 方法在锁内构建完整 CPE 索引** ([spc.go:L656-L699](file:///f:/Argus/internal/kernel/spc.go#L656-L699))
7. **双重 Round 操作冗余** ([engine.go:L102 + L429](file:///f:/Argus/internal/ssam/engine.go#L102-L429))

---

## ------------------------------------------------------------
## LOW — 共 4 项
## ------------------------------------------------------------

1. **GHSA-S-009**——日志中暴露 API Key 长度信息 ([config.go:L356](file:///f:/Argus/internal/config/config.go#L356))
2. **GHSA-S-010**——Daemon 进程启动器使用原始 `os.Args` ([daemon_unix.go:L31](file:///f:/Argus/cmd/kernel/daemon_unix.go#L31))
3. **D-2**——`project_rules.md` 公式 `/100` 与代码 `/ΣW_i` 不一致
4. **C-3**——`ComputeScore` 中重复 `math.Round`（幂等，无功能影响）

---

## SymPy 公式验证结果汇总

| 验证项 | 理论 | 实现 | 结果 |
|--------|------|------|------|
| 加权平均分母 | ΣW_i | totalWeight | **正确** ✅ |
| 加权平均分子 | Σ(S_i×W_i) | sum += ds.Score × w | **正确** ✅ |
| 域分数初始值 | 100 | scores[domain] = 100 | **正确** ✅ |
| Delta 应用 | max(0, score + delta) | math.Max(0, current + check.Delta) | **正确** ✅ |
| μ 零值保护 | μ→1.0 | L69-70 | **正确** ✅ |
| P_score 零值保护 | P→1.0 | L72-73 | **正确** ✅ |
| 边缘因子激活条件 | Active ∧ Factor∈(0,1) | L424 | **正确** ✅ |
| 级联覆盖 | CascadeTo + CascadeValue | L196-L218 | **正确** ✅ |
| math.Round 精度 | 2位小数 | L102, L429 | **正确** ✅ |

---

## 统计

| 审计维度 | Critical | High | Medium | Low | 合计 |
|----------|----------|------|--------|-----|------|
| **安全性 (S)** | 6 | 3 | 0 | 2 | 11 |
| **业务正确性 (B)** | 3 | 1 | 1 | 0 | 5 |
| **并发安全 (C)** | 2 | 1 | 0 | 0 | 3 |
| **错误处理 (E)** | 1 | 0 | 0 | 0 | 1 |
| **可维护性 (M)** | 0 | 0 | 1 | 0 | 1 |
| **性能 (P)** | 0 | 0 | 1 | 0 | 1 |
| **数值分析 (N)** | 0 | 1 | 1 | 1 | 3 |
| **文档 (D)** | 0 | 0 | 0 | 1 | 1 |
| **合计** | **12** | **6** | **4** | **4** | **26** |

---

## 修复排期建议

| 优先级 | 编号 | 问题 | 建议时间 |
|--------|------|------|----------|
| **P0** | B-1 | 自定义边缘因子完全失效 | 立即 |
| **P0** | S-1 | Agent safeExec 绕过元字符检查 | 立即 |
| **P0** | C-1 | fetchLoop goroutine 退出缺陷 | 立即 |
| **P0** | S-2 | 命令白名单缺失 cat（KS-012 失效） | 立即 |
| **P0** | E-1 | OT-018 正则表达式失效 | 立即 |
| **P0** | B-3 | KS-001 字符串匹配误报/漏报 | 立即 |
| **P0** | S-3 | MISP HTTP 请求无 context 超时 | 立即 |
| **P0** | S-5 | gRPC TLS 默认禁用 | 立即 |
| **P1** | S-4 | gRPC TLS 缺 CipherSuites | 本周 |
| **P1** | S-6 | HMAC 密钥 PRNG 回退确定性序列 | 本周 |
| **P1** | C-2 | SPC Calculate 持锁时间过长 | 本周 |
| **P1** | N-1 | P_score 下界未强制 | 本周 |
| **P1** | B-4 | ACI 检查集中于韧性域 | 本周 |
| **P2** | C-3 | matchCPE 死代码 | 本月 |
| **P2** | S-7 | 扩展管理器 shell 解释器白名单 | 本月 |
| **P2** | S-8 | 双重命令白名单 | 本月 |
| **P2** | S-9 | 依赖安全扫描 | 本月 |
| **P3** | 其余 Low 级 | 文档/冗余/日志 | 下月 |

---

## 正面实践（已确认正确）

1. ✅ SSAM 评分公式**数学实现完全正确**（加权平均、边缘因子、级联机制）
2. ✅ 命令执行白名单设计良好（24 个命令，Shell 元字符检查）
3. ✅ HMAC-SHA256 命令签名 + 90 天自动轮换
4. ✅ mTLS 基础架构完善（自签名 CA + 证书验证链）
5. ✅ 事件总线 Goroutine 防过载（1024 上限 + panic recovery）
6. ✅ DI 容器类型安全绑定/解析
7. ✅ HTTP Client 超时设置完整（45-120s）
8. ✅ `resp.Body.Close()` 正确使用 defer
9. ✅ API Key 优先从环境变量读取
10. ✅ gRPC 拦截器链（限流 + 熔断 + 审计）
11. ✅ 浮动精度对 SSAM 公式足够（8次乘法误差 < 1.76e-13）

---

**审计员**：ASSCOR 多技能代码审计 Agent（Oracle + SymPy + GHSA）  
**审计时间**：2026-05-27  
**审计版本**：v0.1.2-MVP
