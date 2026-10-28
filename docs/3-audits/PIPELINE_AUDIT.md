# ASSCOR 全自动化工作链路审计: 探测→响应→报告→修复→验证→归档

**日期**: 2026-07-12 | **审查范围**: 6 阶段全链路 | **方法**: 逐接口/组件/事件追踪，自底向上验证集成点

---

## 执行摘要

| 阶段 | 状态 | 核心问题 |
|------|:--:|------|
| Detect (探测) | :green_circle: 完整 | 6 条并行检测路径，覆盖全面 |
| Respond (响应) | :green_circle: 完整 | 策略驱动自动行动+命令下发，但行动粒度粗 |
| Report (报告) | :green_circle: 完整 | 9 条报告通道，覆盖 SIEM/OSCAL/WebUI/控制台 |
| Remediate (修复) | :yellow_circle: 骨架就绪 | 管理适配器偏向**可读**，**可写路径**仅命令系统 |
| Verify (验证) | :yellow_circle: 隐式 | 依赖下次 heartbeat 隐式验证，无显式 verify 状态 |
| Archive (归档) | :green_circle: 完整 | 3 层持久化 + 快照 + 归档 + HMAC 签名 |

**:green_circle: 组件具备能力**，**:yellow_circle: 修复→验证环节存在集成断层**，需补 3 处。

---

## 一、Detect (探测) — :green_circle: 6 条路径

### 1.1 检测路径拓扑

```
1. Agent Heartbeat → HeartbeatRequest{Checks} → KernelServiceImpl.Heartbeat()
   → AssessorModule.EvaluateFromResults()         [主动推送]
2. SPC 漏洞检测 → FetchFromAllSources(NVD+EPSS+KEV+CNNVD+CNVD+MISP)
   → Calculate(hostID, packages) → CVE匹配+kill-chain评分  [被动扫描]
3. SRD 外部工具扫描 → scanLoop() 目录监听
   → Adapter.Parse() → Pipeline.Process() → Prism评分   [被动扫描]
4. ATT&CK 攻击面 → CalculateCoverage(checkResults)
   → AssessKillChain() → 覆盖率+杀伤链映射             [推算引擎]
5. Config 变更检测 → ConfigWatcher.watchLoop() (30s 轮询)
   → SIGHUP 信号 → forceReload()                       [配置感知]
6. 自检 → AssessorModule.selfAssessmentLoop() (6h)
   → kernel 自身评分                                   [内省]
```

### 1.2 关键组件

| 组件 | 文件 | 行 | 能力 |
|------|------|:--:|------|
| 并发 check 执行 | `engine/assessor.go` | 474 | goroutine 池+信号量限流 |
| Check 注册表 | `checks/registry.go` | 14 | 线程安全，支持按域筛选 |
| 扩展 check 执行 | `extmgr/extension_executor.go` | 199 | 动态加载插件执行 check |
| SPC 多源拉取 | `kernel/spc_fetch.go` | 24 | 6 个数据源并行拉取 |
| OSCAL 导入 | `kernel/spc.go` | 907 | 合规框架 CVE 数据导入 |
| 行为基线检测 | `kernel/attck_apt_detect.go` | 109 | 基线偏离检测 |

**结论**: :green_circle: 探测阶段 6 条路径全部就绪，覆盖主动推送+被动扫描+推算+配置感知+自检。

---

## 二、Respond (响应) — :green_circle: 策略驱动

### 2.1 响应链路

```
评估完成 → bus.TopicAssessorResult
  ├→ PolicyModule.onAssessmentResult() [policy.go:90]
  │   ├→ EvaluateHost() → 分数映射动作 [policy.go:111]
  │   │   Score < Threshold     → notify_admin
  │   │   Score < Threshold-10  → notify_admin
  │   │   Score < Threshold-30  → notify_admin + increase_assessment
  │   │   Score < Threshold-30+ → isolate_host + notify_admin
  │   └→ Prism 崩塌预判 → CollapseRisk > 0.7 → isolate_host [policy.go:173]
  │
  │   └→ PublishSync("policy.action") [policy.go:151]
  │       └→ CommanderModule.onPolicyAction() [commander.go:340]
  │           └→ EnqueueCommand(hostID, action, ...) [commander.go:257]
  │               └→ HMAC-SHA256 签名 [commander.go:316]
  │
  ├→ 下次 heartbeat → DequeueCommands(hostID) → Agent 执行
  │
  ├→ ATT&CK 响应
  │   ├→ RunEmulation(scenario) [attck_emulation.go:269]
  │   ├→ ExecuteHunt(hypothesis) [attck_apt_hunt.go:111]
  │   └→ ReconstructAttackChain(hosts) [attck_apt_chain.go:19]
  │
  └→ 拦截器链
      ├→ CircuitBreaker → 故障隔离 [circuitbreaker.go]
      └→ RateLimiter → 过载保护 [ratelimit.go]
```

### 2.2 命令下发安全

**HMAC-SHA256 签名** (`commander.go:316-329`): 每个下发的命令携带确定性签名（hostID+commandID+key → HMAC），Agent 端验证以防伪造。

### 2.3 通知通道

当前 `notify_admin` 动作的定义是策略模块内部的 strings，**未连接到具体通知实现**（邮件/Webhook/钉钉/Slack 等）。响应"决策"完整，但响应"通知"缺实现。

**结论**: :green_circle: 策略驱动的自动响应链路完整（分数→决策→签名命令→队列→下发），**:yellow_circle: 通知实现待补**。

---

## 三、Report (报告) — :green_circle: 9 条通道

| # | 通道 | 组件 | 输出 |
|---|------|------|------|
| 1 | 控制台报告 | `engine.PrintReport()` | 终端可读文本 |
| 2 | SIEM 推送 | `SIEMPusher.PushAssessment()` | Wazuh REST API 事件 |
| 3 | OSCAL 导出 | `oscal_export.go` | NIST SP 800-53 JSON/XML |
| 4 | Prism IR | `assessor.go:843-856` | 中间表示 JSON |
| 5 | ATT&CK 覆盖报告 | `CalculateCoverage()` | 战术/技术/缓解覆盖率 |
| 6 | ATT&CK 杀伤链报告 | `AssessKillChain()` | 阶段评分+弱点定位 |
| 7 | APT 分析报告 | `GenerateAPTAnalysisReport()` | 归因+风险+建议 |
| 8 | 差距分析报告 | `PerformGapAnalysis()` | MITRE 覆盖差距+改进计划 |
| 9 | WebUI 仪表板 | `server.go` `handleDashboard()` | HTTP JSON API + HTML |

### 关键集成点

- `assessor.go:152-155` — 每次评估后 `pushToSIEM()` 异步推送
- `oscal_export.go` — 完整的 NIST SP 800-53 Rev5 映射（SSAM 分数→OSCAL 风险分、域分→控制评估、check→观察项、Prism→风险特征化）
- `webui/module.go:33-35` — 通过 bus 事件维护内存缓存（每个 host 保留 200 条历史）

**结论**: :green_circle: 报告体系完整，多格式多通道。

---

## 四、Remediate (修复) — :yellow_circle: 骨架完备，执行通路窄

### 4.1 现有修复路径

```
Policy → EnqueueCommand(hostID, "isolate_host" / ..., payload)
   ↓
Heartbeat → DequeueCommands() → Agent 执行
   ↓
Agent → ExecuteCommand() → AckCommand()
```

唯一的修复执行通道是 **命令系统**。命令内容取决于 Agent 端实现，kernel 不提供标准修复步骤库。

### 4.2 管理适配器 — 读多写少

10 个管理适配器均已实现，但 **全部为只读**（获取/查询/解析），无写操作：

| 适配器 | 操作 | 方向 |
|--------|------|:--:|
| Ansible | 解析 inventory 文件 | :arrow_left: 读 |
| NetBox | 查询 DCIM 资产 | :arrow_left: 读 |
| Snipe-IT | 查询 IT 资产 | :arrow_left: 读 |
| FreeIPA | 枚举用户/组/主机 | :arrow_left: 读 |
| Keycloak | 枚举 realm/用户 | :arrow_left: 读 |
| Wazuh | 查询 Agent 状态 | :arrow_left: 读 |
| Rundeck | 查询执行器状态 | :arrow_left: 读 |
| Jira | 查询用户信息 | :arrow_left: 读 |
| Terraform | `terraform show -json` | :arrow_left: 读 |
| OpenTofu | `tofu show` | :arrow_left: 读 |

**问题**: 适配器只负责**发现**，不负责**修复**。没有 `Ansible.ApplyPlaybook()`, `Terraform.Apply()`, `Jira.CreateTicket()`, `Rundeck.RunJob()` 等写操作。

### 4.3 扩展点开放但未接线

`extension_executor.go:199` 定义 `ExtensionExecutor.ExecuteCheck()`，扩展管理器支持：
- `assessor.pre_evaluate` / `assessor.post_evaluate` (评估钩子)
- ATT&CK 12 个扩展点
- SPC 3 个扩展点

**但没有 `remediation` 扩展点**。扩展体系未为修复阶段预留挂载位置。

### 4.4 ImprovementTrack 无执行桥接

`attck_assessment.go:397` 创建改进跟踪，`CalculateImprovementProgress()` 计算进度。但改进动作（`ImprovementAction`）是纯状态标记，**不会触发命令下发或适配器写操作**。

### 4.5 委派规则存在但偏检测

`adapter/delegation.go:17-108` 定义了适配器发现→域映射（如 ansible→OT-001），但 `ApplyDelegation()` 仅转换数据格式，不触发修复行动。

**结论**: :yellow_circle: **修复骨架已就绪（命令队列+策略触发+委派映射），但缺少三个关键组件：**
1. 管理适配器缺少写操作（Ansible apply / Terraform apply / Rundeck run / Jira create）
2. 无 `remediation` 扩展点
3. ImprovementTrack → Command 无桥接

---

## 五、Verify (验证) — :yellow_circle: 隐式路径

### 5.1 现有验证机制

| 机制 | 位置 | 方式 |
|------|------|------|
| 重算分数 | `RecomputeFinalScore()` | 不重跑 check，仅用已有域分重算 |
| 重新评估 | `Evaluate()` / `GetSnapshot()` | 重跑全部 check + 评分 |
| Heartbeat 隐式验证 | `Heartbeat()` | Agent 再次上报 check 结果 |
| 命令确认 | `AckCommand()` | Agent 报告命令执行结果 |
| 算法完整性 | `VerifyAlgo()` | 哈希校验 SSAM/Prism 常量 |
| 自检 | `selfAssessmentLoop()` | 每 6h 自评 kernel |

### 5.2 缺失的显式验证环节

1. **修复后验证检查**: 没有 "verify_after_remediation" 类型的 check — 不会在代理执行修复后自动触发专门的验证 check 集合
2. **验证状态跟踪**: `AckCommand` 记录执行结果，但没有"预期状态"→"实际状态"的比对逻辑
3. **闭环反馈**: Policy → Command → Ack → 下次 Heartbeat 构成隐式闭环，但**没有独立的 verify 阶段确认修复是否产生预期效果**。当前依赖"下次 heartbeat 分数上升"作为验证信号，非显式比对

**结论**: :yellow_circle: **验证机制存在但为隐式**。缺乏：
1. 显式 verify check 类型
2. 修复前后状态比对
3. 验证状态机（pending_verify → verified_ok → verified_failed → re_remediate）

---

## 六、Archive (归档) — :green_circle: 三级存储

### 6.1 持久化层级

```
Layer 1: 实时刷新 (30s) → data/*.jsonl
Layer 2: 每小时快照 → data/snapshots/snapshot-YYYYMMDD-HHMMSS.jsonl (保留 24)
Layer 3: 每日归档 → data/archives/asscor-data-YYYYMMDD.tar.gz (保留 90)
```

### 6.2 归档数据类型

| 数据集 | 方法 | 内容 |
|--------|------|------|
| assessments | `WriteAssessment()` | 完整评估记录（域分+边缘因子+ATT&CK+Prism+SPC CVE） |
| dashboard | `WriteDashboardReport()` | 最新评估摘要（原子写入 `latest-assessment.json`） |
| audit | `WriteAudit()` | gRPC 审计日志（调用者+服务+方法+耗时+结果） |
| commands | `WriteCommand()` | 命令记录 |
| cve_cache | `WriteCVECache()` | CVE 缓存 |

### 6.3 归档签名

**HMAC-SHA256** (`integrity/sign.go:67-80`): 每次 `Evaluate()` 和 `EvaluateFromResults()` 后自动签名（HostID+Hostname+timestamp+score+acceptable+domain_scores+SPC_score+check_count）。Archive 中的评估记录携带此签名，可用于审计追踪。

### 6.4 趋势计算

`HistoricalStore.ComputeTrends()` (`historical_store.go:39-127`): 按 host 聚合每日评分，计算风险趋势。`ComputeRiskLevels()` 提供风险关联度。

### 6.5 WebUI 历史缓存

`webui/module.go:33-35`: 内存中保留每个 host 最近 200 条评估结果，通过 API `/api/hosts/{hostID}/history` 暴露。

**结论**: :green_circle: 归档体系完整，3 层存储 + HMAC 签名 + 自动轮替。

---

## 七、扩展体系在链路中的角色

### 7.1 已定义的扩展点

| 扩展点 | 阶段 | 位置 |
|--------|------|------|
| `assessor.pre_evaluate` | Detect | `assessor.go:125` |
| `assessor.post_evaluate` | Report | `assessor.go:130` |
| `attck.*` (12 个) | Detect/Respond | `attck.go:304-364` |
| `spc.*` (3 个) | Detect | `spc.go:138-148` |

**26 个扩展点均已定义**，但当前 **0 个订阅者**（框架上限问题）。

### 7.2 缺失的扩展点

| 缺失扩展点 | 所属阶段 | 用途 |
|------------|------|------|
| `remediation.pre_apply` | Remediate | 修复前钩子 |
| `remediation.post_apply` | Remediate | 修复后钩子 |
| `remediation.verify` | Verify | 验证钩子 |
| `policy.notify` | Respond | 通知分发钩子 |
| `archive.pre_write` | Archive | 归档前转换钩子 |

**扩展体系未覆盖链路后半段（修复→验证→归档）**。

---

## 八、链路断层分析

```
Detect ──────→ Respond ──────→ Report
    :green_circle:            :green_circle:            :green_circle:
    6 路径完整            策略决策完整            9 通道完整
                        通知实现待补

                                    ↓
                              Remediate ──────→ Verify ──────→ Archive
                                :yellow_circle:          :yellow_circle:          :green_circle:
                              骨架就绪              隐式路径              3 层存储
                              缺 3 项:             缺 3 项:             HMAC 签名
                              ① 适配器写操作      ① verify check 类型
                              ② remediation 扩展点  ② 前后状态比对
                              ③ Track→Command 桥接  ③ verify 状态机
```

**最大断层**: **Remediate 阶段**。策略已能自动决策"需要修复"，命令已能安全下发，但"具体修复什么"的**动作库为空**。管理适配器全是只读探头，没有任何写操作。

---

## 九、建议补全方案

### 9.1 Remediate: 补管理适配器写操作 (Priority: P0)

```
Ansible适配器  + ApplyPlaybook(playbook, inventory)
Terraform适配器 + Apply(plan)
Rundeck适配器  + RunJob(jobID, options)
Jira适配器     + CreateTicket(summary, description, priority)
```

### 9.2 Remediate: 注册扩展点 (Priority: P1)

在 `assessor.go` 扩展注册处添加:
```go
kc.Extensions().RegisterPoint(ExtensionPoint{
    Name:    "remediation.pre_apply",
    Description: "Before executing a remediation action",
})
kc.Extensions().RegisterPoint(ExtensionPoint{
    Name:    "remediation.post_apply",
    Description: "After executing a remediation action",
})
```

### 9.3 Verify: 显式 verify 状态 (Priority: P1)

1. 新增 `verify_check` 类型的 check（轻量级，设计为快速再验证目标已修复）
2. 在 Policy 模块中添加状态机: `pending_verify → verified_ok|verified_failed → (re_remediate|close)`
3. 命令 Ack 后、下次 heartbeat 前，自动调度 verify check

### 9.4 Verify+Respond: 通知实现 (Priority: P2)

实现 `policy.notify` 扩展点，对接 Webhook/SMTP/钉钉/Slack 等通知通道。

### 9.5 Respond: Track→Command 桥接 (Priority: P2)

`ATTACKModule` 的 `ImprovementTrack` → 通过 `CommanderModule` 下发改进动作命令。

---

## 十、总体评分

| 维度 | 评分 | 评语 |
|------|:--:|------|
| **链路完整性** | **B+** | 6 阶段骨架全部存在，修复/验证为隐式 |
| **自动化程度** | **B** | 探测→响应→报告 全自动，修复需 Agent 端实现 |
| **扩展体系覆盖** | **C+** | 26 个扩展点全在 Detect/Respond，遗漏后半程 |
| **安全审计** | **A** | HMAC 签名命令+归档，完整性和不可否认性充足 |
| **闭环能力** | **B** | 隐式闭环（heartbeat 再评估），非显式 verify 状态 |

**:green_circle: ASSCOR 具备"探测→响应→报告→修复→验证→归档"的骨架能力，但修复阶段执行通路窄（仅命令系统），验证阶段为隐式（依赖 heartbeat 自然闭环），扩展体系未覆盖 Remediate/Verify/Archive 三个阶段。建议按 P0→P2 顺序补全。**
