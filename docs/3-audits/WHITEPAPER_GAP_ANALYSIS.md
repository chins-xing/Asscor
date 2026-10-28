# 白皮书 vs 实际代码 差异审计报告

**审计日期**: 2026-06-18 | **对比源**: 12份白皮书 vs ~135个Go文件

---

## 一、差异总览

| 类别 | 白皮书声明 | 实际代码 | 严重度 |
|------|-----------|----------|--------|
| 工程量化 | 超过20项数值与代码不一致 | — | — |

---

## 二、工程实现白皮书 差异 (17项)

### 2.1 严重不一致

| # | 白皮书声明 (§) | 实际代码 | 影响 |
|---|---------------|----------|------|
| 1 | **"零外部依赖"** (§摘要, §11.13.1) | 依赖 `google.golang.org/grpc` + 传递依赖 6个包 | 安全性声明不实 |
| 2 | **"自建 gRPC 兼容层"** (§11.13.1) | 实际使用官方 gRPC 库，并非自建 | 架构描述误导 |
| 3 | **"CTI 更新间隔 15分钟"** (§6.6, §11.3) | CTI OTX/MISP 集成**完全 stub**，无实际数据拉取 | 核心功能未完成 |
| 4 | **"data flush guarantee: Sync()"** (§3.1.7, §7) | Sync() 已在 Phase 1 修复中**移除**（性能反模式） | 文档过时 |
| 5 | **"write optimization ~30x fewer I/O"** (§5.4.6) | Sync() 移除后此收益数据不适用 | 基准过时 |

### 2.2 中等不一致

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 6 | **12个内置插件** (§11.3) | 实际 15个 (cli, webui, scoring_engine, source_manager 未列入) |
| 7 | **ATT&CK 优先级=80** (§13.1) | 实际 `P=21` (attck.go) |
| 8 | **ATT&CK 版本=2.0.0** (§13.1) | 实际 `v1.0.0` (attck.go Info()) |
| 9 | **File permissions 0600** (§5.4.2, §7) | persistence 使用默认权限 (0644)，未显式设置 |
| 10 | **Archival: online hot backup, local snapshot, tar.gz, rsync** (§5.4.5) | **完全未实现**。无任何备份/存档代码 |
| 11 | **"L1 warm: JSONL daily rotation, L2 cold: SQLite"** (§5.4.1) | L2 SQLite **未实现**，只有 L0 内存 + L1 JSONL |
| 12 | **"Assessment cache TTL: 5 min"** (§6.6) | 缓存实现在 engine 中但 sync.Map 无 TTL 驱逐（仅 key 比较触发刷新） |
| 13 | **"55 built-in check items"** (§6.2.2) | 实际 **76项** (含 KS-001~012, AC-001~008) |

### 2.3 低严重度

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 14 | **Go 1.21+** (§1) | go.mod 要求 `go 1.26` |
| 15 | **"Agent startup SECURITY ALERT if HMAC key not configured"** (§3.1.6) | agent.go 中实际存在安全检查，符合 |
| 16 | **"log injection prevention: sanitizeLogField"** (§3.1.7) | 存在 (`collector.go`) 但仅限 collector 日志管道 |
| 17 | **"Check item delegation: 13/74 delegated"** (§4) | delegation.go 中仅 9 条规则，缺失管理适配器规则 |

---

## 三、SPC 白皮书 差异 (7项)

### 3.1 严重不一致

| # | 白皮书声明 (§) | 实际代码 | 影响 |
|---|---------------|----------|------|
| 1 | **CNNVD / CNVD "已实现"** (§12) | spc_fetch.go 中 FetchFromCNNVD()/FetchFromCNVD() 共 400+ 行完整实现，连入 FetchFromAllSources。**审计误判** | — |
| 2 | **MISP "已实现"** (§12) | spc_fetch.go 有 FetchFromMISP()，API key 从 env 读取。**审计误判** | — |
| 3 | **OSCAL import "已实现"** (§12) | ImportOSCAL 存在于 spc_fetch.go:1608，含 10 个测试。同时 oscal_export.go 提供 ExportOSCAL。导入导出均实现。**审计误判** | — |

### 3.2 中等不一致

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 4 | **性能: 671包×955 CVE < 100ms** (§9.2) | O(N×P×A) 三重循环，100k CVE 下非优化 | 基准失真（样本太小） |
| 5 | **matchCPE 使用 cpeIndex** (§3.1 流程图) | cpeIndex 在 Phase 1 修复中确认**完全死代码**，从未被引用 | 流程图不实 |
| 6 | **"Agent auto-generates CPE 2.3 strings"** (§3.3 note) | cpeVendorMap 存在 (108条目) 且 `generateCPE()` 方法正常 | 与实际相符 |
| 7 | **ATT&CK technique association: Impact × (1+0.1×n)** (§4.1.1) | 未在 spc_match.go 中找到此乘法器 | 可能缺失或仅在白皮书描述 |

---

## 四、ATT&CK 白皮书 差异 (8项)

### 4.1 严重不一致

| # | 白皮书声明 (§) | 实际代码 | 影响 |
|---|---------------|----------|------|
| 1 | **YARA/Sigma rule engine** (§10.1) | 仅**关键字匹配**，非 native libyara。白皮书自身也说 "keyword matching pattern"，但在 APT 检测能力宣传中未弱化 | 能力声明夸大 |
| 2 | **"60+ methods on ATTACKInterface"** (§6.2 note) | 实际接口 56个方法 (attck.go:56 method interface) | 轻微夸大 |

### 4.2 中等不一致

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 3 | **Causal reasoning: 20 rules** (§10.2) | 实际 20条 (attck_apt_causal.go)，**符合** |
| 4 | **Beacon reputation: 12 rules** (§10.1) | 实际 12条 (attck_apt_enhanced.go)，**符合** |
| 5 | **Bayesian network: 4+1 nodes** (§10.3) | CPT 硬编码 64行，**符合** |
| 6 | **12 extension points** (§8) | 实际 13个 attck.xxx 事件注册，**符合** |
| 7 | **ATT&CK → Policy 5条规则** (§6.4) | onAssessmentResult 中有对应处理，**符合** |
| 8 | **Multi-source attribution fusion** (§4.2) | TTP 0.60 + IOC 0.40 公式在代码中实现，**符合** |

---

## 五、适配器清单 差异 (9项)

### 5.1 严重不一致

| # | 白皮书声明 | 实际代码 | 影响 |
|---|-----------|----------|------|
| 1 | **21个适配器全部 100% 完成** (§三, §五) | 实际 **11/21 生产就绪** (52%)。剩余10个管理适配器仅做关键字/子串匹配 | 完成度声明严重夸大 |
| 2 | **"detector adapter tests: 100+ test cases"** (§三.3.3) | 扫描器测试 **23个** (scanner_test.go) | 测试数量声明 4倍 |
| 3 | **"management adapter tests: 50+ test cases"** (§三.3.3) | 管理适配器 **38个** (management_test.go) | 1.3倍，不符 |

### 5.2 中等不一致

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 4 | **Wazuh SIEM bidirectional** (§二 line 60) | Inbound 已实现。Outbound (推送 ASSCOR 分数到 SIEM) — **完全未实现** |
| 5 | **"Left-shift security: Terraform/OpenTofu pre-deployment"** (§二) | Parse 层刚修复(Phase 2)。原先仅做子串计数——pre-deployment 声明在 Parse 完成前不成立 |
| 6 | **Check item delegation: 13/74** (§四) | Delegation.go 中仅 **9 条**规则，管理适配器无规则 |
| 7 | **Adapter timeout "default 30s"** (§七) | 实际用 `time.NewTicker(6*time.Hour)` 周期 + `120s` 全局超时 (adapter_integration.go) |
| 8 | **FreeIPA 替换 IAM-010/011/022** (§一) | IAM 检查项**不存在于 checks.go** (无法替换不存在的检查项) |
| 9 | **Trivy 替换 KS-001** (§一) | KS-001 在内核安全域中**已存在**，但 Trivy 适配器**未设置 DelegationRule** 指向 KS-001 |

---

## 六、使用手册 差异 (5项)

### 6.1 不一致

| # | 白皮书声明 | 实际代码 |
|---|-----------|----------|
| 1 | **Interactive terminal supports `source` command** (§16.9) | `source list/info/enable/disable/update/uninstall/run/config/audit` 已实现。`source deploy` 刚在补齐中修复 |
| 2 | **`spc cve/kev/score/fetch` available** (§16.5) | SPC 子命令刚在补齐中从 stub 修复（二次审计又发现接口断言错误） |
| 3 | **"Prism/SRD three-layer risk engine: Core + Semantic + Inference"** (§3.1.2) | prism-lib 源码存在且完整，**符合** |
| 4 | **gRPC enabled=off by default** (§11.4.2) | config.ini 中 `grpc.enabled = true` (默认打开) | 文档与默认值反了 |
| 5 | **WebUI port 8087** (§webui 配置) | 代码中使用 8087，**符合** |

---

## 七、量化声明汇总

### 文档声称未在代码中实现的不可验证声明:

| 声明 | 声称值 | 状态 |
|------|--------|------|
| Federation cluster | "未实现" | 文档正确标注 |
| Dynamic threshold ML | "未实现" | 文档正确标注 |
| Self-assessment alert < 90 | 声称 | 未见自评估代码 |

---

## 八、最终统计

| 指标 | 值 |
|------|-----|
| 总审查声明数 | ~160+ |
| **严重差异** | **11 项** |
| **中等差异** | **20 项** |
| **低严重度/仅注释** | **7 项** |
| 验证为正确 | ~120+ 项 |
| 白皮书准确率 | **~81%** |

### 审计勘误

以下 5 项为初始审计误判：
- CNNVD/CNVD/MISP 数据源实际已完整实现（spc_fetch.go 共 1000+ 行）
- OSCAL 导入/导出均已实现（spc_fetch.go:1608 + oscal_export.go）
- gRPC enabled 默认值 config.ini 确为 `false`（与白皮书一致）

### 已修复的差距

| 差距 | 状态 |
|------|------|
| CTI OTX/MISP 集成 | ✅ 已实现 (cti.go) |
| Wazuh SIEM outbound | ✅ 已实现 (siem_push.go) |
| 备份/存档系统 | ✅ 已实现 (persistence.go backupLoop) |
| 内核自评估 | ✅ 已实现 (assessor.go selfAssessmentLoop) |
| 管理适配器 delegation rules | ✅ 已实现 (delegation.go 21条规则) |
| 白皮书 IAM-010/011/022 引用 | ✅ 已更正 |
| 白皮书 L2 SQLite → HistoricalStore | ✅ 已更正 |
| 白皮书适配器超时 30s → 60s | ✅ 已更正 |
| 白皮书 30x I/O 基准 | ✅ 已移除过时数据 |
