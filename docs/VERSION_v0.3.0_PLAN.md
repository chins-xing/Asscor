# ASSCOR v0.3.0 — 架构加固版本

**目标版本**: v0.3.0 | **起始版本**: v0.2.2 | **预估工期**: 4-6 周

---

## v0.3.0 核心目标

**一句话**: 消除已知的架构债务，让内核真正回到"基础设施协调者"的定位。

---

## 一、ATTACKInterface 接口分解（工作量最大）

### 现状
`ATTACKInterface` 有 85 个方法，涵盖 12 个不同关注点，是项目最大的 God 接口。

### 目标
拆分为 10 个聚焦的子接口，每个 ≤ 10 方法：

| 子接口 | 方法数 | 所属文件 | 职责 |
|--------|:--:|------|------|
| `ATTCKDetector` | ~8 | `attck_detection.go` | 检测规则 CRUD + 告警 + 异常 + 摘要 |
| `ATTCKIntelligence` | ~8 | `attck_ti.go` | IOC CRUD + 威胁角色 + TTP 追踪 |
| `ATTCKEmulation` | ~6 | `attck_emulation.go` | 仿真场景 CRUD + 自动生成 + 安全模式 |
| `ATTCKAssessor` | ~6 | `attck_assessment.go` | 差距分析 + 控制映射 + 缓解建议 |
| `ATTCKAPTChain` | ~4 | `attck_apt_chain.go` | 攻击链重构 |
| `ATTCKAPTCausal` | ~3 | `attck_apt_causal.go` | 因果推理 |
| `ATTCKAPTDetect` | ~6 | `attck_apt_detect.go` | 行为检测 + 信标检测 |
| `ATTCKAPTAttribution` | ~4 | `attck_apt_attribution.go` | 归因 + 报告 + Bayes |
| `ATTCKAPTHunt` | ~4 | `attck_apt_hunt.go` | 威胁狩猎 |
| `ATTCKCore` | ~8 | `attck.go` | 共性方法（GetAllTactics/CalculateCoverage/AssessKillChain/MatchAPTGroup/PredictRisk 等） |

### 改动

1. 在 `attck.go` 中定义 `ATTCKCore` 接口（包含最常用的 8 个方法）
2. 在每个 `attck_*.go` 文件中定义对应的子接口
3. `ATTACKModule` 实现全部 10 个子接口
4. `ATTACKInterface` 改为组合接口：
```go
type ATTACKInterface interface {
    ATTCKCore
    ATTCKDetector
    ATTCKIntelligence
    ATTCKEmulation
    ATTCKAssessor
    ATTCKAPTChain
    ATTCKAPTCausal
    ATTCKAPTDetect
    ATTCKAPTAttribution
    ATTCKAPTHunt
}
```
5. 调用方改为依赖具体子接口而非 `ATTACKInterface`

### 验收标准
- 10 个子接口全部定义
- DI 容器中 `ATTACKInterface` 仍可解析（向后兼容）
- 现有 60 个 ATT&CK 测试全部通过
- `assessor.go` 中 `applyATTACK` 改为依赖 `ATTCKCore`

---

## 二、SPCInterface 接口分解

### 现状
`SPCInterface` 有 20 个方法，混合了数据操作、配置、状态查询。

### 目标
拆分为 4 个子接口：

| 子接口 | 方法数 | 职责 |
|--------|:--:|------|
| `SPCDataSource` | ~6 | Calculate/AddCVE/AddCVEs/MergeCVEs/GetCVEs/GetCVECount |
| `SPCCacheManager` | ~4 | ClearCache/GetKEVCount/GetKEVCatalog/Summary |
| `SPCFetcher` | ~6 | FetchFromAllSources/FetchFromEPSS/FetchFromCISAKEV/ImportOSCAL/LastUpdate/Enabled/SetEnabled |
| `SPCAssetManager` | ~4 | UpsertAsset/GetAsset/ConfigureMISP |

### 验收标准
- 4 个子接口定义完成
- DI 容器兼容
- 现有 SPC 测试全绿

---

## 三、错误处理补齐

### 现状
审计发现 4 处 `io.Copy`、4 处 `os.Remove`、3 处 `time.Parse` 静默丢弃错误。

### 目标
全部添加 `if err != nil` 检查 + 日志记录。

| 位置 | 类型 | 修复 |
|------|------|------|
| `persistence.go:652` | `io.Copy` 丢弃 | 已在 v0.2.0 修复 ? |
| `persistence.go:732` | `io.Copy` 丢弃 | 已在 v0.2.0 修复 ? |
| `persistence.go:676` | `os.Remove` 丢弃 | 待修复 |
| `persistence.go:756` | `os.Remove` 丢弃 | 待修复 |
| `spc_fetch.go:638,640,643` | `time.Parse` 丢弃 | 待修复 |

### 验收标准
- 所有错误路径至少记录 warn 日志
- `grep -r "_ =" internal/` 零遗留静默丢弃

---

## 四、关键文件测试补齐

### 现状
9 个关键内核文件零测试。

### 目标
至少补齐 6 个文件的**基本单元测试**：

| 文件 | 优先级 | 测试内容 |
|------|:--:|------|
| `services.go` | P0 | Heartbeat/Register 请求-响应测试（mock assessor） |
| `bus.go` | P0 | Publish/Subscribe/Stop 正确性测试 |
| `circuitbreaker.go` | P0 | 三态转换 + 滑动窗口测试 |
| `server.go` | P1 | handleConn 拦截器链正确性 |
| `config_watcher.go` | P1 | watchLoop ModTime 变更检测 |
| `ratelimit.go` | P1 | Allow + CleanupStale 正确性 |

### 验收标准
- 6 个文件至少各有 2 个测试
- kernel 包测试覆盖率从 ~25% 提升至 ~40%

---

## 五、小修小补

| 项目 | 说明 |
|------|------|
| `console_report` 键路径 | 确认全局键 `console_report` 与 `webui.console_report` 回退逻辑正确（已修复，需测试验证） |
| 6 行业模板补齐 | 添加缺失的 `[integrity]`/`[attck]`/`[prism]` 节（低优先级，v0.3.1） |
| Go 版本统一 | 已修复 ? |

---

## v0.3.0 验收清单

| # | 项 | 状态 |
|---|-----|:--:|
| 1 | ATTACKInterface 拆分为 10 子接口 | ? |
| 2 | SPCInterface 拆分为 4 子接口 | ? |
| 3 | 所有静默错误丢弃修复 | ? |
| 4 | 6 个关键文件至少 2 个测试 | ? |
| 5 | kernel 包测试覆盖率 ≥ 40% | ? |
| 6 | `go build ./...` + `go vet ./...` 通过 | ? |
| 7 | 现有测试无回归 | ? |
| 8 | DI 容器向后兼容 | ? |
| 9 | 架构评分 ≥ 9.5/10 | ? |

---

## 预估工作量

| 任务 | 人天 | 风险 |
|------|:--:|------|
| ATTACKInterface 拆分 | 8-10 | 高（涉及 60 个测试 + 多处调用方） |
| SPCInterface 拆分 | 3-4 | 中 |
| 错误处理补齐 | 2-3 | 低 |
| 测试补齐 | 5-7 | 中（需要 mock 基础设施） |
| 小修 + 验证 | 2-3 | 低 |
| **合计** | **20-27** | — |
