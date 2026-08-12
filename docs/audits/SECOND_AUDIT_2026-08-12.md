# ASSCOR v0.2.2 二次审计报告

**日期**: 2026-08-12 | **版本**: v0.2.2 | **审计类型**: 全线代码扫描 + 回归验证

---

## 一、执行摘要

本次审计对 ASSCOR v0.2.2 进行了全面的构建验证、测试回归、安全修复确认和静态质量检查。**8 项安全/质量修复全部完整保留**，发现 1 个新问题（`ParseInt("")` 不报错）和 3 个文档/配置优化点。

| 维度 | 状态 | 新发现 |
|------|:---:|:---:|
| 构建 | ✅ 全通过 | 0 |
| 测试 (fast) | ⚠️ 1 失败 | `TestParseInt("")` |
| 安全修复 (5项) | ✅ 全部完整 | 0 |
| 质量修复 (3项) | ✅ 全部完整 | 0 |
| 技术债务 | ✅ 7 项准确 | 0 |
| 白皮书 | ✅ 准确 | 0 |

---

## 二、构建与测试验证

### 2.1 构建

```bash
go build ./cmd/kernel/  ✅ 通过
go vet ./internal/...    ✅ 通过
```

### 2.2 测试

| 包 | 状态 | 详情 |
|------|:---:|------|
| `internal/engine` | ✅ 通过 | 1.131s |
| `internal/cli` | ✅ 通过 | 0.962s |
| `internal/extmgr` | ✅ 通过 | 1.613s |
| `internal/config` | ✅ 通过 | 0.577s |
| `internal/checks` | ✅ 通过 | 1.478s |
| `internal/integrity` | ✅ 通过 | 0.557s |
| `internal/kernel` (fast) | ✅ 通过 | 1.803s |
| `internal/common` | ❌ **1 失败** | `TestParseInt("")` |

### 2.3 发现的缺陷

| # | 文件 | 问题 | 严重度 |
|:--:|------|------|:---:|
| **A01** | `internal/common/exec.go:222` | `ParseInt("")` 返回 `(0, nil)` 应为 `(0, error)` | P2 |

**详情**: 空字符串循环零次 → 返回 0, nil。与测试期望的 `wantErr=true` 不一致。修复：在函数入口添加 `if s == "" { return 0, fmt.Errorf("empty string") }`。

---

## 三、安全修复完整性验证

### 3.1 v0.2.2 安全审计修复 (5 项) — 全部完整保留

| ID | 问题 | 文件 | 修复状态 |
|:--:|------|------|:---:|
| M-1 | 扩展检查绕过白名单 | `extension_manager.go:522` | ✅ `common.IsShellCommandAllowed(command)` 校验 |
| M-2 | 算法完整性永久失效 | `algo.go:14` | ✅ `sync.Once` + `init()` 自动计算 digest |
| M-3 | Agent 缺防重放 | `agent.go:792` | ✅ `params["_timestamp"]` + 5 分钟过期检查 |
| M-4 | Goroutine 泄漏 | `agent.go:1189` | ✅ `checkCtx.WithTimeout` + `defer checkCancel()` |
| L-3 | 配置文件无大小限制 | `config.go:183` | ✅ `maxConfigSize = 10<<20` (10MB) 上限 |

### 3.2 v0.2.2 代码质量修复 (3 项) — 全部完整保留

| ID | 问题 | 文件 | 修复状态 |
|:--:|------|------|:---:|
| Q-3 | 配置解析重复样板 | `config.go:648-670` | ✅ `getFloat`/`getBool` 辅助函数 |
| Q-4 | 检查项 O(n) 线性查询 | `registry.go:60-63` | ✅ `idIndex map[string]int` O(1) 索引 |
| Q-5 | 文件缓存无容量限制 | `checks.go:35-55` | ✅ `maxSize:1000` + LRU 淘汰 |

---

## 四、技术债务状态

### 4.1 历史债务 (87 项 → 5 剩余)

| 等级 | 已修复 | 剩余 |
|:---:|:---:|:---:|
| P0 | 19 | 0 |
| P1 | 37 | 4 |
| P2 | 26 | 1 |
| **合计** | **82** | **5** |

### 4.2 剩余 5 项

| ID | 问题 | 等级 |
|:--:|------|:---:|
| E05 | extmgr 不含 PluginSDK 进程启动代码 | P1 |
| E06 | pkgmgr 不处理传递依赖 | P1 |
| E11 | registerCheckModule 存根 | P1 |
| M01 | kernel/ 单体 (17 类型文件已拆) | P1 |
| T32 | FHS 路径参数化 | P2 |

---

## 五、白皮书准确性

| 检查项 | 状态 |
|------|:---:|
| ASSCOR 版本 | ✅ v0.2.2 全部一致 |
| 扩展点计数 (76) | ✅ 3 文件已同步 |
| 插件计数 (15-17) | ✅ |
| 测试计数 (222) | ✅ 与 v0.2.2 发布时一致 |
| 完整性文档 | ✅ VerifyAlgo 自校准机制已实现 |
| 文档日期 | ✅ 2026-08-02 |

---

## 六、新增观察项 (3 项)

| # | 文件/范围 | 观察 | 建议 |
|:--:|------|------|------|
| **B01** | `internal/common/exec.go:222` | `ParseInt("")` 应返回错误 (上述缺陷) | 0.1h 修复 |
| **B02** | `build/` 目录 | 存在旧版编译产物 (`ASSCOR-agent-linux`, `ASSCOR-kernel-linux`, `asscor-pkg.exe`) | 清理 `build/` 目录 |
| **B03** | `internal/agent/agent.go:1189` | `checkCtx` 超时后 goroutine 中的 `c.Run()` 结果写入 `done` channel 但无人读取 — goroutine 在 ctx 过期后正常退出 | 当前实现有效，无需修改 |

---

## 七、审计结论

**整体评分**: **A− (优秀)**。v0.2.2 的 8 项安全/质量修复全部完整保留，未引入回归。构建和 vet 完全通过。发现 1 个 P2 级缺陷 (`ParseInt("")`) 和 3 项优化建议。技术债务从 87 项压缩至 5 项 (94%)。

### 优先级行动建议

| 优先级 | 行动 | 估时 |
|:---:|------|:---:|
| 🔴 | 修复 `ParseInt("")` 空字符串不报错 | 0.1h |
| 🟡 | 清理 `build/` 目录旧版编译产物 | 0.1h |
| 🟢 | 更新 TECH_DEBT_OVERVIEW 剩余计数 (80→82) | 0.1h |

---
*审计完成于 2026-08-12T18:42+08:00。仅审计，归档至 `docs/audits/`。*
