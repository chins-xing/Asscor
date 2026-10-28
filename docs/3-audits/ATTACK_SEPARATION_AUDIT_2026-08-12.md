# ATT&CK 模块剥离完整性审计

**日期**: 2026-08-12 | **版本**: v0.2.2 | **状态**: 通过 ✅

---

## 审计结论

**ATT&CK 模块分离完整且干净。零 P0/P1 泄露。**

| # | 检查项 | 结果 |
|:--:|------|:--:|
| 1 | 13 源文件 Build Tag | ✅ 全部有 `//go:build attck_ext` |
| 2 | 扩展包文件完整性 | ✅ 4 文件 (register/enable/package.json/README) |
| 3 | 无 tag 编译 | ✅ 通过 |
| 4 | 有 tag 编译 | ✅ 通过 |
| 5 | `engine.ATTACKProvider` 接口解耦 | ✅ IsEnabled/Version 补齐，评估器仅通过接口访问 |
| 6 | CLI 优雅降级 | ✅ `attck` 命令提示 "module not available" |
| 7 | `applyATTACK` 接口注入 | ✅ `m.attackProvider` 替代 DI cast |
| 8 | 内核残余引用 | ✅ 0 具体类型引用 (仅字符串常量 + 数据模型字段) |
| 9 | cmd/* Build Tag 隔离 | ✅ `attck_ext_on.go` / `attck_ext_off.go` 双文件 |

---

## 一、Build Tag 隔离

```
internal/kernel/attck*.go         (13 文件) → //go:build attck_ext
internal/kernel/modules_attck_test.go       → //go:build attck_ext
cmd/kernel/attck_ext_on.go                  → //go:build attck_ext
cmd/kernel/attck_ext_off.go                 → //go:build !attck_ext
cmd/asscor/attck_ext.go                     → //go:build attck_ext
optional/.../attck-ext-pack/register.go     → //go:build attck_ext
optional/.../attck-ext-pack/enable.go       → //go:build attck_ext
```

## 二、解耦架构

```
cmd/kernel/main.go (无 build tag)
  └─ initATTACK(assessor)
       ├─ attck_ext_off.go: 空函数
       └─ attck_ext_on.go: → attckext.Register()
                              → kernel.NewATTACKModule()
                              → assessor.SetATTACKProvider()

internal/kernel/assessor.go
  └─ applyATTACK: provider.IsEnabled() → provider.CalculateCoverage() ...
       ↑ engine.ATTACKProvider (接口，定义在 internal/engine/)
```

## 三、残余引用分析 (全 P2)

17 处"attck"字符串出现在非 gated 文件中，经分析全部为非耦合引用：

| 类型 | 数量 | 说明 |
|------|:---:|------|
| 扩展点字符串名 | 13 | `"attck.coverage.complete"` 等 — 发布/订阅体系的字符串标识 |
| SPC CVE 数据字段 | 3 | `AttckTechniques []string` — CVE 与 ATT&CK 技术的映射数据 |
| MISP 解析器 | 1 | `extractATTCKTechnique()` — Galaxy tag 字符串解析 |

---

## 四、编译验证

| 命令 | 结果 |
|------|:--:|
| `go build ./cmd/kernel/` | ✅ |
| `go build -tags attck_ext ./cmd/kernel/` | ✅ |
| `go test ./internal/kernel/ -run TestHeartbeat\|TestAssessor` | ✅ |
| `go test -tags attck_ext ./internal/kernel/ -run TestATTACK` | ✅ |

---
*审计完成于 2026-08-12T21:50+08:00。仅审计，不修复。*
