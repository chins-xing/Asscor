# ASSCOR v0.2.2 安全审计问题清单

**日期**: 2026-08-03 | **版本**: v0.2.2 | **来源**: `build/audit-issues.md` | **验证状态**: 全部确认

---

## 一、中危问题 (5 项)

### 1. 扩展检查命令绕过全局命令白名单机制

**文件**: `internal/extmgr/extension_manager.go:519-534`  
**函数**: `buildExtCheckFunc()`  
**严重度**: 中  
**验证**: ✅ 确认

**问题**: 扩展 `checks.json` 中定义的 command 直接通过 `exec.Command("sh", "-c", command)` 执行，未经过 `common/exec.go` 的全局命令白名单 (`IsShellCommandAllowed`/`ParseCommand`) 和 Shell 特殊字符过滤。恶意扩展可执行任意 OS 命令。

```go
// 第522行 — 直接执行，无白名单检查
cmd := exec.Command("sh", "-c", command)
```

### 2. 算法完整性校验逻辑永久失效

**文件**: `internal/integrity/algo.go:14-42`  
**函数**: `VerifyAlgo()`  
**严重度**: 中  
**验证**: ✅ 确认

**问题**: 常量 `expectedAlgoDigest = ""` 为空字符串。第 40 行判断该常量为空时直接返回 `true`。无论 SSAM/Prism 算法源码和常量是否被篡改，完整性校验均判定合法。

```go
const expectedAlgoDigest = ""  // 第14行

if expectedAlgoDigest == "" {   // 第40行 — 总是 true
    return true
}
```

### 3. Agent 远程命令签名缺少防重放机制

**文件**: `internal/agent/agent.go:764-790`  
**函数**: `verifyCommandSignature()`  
**严重度**: 中  
**验证**: ✅ 确认

**问题**: HMAC 签名数据源仅包含 `CommandId + ":" + Command` + 排序参数。未引入 timestamp 或 nonce。攻击者捕获合法已执行命令的签名数据包后，可重复发送执行相同指令。

```go
// 第783行 — 仅使用 CommandId + Command，无时间戳/随机数
mac.Write([]byte(cmd.CommandId + ":" + cmd.Command))
```

### 4. 检查项执行超时引发 Goroutine 与资源泄漏

**文件**: `internal/agent/agent.go:1184-1203`  
**函数**: `runChecks()`  
**严重度**: 中  
**验证**: ✅ 确认

**问题**: 第 1189 行 goroutine 执行 `c.Run()`，第 1196 行 60 秒超时后返回超时结果。但内部 goroutine (第 1189 行) 无 context 取消机制，若检查项阻塞/挂起，goroutine 持续运行，累积造成 goroutine 泄漏和资源耗尽。

```go
go func() {                    // 第1189行 — 永不取消
    done <- c.Run()
}()
select {
case r := <-done:              // 正常完成
case <-time.After(60*time.Second): // 超时返回 — 但 goroutine 未取消
}
```

### 5. Linux 平台反调试检测手段单一

**文件**: `internal/integrity/debug_linux.go:11-26`  
**函数**: `IsDebugged()`  
**严重度**: 中  
**验证**: ✅ 确认

**问题**: 仅依靠 `/proc/self/status` 中 `TracerPid` 判断是否被调试。可通过 LD_PRELOAD 劫持文件读取、ptrace 技巧、修改 /proc 伪文件等多种方式绕过。

---

## 二、低危问题 (7 项)

| # | 问题 | 文件 | 函数 | 验证 |
|---|------|------|------|:--:|
| 1 | HMAC 签名密钥采用相对路径 `certs/ASSCOR-assessment-key`，依赖进程工作目录 | `internal/integrity/sign.go` | `loadOrCreateKey()` | ✅ |
| 2 | 远程命令执行输出完整记录日志，存在敏感信息泄露风险 | `internal/agent/agent.go` | `runCommand()` | ✅ |
| 3 | 配置解析未限制最大读取大小，大文件可造成内存耗尽 DoS | `internal/config/config.go` | `Parse()` | ✅ |
| 4 | 检查项注册表使用切片结构，`GetByID()` 线性遍历 O(n) | `internal/checks/registry.go` | `GetByID()` | ✅ |
| 5 | 文件读取缓存 `fileReadCache` 无最大容量限制，可无上限增长 | `internal/checks/linux/checks.go` | `fileReadCache` | ✅ |
| 6 | 模块初始化依赖 `init()` 执行时序，缺少显式管控 | 多处 | — | ✅ |
| 7 | 对外错误信息泄露内部程序细节（绝对路径、函数名称） | 多处 | — | ✅ |

---

## 三、代码质量问题 (4 项)

| # | 问题 | 关联 TECH_DEBT | 状态 |
|---|------|:---:|:--:|
| 1 | `internal/engine/assessor.go` 单文件 >1100 行，承担多项独立职责 | M01 | 🟡 已审计 |
| 2 | model 包形成中心化依赖，任一提修改触发大量联动变更 | 架构 | 🟡 已审计 |
| 3 | 配置解析逻辑存在大量重复样板代码 (if-else 分支) | T10 相关 | 🟡 P2 |
| 4 | 存在 checks 独立注册器 + 内核 DI 容器两套注册机制 | 架构 | 🟡 已审计 |

---

## 四、优先修复建议

| 优先级 | 问题 | 估时 | 影响 |
|:---:|------|:---:|------|
| 1 | **算法完整性永久失效** (M-2) | 0.5h | 算法防篡改完全无效 — 设置正确 digest 值即可修复 |
| 2 | **扩展检查绕过白名单** (M-1) | 0.5h | 恶意扩展可执行任意命令 — 接入 `common.IsShellCommandAllowed` |
| 3 | **Goroutine 泄漏** (M-4) | 1h | 资源耗尽 — 添加 context.WithTimeout 取消机制 |
| 4 | **Agent 缺防重放** (M-3) | 1h | 重放攻击 — 添加 timestamp + nonce 到签名数据 |
| 5 | **配置文件无大小限制** (L-3) | 0.3h | DoS — 添加 `io.LimitReader` |

---
*审计报告归档于 2026-08-03。5 中危 + 7 低危 + 4 代码质量，全部 17 项已通过代码读取验证确认。*
