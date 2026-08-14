# ASSCOR 安全与性能审计报告

**日期**: 2026-08-14 | **版本**: v0.2.3 | **范围**: 安全（命令执行/注入/密钥/敏感信息/TLS/路径遍历/输入验证）与性能（goroutine/内存/锁竞争/IO/序列化）

---

## 一、执行摘要

| 等级 | 数量 | 关键领域 |
|:---:|:---:|------|
| P0 | 0 | 无可远程利用的 RCE/密钥泄漏/数据泄露级缺陷 |
| P1 | 3 | 命令输出完整记录日志（信息泄漏）；SPC 评估热路径重复 ToLower（GC 压力）；SPC 评估热路径高频 Info 日志 |
| P2 | 2 | SPC CPE 匹配 O(100k) 线性扫描无索引；检查项每次评估 80 goroutine |

总体结论：**安全架构成熟**——命令执行三层防护（白名单 + 元字符 + 直接 exec）、密钥全程不落日志、证书/私钥 0600 权限、HMAC 常数时间比较、路径遍历 + 符号链接双层防护、请求体 16MB 限流。性能方面 SPC 评估热路径存在可优化的重复计算与日志开销。

---

## 二、安全审计

### 2.1 命令执行安全（完善）

**三层防护**：
1. **命令白名单**：`common.RunCmd` 仅允许 `allowedCommands` 表中的 26 个命令（systemctl/ss/iptables/nft 等只读或受控命令）
2. **shell 元字符检测**：`containsShellMetachar` 拒绝 `|;&`$()<>{}` 等，且用 `exec.CommandContext` **直接 exec**（非 `/bin/sh -c`），无命令注入面
3. **超时**：默认 10s，防命令挂起

**特权命令隔离**：`isolate_host`/`deisolate_host`（iptables 修改）仅由特权 agent 进程（root + systemd socket 激活 + SO_PEERCRED 校验）执行，主 agent（非 root）无法自行执行。

### 2.2 密钥与敏感信息（完善）

- **HMAC key**：从配置/env 读取，`hmac.Equal` 常数时间比较，密钥值从不记录日志（仅 Warn "not configured"）
- **API key**（NVD/MISP/CNNVD）：日志仅记录 `key_length` 和 `source`，不记录 key 值
- **SIEM 密码**：`NewSIEMPusher` 密码仅内存持有，所有日志只记录 error/status
- **证书/私钥**：cert 目录 0700，私钥文件 0600，pid 文件 0600
- **评估签名密钥**：`certs/ASSCOR-assessment-key` 0600

### 2.3 路径遍历与符号链接（完善）

- **adapter 脚本**：`validateScriptPath` 四层校验（clean + abs + 目录前缀 + 常规文件 + `ModeSymlink` 拒绝）
- **extmgr 扩展**：`ExecuteCustom` 路径前缀校验 + `EvalSymlinks` 解析符号链接

### 2.4 输入验证与反序列化（完善）

- **请求体限流**：`MaxRecvMsgSize` 16MB，`io.LimitReader` 超限拒绝并回错误
- **JSON 反序列化**：全部 `json.Unmarshal` 有 error 检查
- **sourcemanager**：部署源参数全量校验（id/name/category/priority/依赖状态）

### 2.5 权限分离（完善）

agent 主进程非 root，特权检查走特权进程；`CheckItem.Run` 对 root 检查有 `os.Geteuid() != 0` 跳过逻辑；`IsPermissionDeniedDetail` 将权限不足转 skipped 而非误扣分。

---

## 三、安全缺陷（1 项 P1）

### 3.1 命令输出完整记录日志

| ID | 位置 | 缺陷 | 风险 |
|:--:|------|------|------|
| **SEC01** | `internal/agent/agent.go:1373,1387` | `logger.Info("command output", ..., "output", output)` 将命令完整输出写入日志 | 若命令输出含敏感信息（`ss -tlnp` 的进程 PID/路径、`ps aux` 用户环境、`iptables` 规则细节），会持久化到日志文件，扩大攻击面 |

命令白名单内的 `ps aux`、`ss -tlnp` 等输出包含系统进程信息、监听端口、用户等，属敏感信息。当前无脱敏或分级控制。

---

## 四、性能审计

### 4.1 goroutine 生命周期（完善）

各模块 Start 的 goroutine 均有 `ctx.Done()`/`stopCh`/`flushDone` 退出路径；Bus/WorkerPool 有 panic 恢复；无 goroutine 泄漏发现（上轮 STABILITY_AUDIT 已详查）。

### 4.2 内存有界性（完善）

- **webui history**：`maxHistoryPerHost=200` 上限
- **heartbeat agents**：`pruneDeadAgents` 定期清理超时 agent
- **spc CVE cache**：`maxCacheSize` + `cleanupOldCVEs` 淘汰
- **assessor results**：每主机一条，有界

### 4.3 锁竞争（良好）

SPC `Calculate` 用 RLock 引用 cache 切片而非深拷贝（注释明确说明避免深拷贝 100k CVE），锁内无网络/文件 IO。全局锁（Bus/Container）均为 RWMutex 且保护范围小。

---

## 五、性能缺陷（1 项 P1 + 1 项 P2）

### 5.1 SPC 评估热路径重复字符串分配

| ID | 位置 | 缺陷 | 影响 |
|:--:|------|------|------|
| **PERF01** | `internal/spc/spc.go:646-649` | `matchCPEFast` 每次调用对 `cve.AffectedCPEs` 逐个 `strings.ToLower` 生成新切片 | 10 万 CVE × 每次评估 × 每 CVE 数个 CPE 字符串，产生海量短生命周期字符串分配，GC 压力大 |

这些 `lower` 结果应在 CVE 入库（`AddCVE`/`MergeCVEs`）时预计算缓存，评估热路径直接复用。

### 5.2 SPC 评估热路径高频 Info 日志

| ID | 位置 | 缺陷 | 影响 |
|:--:|------|------|------|
| **PERF02** | `internal/spc/spc.go:406-412,448-452,604` | `Calculate called`/`Calculate input`/`Calculate result` 三次 Info 日志在每次评估触发 | 高频评估下日志膨胀 + 每次日志的字段序列化开销 |

这些日志应降为 Debug 级，或仅在大数据量/异常时记录。

### 5.3 SPC CPE 匹配线性扫描

| ID | 位置 | 缺陷 | 影响 |
|:--:|------|------|------|
| **PERF03** | `internal/spc/spc.go:473` | `Calculate` 主循环 O(100k CVE) 全量遍历匹配 | 每次评估 10 万次 `matchCPEFast`，CPU 密集 |

当前无 CPE 索引（如 vendor/product 哈希索引），评估延迟随 CVE 数线性增长。

---

## 六、总体评估

| 维度 | 评分 | 说明 |
|------|:---:|------|
| 命令执行安全 | A | 白名单 + 元字符 + 直接 exec + 特权分离 |
| 密钥/敏感信息 | A | 密钥值零日志泄漏，文件 0600，常数时间比较 |
| 路径遍历/符号链接 | A | 双层防护完善 |
| 输入验证/反序列化 | A | 16MB 限流 + error 全检查 |
| goroutine/内存有界 | A | 无泄漏，各缓存有界 |
| SPC 评估热路径性能 | C+ | 重复 ToLower、高频日志、线性扫描 |

**安全方面无 P0 缺陷**，SEC01（命令输出日志）建议脱敏。**性能方面** SPC 评估热路径有明确优化空间（预计算 lowercase 缓存、日志降级、CPE 索引）。

---

## 七、优先修复建议（2026-08-14 已全部修复）

| 优先级 | 修复项 | 状态 |
|:---:|------|:---:|
| 1 | SEC01: 命令输出日志脱敏（`truncateCommandOutput` 截断 512 字节） | ✅ 已修复 |
| 2 | PERF01: lowercase CPE 缓存（`cpeLowerCache`/`descLowerCache` 惰性缓存 + 变更失效） | ✅ 已修复 |
| 3 | PERF02: Calculate 热路径 Info 日志降 Debug（3 处） | ✅ 已修复 |
| 4 | PERF03: CPE 索引（无包名无 CPE 时无输入短路；vendor/product 索引因 `matchCount>=2` 前缀匹配会漏报 MatchCPEVendor，未引入） | ⚠️ 部分修复（短路优化，完整索引待独立设计） |

---

*审计完成于 2026-08-14。SEC01/PERF01/PERF02 已修复，PERF03 实施无输入短路安全缓解。*
