# ASSCOR 全项目稳定性审计报告

**日期**: 2026-08-14 | **版本**: v0.2.3 | **范围**: 错误处理完备性 / 运行日志存留 / 模块与扩展包错误隔离 / 内核稳定性

---

## 一、执行摘要

本次审计聚焦四个维度：错误处理是否完善、各组件运行日志是否完整存留、内核对模块与扩展包的错误隔离是否完善、内核自身是否稳定。

| 等级 | 数量 | 关键领域 |
|:---:|:---:|------|
| P0 | 0 | 无关键/数据丢失/内核崩溃级问题 |
| P1 | 2 | persistence flush 静默忽略 sync 错误；pluginsdk Serve 无 panic 恢复 |
| P2 | 3 | 拦截器链无 recover（依赖 server 兜底）；PublishSync 无 recover；若干 goroutine 无 recover（低风险） |

总体结论：**内核稳定性架构成熟**——双层 panic 恢复（任务级 + 进程级）、超时控制、错误状态持久化、原子写、依赖校验、健康检查均已建立。错误隔离能力从"单个检查项"到"扩展包独立进程"分层完备。

---

## 二、错误处理完备性

### 2.1 忽略错误审计（已扫描）

全仓库 `_ = ` / `_, _ = ` 忽略模式仅 5 处，均为安全场景：

| 位置 | 代码 | 评估 |
|------|------|------|
| `cti.go:324` | `_ = cutoff` | 类型转换，无副作用 |
| `guard.go:90` | `_ = payload` | 注释说明待接线 |
| `server.go:308` | `_ = enc.Encode(data)` | 响应编码，客户端已断开 |
| `cli_client_linux.go:132` | `_ = ch` | channel 接收，非关键 |
| `main.go:161` | `_ = payload` | 占位 |

**结论**：错误忽略极少且均有理由，无系统性吞错问题。

### 2.2 网络/IO 错误处理（完善）

- **cti**：OTX/MISP 请求构建、fetch、parse 每个失败路径均有 Warn 日志
- **spc**：NVD API 超时重试（指数退避）+ panic 恢复 + 回退样例数据
- **spc persist**：临时文件 + rename 原子写，mkdir/marshal/write/rename 错误均有 Error 日志
- **persistence**：marshal/write/sync 全检查；dashboard 用临时文件 + rename 原子写
- **SIEM 推送**：auth/build/push/retry 每路径均有 Warn 日志

---

## 三、运行日志存留覆盖度

### 3.1 日志组件覆盖

全项目 **57 个日志组件**（`logger.WithComponent`），覆盖：全部内核核心（kernel/bus/workerpool/interceptor/audit/lifecycle/locator/blocker）、全部 18 个功能模块、agent/agent-priv、attck 全子域（9 个）、grpc/grpc_server/grpc_client、siem、tls、扩展体系（extmgr/adapter/adapterhub）。

### 3.2 生命周期日志完整性

| 模块 | Init/Start/Stop 日志 |
|------|:---:|
| heartbeat/commander/cti/spc/policy/collector/sourcemanager/persistence | ✅ 完整 |
| srdwrapper/adapterhub | ⚠️ 无 Start/Stop（srdwrapper 无 Module 生命周期，adapterhub 为 lib 型） |

内核 `Bootstrap`/`Shutdown` 全程日志：plugin registered/initialized/started/stopped、kernel 6 个扩展点执行、shutdown complete。

---

## 四、模块与扩展包错误隔离

### 4.1 分层隔离体系（完善）

| 层级 | 机制 | 隔离效果 |
|------|------|------|
| 单检查项 | `model.CheckItem.Run()` recover → 转失败 | 单检查 panic 不影响评估 |
| 任务级 | `WorkerPool` 双层 recover + 30min 超时 + 泄漏检测 | 任务 panic/超时不拖垮内核 |
| 消息级 | `Bus.Publish` 每订阅者 recover + metrics | 订阅者 panic 被记录不传播 |
| 模块级 | 插件生命周期 `Init/Start` 失败 fail-fast，`Stop` 错误仅记录 | 启动期失败明确，停止期容错 |
| 扩展包进程级 | extmgr 独立进程执行 + 白名单 + checksum + 超时 + 路径遍历防护 | 扩展崩溃不连累内核 |

### 4.2 扩展包隔离细节（完善）

- **ExecutionPolicy**：allowed/whitelist/sandboxed/disabled 四档
- **命令白名单**：base + 绝对路径 + EvalSymlinks 解析三层匹配
- **完整性**：SHA-256 checksum 校验
- **超时**：context.WithTimeout（默认 30s）
- **路径遍历防护**：`ExecuteCustom` 校验 script 路径前缀
- **状态持久化**：extensions_state.json，依赖校验（版本约束）、禁用/删除级联保护、`ExtStateError` 错误状态

### 4.3 内核生命周期错误隔离

`Bootstrap` 中 `Init`/`Start` 失败返回 error（fail-fast，不会带病运行）；`Configure` 失败仅 Warn（可降级启动）；`Shutdown` 按优先级逆序停止，单插件 Stop 失败仅 Error 记录不阻塞整体关闭。

---

## 五、P1 缺陷（2 项）

### 5.1 persistence flushAll 静默忽略 sync 错误

| ID | 文件 | 缺陷 | 风险 |
|:--:|------|------|------|
| **S01** | `internal/persistence/persistence.go:380` | `flushAll()` 中 `w.sync()` 返回 error 被忽略；`close()` 中 `w.buf.Flush()` 同样忽略 | 磁盘满/IO 错误时数据静默丢失，无任何日志 |

`sync()` 内部会 `Flush + file.Sync`，若失败（如磁盘满）无日志，评估数据、审计日志可能静默丢失。

### 5.2 pluginsdk Serve 主循环无 panic 恢复

| ID | 文件 | 缺陷 | 风险 |
|:--:|------|------|------|
| **S02** | `pluginsdk/sdk.go:51` | `Serve()` 主循环直接调用 `p.Init`/`p.HandleRequest`/`p.Shutdown`，无 recover | 插件 panic 导致插件进程整体崩溃退出，且无堆栈日志 |

虽独立进程崩溃不影响内核（进程隔离），但插件崩溃无日志、无状态记录，运维难定位。

---

## 六、P2 缺陷（3 项）

| ID | 位置 | 缺陷 | 说明 |
|:--:|------|------|------|
| S03 | `internal/kernel/bus.go:165` `PublishSync` | 同步发布直接调用 handler 无 recover | 若同步订阅者 panic 会传播到调用方（assessor/policy/spc 5 处调用点）。当前依赖上层无 panic，风险低 |
| S04 | `internal/kernel/interceptor.go` `Then` | 拦截器链无 recover | 依赖 server 层 `handleConn` 的 recover 兜底（含 stack trace），分层设计可接受 |
| S05 | `internal/agent/agent.go:130` 信号 goroutine | 无 recover | 仅 `<-sigCh + cancel`，风险极低 |

---

## 七、内核稳定性评估

| 维度 | 评分 | 说明 |
|------|:---:|------|
| panic 恢复覆盖 | A- | 15 文件 48 处 recover，任务/消息/进程三层覆盖，仅 pluginsdk 主循环缺 |
| 超时控制 | A | WorkerPool 30min、扩展执行 30s、bus 停止排空 10s、agent 指数退避 |
| goroutine 生命周期 | A | 各模块 Start 的 goroutine 均有 ctx.Done/stopCh/flushDone 退出路径，无泄漏 |
| 数据持久化原子性 | A- | 临时文件 + rename 原子写（persistence/spc），但 flush sync 错误静默 |
| 错误状态可观测 | A | 57 组件日志 + BusMetrics + WorkerPoolMetrics + 健康检查 + ConcurrencyStatus |
| 资源清理 | A | plugin Stop、bus UnsubscribeAll、server 优雅关闭、文件 Sync+Close |

**内核自身稳定**：引导 fail-fast 避免带病运行，关闭逆序优雅，信号处理规范，无发现会导致内核崩溃、死锁、goroutine 泄漏的缺陷。

---

## 八、优先修复建议（不立即修复，归档备查）

| 优先级 | 修复项 | 估时 |
|:---:|------|:---:|
| 1 | S01: flushAll/close 检查 sync/Flush 错误并 Error 日志 | 0.2h |
| 2 | S02: pluginsdk Serve 加 recover（返回 JSON-RPC internal error） | 0.2h |
| 3 | S03: PublishSync 加 recover | 0.3h |

---

*审计完成于 2026-08-14。仅审计归档，不立即修复。*
