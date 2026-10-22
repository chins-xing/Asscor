# ASSCOR 深度源代码审计报告 (v0.3.0 VS Code Review)

**日期**: 2026-07-12 | **审查范围**: `F:\Argus\internal\kernel\*` | **方法**: 逐文件 diff + 语义验证 + 交叉引用分析

---

## 一、构建与测试状态

| 指标 | 值 |
|------|:--:|
| `go build ./...` | :white_check_mark: 全通过 |
| `go vet ./internal/kernel/...` | :white_check_mark: 零警告 |
| 测试包 | 15 passed / 2 pre-existing fails |
| v0.3.0 新增测试 | 22/22 :white_check_mark: |

---

## 二、接口拆分 — 结构验证

### 2.1 ATTACKInterface (attck.go:1580-1589)

```
ATTACKInterface ──┬── ATTCKCore (10 方法)
                  ├── ATTCKDetection (11 方法)
                  ├── ATTCKIntelligence (13 方法)
                  ├── ATTCKEmulation (7 方法)
                  ├── ATTCKAssessment (8 方法)
                  ├── ATTCKAPTModules (21 方法)
                  ├── ATTCKEnhanced (13 方法)
                  └── ATTCKAuxiliary (6 方法)
```

**评估**: :white_check_mark: 拆分正确。每个子接口语义内聚，边界清晰。`ATTCKAuxiliary` 明确标注 "考虑弃用 `GetTransitionMatrix` (0 调用方)"，注释到位。

**消费端验证** (`assessor.go:532`):
```go
attck, ok := impl.(ATTCKCore)  // 类型收窄到 Core，仅用 9/89 方法
```
此用法证明拆分有效——调用方只拿所需接口。

### 2.2 SPCInterface (spc.go:906-911)

```
SPCInterface ──┬── SPCCalculator (6 方法)
               ├── SPCFetcher (7 方法)
               ├── SPCAssetManager (3 方法)
               └── SPCCacheManager (4 方法)
```

**评估**: :white_check_mark: 拆分正确。

### 2.3 AssessorInterface (assessor.go:727-732)

当前有 4 个方法（未进一步拆分），作为 `KernelServiceImpl.assessor` 字段类型。此接口仅由 `services.go` 的 `KernelServiceImpl` 消费，方法集已足够精简。

---

## 三、测试代码质量审计

### 3.1 circuitbreaker_test.go — 5 用例

| 用例 | 模式 | 评价 |
|------|------|:--:|
| `AllowInitially` | 新鲜熔断器 Allow()=true | :white_check_mark: |
| `OpensAfterFailures` | 10 次失败 → 开闸 | :white_check_mark: |
| `HalfOpenAfterTimeout` | 开闸 → 超时 → 半开 → 成功关闭 | :white_check_mark: |
| `ClosesOnSuccess` | 半开成功 → 关闭 | :white_check_mark: |
| `ServiceIsolation` | svc-a 失败不影响 svc-b | :white_check_mark: |

**发现**: 无问题。每个用例 `defer cb.Stop()` 正确释放后台 goroutine。

### 3.2 bus_test.go — 5 用例

| 用例 | 模式 | 评价 |
|------|------|:--:|
| `PublishSubscribe` | 异步 pub → 50ms 后 assert | :white_check_mark: |
| `PublishSync` | 同步 pub → 即时 assert | :white_check_mark: |
| `MultipleSubscribers` | 同一 topic 多订阅者 | :white_check_mark: |
| `StopGracefulDrain` | Stop() 等待 in-flight handler 完成 | :white_check_mark: |
| `TopicIsolation` | topic.a 的 handler 不收 topic.b 消息 | :white_check_mark: |

**发现**: `PublishSubscribe` 使用 `time.Sleep(50ms)` 作为同步机制。异步断言无竞态，但 `PublishSync` 作为替代方案也可验证相同行为。

### 3.3 ratelimit_test.go — 4 用例

| 用例 | 模式 | 评价 |
|------|------|:--:|
| `AllowsWithinBurst` | burst=5, 5 次请求通过 | :white_check_mark: |
| `BlocksBeyondBurst` | burst=2, 第 3 次拒绝 | :white_check_mark: |
| `ClientsIsolated` | 客户端 A 耗尽不影响 B | :white_check_mark: |
| `StopDoubleCall` | 重复 Stop() 不 panic | :white_check_mark: |

**发现**: 直接调用非导出方法 `rl.allow()` —— 同一包内白盒测试，符合 Go 惯例。

### 3.4 services_test.go — 2 用例

| 用例 | 模式 | 评价 |
|------|------|:--:|
| `Heartbeat_ProcessesCheckResults` | 含 assessor 的 Heartbeat | :white_check_mark: |
| `Heartbeat_EmptyResultReturnsOk` | nil assessor 仍返回 Ok | :white_check_mark: |

**小问题**: `mockAssessorForService.ListResults()` 方法定义于 services_test.go:25，但 AssessorInterface 不含此方法，且没有额外消费方。属无害死代码。

### 3.5 config_watcher_test.go — 2 用例

| 用例 | 模式 | 评价 |
|------|------|:--:|
| `WatchLoopStartsAndStops` | 启动→运行→停止 goroutine | :white_check_mark: |
| `CheckReloadSkipsOnError` | 不存在文件不 panic | :white_check_mark: |

**发现**: `WatchLoopStartsAndStops` 直接设置未导出字段（`w.interval`、`w.state`、`w.stopCh`、`w.lastMod`），白盒测试写法。如果字段名变更会同时破坏测试，可接受。

---

## 四、并发与数据竞争审计

**生产代码**:
- `bus.go`: `Publish` 中先 `RLock` 拷贝订阅者，再释放锁后 dispatch，无 hold-lock-call 问题
- `circuitbreaker.go`: `getRecord` 使用经典 double-check pattern（先 RLock→不存在→Lock→再检查），正确
- `ratelimit.go`: `Stop()` 在 `mu` 保护下关闭 channel 防止 double-close，正确

**:white_check_mark: 无发现新数据竞争**。

---

## 五、资源泄漏审计

| 组件 | Goroutine 清理 | 审查 |
|------|------|:--:|
| Bus | `Stop()` → atomic stopped + wg.Wait + 10s timeout | :white_check_mark: |
| CircuitBreaker | `Stop()` → close(stopCleanup) + ticker.Stop() | :white_check_mark: |
| RateLimiter | `Stop()` → close(stopCleanup) + ticker.Stop() + stopped flag | :white_check_mark: |
| ConfigWatcher | `Stop()` → close(stopCh) 触发 watchLoop + sighupLoop 退出 | :white_check_mark: |

---

## 六、Consumer→Interface 交叉引用矩阵

| 消费者 (文件:行) | 要求接口 | 实际断言 | 紧致度 |
|------|------|------|:--:|
| `assessor.go:532` | ATTCKCore | `impl.(ATTCKCore)` | :white_check_mark: 只用 Core 9 方法 |
| `assessor.go:453` | SPCFull | `impl.(SPCInterface)` | :ballot_box_with_check: 用 Calculator+Fetcher+AssetMgr 15 方法 |
| `services.go:28` | AssessorInterface | 字段类型 | :white_check_mark: 4 方法全部消费 |
| `services.go:98` | SPCCalculator+SPCFetcher+SPCAssetManager | 字段 `SPCInterface` | :ballot_box_with_check: 用 3/4 子接口 |

---

## 七、已知问题（不变）

| # | 问题 | 位置 | 严重度 |
|---|------|------|:--:|
| 1 | `TestSPCImportOSCALDuplicateHandling` merge 语义不匹配 | spc_test.go:565 | :yellow_circle: 预存 |
| 2 | `TestSourceManagerModule_AuditLogTimeOrder` 时序依赖 | source_manager_test.go:563 | :yellow_circle: 预存 |
| 3 | `mockAssessorForService.ListResults()` 0 调用方 | services_test.go:25 | :green_circle: 无害 |

---

## 八、总体结论

| 维度 | 评分 |
|------|:--:|
| 接口内聚 | A — 拆分维度合理，消费端正确收窄 |
| 测试充分度 | A — 22 新测试覆盖各组件边界 |
| 并发安全 | A — 生产代码锁模型正确 |
| 资源回收 | A — 所有组件 Stop 路径完整 |
| 向后兼容 | A — 复合接口保留，消费端可独立迁移 |
| 构建清洁度 | A — build/vet 零问题 |

**建议**: 无阻塞项。`listResults` 死代码可在下版本清理。
