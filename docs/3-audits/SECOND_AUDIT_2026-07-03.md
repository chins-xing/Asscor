# ASSCOR 二次架构审计报告

**审计日期**: 2026-07-03 | **版本**: v0.2.0-dev | **首次审计**: 7.6/10 → **二次审计**: 8.8/10 (+1.2)

---

## 审计维度

| 维度 | 首次 | 二次 | 提升 | 关键变化 |
|------|------|------|------|----------|
| 松耦合 (无循环依赖) | 10/10 | **10/10** | — | 26包严格DAG，0循环 |
| 无冗余依赖 | 9/10 | **9/10** | — | 仅2个真正外部依赖 |
| 强扩展能力 | 5/10 | **8/10** | +3 | 扩展点18/18执行，srd桥接，extmgr补全 |
| 透明统一管线 | 7/10 | **9/10** | +2 | 适配器管线100%统一ApplyDelegation |
| 设计落实度 | 7/10 | **8/10** | +1 | 死代码清理，接口统一 |
| **总评** | **7.6** | **8.8** | **+1.2** | — |

---

## 13项修复确认

### 数据竞争 & 并发安全 (9项)

| 问题 | 修复 |
|------|------|
| server.SetInterceptors 无锁 | RWMutex + RLock |
| handleConn s.interceptors 无锁读取 | RWMutex + RLock |
| InterceptorChain.Use/Then 竞态 | sync.Mutex + 快照链 |
| CircuitBreaker lastStateChange | rec.mu保护读写 |
| AssessorModule.cfg 竞态 | RLock → local capture |
| SPC Enabled() 无锁 | RLock |
| SPC cancelFunc 竞态 | Lock内读取 |
| ATT&CK tactics 无锁 | RLock |
| ScoringEngineModule.State 无锁 | sync.Mutex |

### 架构完整性 (4项)

| 问题 | 修复 | 提交 |
|------|------|------|
| srd_adapters 孤立模块 | kernel/srd_wrapper.go 桥接层注册 | `93b2f56` |
| 9 ATT&CK 扩展点死线 | 7文件新增 Extensions().Execute() | `8ad6b2e` |
| adapterhub Severity 重复 | type alias = adapter.Severity | `93b2f56` |
| TopologyProvider 死接口 | 删除 | `3a096a9` |

### 功能缺陷 & Bug (4项)

| 问题 | 修复 | 提交 |
|------|------|------|
| Keycloak/FreeIPA CheckID 为空 | ExecuteAdapter 管线注入 ApplyDelegation | `3a096a9` |
| CLI plugin info 类型断言 bug | p.(kernel.Plugin).Info() | `f4dc5b2` |
| 引擎 PhasePostReport 缺失 | Assess/AssessFromResults 添加 | `e421ae1` |
| PrismEngineProvider DI 回退 | main.go 预绑定 | `e421ae1` |

---

## 延后项 (4项)

| 问题 | 严重度 | 原因 | 建议 |
|------|--------|------|------|
| ATTACKInterface 71 方法 | 🔴 高 | ISP 重构，跨 10+ 文件 | 专项 PR |
| NormalizedFinding 字段差异 | 🟡 中 | adapter(17) vs adapterhub(12) | adapterhub 迁移 |
| 7 Bus 主题零订阅者 | 🟡 低 | 预定义常量无消费者 | 增量添加 |
| TestSPCImportOSCALDuplicate | 🟡 低 | 预存 merge 语义 | 测试修复 |

---

## 构建与测试

| 指标 | 状态 |
|------|------|
| `go build ./...` | ✅ 全量通过 |
| `go vet ./...` | ✅ 零警告 |
| 测试通过率 | **15/16 (93.8%)** |
| 唯一失败 | TestSPCImportOSCALDuplicateHandling (预存) |
| 交叉编译 | ✅ linux/amd64 3二进制 |

---

## 本会话提交清单 (8次)

```
93b2f56 srd_adapters桥接 + extmgr生命周期 + adapterhub类型统一
f4dc5b2 CLI plugin info 类型断言bug修复
6222454 适配器测试委托规则期望同步
3a096a9 适配器管线ApplyDelegation统一 + TopologyProvider清理
8ad6b2e ATT&CK 9个死扩展点Execute接线
e421ae1 CheckID空值/引擎PhasePostReport/PrismEngineProvider DI
0633e4d 首次架构审计报告归档
8788f66 韧性域RS-013~016新增检查项
```

---

## 项目最终指标

| 指标 | 值 |
|------|-----|
| 插件注册 | 16 (含 srd_adapters) |
| 适配器 | 21 |
| 检查项 | 80 (RS-013~016 新增) |
| 测试项 | 162 |
| 源代码文件 | 145 |
| 测试文件 | 26 |
| 外部依赖 | 2 (gRPC + protobuf) |
