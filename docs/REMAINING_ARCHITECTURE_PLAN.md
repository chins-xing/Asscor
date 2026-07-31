# ASSCOR 剩余架构级变更规划

**日期**: 2026-07-31 | **版本**: v0.2.1 | **当前进度**: 52/87 (60%)

---

## 剩余 35 项分类

| 领域 | P0 | P1 | P2 | 合计 |
|------|:---:|:---:|:---:|:---:|
| 扩展体系 | 0 | 6 | 0 | 6 |
| 内核架构 | 2 | 4 | 0 | 6 |
| 测试覆盖 | 0 | 0 | 0 | 0 |
| 接口质量 | 0 | 3 | 0 | 3 |
| 配置/安全 | 0 | 6 | 10 | 16 |
| **合计** | **2** | **19** | **10** | **35** |

---

## Phase A: 扩展体系激活 (P1 × 6, 估时 5 天)

### A1. 扩展体系端到端集成 (E01)
**现状**: 66 个扩展点有 0 个订阅者
**计划**:
1. 创建 `optional/algorithms/modules/sample-extension/` 示例扩展
2. 通过 extmgr 安装 → `SetKernelExtensions` → `RegisterExtension` 完整链路验证
3. 添加集成测试：安装扩展 → 触发评估 → 验证扩展点被调用
4. 修复发现的阻塞性 bug

### A2. extmgr 6/9 类型全面激活 (E10)
**现状**: CheckModule/ScoringPlugin/Adapter/CLICommand/WebPanel/Custom 均为存根
**计划**:
1. 为 CheckModule 添加 checks.json 清单解析 → checks.Register() (已实现 `registerCheckModule`)
2. 为 ScoringPlugin 桥接到 engine.FormulaRegistry
3. 为 CLICommand/WebPanel 桥接到 Extension Point
4. 为 Adapter/Custom 桥接到 adapter.Register()

### A3. extmgr 回调线程安全 (E13)
**现状**: `onExtension*` 回调在锁外调用
**计划**: 将 `m.kernelExtensions.RegisterExtension()` 移入锁保护范围内，或使用快照模式

---

## Phase B: 内核解耦 (P0 × 2 + P1 × 4, 估时 8 天)

### B1. 内核测试覆盖收尾 (P0)
**剩余 2 项**: server.go + config_watcher.go
**计划**:
- server.go: 使用 `net.Pipe()` 模拟连接测试拦截器链、JSON codec、mTLS 配置
- config_watcher.go: 使用 `testing/fstest.MapFS` 或临时文件测试 `forceReload`、`watchLoop` 信号处理

### B2. kernel/ 单体拆分 (M01)
**现状**: 66 文件, 17 插件在同一包
**计划**:
1. Phase 1: 提取 SPC fetch 子包 (已验证可行，需处理 method receiver → function 转换)
2. Phase 2: 提取 ATT&CK 子包 (已有 build tag，需添加物理隔离)
3. Phase 3: 提取 heartbeat/policy/commander 为子包

**关键障碍**: Go method receiver 必须在类型同包定义
**解决方案**: 将方法转为函数 (如 `FetchFromNVD(m *SPCModule, ...)`) 或定义 KernelSubContext 接口

---

## Phase C: 上帝接口拆分 (P1 × 3, 估时 3 天)

### C1. ATTACKInterface 拆分 (T01)
**现状**: 85 方法，已文档化 8 子接口
**计划**: 将复合接口拆分为独立 DI 注册项，消费方按需解析子接口
```
ATTACKInterface → 拆分为:
  - ATTCKCore (18 methods) — DI 主接口
  - ATTCKDetection (8 methods) — 可选，按需注入
  - ATTCKIntelligence (12 methods) — 可选
  - ATTCKEmulation (12 methods) — 可选
  - ATTCKAssessment (9 methods) — 可选
  - ATTCKAPTModules (18 methods) — 可选
```

### C2. SPCInterface 验证 (T02)
**现状**: 已验证已分 4 子接口 (审计误报)
**计划**: 确认，无需修改

### C3. SourceManagerModule 方法文档化 (T03)
**现状**: 29 个方法，是 concrete struct 非 interface
**计划**: 按功能分组文档化: CRUD (7), Config (4), Audit (1), Sync (5), Plugin lifecycles (7), Internal (5)

---

## Phase D: 配置与安全收尾 (P1 × 6 + P2 × 10, 估时 3 天)

### D1. 扩展点文档补全
**现状**: 部分扩展点描述过于简略
**计划**: 为 `platform_extensions.go` 的每个扩展点补充触发时机、数据格式、示例

### D2. FHS 路径参数化 (T32)
**现状**: 安装路径硬编码为 `/opt/asscor`
**计划**: 提取为常量 + 环境变量 override

### D3. 性能优化
- RegisterExtension 插入排序替代全量重排 (O(log n) 替代 O(n log n))
- 扩展点 Execute 快照拷贝可优化为 RCU 模式

### D4. 日志/审计增强
- 扩展点触发记录到 event log
- extmgr 安装/卸载/启用/禁用审计轨迹

---

## 工作量估算

| Phase | 内容 | P0 | P1 | P2 | 估时 |
|-------|------|:---:|:---:|:---:|:---:|
| A | 扩展体系激活 | 0 | 6 | 0 | 5 天 |
| B | 内核解耦 | 2 | 4 | 0 | 8 天 |
| C | 上帝接口拆分 | 0 | 3 | 0 | 3 天 |
| D | 配置与安全 | 0 | 6 | 10 | 3 天 |
| **合计** | | **2** | **19** | **10** | **19 天** |

## 风险排序

| 风险 | Phase | 影响 |
|------|:---:|------|
| kernel/ 单体拆分被 method receiver 限制阻塞 | B2 | 需转换 30+ 方法为函数，破坏 API |
| ATT&CK 接口拆分会破坏现有 DI 注册 | C1 | 需修改 cmd/kernel/main.go + cmd/asscor/main.go |
| extmgr 回调线程安全修复引入死锁 | A3 | 锁嵌套风险 |
| server.go 测试需 mTLS 证书 mock | B1 | 证书生成耗时 |

---
*规划完成于 2026-07-31。建议按 Phase A → B → C → D 顺序推进。*
