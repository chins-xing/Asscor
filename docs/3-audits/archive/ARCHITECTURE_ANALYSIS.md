# ASSCOR 架构、耦合度与性能分析报告

**分析日期**: 2026-06-05 | **代码库规模**: ~135个Go文件，18个内部模块 | **版本**: ASSCOR v0.2.0 / SSAM 2.0

---

## 一、架构分析

### 1.1 整体架构层次

```
┌────────────────────────────────────────────────────┐
│  cmd/          入口层 (3 入口)                       │
│  kernel/ agent/ asscor/                             │
├────────────────────────────────────────────────────┤
│  internal/cli/    internal/webui/   外部界面层        │
├────────────────────────────────────────────────────┤
│  internal/kernel/  ─── 微内核核心 (47 文件)           │
│  ┌──────┬───────┬────────┬───────┬──────────────┐  │
│  │Plugin │ DI    │ Bus    │  SPC  │ ATT&CK V19   │  │
│  │System │ Cont. │ (PubSub)│      │ (4+4 子模块)  │  │
│  ├──────┼───────┼────────┼───────┼──────────────┤  │
│  │Assessor│Policy│Commander│CTI  │AdapterInt.   │  │
│  └──────┴───────┴────────┴───────┴──────────────┘  │
├────────────────────────────────────────────────────┤
│  internal/engine/   评估引擎     internal/ssam/ 评分 │
│  internal/adapter/  21适配器    internal/checks/检查 │
│  internal/srd/      风险判定    internal/prism/传播  │
│  internal/model/    领域模型    internal/config/配置 │
├────────────────────────────────────────────────────┤
│  internal/logger/ common/ version/  基础层 (无依赖)   │
├────────────────────────────────────────────────────┤
│  ssam-lib/  prism-lib/   外部纯函数库 (零内部依赖)    │
│  github.com/chins-xing/ssam  github.com/chins-xing/prism │
└────────────────────────────────────────────────────┘
```

### 1.2 架构模式识别

| 模式 | 应用位置 | 评价 |
|------|----------|------|
| **微内核 + 插件** | `kernel.go` Plugin 接口，18个插件按优先级(1-90)加载 | 成熟 |
| **依赖注入容器** | `kernel/di.go` 反射型 IoC，17个绑定 | 实现完整，但字段注入(`Inject`)未使用 |
| **发布/订阅事件总线** | `kernel/bus.go` 双层信号量(1024+256)并发控制 | 无优雅排空 |
| **拦截器链** | `kernel/interceptor.go` 中间件模式 | 内置速率限制/熔断/审计 |
| **适配器架构** | `adapter/` + `adapterhub/` 21个外部工具适配器 | init()自注册，解耦良好 |
| **熔断器** | `kernel/circuitbreaker.go` Closed→Open→Half-Open 三态 | 滑动窗口，有效 |
| **策略模式** | `kernel/policy.go` 基于分数的自动动作 | 阈值逻辑已修复为互斥 |
| **策略模式** | `internal/engine/extensibility.go` 8阶段钩子 | 生命周期完整 |
| **纯函数式内核** | `ssam-lib/` 零依赖、无 I/O、无锁 | 架构亮点 |

### 1.3 架构质量评估

**优势**:
- **清晰的分层边界**: model/logger/common/version 是真正的叶节点包（零内部依赖）
- **无循环依赖**: 依赖图是完全的 DAG
- **接口隔离**: SSAM 通过 `Provider` 四子接口暴露能力
- **独立库拆分**: ssam-lib 可被任意 Go 项目独立引用
- **插件生命周期完整**: Init→Start→Stop→HealthCheck 四阶段

**问题**:
- **`internal/kernel/` 是上帝包**: 47个文件，10个内部包+2个外部包依赖，承担了过多职责
- **SPC 模块完全重复**: `internal/kernel/spc*.go` 与 `internal/spc/*.go` 各约3500行，完全相同的实现
- **CLI 和 WebUI 直接依赖 kernel 包**: 破坏了依赖倒置原则，应通过接口抽象
- **srd/ 包重复定义了简化的 KernelContext**: 无法使用完整的 DI 容器

### 1.4 模块职责分布

| 模块 | 文件数 | 代码行数(估算) | 职责 |
|------|--------|---------------|------|
| kernel/ | 47 | ~15,000 | 微内核核心(插件系统+DI+总线+SPC+ATT&CK) |
| spc/ | 6 | ~3,500 | SPC 安全态势计算(与 kernel/spc*.go 重复) |
| engine/ | 4 | ~1,200 | 评估引擎核心流程 |
| ssam/ | 6 | ~800 | SSAM 适配层 |
| adapter/ | 5+12 | ~3,000 | 21个外部工具适配器 |
| cli/ | 7 | ~2,500 | 交互式命令行 |
| checks/ | 3+2 | ~2,800 | 安全检查项定义 |
| srd/ | 7 | ~1,200 | 外部报告与 Prism 集成 |

---

## 二、耦合度分析

### 2.1 依赖图

```
cmd/kernel, cmd/asscor (入口)
  ├── internal/cli/ ──────────► kernel/ (接口消费)
  ├── internal/webui/ ────────► kernel/ (总线+容器)
  ├── internal/engine/ ───────► adapter, checks, config, model, ssam (不依赖 kernel!)
  ├── internal/kernel/ ───────► engine, config, model, ssam, prism, adapter, common, api/v1 (10个内部+2个外部)
  ├── internal/extmgr/ ───────► checks, engine, model
  ├── internal/srd/ ──────────► prism + logger
  ├── internal/ssam/ ─────────► config, model + github.com/chins-xing/ssam
  ├── internal/adapterhub/ ───► adapter, model
  ├── internal/adapter/ (根)
  │   ├── scanner/ ───────────► 父 adapter/, model
  │   └── management/ ────────► 父 adapter/, model
  ├── internal/checks/
  │   └── linux/ ─────────────► common, model
  ├── internal/model/ ────────► (纯标准库 — 叶节点)
  ├── internal/config/ ───────► model, logger
  ├── internal/logger/ ───────► (纯标准库 — 叶节点)
  ├── internal/common/ ───────► (纯标准库 — 叶节点)
  └── api/v1/ ────────────────► google.golang.org/grpc (仅外部)
```

**结论: 无循环依赖**，整个依赖图是严格的 DAG。

### 2.2 耦合度量

| 指标 | 数值 | 评价 |
|------|------|------|
| model/ 被引用次数 | 12 个包 | **最高** (符合预期——领域模型中心) |
| kernel/ 外部消费者 | 3 个包 (cli, webui, cmd) | 低 (内核封装良好) |
| kernel/ 内部依赖数 | 10 个内部包 | **高** (上帝包特征) |
| ssam/ 外部引用 | 2 个包 (kernel, engine) | 低 (使用集中) |
| 外部依赖总数 | 4 个 (grpc, grpc/*, ssam, prism) | **极低** (加分项) |
| 循环依赖 | 0 | **优秀** |
| 叶节点包 | 4 个 (model, logger, common, version) | 稳健 |

### 2.3 DI 容器耦合分析

容器通过 `internal/kernel/di.go` 实现，基于反射的类型映射 + 命名别名：

**绑定清单 (17项)**:
| 优先级 | 绑定接口 | 绑定方 | 模式 |
|--------|----------|--------|------|
| 预绑定 | `*config.Config` (命名"config") | `main.go` | 命名绑定 |
| 预绑定 | `*ScoringEngineProvider` | `main.go` | 类型绑定 |
| P=2 | `*ConcurrencyInterface`, `*WorkerPoolInterface` | `ConcurrencyModule` | 自注册 |
| P=3 | `*PersistenceInterface` | `PersistenceModule` | 自注册 |
| P=5 | `*HeartbeatInterface` | `HeartbeatModule` | 自注册 |
| P=10 | `*CTIInterface` | `CTIModule` | 自注册 |
| P=20 | `*SPCInterface` | `SPCModule` | 自注册 |
| P=21 | `*ATTACKInterface` | `ATTACKModule` | 自注册 |
| P=40 | `*ssam.ScoringProvider` | `AssessorModule` | 子对象绑定 |
| P=40 | `*AssessorInterface` | `AssessorModule` | 自注册 |
| P=45 | `*AdapterIntegrationInterface` | `AdapterIntegrationModule` | 自注册 |
| P=50 | `*PolicyInterface` | `PolicyModule` | 自注册 |
| P=55 | `*SourceManagerInterface` | `SourceManagerModule` | 自注册 |
| P=60 | `*CommanderInterface` | `CommanderModule` | 自注册 |
| P=70 | `*LogCollectorInterface` | `LogCollectorModule` | 自注册 |
| P=90 | `*CLIInterface` | `CLIModule` | 自注册 |

**耦合问题**:
1. **字段注入(`Inject`)完全未使用**: 所有解析都用显式 `Resolve()/ResolveNamed()`，sturct tag 注入机制是死代码
2. **双重解析模式**: `Resolve` 和 `ResolveNamed` 同时存在但 `BindNamed` 也将绑定存为类型键——冗余索引
3. **容器仅在 kernel/ 和 cmd/ 中使用**: srd/、spc/ 独立包定义了自己的简化 `KernelContext` 接口，无法使用 DI
4. **手动构造服务层**: `main.go` 和 `services.go` 仍然手动 `NewXxxServiceImpl(heartbeat, commander, ...)` 传参，DI 与手动构造并存

### 2.4 Adapter 架构耦合

适配器采用 `init()` 自注册模式——这是清晰的松耦合设计:
- `adapter/registry.go` 定义全局 `Register/Get/List` 接口
- 每个适配器在 `init()` 中调用 `Register()`
- `engine/adapter_import.go` 通过空白导入触发注册
- 父包不依赖子包——单向依赖流

---

## 三、性能分析

### 3.1 关键热路径

#### 3.1.1 评估主路径 (每条心跳触发)

```
AssessorModule.Evaluate()
  ├─ engine.Assess()                    [O(C+P) C=200检查项]
  │   ├─ runChecksConcurrently()        [信号量10, goroutine/检查 = 200]
  │   ├─ computeSPCScore()              [O(N*P*A), N=100k CVEs, P=50k包, A=百位CPE] ★瓶颈
  │   ├─ ssam.ComputeScore()            [O(C)]
  │   └─ applyATTACK()                 [O(T*M*K)]
  ├─ applySPCAndCTI()                   [重复调用! SPC计算执行两次] ★BUG
  ├─ applyATTACK()                      [重复调用!]
  └─ applyPrismToResult()              [O(N) 拓扑边遍历]
```

**严重问题: SPC 分数被计算两次**。`engine.Assess()` (L230) 已调用 `computeSPCScore()`，`AssessorModule.Evaluate()` (L162) 再次调用 `applySPCAndCTI()` 导致完整的 CVE→资产匹配执行两遍。在 100k CVE 缓存下翻倍延迟。

#### 3.1.2 SPC 计算复杂度 `internal/spc/calculate.go`

```
Calculate()
  for 每个 CVE (N=100,000):
    matchCPE(cve, asset, packages)
      for 每个包名 (P=50,000):
        for 每个受影响 CPE (A=~10):
          strings.Contains()           → O(N*P*A) ≈ 500亿次比较
    Impact = 0.2*cvss + 0.5*log(epss) + 0.3*kev
    Penalty = Impact * LocalFactor * TimeWindow
  P_score = max(0.60, 1.0 - sqrt(sum(Penalty²)))
```

**复杂度**: O(N × P × A) + O(N)。在 100k CVE / 50k 包的最坏情况下接近 500亿次字符串比较。`cpeIndex` 在 `calculate.go:42` 构建但**从未使用**——这是死代码，实际匹配委托给 `matchCPE()` 中的 O(N*P*A) 循环。

#### 3.1.3 gRPC Heartbeat 处理 `internal/kernel/services.go`

`Heartbeat()` 同步完成:
1. 心跳记录 (快)
2. CPE 正则验证 (50k封顶, regex.Match)
3. SPC asset upsert (快)
4. **完整评估**: `assessor.EvaluateFromResults()` — 阻塞直到完成包括 SPC 计算
5. 待执行命令出队

没有超时控制，无异步化。一次心跳可能阻塞数秒至数分钟。

### 3.2 并发模型分析

| 组件 | 并发策略 | 评价 |
|------|----------|------|
| **Bus (bus.go)** | 双层信号量: maxGoroutines=1024 + dispatchSem=256 | 防止无界 goroutine 增长 |
| **WorkerPool (workerpool.go)** | 信号量=10 + per-task 30min 超时 | 存在 goroutine 泄漏风险 |
| **Assessor 检查执行** | 信号量=10, WaitGroup, 1 goroutine/检查 | 200检查=200 goroutine |
| **Agent 检查执行** | 信号量=10, 双层 goroutine | 不必要的双重 goroutine |
| **SPC NVD 拉取** | 信号量=并发数(无API Key=4), WaitGroup | 分片并发拉取 |
| **gRPC 服务** | grpc-go 内置 per-connection goroutine | 原生并发 |
| **TCP 服务** | 连接信号量=100, WaitGroup | 过载保护 |
| **Adapter 流水线** | 信号量=10, WaitGroup, 适配器级超时 | 有超时控制 |

**问题**:
- **WorkerPool 内部 goroutine 泄漏**: 任务超时后内部 goroutine 可能永久阻塞 `done <- task()`
- **Agent 双重 goroutine**: `agent.go:1161-1167` 每个检查创建外层+内层两个 goroutine, 200检查=400 goroutine
- **Bus Stop() 无优雅排空**: 设置 `stopped` 标志后立即清理订阅者，已发起的 goroutine 未等待

### 3.3 内存与缓存分析

#### 3.3.1 无界增长

| 严重性 | 位置 | 结构 | 问题 |
|--------|------|------|------|
| **严重** | `attck.go:134-156` | alerts, anomalies, IOCs, ttpTracks, emulationResults, attackChains, behavioralAlerts, beaconDetections, huntHypotheses, huntResults | 定义了 max 常量(1k-50k)但**零执行**，仅追加无修剪 |
| **严重** | `kernel/spc*.go` vs `spc/*.go` | 整个 SPC 模块 | **完全重复的双份实现**，都包含 100k CVE 缓存 |
| **高** | `heartbeat.go:26` | agents map | Agent 记录**永不移除**，动态主机下无限增长 |
| **高** | `assessor.go:42` | results map | 评估结果**永不移除** |
| **中** | `webui/module.go:33-35` | history/latest/hostnames | 下线主机条目永不清除 |

#### 3.3.2 缓存策略

| 缓存 | 大小限制 | 驱逐策略 | 评价 |
|------|----------|----------|------|
| CVE 缓存 | 100,000 | 1 年时间窗口 + KEV 永不过期 | AddCVE 满时静默丢弃 |
| WebUI 历史 | 200/主机 | FIFO (切片截断) | 正确 |
| EPSS 临时 map | 无限制 | 函数返回时释放 | 预分配 50k 但实际 250k+，多次 rehash |
| 心跳 Agent map | 无限制 | 无驱逐 | 问题 |
| ATT&CK 所有缓存 | 有常量但无执行 | 仅 analysisHistory(50) 修剪 | 严重 |
| Circuit Breaker | 无限制 | 5分钟清理关闭状态的旧记录 | 正确 |

#### 3.3.3 分配热点

- **无 `sync.Pool` 使用**: 整个代码库零对象池化。cpeIndexEntry、EPSS 临时 map 等高频分配对象可从池化受益
- **`defer` 不在热循环内**: defer 使用正确，仅用于锁/连接释放
- **`strings.Builder`**: CLI 输出路径正确使用，`regexp.MustCompile` 在 `checks/linux/checks.go:1654-1655` 热路径内编译

### 3.4 I/O 性能

| 问题 | 位置 | 影响 |
|------|------|------|
| **每次日志条目后 `f.Sync()`** | `kernel/collector.go:136` | 每条日志强制磁盘刷新，严重降低吞吐 |
| 49+ `os.ReadFile` 每次检查周期 | `checks/linux/checks.go` | 多个检查重复读取相同配置文件(sshd_config等)，无缓存 |
| `json.Marshal` 批处理逐条 | `kernel/collector.go:160` | 可用 `json.Encoder` 流式编码 |
| `time.After` + `time.Sleep` 双重阻塞 | `spc_fetch.go:562-569` | timer 泄漏 + 冗余阻塞 |
| `regexp.MustCompile` 在热路径内 | `checks/linux/checks.go:1654-1655` | OT-018 每次执行时编译两个正则 |

### 3.5 goroutine 泄漏

| 位置 | 机制 | 严重性 |
|------|------|--------|
| `workerpool.go:75` | 内部 goroutine `done <- task()` 阻塞后未取消 | 中 (有日志警告) |
| `agent.go:1166` | 同样模式，`done <- c.Run()` | 低 (60s超时) |
| `kernel.go:163` | 插件 Unregister 异步 Stop，未跟踪 | 低 (共享 ctx 会传播取消) |
| 总计后台 goroutine | 14 个长期运行的循环 | 全部有正确取消机制 |

---

## 四、发现汇总

### 严重问题 (建议优先修复)

| # | 类别 | 问题 | 位置 |
|---|------|------|------|
| C1 | 性能 | SPC 评估每次心跳执行两次(SPC计算+ATT&CK分析重复) | `kernel/assessor.go:162-163` vs `engine/assessor.go:230,258` |
| C2 | 性能 | SPC Calculate O(N*P*A) 三重循环，500亿次字符串比较 | `spc/calculate.go:282-343` |
| C3 | 内存 | ATT&CK 10+缓存无界增长，max常量未执行 | `attck.go:134-156` |
| C4 | 架构 | SPC 模块完全重复(两份实现各3500行) | `internal/kernel/spc*.go` vs `internal/spc/*.go` |
| C5 | 性能 | 日志收集器每次写入后 `f.Sync()` | `kernel/collector.go:136` |

### 高优先级问题

| # | 类别 | 问题 | 位置 |
|---|------|------|------|
| H1 | 内存 | Agent记录永不移除 | `heartbeat.go:26` |
| H2 | 内存 | 评估结果永不移除 | `assessor.go:42` |
| H3 | 性能 | `regexp.MustCompile` 在检查热路径内 | `checks/linux/checks.go:1654-1655` |
| H4 | 耦合 | `internal/kernel/` 上帝包 (47文件, 10内部依赖) | 架构层面 |
| H5 | 内存 | EPSS map 预分配不充分导致重复rehash | `spc_fetch.go:723` |
| H6 | 并发 | WorkerPool 内部goroutine泄漏风险 | `workerpool.go:75` |
| H7 | 性能 | gRPC Heartbeat 同步阻塞执行完整评估无超时 | `services.go:163` |

### 中优先级问题

| # | 类别 | 问题 | 位置 |
|---|------|------|------|
| M1 | 内存 | 零 `sync.Pool` 使用 | 全局 |
| M2 | 架构 | CLI/WebUI直接依赖kernel破坏依赖倒置 | `cli/module.go`, `webui/module.go` |
| M3 | 耦合 | DI字段注入(Inject)实现完整但从未使用 | `kernel/di.go` |
| M4 | 性能 | Agent 双层goroutine每检查(400 goroutine/评估) | `agent.go:1161-1167` |
| M5 | 内存 | CVE缓存满时静默丢弃无优先级驱逐 | `spc_persist.go:25` |
| M6 | 并发 | Bus Stop()无优雅排空 | `bus.go:201-206` |
| M7 | 性能 | `time.After` + `time.Sleep` 双重阻塞 | `spc_fetch.go:562-569` |
| M8 | 性能 | CPE索引构建后从未使用(死代码) | `spc/calculate.go:42-62` |

### 架构亮点

1. **无循环依赖** — 依赖图是严格的 DAG
2. **ssam-lib 纯函数式设计** — 零依赖、无锁、无 I/O，可被任意项目独立引用
3. **极低外部依赖** — 仅 4 个外部包 (grpc, grpc/*, ssam, prism)
4. **适配器自注册模式** — `init()` + `Register()` 松耦合
5. **双层信号量总线路由** — 有效防止 goroutine 爆炸
6. **熔断器 + 速率限制 + 审计日志** — 完整的拦截器链
7. **8阶段评估钩子** — 扩展性良好
8. **原子操作用于锁无关指标** — bus.go metrics 使用 `atomic.Int64`
