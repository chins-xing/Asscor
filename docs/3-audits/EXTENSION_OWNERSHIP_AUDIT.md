# ASSCOR 扩展体系归属审计

**日期**: 2026-07-12 | **结论**: :green_circle: 平台独占比定义权, 模块保有订阅/触发/管理能力

---

## 一、审计目标

1. :heavy_check_mark: 扩展点**定义权**是否归属 ASSCOR 平台层 (而非各模块)
2. :heavy_check_mark: 模块是否**丧失** `RegisterPoint` 能力
3. :heavy_check_mark: 模块是否**保留**扩展能力: 订阅 (`RegisterExtension`) + 触发 (`Execute`) + 管理 (`UnregisterPlugin`)

---

## 二、架构验证

### 2.1 接口隔离: 两套接口, 权限分层

```
┌──────────────────────────────────────────┐
│  *ExtensionRegistry (平台层, 内部)        │
│  methods:                                │
│    RegisterPoint()          ← 平台独占    │
│    RegisterExtension()      ← 平台+模块   │
│    UnregisterPlugin()       ← 平台+模块   │
│    Execute()                ← 平台+模块   │
│    ListPoints()            ← 平台+模块   │
│    GetPoint()              ← 平台+模块   │
└──────────────────────────────────────────┘
                    │
                    │ PlatformExtensionRegistry()
                    │ (concrete *Kernel only, NOT on KernelContext)
                    ▼
┌──────────────────────────────────────────┐
│  ModuleExtensions (对模块暴露接口)        │
│  methods:                                │
│    RegisterExtension()      ✅ 订阅扩展    │
│    UnregisterPlugin()       ✅ 管理订阅    │
│    Execute()                ✅ 触发事件    │
│    ExecuteUntilFirst()      ✅ 链式触发    │
│    ListPoints()            ✅ 查询点列表   │
│    GetPoint()              ✅ 查询点详情   │
│    ListExtensions()        ✅ 查询订阅者   │
│                                         │
│    RegisterPoint()          ❌ NOT PRESENT │
└──────────────────────────────────────────┘
```

### 2.2 接口定义位置

| 接口 | 文件 | 行 | 可见性 |
|------|------|:--:|:--:|
| `ModuleExtensions` | `extensions.go:14-22` | 7 方法 | `KernelContext.Extensions()` 返回值 |
| `*ExtensionRegistry` | `extensions.go:39` | 全部 | 仅 `Kernel.PlatformExtensionRegistry()` |

### 2.3 KernelContext 暴露面

`plugin.go:55-67` — `KernelContext` 接口:
```go
Extensions() ModuleExtensions   // 模块看到的扩展接口
```

**模块无法调用 `RegisterPoint()`** — 编译器会拒绝: `ModuleExtensions has no field or method RegisterPoint`

### 2.4 平台调用入口

仅两处可调用 `RegisterPoint()`:

| 位置 | 功能 | 性质 |
|------|------|:--:|
| `kernel.go:53-82` | 6 个 kernel 生命周期点 | 内核构造时注册 |
| `platform_extensions.go:7-115` | 30 个域扩展点 | main.go 启动时 `RegisterAllExtensionPoints()` |
| `extensions.go:53` | `RegisterPoint` 方法定义 | — |

---

## 三、模块能力验证

### 3.1 模块可以: 订阅扩展 (`RegisterExtension`)

`extensions.go:66` — 任何拥有 `KernelContext` 的模块均可:
```go
kc.Extensions().RegisterExtension("myPlugin", "assessor.post_evaluate", handler, priority)
```

### 3.2 模块可以: 触发事件 (`Execute`)

6 个模块中 34 处 `Execute()` 调用均正常工作，例如:
```go
m.kernel.Extensions().Execute(ctx, "verify.post_check", data)  // assessor.go
```

### 3.3 模块可以: 管理订阅 (`UnregisterPlugin`)

`extensions.go:88` — 模块停止时清理:
```go
kc.Extensions().UnregisterPlugin("myPlugin")
```

### 3.4 模块可以: 查询扩展点 (`ListPoints`, `GetPoint`, `ListExtensions`)

三种查询方法均在 `ModuleExtensions` 接口中。

---

## 四、扩展点全量清单 (Platform-Owned)

### 4.1 域扩展点 (platform_extensions.go, 30 点)

| 阶段 | 扩展点 | 订阅模块名 | 触发位置 |
|------|--------|---------|------|
| Detect | `assessor.pre_evaluate` | — | `assessor.go:337,408` |
| Detect | `assessor.post_evaluate` | — | `assessor.go:379,479` |
| Detect | `spc.pre_calculate` | — | `spc.go:398` |
| Detect | `spc.post_calculate` | — | `spc.go:629` |
| Detect | `spc.cve_updated` | — | SPC fetch sub |
| Detect | `attck.coverage.complete` | — | `attck.go:517,1173` |
| Detect | `attck.detection.alert` | — | `attck.go:671`, `attck_detection.go:140` |
| Detect | `attck.detection.anomaly` | — | `attck_detection.go:226` |
| Detect | `attck.behavioral.alert` | — | `attck_apt_detect.go:168` |
| Detect | `attck.behavioral.beacon` | — | `attck_apt_detect.go:288` |
| Respond | `policy.action_decided` | — | `policy.go:161` |
| Respond | `policy.notify` | — | `policy.go:170` |
| Respond | `policy.status_changed` | — | `policy.go:154` |
| Respond | `attck.emulation.complete` | — | `attck_emulation.go:356` |
| Respond | `attck.apt.hunt_confirmed` | — | `attck_apt_hunt.go:163` |
| Respond | `attck.apt.chain_detected` | — | `attck_apt_chain.go:94` |
| Respond | `attck.apt.matched` | — | `attck.go:536,1286` |
| Respond | `attck.apt.attribution` | — | `attck.go:566` |
| Report | `attck.risk.predicted` | — | `attck.go:582,1359` |
| Report | `attck.assessment.complete` | — | `attck_assessment.go:144` |
| Report | `attck.apt.report_generated` | — | `attck_apt_attribution.go:434` |
| Remediate | `remediation.pre_apply` | — | `commander.go:266` |
| Remediate | `remediation.post_apply` | — | `commander.go:311` |
| Remediate | `remediation.action_resolved` | — | `commander.go:318` |
| Verify | `verify.pre_check` | — | `assessor.go:355,412` |
| Verify | `verify.post_check` | — | `assessor.go:384,479` |
| Verify | `verify.status_changed` | — | 待接线 |
| Archive | `archive.pre_write` | — | `persistence.go:468` |
| Archive | `archive.post_write` | — | `persistence.go:476` |
| Archive | `archive.rotation` | — | `persistence.go:698,784` |

### 4.2 平台自身扩展点 (platform_extensions.go, 2 点)

| 扩展点 | 用途 |
|--------|------|
| `cli.command.register` | 插件注册自定义 CLI 命令 |
| `webui.route.register` | 插件注册 HTTP 路由 |

### 4.3 内核生命周期扩展点 (kernel.go NewKernel, 6 点)

| 扩展点 | 时机 |
|--------|------|
| `kernel.pre_init` | 所有插件初始化前 |
| `kernel.post_init` | 所有插件初始化后 |
| `kernel.pre_start` | 所有插件启动前 |
| `kernel.post_start` | 所有插件启动后 |
| `kernel.pre_stop` | 关机序列开始前 |
| `kernel.post_stop` | 所有插件停止后 |

**总计: 38 个扩展点, 全部由平台层定义, 0 个由模块定义。**

---

## 五、编译器保证

尝试在模块中调用 `RegisterPoint()`:

```go
// 假设在 policy.go 的 Init 中
kc.Extensions().RegisterPoint(...)
```

编译错误:
```
kc.Extensions().RegisterPoint undefined
(type kernel.ModuleExtensions has no field or method RegisterPoint)
```

**模块已从类型系统层面被禁止定义扩展点。这不是约定，是约束。**

---

## 六、扩展点注册时序

```
NewKernel()
  └→ extPoints = NewExtensionRegistry()                    ← 创建注册表
  └→ RegisterPoint: kernel.pre_init/post_init/pre_start/   ← 内核生命周期点
     post_start/pre_stop/post_stop (6 点)

main.go:
  ├→ RegisterPlugin(attck, spc, assessor, ...)             ← 模块注册
  ├→ RegisterAllExtensionPoints(k.PlatformExtensionRegistry())  ← 30 域扩展点注册
  ├→ k.Start()
  │   ├→ kernel.pre_start
  │   ├→ plugin.Start() (按优先级)
  │   │   └→ kc.Extensions().RegisterExtension(...)        ← 模块订阅扩展
  │   └→ kernel.post_start
```

**关键保证**: 扩展点在所有模块启动前已定义完毕 (`RegisterAllExtensionPoints` 在 `RegisterPlugin` 之后、`Start` 之前调用)。模块启动时即可安全订阅。

---

## 七、结论

| 检查项 | 结果 | 证据 |
|--------|:--:|------|
| 平台独占扩展点定义权 | :green_circle: | `RegisterPoint` 仅 `platform_extensions.go` + `kernel.go` |
| 模块无法定义扩展点 | :green_circle: | `ModuleExtensions` 不含 `RegisterPoint` — 编译器保证 |
| 模块可订阅扩展 | :green_circle: | `ModuleExtensions.RegisterExtension()` |
| 模块可触发事件 | :green_circle: | 34 处 `Execute()` 调用全部正常 |
| 模块可管理扩展 | :green_circle: | `ModuleExtensions.UnregisterPlugin()` / `ListExtensions()` |
| 编译器强制隔离 | :green_circle: | 类型系统禁止模块调用 `RegisterPoint` |

**:white_check_mark: 扩展体系归属 ASSCOR 平台层, 模块保有订阅/触发/管理能力, 编译器保证不可越权。**
