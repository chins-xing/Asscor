# ASSCOR 扩展体系与架构设计审计

**日期**: 2026-07-25 | **版本**: v0.2.1 | **审计范围**: 6 种扩展机制、66 个扩展点、9 种扩展类型、8 个引擎钩子

---

## 执行摘要

ASSCOR 扩展体系由 **6 种独立运行的、互不协作的扩展机制** 组成。整体评分：**架构设计完整（66 点覆盖 11 模块），但可插拔性为零（0 订阅者）。**

| 维度 | 评级 | 关键发现 |
|------|:---:|---------|
| 覆盖完整度 | A | 66 个扩展点覆盖全部 11 个业务模块 |
| 可插拔性 | **F** | 0 订阅者 — 整套系统是死代码 |
| 机制间互操作 | **F** | 6 种机制互不连接 |
| 实现质量 | C | 8 P0 / 14 P1 / 5 P2 缺陷 |

---

## 一、六大扩展机制现状

```
┌───────────────────────────────────────────────────────────────┐
│ 1. Plugin 接口      ✅ 15 个内置插件运行中                    │
│ 2. Extension Point  ❌ 66 点, 0 订阅者, 全部死代码            │
│ 3. ExtensionMgr     ⚠️ 9 类型仅 3 可用, 与扩展点无桥接       │
│ 4. PluginSDK        ❌ 独立 JSON-RPC 协议, 无调用者           │
│ 5. PkgMgr (可选)    ⚠️ 独立 dep 管理, 无集成                 │
│ 6. Engine Hooks     ❌ 8 阶段仅 1 被用, 与扩展点无关         │
└───────────────────────────────────────────────────────────────┘
```

核心缺陷：**Extension Point 系统基础设施最完整（66 点），但无订阅者。ExtensionMgr 类型系统最丰富（9 种），但无桥接代码连接到扩展点系统。** 如果 ExtMgr 能在安装时通过 `RegisterExtension` 订阅扩展点，整个体系即可激活。

---

## 二、P0 级缺陷 (8 项)

| # | 缺陷 | 位置 |
|---|------|------|
| 1 | **66 个扩展点零订阅者** — 全系统死代码。74 个触发点全部 fire-and-forget，返回的 error 被丢弃 | `extensions.go:66`, 全代码库 |
| 2 | **extmgr 与 Extension Point 零桥接** — 6/9 类型因无回调(nil)而失效，其余仅桥接到 engine hooks | `extension_manager.go:339-358` |
| 3 | **InstallFromSpec TOCTOU 竞态** — 依赖检查与安装之间的锁释放窗口 | `extension_manager.go:138-147` |
| 4 | **无二进制签名验证** — `resolveBinary` 仅 `os.Stat`，任意可执行文件均可通过 | `extension_executor.go:280-304` |
| 5 | **extmgr 不含 PluginSDK 启动代码** — JSON-RPC 协议定义了但无进程 spawn 逻辑 | `extmgr/` vs `pluginsdk/` |
| 6 | **pkgmgr 不处理传递依赖** — 仅解析一级依赖 | `manifest.go:192-237` |
| 7 | **`ExecuteUntilFirst` 损坏** — 返回 pluginID 而非 handler 结果；从未被调用 | `extensions.go:124-137` |
| 8 | **完整 `AssessmentResult` 通过扩展点传递** — 敏感安全数据无过滤暴露给所有处理器 | `assessor.go:363` |

---

## 三、P1 级缺陷 (14 项)

| # | 缺陷 | 位置 |
|---|------|------|
| 1 | 5 个扩展点定义但从未触发：`log.entry_received`、`agent.log_uploaded`、`siem.post_push`、`siem.push_failure`、`commander.key_rotated` | `platform_extensions.go:164-186` |
| 2 | 6/9 extmgr 类型非功能性：CheckModule/ScoringPlugin/Adapter/CLICommand/WebPanel/Custom 均为存根 | `extension_manager.go:339-358` |
| 3 | `registerCheckModule` 仅日志，不注册实际检查 | `extension_manager.go:390-418` |
| 4 | `OnScoringPlugin`/`OnCLICommand`/`OnWebPanelRoute` 回调默认 nil | `extension_manager.go:340-356` |
| 5 | `onExtension*` 回调在锁外调用 — assessor 引用可能过期 | `extension_manager.go:302-309` |
| 6 | PluginSDK 错误码不标准（缺少 -32600 至 -32603） | `sdk.go:89` |
| 7 | pkgmgr 版本约束语法与 extmgr 不兼容（pkgmgr 支持 `^`/`~`/`x`，extmgr 不支持） | `manifest.go:334-395` vs `extension_spec.go:125-196` |
| 8 | SemVer 解析在 extmgr 和 pkgmgr 中重复实现 | `extension_spec.go:42` / `manifest.go:397` |
| 9 | 7/8 引擎阶段钩子从未使用 | `extensibility.go:16-23` |
| 10 | 引擎钩子无法从 Extension Point 访问 — 两套独立钩子系统 | `extensibility.go:35-37` |
| 11 | pkgmgr 和 extmgr 为两套竞争性包管理，无桥接 | 架构 |
| 12 | ASSCOR 版本硬编码为 "0.2.1"（非运行时检测） | `fetcher.go:148` |
| 13 | extmgr 白名单默认包含 7 个脚本解释器 | `extension_manager.go:37-39` |
| 14 | `ExecuteCustom` 符号链接遍历未完全守护 | `extension_executor.go:225-229` |

---

## 四、P2 级缺陷 (5 项)

| # | 缺陷 |
|---|------|
| 1 | `RegisterExtension` 每次追加排序 — O(n log n) |
| 2 | EdgeFactor 启用时值硬编码为 1.0，忽略自定义配置 |
| 3 | 优先级排序语义未文档化（仅升序, 无"最后运行"哨兵值） |
| 4 | 缺少 `extension.config_changed` 生命周期钩子 |
| 5 | 7 个内核模块无扩展点入口（collector/srd/auditlog/historical/circuitbreaker/workerpool/ratelimit） |

---

## 五、架构集权分析

### 5.1 关键断点

```
ExtMgr ──❌── Extension Points (66 点)
ExtMgr ──❌── PluginSDK (JSON-RPC spawn)
PkgMgr ──❌── ExtMgr (import/install 桥)
ExtPoints ──❌── EngineHooks (两套独立钩子系统)
Plugins ──❌── ExtMgr (插件无法管理扩展)
```

### 5.2 冗余

| 冗余项 | 位置 |
|--------|------|
| 版本约束解析 — extmgr 和 pkgmgr 各有一套实现 | `extension_spec.go` / `manifest.go` |
| 钩子/事件分发 — ExtensionRegistry 和 HookRegistry 近乎相同的结构 | `extensions.go` vs `extensibility.go` |
| 包管理 — extmgr（二进制）和 pkgmgr（源码）无共享协议 | `extmgr/` vs `pkgmgr/` |

### 5.3 类型安全

所有 74 个扩展点触发点通过 `interface{}` 传递数据。如果订阅者存在，需要盲类型断言。无编译期类型验证保证 handler 期望的类型与触发点传递的类型匹配。

---

## 六、P0 修复路径（最小改动恢复功能）

| 步骤 | 变更 | 影响 |
|:---:|------|------|
| 1 | 在 `extension_manager.go` 的 `onExtensionInstalled` 中添加 `m.kernel...(Extensions()).RegisterExtension(...)` | extmgr 安装的扩展可订阅扩展点 |
| 2 | 为 extmgr 的 `ExtTypeHook` 类型扩展注册路径，支持任意扩展点名称（非仅 engine hooks） | Hook 类型获得全部 66 点访问权限 |
| 3 | 修复 `ExecuteUntilFirst`：返回 handler 结果，并在 CLI `webui.route.register` / `cli.command.register` 中使用 | 独占性扩展点可用 |
| 4 | 接入 5 个死扩展点：`log.entry_received` → collector，`siem.post_push/failure` → siem_push，`agent.log_uploaded` → services，`commander.key_rotated` → commander | 死点变活 |

---

## 七、总结

ASSCOR 扩展体系是**架构设计完备但可插拔性为零**的状态。66 个扩展点全面覆盖了探测→响应→报告→修复→验证→归档全生命周期，但有 0 个订阅者。extmgr、pkgmgr、PluginSDK、EngineHooks 四个独立系统未与核心 Extension Point 系统建立连接。修复的关键是在 extmgr 和 Extension Point 之间建立桥接层 — 这是单一改动即可激活整套体系的最小变更。

---
*审计完成于 2026-07-25T14:43+08:00。仅审计，不立即修复。*
