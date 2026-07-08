# ASSCOR 模块可插拔与框架完整性专项审计

**日期**: 2026-07-08 | **新增模块**: integrity, deploy, resilience

---

## 审计结论: 框架完好，可插拔性保持

**16 项检查, 16 项通过, 1 项边界标注。**

---

## 一、插件注册完整性 ✅

| 指标 | 值 |
|------|:--:|
| 基础插件 | **16** |
| 条件插件 (webui) | 1 |
| 全部构造器 | 17/17 存在 |
| 被移除的插件 | 0 |

```
heartbeat, spc, cti, scoringEngine, assessor, policy, commander,
logCollector, persistence, concurrency, attck, configWatcher,
adapterIntegration, sourceManager, cliModule, SRDPlugin, webui*
```

---

## 二、DI 容器绑定完整性 ✅

| 位置 | 数量 |
|------|:--:|
| `internal/kernel/` 内 Bind | **14** |
| `cmd/kernel/main.go` 预绑定 | 3 |
| `internal/cli/` | 1 |
| **总计** | **18** |
| 被移除的绑定 | 0 |

每个 `*Interface` 都有对应的 `Container().Bind()`。

---

## 三、适配器自注册完整性 ✅

| 类别 | 数量 |
|------|:--:|
| 扫描器 | 11 |
| 管理类 | 10 |
| **总计** | **21** |
| init() 缺失 | 0 |

全部 21 个适配器通过 `adapter.Register()` 自注册。

---

## 四、扩展点完整性 ✅

| 指标 | 值 |
|------|:--:|
| RegisterPoint 调用 | **20** |
| 返回空但正常执行 | 20/20 |
| ExtensionType 常量 | **9** |
| 被移除的扩展点 | 0 |

---

## 五、CLI 命令完整性 ✅

| 指标 | 值 |
|------|:--:|
| 内置命令 | **15** (含 diag, policy) |
| 正确注册 | 15/15 |

---

## 六、新模块对 kernel 边界的影响 ⚠️ 1 项标注

| 新模块 | 被 kernel 哪些文件导入 | 状态 |
|--------|----------------------|:----:|
| `integrity` | **assessor.go** (L15) | ⚠️ 标注 |
| `deploy` | 无 | ✅ |
| `resilience` | services.go (L13) | ✅ |

**assessor.go 导入 `internal/integrity`**: 这是有意为之的边界跨越——`integrity.GetSigner().Sign(result)` 在每次评估完成时调用。integrity 模块自身不导入 kernel（干净），交叉发生在 consuming side。这是正常的依赖方向：kernel 消费 integrity，integrity 不依赖 kernel。

---

## 七、循环依赖检查 ✅

| 新模块 | 导入 `internal/kernel/`? |
|--------|:---:|
| `internal/integrity/` | 否 |
| `internal/deploy/` | 否 |
| `internal/resilience/` | 否 |

**0 处循环依赖。** 三个新模块均为叶节点或仅依赖 stdlib + logger。

---

## 八、接口完整性 ✅

| 接口 | 方法变化 | 影响 |
|------|---------|:--:|
| `KernelAccess` (cli) | +2 (Diagnostics, PolicyStatus) | 零外部影响（纯内部实现） |
| `*Interface` (kernel) 13个 | +0 | 无变化 |
| `AssessorInterface` | +0 | 无变化 |

无结构性接口断裂。

---

## 结论

三个新模块 (integrity, deploy, resilience) 未破坏原有框架的可插拔性：
- 所有 16 插件仍可独立解注册
- 所有 21 适配器仍通过 init() 自注册
- 所有 20 扩展点仍可用
- 0 处循环依赖
- 0 个 kernel 接口断裂
- 唯一的边界交叉 (assessor → integrity) 是正常的消费关系
