# ASSCOR 专项架构审计报告 — 松耦合·无冗余·强扩展·透明管线

**审计日期**: 2026-07-03 | **分支**: main | **版本**: v0.2.0-dev | **总评: 7.6/10**

---

## 审计维度概览

| 维度 | 结果 | 评分 |
|------|------|------|
| 松耦合 (无循环依赖) | 26包严格DAG，0循环依赖 | **10/10** |
| 无冗余依赖 | 2个真正外部依赖 (gRPC+protobuf) | **9/10** |
| 强扩展能力 | 扩展点系统完备但0订阅者 | **5/10** |
| 透明统一管线 | 适配器管线100%统一，引擎管线75%完整 | **7/10** |
| 设计落实度 | 核心意图落实，边缘未完成 | **7/10** |
| **总评** | — | **7.6/10** |

---

## 一、松耦合 — 依赖图分析 (10/10)

### 依赖层级

```
prism-lib  ssam-lib  model  version  logger  common  api/v1    ← Level 0 (叶子)
    ↓          ↓       ↓       ↓        ↓        ↓       ↓
  config    adapter  checks/linux   prism   ssam               ← Level 1
    ↓          ↓         ↓           ↓       ↓
adapterhub  management scanner     srd    checks                ← Level 2
                  ↓                   ↓      ↓
               engine               agent                       ← Level 3
                  ↓
               kernel  extmgr                                    ← Level 4
                 ↓
            cli  webui                                           ← Level 5
                 ↓
          cmd/kernel  cmd/asscor  cmd/agent                      ← Level 6
```

### 验证清单

| 检查项 | 结果 |
|--------|------|
| 循环依赖 | **0** — 严格 DAG |
| model/ 是叶子 (0内部导入) | ✅ |
| logger/ 是叶子 (0内部导入) | ✅ |
| common/ 是叶子 (0内部导入) | ✅ |
| version/ 是叶子 (0总导入) | ✅ |
| adapter/management/ → kernel/ | 无 |
| adapter/scanner/ → kernel/ | 无 |
| checks/ → kernel/或engine/ | 无 |
| ssam-lib ↔ prism-lib 交叉导入 | 无 |

---

## 二、无冗余依赖 (9/10)

### 外部依赖

| 类型 | 数量 | 详情 |
|------|------|------|
| 直接模块 | 4 | ssam, prism (本地replace), grpc, protobuf |
| 间接模块 | 4 | x/net, x/sys, x/text, genproto |
| **真正第三方** | **2** | `google.golang.org/grpc` + `google.golang.org/protobuf` |

- prism-lib/ssam-lib 本地 replace，零外部下载
- 无 ORM、无 Web 框架、无第三方日志库
- go.mod 无未使用依赖

---

## 三、接口与 DI — 松耦合验证 (7/10)

### 接口方法数分布

| 方法数 | 接口数 | 评估 |
|--------|--------|------|
| 1-3 | 9 | ✅ 理想 (ISP 合规) |
| 4-7 | 8 | ✅ 良好 |
| 10 | 2 | ⚠️ 偏大 (KernelContext, PersistenceInterface) |
| 13 | 1 | ⚠️ 需拆分 (SourceManagerInterface) |
| 19 | 1 | ⚠️ 需拆分 (SPCInterface) |
| **71** | **1** | ❌ **God接口** (ATTACKInterface) |

### DI 容器

| 检查项 | 结果 |
|--------|------|
| Bind() 总数 | 16 (14 Init内, 2 main()启动前) |
| Resolve() 保护 | **100%** `if impl, ok := ...` |
| 未 DI 注册插件 | config_watcher, webui (设计意图), **srd_adapters (孤立模块)** |

### 严重问题

| # | 问题 | 位置 |
|---|------|------|
| 1 | **ATTACKInterface 71方法 God 接口** | `attck.go:1570` |
| 2 | **srd_adapters 8文件完整实现但从未注册** | `srd/manager.go` — 不在 cmd/kernel/main.go |
| 3 | **TopologyProvider 死接口 (0实现)** | `assessor.go:921` |
| 4 | ConfigurablePlugin 0实现 | `plugin.go:126` |

---

## 四、适配器管线 — 统一性 (7/10)

### Fetch→Parse→Map→Validate 覆盖率: 100%

全部 21 个适配器实现完整四阶段管线。`ExecuteAdapter()` 强制执行规范顺序。

### 管线统一性评分

| 适配器组 | 数量 | 统一性 | 问题 |
|----------|------|--------|------|
| 扫描器 P0 (trivy,nuclei,lynis) | 3 | 100% | — |
| 扫描器 P1 (openscap,wazuh_agent,suricata,falco,clamav) | 5 | 85% | 4个未调用 ApplyDelegation |
| 扫描器 P2 (osv_scanner,aide,nikto) | 3 | 90% | 3个硬编码 CheckID |
| 管理 P0 (ansible,netbox,snipe_it) | 3 | 100% | — |
| 管理 P1 (freeipa,keycloak,wazuh_siem,rundeck) | 4 | 60% | Keycloak/FreeIPA CheckID为空 |
| 管理 P2 (jira,terraform,opentofu) | 3 | 95% | — |

### 缺陷

| # | 缺陷 | 位置 |
|---|------|------|
| 1 | Keycloak/FreeIPA 产出 Finding 的 CheckID="" | `p1_management.go:194,61` |
| 2 | adapter/adapterhub NormalizedFinding 类型重复 (17vs12字段) | 转换丢失6字段 |
| 3 | 14/21 适配器绕过 ApplyDelegation | — |

---

## 五、扩展系统 — 强扩展性 (5/10)

### ❌ 18 个扩展点全部 0 订阅者

```
18 个 RegisterExtensionPoint() 调用 → ZERO RegisterExtension() 调用
ExtensionRegistry.Execute() 在 11 个点执行但返回空 (无handler)
extmgr 有自己的生命周期但从不桥接至 kernel 扩展表
```

### 引擎 8 阶段钩子: 5/8 执行

| 执行 ✅ | 缺失 ❌ |
|---------|---------|
| pre_check, post_check, pre_score, post_score, pre_report | pre_edge, post_edge, post_report |

### 事件总线: 7/15 主题有订阅者

15 个常量定义 → 8 个被发布 → 仅 7 个主题有订阅者
19 个临时主题 (ad-hoc strings) 全部零订阅者

### 正常管线

| 管线 | 状态 |
|------|------|
| SSAM 钩子 4/4 | ✅ |
| Prism 三层 Core→Semantic→Inference | ✅ |
| CLI 扩展点 | ⚠️ 触发但 extmgr 接线断裂 |

---

## 六、设计落实度总结

| 设计意图 | 状态 |
|----------|------|
| 微内核+插件架构 | ✅ 15插件完整生命周期，100%接口实现 |
| DI 反射容器 | ✅ 16绑定，100%安全 Resolve |
| 适配器四阶段管线 | ✅ 21/21 统一 |
| 扩展点系统 | ❌ 18/18 零订阅者 — 框架被架空 |
| 引擎 8 阶段钩子 | ⚠️ 5/8 落实 |
| 事件总线 PubSub | ⚠️ 7/15 主题有订阅者 |
| srd_adapters | ❌ 完整实现但从未接入 |
| ATT&CK V19 模块化 | ❌ 71 方法 God 接口 |
| Prism 三层模型 | ✅ 完美 |

### 结论

核心架构设计优秀 (依赖图、接口隔离、管线统一)。扩展系统被架空 — 框架完善而使用者缺失。代码自洽性高，但「可扩展」的设计意图尚未被内部代码利用验证。
