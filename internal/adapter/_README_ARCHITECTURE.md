# Adapter Framework Architecture

## 分层说明

```
internal/adapter/      — 适配器接口 + 具体实现 (Leaf Layer)
  ├── adapter.go       —  Adapter 接口定义 (Fetch/Parse/Map/Validate)
  ├── registry.go      —  全局适配器注册表 (List/Get)
  ├── delegation.go    —  委托规则 (将适配器发现映射到内置检查项)
  ├── script.go        —  脚本适配器 (零代码扩展)
  ├── scanner/          —  探测器实现 (11 个: Trivy/Nuclei/Lynis/...)
  └── management/       —  管理工具实现 (10 个: Ansible/NetBox/...)

internal/adapterhub/   — 适配器编排层 (Orchestration Layer)
  ├── manager.go       —  运行时生命周期管理 (初始化/健康检查/同步循环)
  ├── types.go         —  统一适配器接口 (UnifiedAdapter)
  ├── wrapper.go       —  SSAMAdapter 包装器 (将旧 Adapter 适配为新接口)
  ├── rules.go         —  规则引擎 (6 种规则类型: Transform/Severity/Domain/Delta/Filter)
  ├── config.go        —  编排配置
  └── builder.go       —  构建器模式 API
```

## 调用关系

```
  引擎评估器 (kernel/assessor)
  │
  ├─→ adapter.List() → 从全局注册表获取所有已注册 Adapter
  │   └─→ adapter.ExecutePipeline() → 执行 Fetch→Parse→Map→Validate
  │
  └─→ kernel/adapter_integration → 管理适配器的运行时生命周期（同步循环/健康检查）
      └─→ extmgr.SetKernelExtensions() → 通过扩展点桥接外部扩展适配器
```

**关键区分**: `adapter/` 定义适配器接口和具体实现（静态注册 + 委托规则）。`kernel/adapter_integration` 在运行时编排适配器管线（周期执行 + 发现注入）。外部扩展通过 `extmgr` 桥接到内核扩展点。

## 文件命名规范

| 优先级 | 文件命名 | 示例 |
|:---:|------|------|
| P0 | 专用文件 (`<adapter>.go`) | `trivy.go`, `lynis.go`, `ansible.go`, `nuclei.go` |
| P1 | 分组文件 (`p1_<category>.go`) | `p1_scanners.go`, `p1_management.go` |
| P2 | 分组文件 (`p2_<category>.go`) | `p2_scanners.go`, `p2_management.go` |

P0 适配器（核心安全扫描器）有专用文件以容纳复杂的 Parse/Map 逻辑。P1/P2 适配器按类别分组以减少文件数量。
