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
  └─→ adapterhub.Manager → 管理适配器的运行时生命周期
      └─→ adapterhub.Builder → 构建/启用适配器
```

**关键区分**: `adapter/` 定义适配器接口和具体实现（静态注册），`adapterhub/` 在运行时编排它们（生命周期/规则/健康检查）。adapter/ 不知道自己如何被编排；adapterhub/ 不直接实现任何适配器。
