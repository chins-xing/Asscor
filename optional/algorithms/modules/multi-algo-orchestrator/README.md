# ASSCOR Multi-Algorithm Orchestrator (可选模块)

消除单一评估算法的"木桶效应"——通过编排多个评分算法(SSAM 2.0、Legacy、自定义引擎)并行/串行/级联执行，取最低分消除算法偏差。

## 安装

```bash
# 1. 将本模块克隆到 ASSCOR 仓库的 optional/ 目录
cd ASSCOR/optional/algorithms/modules/
git clone https://github.com/asscor/asscor-optional-multi-algo.git

# 2. 在 cmd/kernel/main.go 中添加导入和注册
```

## 集成方式

在 `cmd/kernel/main.go` 中：

```go
import multialgo "github.com/asscor/asscor-optional-multi-algo"

// 在 Bootstrap 之后:
cfg := multialgo.OrchestrationConfig{
    Mode:  multialgo.ModeCascade,
    Merge: multialgo.MergeWorstOf,   // 取最低分，消除木桶效应
    CheckMode: multialgo.CheckMerge,
    CascadeThreshold: 80,
    Algorithms: []multialgo.AlgorithmProfile{
        {
            ID: "ssam_v2", Name: "SSAM 2.0", Role: multialgo.RolePrimary,
            EngineConstructor: func() engine.AssessorEngine {
                return ssam.NewEngineAdapter(config)
            },
            Confidence: 0.9, SharedChecks: []string{"AS-004", "OT-005"},
        },
        {
            ID: "baseline", Name: "Baseline", Role: multialgo.RoleSecondary,
            EngineConstructor: func() engine.AssessorEngine { return nil },
            Confidence: 0.6,
            IndependentChecks: []model.CheckItem{...},
        },
    },
}
orch := multialgo.NewOrchestrator(cfg)
orch.Register(k.PlatformExtensionRegistry())

# 3. 重新编译
go build -o ASSCOR-kernel ./cmd/kernel/
```

## 配置驱动 (config.ini)

```ini
[optional.multi_algo]
enabled = true
mode = cascade
merge = worst_of
check_mode = merge
cascade_threshold = 80
```

## 执行模式

| 模式 | 行为 | 适用场景 |
|------|------|---------|
| `sequential` | 按序串行执行所有算法 | 调试/验证 |
| `parallel` | goroutine 并发执行 | 高性能需求 |
| `cascade` | 主算法及格(≥阈值)则跳过辅算法 | 生产环境节省资源 |

## 合并策略

| 策略 | 行为 | 木桶效应消除 |
|------|------|-------------|
| `best_of` | 取最高分 | ❌ |
| `worst_of` | 取最低分 | ✅ |
| `weighted_average` | 按置信度加权平均 | ⚠️ 部分 |
| `consensus` | 一致则平均，分歧取最低 | ✅ |
| `primary_only` | 仅主算法 | ❌ |

## 目录结构

```
optional/
├── algorithms/
│   ├── modules/           ← 单模块扩展
│   │   └── multi-algo-orchestrator/
│   └── packages/          ← 多模块打包
├── adapters/
│   ├── modules/
│   └── packages/
├── checks/
│   ├── modules/
│   └── packages/
└── platform/
    ├── modules/
    └── packages/
```
