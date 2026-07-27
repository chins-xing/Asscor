# Engine Architecture

## 接口定义

`internal/engine/` 定义评估引擎的核心接口。子包实现这些接口，通过 DI 容器在运行时注入。

## 接口层次

```
engine/assessor.go
  ├── AssessorEngine       — 评分引擎接口
  ├── ATTACKProvider       — ATT&CK 分析提供商 (v0.2.1+ 包含 IsEnabled/Version)
  ├── SPCProvider          — SPC 漏洞态势提供商
  ├── ATTACKCoverageResult — 管线 DTO (不依赖 kernel 包)
  └── ScoringEngine        — 评分引擎抽象

engine/extensibility.go
  ├── HookRegistry         — 引擎内部 8 阶段钩子
  ├── FormulaRegistry      — 可插拔评分公式
  └── CheckRegistryExt     — 条件检查激活器
```

## 子包 — 引擎实现

```
engine/
├── assessor.go             — 接口定义 + 评估引擎核心
├── extensibility.go        — 引擎内部钩子系统
├── srd/                    — SRD 外部结果适配器管道 (Lynis/OpenSCAP/AtomicRed)
│   └── pipeline.go         — 实现模型数据管线
├── prism/                  — Prism 三层风险动力学引擎适配
│   └── engine.go           — 线程安全 Prism 包装器
├── ssam/                   — SSAM 2.0 评分引擎适配
│   ├── adapter.go          — ASSCOR→SSAM 数据转换
│   ├── adapter_engine.go   — 实现 engine.AssessorEngine
│   └── engine.go           — SSAM 引擎配置
└── orchestrator.go         — 多算法编排器 (v0.2.1+, 已移至 optional/)
```

## 依赖方向

```
engine/ (定义接口)
  ↑ 实现
  ├── ssam/     — 实现 AssessorEngine
  ├── prism/    — 实现 PrismEngine (通过 prism-lib/)
  └── srd/      — 消费 prism/ 引擎
```

所有引擎实现**不导入** `internal/kernel/` — 通过 `internal/model/` DTO 和 `engine/` 接口与核心通信。
