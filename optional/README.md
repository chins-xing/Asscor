# ASSCOR 可选模块与扩展包

本目录存放 **不属于 ASSCOR 核心框架** 的可选扩展。用户需手动下载后重新编译内核才能启用。

## 目录结构

```
optional/
├── algorithms/         ← 按用途分类: 算法扩展
│   ├── modules/        ←   单模块扩展
│   └── packages/       ←   多模块扩展包
├── adapters/           ← 按用途分类: 适配器扩展
│   ├── modules/
│   └── packages/
├── checks/             ← 按用途分类: 检查项扩展
│   ├── modules/
│   └── packages/
└── platform/           ← 按用途分类: 平台层扩展
    ├── modules/
    └── packages/
```

## 使用方式

1. 将所需模块克隆到对应目录
2. 在 `cmd/kernel/main.go` 中导入并注册（通过 Extension Point 系统）
3. 或在 `config.ini` 中添加 `[optional.*]` 配置段
4. 运行 `go build -o ASSCOR-kernel ./cmd/kernel/` 重新编译

所有可选模块通过 **ASSCOR Extension Point 系统** 与核心框架交互，不修改核心代码。

## 已有模块

| 用途 | 模块 | 类型 | 说明 |
|------|------|------|------|
| 算法 | `multi-algo-orchestrator` | 单模块 | 多算法并行编排，消除单一算法木桶效应 |
