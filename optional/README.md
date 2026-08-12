# ASSCOR 可选模块与扩展包

本目录存放 **不属于 ASSCOR 核心框架** 的可选扩展。用户需手动下载后重新编译内核才能启用。

## 目录结构

```
optional/
├── algorithms/                  ← 算法扩展
│   ├── modules/                 ←   单模块
│   │   └── multi-algo-orchestrator/
│   └── packages/                ←   多模块扩展包
│       └── attck-ext-pack/
│           ├── enable.go
│           ├── package.json
│           └── README.md
├── pkgmgr/                      ← 扩展包管理工具 CLI
│   ├── main.go
│   ├── manifest.go
│   └── fetcher.go
├── README.md
└── SCHEMA.md
```

> 注：`multi-algo-orchestrator` 和 `pkgmgr` 属于"monorepo 扩展" — 仍导入 `internal/*` 包，非独立部署模块。其他类别目录 (adapters/checks/platform) 按需创建。

## 单模块 vs 扩展包

| 形式 | 目录 | 接入方式 | 适用 |
|------|------|---------|------|
| **单模块** | `<category>/modules/<name>/` | `import` + Extension Point 注册 (monorepo) | 单功能扩展 |
| **扩展包** | `<category>/packages/<name>/` | `package.json` + build tag 启用 | 多模块 / 编译开关控制 |

## 扩展包管理器 (asscor-pkg)

```bash
# 构建
cd optional/pkgmgr && go build -o asscor-pkg .

# 解析依赖
./asscor-pkg resolve

# 安装 (自动克隆外部仓库)
./asscor-pkg install --force

# 列出所有扩展包
./asscor-pkg list

# 查看扩展包详情
./asscor-pkg info example-security-pack

# 输出依赖图 (DOT格式)
./asscor-pkg graph

# 校验所有 package.json
./asscor-pkg validate
```

## 已有模块

| 用途 | 名称 | 类型 | 说明 |
|------|------|------|------|
| 算法 | `multi-algo-orchestrator` | 单模块 | 多算法并行编排，消除单一算法木桶效应 |
