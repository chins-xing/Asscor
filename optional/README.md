# ASSCOR 可选模块与扩展包

本目录存放 **不属于 ASSCOR 核心框架** 的可选扩展。用户需手动下载后重新编译内核才能启用。

## 目录结构

```
optional/
├── pkgmgr/                      ← 扩展包管理器 (asscor-pkg CLI)
│   ├── main.go                  ←   CLI 入口
│   ├── manifest.go              ←   package.json 解析 + 依赖求解 + 版本约束
│   └── fetcher.go               ←   git 外部仓库克隆 + 兼容性校验
├── SCHEMA.md                    ← package.json 格式规范文档
├── algorithms/                  ← 按用途: 算法扩展
│   ├── modules/                 ←   单模块扩展
│   │   └── multi-algo-orchestrator/
│   └── packages/                ←   多模块扩展包
│       └── example-pack/
│           └── package.json
├── adapters/                    ← 按用途: 适配器扩展
├── checks/                      ← 按用途: 检查项扩展
└── platform/                    ← 按用途: 平台层扩展
```

## 单模块 vs 扩展包

| 形式 | 目录 | 接入方式 | 适用 |
|------|------|---------|------|
| **单模块** | `<category>/modules/<name>/` | 直接 `import` + Extension Point 注册 | 单个独立功能 |
| **扩展包** | `<category>/packages/<name>/` | `package.json` 声明 + `asscor-pkg install` | 多模块聚合 / 含外部依赖 |

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
