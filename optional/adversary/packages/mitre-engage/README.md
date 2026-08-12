# MITRE Engage 轻量主动防御扩展包

MITRE Engage 主动防御的轻量化实现：蜜罐、蜜标、蜜凭证。**零外部依赖，纯 Go 标准库。**

## 设计原则

| 原则 | 说明 |
|------|------|
| 轻量 | 核心 ~200 行 Go，无 T-Pot 级重型蜜罐集群 |
| 零依赖 | 纯标准库（`net` + `os`） |
| 内核零膨胀 | 扩展包默认不编译，通过 `block.*` 扩展点接入 |
| 白盒可审计 | 欺骗策略是确定性规则 |

## 目录结构

```
mitre-engage/
├── package.json       # 扩展包清单
├── engage.go          # Blocker 接口实现 + 欺骗策略
├── honeypot.go        # 轻量 TCP 蜜罐（端口诱饵）
├── honeytoken.go      # 蜜标/诱饵文件部署
└── README.md
```

## 能力映射（MITRE Engage 8 方法覆盖 4 种）

| MITRE Engage 方法 | 实现 |
|------|------|
| Expose（暴露） | 蜜罐端口监听，记录连接来源 |
| Elicit（诱导） | 蜜标文件/蜜凭证，触碰即告警 |
| Deny（拒绝） | 由内核 `isolate_host` 兜底 |
| Collect（收集） | 蜜罐命中记录 |

## 使用方式

```go
import mitreengage "github.com/asscor/asscor/optional/adversary/packages/mitre-engage"

// 创建 Blocker 增强型实现
blocker := mitreengage.NewEngageBlocker("/var/lib/asscor/decoy")

// 设置命中回调（发布到内核扩展点）
blocker.SetHitHooks(
    func(hit honeypotHit) {
        // 蜜罐命中 → locate.threat_active → 反哺定位
    },
    func(hit honeytokenHit) {
        // 蜜标触碰 → 告警
    },
)

// 注入 LifecycleEngine
engine.SetBlocker(blocker)
```

## 轻量化对比

| 维度 | T-Pot（重型） | 本扩展包（轻量） |
|------|:---:|:---:|
| 蜜罐类型 | 20+ 容器 | 单 TCP listener |
| 体积 | 数 GB | ~几 KB |
| 依赖 | Docker + 多镜像 | Go 标准库 |
| 覆盖 | 全协议仿真 | 端口扫描检测 + 蜜标 |

## 安全注意

- 蜜罐端口应部署在**独立 VLAN 隔离**的诱饵主机上，防止被攻击者利用作跳板
- 蜜标/蜜凭证应仅针对已确认的攻击者部署
- 主动防御需遵守**法律合规边界**（授权范围）
