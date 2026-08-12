# MITRE Engage 轻量主动防御扩展包

MITRE Engage 主动防御的轻量化实现。**重心不在蜜罐，而在捕获后的信息收集——用捕获质量平衡捕获次数。**

## 设计原则

| 原则 | 说明 |
|------|------|
| 蜜罐仅辅助 | 轻量蜜罐不够真，攻击者易识破，仅作触发器 + 辅助阻断 |
| **重心在信息收集** | 捕获后的攻击者行为（IP/凭据/文件/技术）才是核心价值 |
| **质量 > 数量** | 过滤自动化端口扫描（低质量），聚焦真实攻击者（高质量） |
| 零依赖 | 纯 Go 标准库 |
| 内核零膨胀 | 扩展包默认不编译，通过 `block.*` 扩展点接入 |

## 捕获质量分级

| 捕获类型 | 质量分 | 价值 |
|------|:---:|------|
| 端口扫描命中 | 0.15 | 低（自动化扫描器，无攻击意图） |
| 蜜标文件访问 | 0.55 | 中（攻击者已进入文件系统） |
| 蜜凭证使用 | 0.85 | 高（攻击者尝试横向移动/提权） |

**用捕获质量平衡捕获次数**：`Collector` 按质量阈值过滤，默认丢弃纯端口扫描噪声，只保留真实攻击者行为。

## 目录结构

```
mitre-engage/
├── package.json       # 扩展包清单
├── collector.go       # 捕获信息收集器（重心）+ 质量过滤
├── engage.go          # Blocker 辅助实现 + 情报收集编排
├── honeypot.go        # 轻量 TCP 蜜罐（辅助触发器）
├── honeytoken.go      # 蜜标/诱饵文件（高质量触发器）
└── README.md
```

## 使用方式

```go
blocker := mitreengage.NewEngageBlocker("/var/lib/asscor/decoy")

// 设置捕获回调（发布到内核 locate.threat_active → 反哺归因）
blocker.SetCaptureHook(func(cap CaptureInfo) {
    // cap.Quality 已按质量过滤，只保留高价值捕获
    kernel.Extensions().Execute(ctx, "locate.threat_active", cap)
})

engine.SetBlocker(blocker)

// 查询高价值情报
highValue := blocker.HighValue(mitreengage.QualityCredentialUse)
```

## 能力映射

| MITRE Engage 方法 | 实现 | 定位 |
|------|------|------|
| Expose（暴露） | 蜜罐端口监听 | 辅助（低质量） |
| Elicit（诱导） | 蜜标/蜜凭证 | 重心（高质量） |
| Collect（收集） | **Collector 情报收集** | **核心** |
| Deny（拒绝） | 内核 `isolate_host` | 兜底 |

## 安全注意

- 蜜罐端口部署在独立 VLAN 隔离的诱饵主机，防跳板
- 蜜标/蜜凭证仅针对已确认攻击者
- 主动防御遵守法律合规边界（授权范围）

