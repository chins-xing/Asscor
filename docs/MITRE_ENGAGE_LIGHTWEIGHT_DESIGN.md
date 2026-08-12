# MITRE Engage 轻量化扩展包设计（生态轻量化原则）

**日期**: 2026-08-13 | **版本**: v0.2.3 | **性质**: 主动防御扩展包的轻量化设计

---

## 一、轻量化原则

用户核心诉求：**不仅 Asscor 本身轻量，扩展生态也要轻量。**

| 原则 | 说明 |
|------|------|
| P1 内核零膨胀 | 扩展包默认不编译进内核 |
| P2 零重型依赖 | 纯 Go 标准库，不引入 T-Pot/Honeyd 等重型蜜罐框架 |
| P3 轻量蜜罐 | 蜜罐 = 几十行 TCP listener，非完整容器化蜜罐集群 |
| P4 即插即用 | 通过扩展点接入，无需改造内核 |
| P5 白盒可审计 | 欺骗策略是确定性规则，可追溯 |

---

## 二、扩展包结构

```
optional/adversary/packages/mitre-engage/
├── package.json       # 扩展包清单（9 种类型之 hook/adapter）
├── README.md          # 使用指南
├── engage.go          # Blocker 接口实现 + 欺骗策略
├── honeypot.go        # 轻量蜜端口（TCP listener，~50 行）
├── honeytoken.go      # 蜜标/诱饵文件部署（~60 行）
└── honeytoken_test.go # 测试
```

**零外部依赖**：全部 Go 标准库（`net`/`os`/`sync`/`time`）。

---

## 三、轻量蜜罐实现（不引入重型框架）

### 3.1 轻量蜜端口（honeypot.go）

```go
// 轻量 TCP 蜜罐: 监听常见攻击端口, 记录连接来源 → 暴露攻击者
// 对比 T-Pot(多容器蜜罐集群, 数 GB) — 本实现仅 ~50 行 Go, 零依赖
func (h *honeypot) listen(port int) {
    ln, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    for {
        conn, _ := ln.Accept()
        // 记录: 来源 IP + 端口 + 时间 → 触发告警
        h.recordConn(conn.RemoteAddr())
        conn.Close() // 不回应, 只记录
    }
}
```

### 3.2 蜜标/诱饵文件（honeytoken.go）

```go
// 蜜标: 部署虚假凭据/文件, 攻击者触碰即暴露
// 部署: 虚假的 SSH 密钥/数据库凭据/敏感文档
// 检测: 文件访问监控 → 触发告警
```

### 3.3 蜜凭证

```go
// 虚假登录凭证: 攻击者使用即暴露(通过认证失败日志识别)
```

---

## 四、Blocker 接口实现

```go
// MITRE Engage 作为 Blocker 增强型实现
type engageBlocker struct { ... }

func (b *engageBlocker) Block(ctx, loc) (*BlockResult, error) {
    // 1. 部署蜜罐(在 loc.ActiveSubnets 监听攻击端口)
    // 2. 部署蜜标(在 loc.FootholdHost 布设虚假凭据)
    // 3. 传统 isolate 由内核 Blocker 兜底
}
func (b *engageBlocker) Unblock(ctx, loc) error { /* 拆除蜜罐/蜜标 */ }
func (b *engageBlocker) IsBlocked(ctx, hostID) bool { /* 查询状态 */ }
```

---

## 五、与内核的接入（扩展点，零内核侵入）

```
内核 Blocker 接口（白盒, 已有）
  ├─ 传统实现: isolate_host（内核内, 兜底）
  └─ MITRE Engage（扩展包, 通过扩展点接入）
       │
       ├─ 订阅 block.pre_apply → 部署蜜罐
       ├─ 发布蜜罐命中事件 → locate.threat_active（反哺定位）
       └─ 订阅 block.confirmed → 确认阻断
```

**零内核修改**：MITRE Engage 通过 `block.*` 扩展点接入（已在内核注册），不新增接口、不新增插件。

---

## 六、轻量化对比

| 维度 | T-Pot（重型） | 本方案（轻量） |
|------|:---:|:---:|
| 蜜罐类型 | 多容器（20+ 蜜罐） | 单文件 TCP listener |
| 体积 | 数 GB | ~几 KB |
| 依赖 | Docker + 多镜像 | Go 标准库 |
| 部署 | 独立集群 | 随扩展包即插即用 |
| 覆盖 | 全协议仿真 | 端口扫描检测 + 蜜标 |
| 内核影响 | 无（独立） | 无（扩展包） |

---

## 七、裁定

**轻量 MITRE Engage 扩展包可行，符合"生态轻量化"原则。**

| 结论 | 说明 |
|------|------|
| 内核零膨胀 | 扩展包默认不编译，`block.*` 扩展点已就位 |
| 零重型依赖 | 纯 Go 标准库，~200 行实现核心蜜罐+蜜标 |
| 与推演协同 | 蜜罐命中 → locate.threat_active → 反哺推演 |
| 白盒确定性 | 欺骗策略是规则驱动，可审计 |
| 定位 | Blocker 增强型，内核 isolate 兜底 |

**核心原则**：轻量 MITRE Engage 用"~200 行 Go + 零依赖"实现"端口蜜罐 + 蜜标 + 蜜凭证"三类主动防御活动，覆盖 MITRE Engage 8 方法中的 Deny/Disrupt/Deceive/Collect 四种，足以作为 Blocker 的增强型实现，而不引入 T-Pot 级重型蜜罐集群。

---
*归档于 2026-08-13T01:20+08:00。*
