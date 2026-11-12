# 防御性编程审计（2026-11-13）

> 范围：内核/Agent/联邦/扩展管理/配置/外部拉取，重点看输入校验、鉴权、资源上限、并发、错误处理、密码学与信任边界。
> 方法：`go vet`、`staticcheck`、高危模式 grep、关键路径手工追踪、运行时探针（NaN 配置）；race 测试因本机无 gcc 未执行。

## 1. 结论

**做得好的部分（已落实）**

- mTLS：`RequireAndVerifyClientCert`、TLS ≥1.2、证书指纹绑定 host_id + 撤销检查（Register/Heartbeat）。
- 命令：HMAC-SHA256 常量时间比较、`_timestamp` 参与签名、Agent 只接受 `isolate_host/deisolate_host/securemode_*` 白名单动作。
- 执行：Agent 检查命令走严格白名单；用户自定义检查拒绝 shell 元字符并直接 `exec`（无 `sh -c`）。
- 扩展：zip/tar 解压做路径包含校验、去除 setuid/组可写位；http 源强制 sha256、git 源要求 commit。
- 输入上限：联邦上报 `MaxBytesReader`；gRPC `MaxRecvMsgSize=4MB`；多数外部 HTTP 客户端有超时和 `LimitReader`。
- 密钥：HMAC/证书私钥文件 0600；token 使用常量时间比较；日志未发现密钥值泄漏。

**需要修的部分**

| ID | 类型 | 级别 | 问题 | 位置 |
|---|---|---|---|---|
| D-01 | 明显 | **P1** | 联邦 master 在 `token==""` 时**直接放行所有请求**，且默认 token 为空、默认监听 `:5099` 全接口、明文 HTTP | `extensions/federation/master.go:115-121`、`config.go:82-88,150` |
| D-02 | 明显 | **P1** | 配置范围校验不拒绝 **NaN**：`threshold=NaN`、`weights=NaN` 都能通过，NaN 会污染全部评分 | `internal/config/ranges.go:11-101`、`config.go:674` |
| D-03 | 明显 | **P1** | gRPC 同一监听端口注册 KernelService + AgentService，**无角色拦截器**：任意有效 Agent 证书可调用 `GetSnapshot(任意 host)`、`StreamLogs` | `internal/comms/grpc_server.go:117-131`、`services.go:635-706` |
| D-04 | 隐式 | P2 | 注册允许任意未占用的 `host_id`（只校验字符集，无 provisioning/allowlist）：被攻陷的 Agent 可注册假主机、污染拓扑与联邦 | `internal/comms/services.go:170-229` |
| D-05 | 明显 | P2 | CTI 拉取 **无响应体上限**：`io.ReadAll(resp.Body)`，恶意/被控 feed 可打爆内存 | `internal/cti/cti.go:218-229` |
| D-06 | 明显 | P2 | 联邦 HTTP 服务只有 `ReadHeaderTimeout`，缺 `ReadTimeout/WriteTimeout/IdleTimeout` → 慢请求/空闲连接耗尽 | `extensions/federation/master.go:61-64` |
| D-07 | 隐式 | P2 | gRPC 客户端在 `TLSEnabled=false` 时**静默退回明文**（`insecure.NewCredentials`），无 fail-closed/显式 dev 开关 | `internal/comms/grpc_server.go:345-353` |
| D-08 | 隐式 | P3 | 命令时间戳只检查"过期"，**未来时间戳可通过**（`time.Since` 为负），且无 nonce 去重 → 5 分钟窗口内可重放 | `internal/agent/agent.go:1016-1024` |
| D-09 | 隐式 | P3 | 扩展 `git clone` 的 URL 未用 `--` 分隔（参数注入）；zip/tar 解压对解压后体积无上限（压缩炸弹） | `internal/extmgr/extension_installer.go:85-92,310-410` |
| D-10 | 隐式 | P3 | 多处忽略错误：SPC `ReadAll` 丢弃错误、解压 `MkdirAll` 不检查、trace `rand.Read` 忽略、session 后缀在 rand 失败时回退可预测字节 | `spc_fetch_cn.go:69,220`、`extension_installer.go:324/328/395`、`logger/observability.go:64`、`services.go:709-715` |
| D-11 | 隐式 | P3 | 缺少按证书/连接的速率与配额限制：注册、心跳、联邦上报均可高频调用（valid cert / token 即可放大） | `services.go`、`heartbeat.go`、`master.go` |

## 2. 重点问题展开

### D-01 联邦鉴权 fail-open（P1）

```go
func (m *MasterServer) authorized(r *http.Request) bool {
    if m.token == "" {
        return true          // ← 未配置 token = 全部放行
    }
    ...
}
```

- `Defaults()` 的 `Token` 为空，`ParseConfig` 不强制；默认 `ListenAddr=:5099`（`net.Listen("tcp", ...)` 全接口）。
- master 用**明文 HTTP**，token 在 `X-Federation-Token` 头里传输，可被嗅探/重放；且 `check/export/nodes/report` 全部共享同一静态 token。
- 影响：忘记配 token 的部署，任何能访问 5099 的人可读取合并拓扑、伪造节点上报（污染 SRD/评分）。
- 修复：master 在非 loopback 监听时**必须**有 token（fail-fast），或显式 `allow_insecure = true`；默认绑 `127.0.0.1`；文档/启动日志高亮；后续换 mTLS/HTTPS。

### D-02 NaN 配置绕过（P1）

`validateRanges` 用 `value < 0`、`<= 0 || > 1` 这类比较，NaN 与任何数比较都是 false，全部通过：

```text
NaN threshold      -> ok threshold=NaN
NaN weight         -> ok，Normalize 后全部权重变 NaN
NaN edge           -> ok
+Inf threshold     -> error（Inf 能被抓住，NaN 不能）
```

`Weights.Normalize()`：`coreSum` 为 NaN 时既不等于 0 也不等于 100，直接除 → 所有领域权重 NaN；SSAM 加权和与最终分变 NaN；策略层 `score >= threshold` 恒 false，告警/阻断逻辑可能静默失效。
修复：所有 float 校验统一加 `math.IsNaN/IsInf`；对全零权重给默认或报错；加 `TestValidateRangesRejectsNaN`。

### D-03 gRPC 无角色隔离（P1）

```go
s.server = grpc.NewServer(opts...)          // 没有 UnaryInterceptor/StreamInterceptor
apiv1.RegisterKernelServiceServer(s.server, kernelHandler)
apiv1.RegisterAgentServiceServer(s.server, agentHandler)   // 同一个 mTLS 端口
```

`AgentServiceImpl.GetSnapshot` 只按请求里的 `HostId` 查数据，不校验"调用者证书是否属于该 host"；`StreamLogs` 直接 `AppendBatch` 任意条目。任何持有 CA 签发证书的 Agent 都能读其他主机的评估结果（分数、检查项、ATT&CK 覆盖）、污染审计日志。
修复：按证书指纹/CN 做服务级授权（Agent 只能访问自己 host 的 snapshot，AgentService 仅限运维证书）；或把运维面拆到独立监听/端口。

### D-04 注册身份抢占（P2）

Register 只做 `hostIDPattern` 校验 + 首次绑定指纹（`BindAgentCert`）；没有"该 host_id 是否已预置/授权给此证书"的校验。任何被纳管的 Agent 都能注册一个新 host_id（如 `pve`、`router-x`），随后通过心跳上报伪造拓扑/检查结果。虽然不能覆盖已绑定主机（会被指纹冲突拒绝），但可以**新增**假主机进入 SRD/联邦合并图。
修复：主机清单/一次性注册令牌；或证书 CN 必须等于 host_id 并校验；至少对新增 host 告警+人工确认。

### D-05 CTI 无上限读取（P2）

```go
body, err := io.ReadAll(resp.Body)   // 无 LimitReader
```

OTX/MISP 响应大小由远端决定；30s 超时不能限制字节数。其他 SPC 拉取均已用 `io.LimitReader(..., kernel.MaxHTTPBodySize)`，CTI 是漏网。
修复：统一 `LimitReader` + 明确上限（如 16–64MB），超限报错。

### D-06 联邦 HTTP 超时缺失（P2）

```go
srv := &http.Server{ Handler: ..., ReadHeaderTimeout: 5 * time.Second }
```

没有 `ReadTimeout/WriteTimeout/IdleTimeout`；慢速请求体可长期占用连接（`MaxBytesReader` 只限制大小，不限制速率）。修复：补齐三个超时（如 Read 15s、Write 30s、Idle 60s）。

### 隐式问题（D-07–D-11）

- **D-07**：`TLSEnabled=false` 时 gRPC 客户端走明文，且没有"仅当显式 dev 模式才允许"的闸门；生产误配会静默降级。
- **D-08**：`_timestamp` 未来值可通过（`time.Since` 为负），无 nonce 缓存，重放窗口 5 分钟；需要 HMAC 密钥才能利用，但横向移动场景值得防。
- **D-09**：`git clone` 参数未加 `--`，恶意扩展 URL 可能被解析为 git 选项；解压只限制下载包大小，不限制解压后总量（zip bomb）。
- **D-10**：错误吞掉是防御性编程的反面：`ReadAll` 失败被当作空响应、`MkdirAll` 失败继续、`rand.Read` 失败静默；其中 session 后缀回退是 `byte(i)` 可预测。
- **D-11**：gRPC/HTTP 没有按连接或证书的速率限制；注册表靠超时清理，突发注册可短时膨胀。

## 2.1 修复记录（2026-11-13，`aeb1ccc`）

| ID | 状态 | 修复内容 |
|---|---|---|
| D-01 | ✅ 已修 | `ParseConfig` 对 role=master：非 loopback 且 token 空直接报错；新增 `config_test.go` 覆盖 loopback/token/`0.0.0.0`/`[::]` |
| D-02 | ✅ 已修 | `validateRanges` 对 weights/threshold/threat/ACI/edge/delta/confidence/SPC/ATT&CK 全部拒绝 NaN/Inf；`ranges_test.go` 新增 NaN 回归 |
| D-03 | ✅ 已修（Agent 侧） | 新增 `VerifyAgentCertStrict`（无 first-contact 放行）；Agent 证书调用 `GetSnapshot/ExecuteCommand/StreamLogs` 必须指纹绑定到目标 host；运维证书保留跨主机（角色分离留后续） |
| D-04 | ✅ 已验证 | 既有 `BindAgentCert` 已保证一证书一 host；未新增代码，文档标注 provisioning 仍靠人工签发 |
| D-05 | ✅ 已修 | CTI 响应 `io.LimitReader(..., 32 MiB)` |
| D-06 | ✅ 已修 | 联邦 HTTP `ReadTimeout=15s / WriteTimeout=30s / IdleTimeout=60s` |
| D-07～D-11 | ⏳ 未做 | 仍在未完成清单 P2/P3 |

## 3. 建议优先级

- **P0（本周）**：D-01（fail-closed + 默认 loopback）、D-02（NaN 校验 + 回归测试）、D-03（gRPC 角色/服务授权）。
- **P1**：D-04（注册授权）、D-05（CTI 上限）、D-06（HTTP 超时）。
- **P2**：D-07（TLS 显式开关）、D-08（nonce/未来时间窗）、D-09（git `--`/解压配额）、D-10（错误处理清理）、D-11（限速）。

## 4. 复现

```bash
go vet ./...
staticcheck ./...                     # 22 条，多为 unused/deprecated，非安全
# NaN 探针（本地临时）
go run ./build/nanprobe.go
# 关键路径
sed -n '110,130p' extensions/federation/master.go
sed -n '11,102p' internal/config/ranges.go
sed -n '117,132p' internal/comms/grpc_server.go
sed -n '635,706p' internal/comms/services.go
sed -n '218,229p' internal/cti/cti.go
```

## 5. 限制

- race 检测未跑：Windows 本机无 gcc，`-race` 需要 cgo；建议在 Linux 构建机补 `go test -race`。
- gosec 全仓扫描未完成（进程被管道中断）；staticcheck 结果已覆盖未使用/废弃 API 类问题。
- 未做动态 fuzz/渗透；本文结论基于静态追踪与配置探针。
