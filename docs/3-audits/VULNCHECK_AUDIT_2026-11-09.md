# govulncheck 漏洞审计（2026-11-09）

> 工具：`govulncheck v1.9.0`（`golang.org/x/vuln@v1.9.0`），漏洞库 `vuln.go.dev`（`db_last_modified=2026-11-05T23:49:57Z`），
> 扫描模式：source / symbol level；Go 工具链 **go1.26.3**。
> 生成时间：2026-11-09 13:06。

## 1. 扫描范围与结果

| 扫描对象 | 构建 | 可达漏洞（called） | 仅导入/依赖（未调用） |
|---|---|---|---|
| 根模块 `./...` | 默认（无 tag） | **18**（全部 Go 标准库） | — |
| 根模块 `./...` | 全 tag（`MODULE_TAGS`） | **26**（标准库 + grpc + x/net） | 5 imported / 6 required |
| `pluginsdk` | 默认 | **0** | 2 imported / 25 required |
| `ssam-lib` | 默认 | **0** | 2 imported / 25 required |
| `prism-lib` | 默认 | **0** | 2 imported / 25 required |

**结论：可达漏洞全部来自两类过旧依赖**：

1. **Go 工具链 1.26.3**（标准库漏洞，修复版本最高到 **1.26.10**）；
2. **`google.golang.org/grpc v1.68.0`**（修复需 **≥ v1.83.1**）与 **`golang.org/x/net v0.57.0`**（修复需 **≥ v0.60.0**）。

> 说明：lab 里部署的二进制是用 `GOTOOLCHAIN=go1.26.0` 构建的，**确定受影响**；Dockerfile 的 `golang:1.26-alpine` 会浮到最新 patch，但本地/CI 需要显式 pin。

## 2. 可达漏洞明细（26 条，按包分组）

| # | OSV | CVE/GHSA | 影响包 | 修复版本 | 调用栈数 | 摘要 | 示例调用点 |
|---|---|---|---|---|---|---|---|
| 1 | `GO-2026-5026` | CVE-2026-39821 | `stdlib` | v1.26.6 | 2 | Invoking failure to reject ASCII-only Punycode-encoded labels in golang.org/x/net/idna | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:373) |
| 2 | `GO-2026-5037` | CVE-2026-27145 | `stdlib` | v1.26.4 | 3 | Inefficient candidate hostname parsing in crypto/x509 | `github.com/chins-xing/asscor/internal/agent.*ClientConnect` (internal/agent/client.go:52) |
| 3 | `GO-2026-5039` | CVE-2026-42507 | `stdlib` | v1.26.4 | 1 | Arbitrary inputs are included in errors without any escaping in net/textproto | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:379) |
| 4 | `GO-2026-5856` | CVE-2026-42505 | `stdlib` | v1.26.5 | 6 | Invoking Encrypted Client Hello privacy leak in crypto/tls | `github.com/chins-xing/asscor/internal/comms.*ServerStart` (internal/comms/server.go:108) |
| 5 | `GO-2026-5972` | CVE-2026-33818 | `stdlib` | v1.26.6 | 1 | Enforce maximum recursion depth in encoding/asn1 | `github.com/chins-xing/asscor/internal/kernel.VerifySignature` (internal/kernel/crypto.go:251) |
| 6 | `GO-2026-6088` | CVE-2026-56859 | `stdlib` | v1.26.6 | 1 | Add recursion depth guard during decode in encoding/xml | `github.com/chins-xing/asscor/internal/spc.*ModuleImportOSCAL` (internal/spc/spc_fetch_oscal.go:38) |
| 7 | `GO-2026-6089` | CVE-2026-56853 | `stdlib` | v1.26.6 | 1 | Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check in net/http | `github.com/chins-xing/asscor/extensions/federation.*MasterServerStart` (extensions/federation/master.go:71) |
| 8 | `GO-2026-6090` | CVE-2026-56862 | `stdlib` | v1.26.6 | 6 | Limit handshake messages we are willing to accept post-handshake in crypto/tls | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:373) |
| 9 | `GO-2026-6218` | CVE-2026-56860 | `stdlib` | v1.26.6 | 1 | Avoid quadratic complexity in resolvePath in net/url | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:373) |
| 10 | `GO-2026-6605` | CVE-2026-56866 | `stdlib` | v1.26.9 | 2 | HTTP/1 client connection desynchronization after CONNECT rejection in net/http | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:373) |
| 11 | `GO-2026-6607` | CVE-2026-97031 | `stdlib` | v1.26.9 | 6 | Reject malformed ECH outer extension references in crypto/tls | `github.com/chins-xing/asscor/internal/comms.*ServerStart` (internal/comms/server.go:108) |
| 12 | `GO-2026-6610` | CVE-2026-78660 | `stdlib` | v1.26.9 | 4 | HTTP/2 transport accepts malformed framing-related headers in net/http | `github.com/chins-xing/asscor/internal/spc.*ModuleFetchFromEPSS` (internal/spc/spc_fetch_epss.go:41) |
| 13 | `GO-2026-6809` | CVE-2026-111943 | `stdlib` | v1.26.10 | 1 | Distrust compromised intermediate certificates in crypto/x509 | `github.com/chins-xing/asscor/internal/kernel.VerifyCertChain` (internal/kernel/crypto.go:237) |
| 14 | `GO-2026-4762` | CVE-2026-33186 | `google.golang.org/grpc` | v1.79.3 | 1 | Authorization bypass in gRPC-Go via missing leading slash in :path in google.golang.org/grpc | `github.com/chins-xing/asscor/internal/comms.*GRPCServerStart` (internal/comms/grpc_server.go:150) |
| 15 | `GO-2026-6061` | - | `google.golang.org/grpc` | v1.82.1 | 9 | Vulnerabilities in the xDS RBAC authorization engine and the HTTP/2 transport server implementation in google.golang.org/grpc | `github.com/chins-xing/asscor/internal/comms.*GRPCClientClose` (internal/comms/grpc_server.go:383) |
| 16 | `GO-2026-6348` | CVE-2026-84304 | `google.golang.org/grpc` | v1.83.1 | 14 | Heap Memory Exhaustion (OOM) via HTTP/2 DATA Frame Fragmentation in google.golang.org/grpc | `github.com/chins-xing/asscor/api/v1.*kernelServiceClientHeartbeat` (api/v1/grpc.go:159) |
| 17 | `GO-2026-6443` | CVE-2026-84445 | `google.golang.org/grpc` | v1.82.2 | 1 | Server panic via missing authority or Host headers in google.golang.org/grpc | `github.com/chins-xing/asscor/internal/comms.*GRPCServerStart` (internal/comms/grpc_server.go:150) |
| 18 | `GO-2026-6091` | CVE-2026-56858 | `golang.org/x/net` | v1.26.6 | 2 | Fix Javascript regexp context tracking in html/template | `github.com/chins-xing/asscor/extensions/federation.*MasterServerStart` (extensions/federation/master.go:71) |
| 19 | `GO-2026-6599` | CVE-2026-94448 | `golang.org/x/net` | v1.26.9 | 2 | Reset context tracking on consecutive template expressions in html/template | `github.com/chins-xing/asscor/extensions/federation.*MasterServerStart` (extensions/federation/master.go:71) |
| 20 | `GO-2026-6600` | CVE-2026-97030 | `golang.org/x/net` | v1.26.9 | 2 | Recognize yield as regexp preceder keyword in html/template | `github.com/chins-xing/asscor/extensions/federation.*MasterServerStart` (extensions/federation/master.go:71) |
| 21 | `GO-2026-6608` | CVE-2026-94440 | `golang.org/x/net` | v1.26.9 | 2 | Memory limit bypass when parsing MIME headers in net/textproto, mime/multipart | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:379) |
| 22 | `GO-2026-6603` | CVE-2026-78659 | `golang.org/x/net,google.golang.org/grpc` | v0.60.0,v1.26.9 | 174 | HTTP/2 server memory exhaustion due to Trailer headers in net/http | `github.com/chins-xing/asscor/cmd/exprunner.main` (cmd/exprunner/main.go:470) |
| 23 | `GO-2026-6611` | CVE-2026-78669 | `golang.org/x/net,google.golang.org/grpc` | v0.60.0,v1.26.9 | 174 | Excessive CPU consumption from repeated initial window changes in net/http | `github.com/chins-xing/asscor/cmd/srdbench.main` (cmd/srdbench/main.go:298) |
| 24 | `GO-2026-6612` | CVE-2026-78663 | `golang.org/x/net,google.golang.org/grpc` | v0.60.0,v1.26.9 | 174 | Double flow control refund on HTTP/2 server streams in net/http | `github.com/chins-xing/asscor/cmd/exprunner.main` (cmd/exprunner/main.go:470) |
| 25 | `GO-2026-6613` | CVE-2026-94439 | `golang.org/x/net,google.golang.org/grpc` | v1.26.9 | 45 | HTTP/1 server connection desynchronization after 2xx CONNECT response in net/http | `github.com/chins-xing/asscor/internal/adapter/management.*RundeckAdapterFetch` (internal/adapter/management/p1_management.go:379) |
| 26 | `GO-2026-6617` | CVE-2026-97032 | `golang.org/x/net,google.golang.org/grpc` | v0.60.0,v1.26.9 | 174 | HTTP/2 server crash due to HPACK encoder race in net/http | `github.com/chins-xing/asscor/internal/adapter/scanner.*ClamAVAdapterFetch` (internal/adapter/scanner/p1_scanners.go:657) |

## 3. 影响面（按攻击路径）

| 路径 | 涉及漏洞 | 影响 |
|---|---|---|
| **TLS / mTLS**（agent↔kernel、adapter HTTPS、federation） | GO-2026-5856/6090/6607、5037/6809 | ECH 隐私泄漏、握手消息无上限、x509 主机名校验退化、中间证书信任问题 |
| **gRPC 服务/客户端**（comms） | GO-2026-4762/6061/6348/6443 | 鉴权绕过、HTTP/2 服务端 OOM/panic、xDS RBAC 问题 |
| **HTTP 服务/客户端**（federation master、SIEM push、SPC/OSCAL/EPSS 拉取、Rundeck 等适配器） | GO-2026-6603/6610/6611/6612/6613/6617/6089/6605/6609 | HTTP/2 OOM/CPU/崩溃、HTTP/1 反同步、Header 解析问题 |
| **签名/证书解析** | GO-2026-5972（asn1 递归）、6088（xml 递归）、6809（x509） | 恶意输入可打爆栈/信任错误证书链 |
| **模板/URL/MIME** | GO-2026-6091/6599/6600、6218、5039/6608 | 模板上下文逃逸、URL 二次复杂度、MIME 头部内存限制绕过 |

## 4. 修复方案（建议 P0）

### 4.1 升级 Go 工具链到 ≥ 1.26.10

```bash
# go.mod 增加 toolchain 指令，确保本地/CI/构建机一致
go mod edit -toolchain=go1.26.10
# Dockerfile
# FROM golang:1.26.10-alpine AS builder
```

> 修复版本跨度：1.26.4 → 1.26.10；一次升到 **1.26.10** 可覆盖全部标准库条目。

### 4.2 升级 grpc / x/net

```bash
go get google.golang.org/grpc@v1.83.1 golang.org/x/net@v0.60.0
go mod tidy
go test ./...
```

### 4.3 重新构建并复扫

```bash
govulncheck ./...
govulncheck -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine,oscal,expr,edgeexp" ./...
```

目标：可达漏洞从 26 → **0**（剩余 imported/required 未调用项可接受，记录即可）。

### 4.4 防回归

- CI 增加 `govulncheck` job（默认 + 全 tag 各一次），失败即红；
- 固定 `toolchain` + Dockerfile 基础镜像到 patch 版本；
- 每季度/每次发版前重跑本审计。

## 5. 复现

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
cd <repo>
govulncheck ./...
govulncheck -tags "<MODULE_TAGS>" ./...
# JSON 明细（用于自动化）：
govulncheck -json ./... > vuln.json
```

> 原始输出：`build/vuln-default.txt`、`build/vuln-fulltags.txt`、`build/vuln-fulltags.json`（未入库，`build/` 为本地目录）。

