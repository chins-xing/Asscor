# 内核膨胀专项审计 + 修复（默认最小内核携带 gRPC 运行时）

- **日期**：2026-09-03
- **分支**：main（HEAD 基线 `48ea2cc`，审计后修复提交见文末）
- **性质**：审计 + 立即修复 + 归档
- **范围**：默认构建 `go build ./cmd/kernel`（无 tag）的编译闭包与产物体积，核对"微内核 + build-tag 可选模块零膨胀"宣称

---

## 一、方法与实测

四种构建实测 + `go list -deps` 闭包 diff + `go tool nm` 符号级确认（产物/清单置于 `build/audit/`，已随清理删除）：

| 构建 | 修复前体积 | 依赖包数 | 说明 |
|---|---|---|---|
| 默认（无 tag） | **16.15 MiB** | 325 | 全仓唯一 grpc import 无 tag 残留 |
| 仅 `-tags comms` | 18.9 MiB | — | comms 增量小 → grpc 已含在默认里 |
| 全 17 tag | 21.42 MiB | 348 | +5.6 MiB 换全部功能模块 |
| agent 默认 | 16.3 MiB | — | 同样携带 grpc/protobuf |

nm 实测默认 exe 含 **grpc 1286 + protobuf 2114 个文本函数**（ClientConn/Server/transport 全在），尽管 comms tag 关闭、运行时 0 监听。

## 二、结论

**模块层宣称成立**：17 个功能模块（heartbeat/commander/policy/cti/assessor/attck/spc/collector/sourcemanager/persistence/srdwrapper/engine/adapterhub 等）的 `_on/_off` 文件对 + 内部 build tag 齐全，默认产物 0 符号，全 tag 才进入——门控干净，无功能模块泄漏。

**但存在一处基座级膨胀（P0）**：内核核心（无 tag 的 `internal/kernel` 契约/服务文件）无条件 import `api/v1`，而 `api/v1/grpc.go` **无条件** import `google.golang.org/grpc` → 默认最小内核整体链接 gRPC+protobuf 运行时。agent（默认构建）import api/v1 仅用 asscor.pb.go 的纯消息类型，也被同文件拖累。

### 膨胀点定位

| 位置 | 问题 | 处置 |
|---|---|---|
| `api/v1/grpc.go`（无 tag） | 手写 gRPC 绑定（Server/Client 接口 + Register + stream），无条件 import grpc/codes/status | **已修复**：拆分 |
| `internal/kernel/source_manager_service.go` 等（无 tag） | 引用 api/v1 类型把 kernel 钉在 api/v1 闭包 | 拆分后成本归零 |
| `internal/kernel/collector_interface.go` / `commander_interface.go` | 接口绑定 PB 消息类型 | 同上（PB 消息留在无 tag 文件，可继续引用） |
| `internal/kernel/scoring_engine_interface.go` | prismlib import 进编译闭包 | linker 已剪枝（默认 exe 0 符号），非膨胀，P2 可留 |

## 三、修复（本次立即执行）

**方案（最小攻击面）**：`api/v1/grpc.go` 按依赖边界拆分为两个文件：

1. **`api/v1/messages.go`（无 tag）**：原 1–187 行——纯 PB 消息 struct（PBRegisterRequest/PBHeartbeatRequest/PBAssessmentResult/PBCheckResult/PBCommand/PBLogEntry/PBAck 等）+ `ConvertAssessmentResultToPB`/`ConvertPBToAssessmentResult`/`ConvertPBCommandsToJSON` 转换函数。仅 import `fmt`。agent/kernel 契约/collector/commander（默认构建）继续使用，不再携带 grpc。
2. **`api/v1/grpc.go`（`//go:build comms`）**：原 189–453 行——`KernelServiceServer`/`AgentServiceServer`/`AgentServiceClient` 接口、`RegisterKernelServiceServer`/`RegisterAgentServiceServer`、client 实现、`AgentService_StreamLogs{Server,Client}`、`GRPCStatus`/`GRPCError`。仅 comms tag 下编译。

**验证**：
- 默认构建（api/kernel/agent/collector/commander）exit 0，无 grpc 依赖
- `-tags comms` 构建（comms/grpc_server/cmd/kernel）exit 0
- `go vet` 默认 + comms 双态干净
- `internal/kernel` 全量测试 PASS
- **产物：默认内核 16.15 → 9.09 MiB（-44%）；全量构建 21.42 MiB 不变** —— gRPC+protobuf 运行时从最小内核整体移出

## 四、归档说明

- 既有审计（CODE_QUALITY_AUDIT_2026-08-14 / SECOND_AUDIT_2026-08-15 / EXTENSION_KERNEL_AGENT_ISOLATION_AUDIT_2026-08-13）验证模块门控一致性，但未逐字节核对"comms 关闭时 grpc 仍被 kernel→api/v1 链路拖进默认产物"——本审计的增量结论。
- 修复后建议后续在 CI 或发布脚本增加"默认构建体积上限"守护（如 >10 MiB 告警），防止回归（未纳入本次改动，记录为建议）。
- 附带修复（测试驱动发现）：本批次测试推进中发现并修复——`workerpool.peakActiveWorkers` 恒 0（缺陷）、`Submit-after-Shutdown` 不确定执行、`resilience` 半开 trial 失败不重开熔断、`semver` pre 数字 id 判反与超长版本被接受（详见对应测试/修复提交）。
