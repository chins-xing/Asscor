# SRD-DYN & LayeredGraph 增量验证（2026-11-28）

> 目标：按“本地 → dl360gen9 源码级 → dl360gen9 小拓扑”的顺序逐步验证，避免一次性拉起全部拓扑。
> 本轮完成 Stage 0/1；Stage 2 需要先恢复 kernel/小拓扑，单独进行。

## Stage 0：本地（Windows）

| 包/用例 | 结果 |
|---|---|
| `go test ./internal/topology` | PASS |
| `go test ./internal/srddyn` | PASS |
| `go test -tags federation,engine ./extensions/federation` | PASS |
| `go vet ./internal/topology` | PASS |

新增关键用例：

- `layers_depth_test.go`：深度耗尽 → `probable`（`max_hops_exhausted`）；足够深度 → `reachable`；真无路径 → `blocked`。
- `TestPartialPolicyUnknownBySubnet`：按子网 unknown → `probable`。
- `merge_conflict_test.go`：allow/deny 冲突暴露、不静默选边、来源保留。
- `TestMergePartialPolicyUnknown`：未知节点子网局部降级。
- `internal/srddyn`：独立状态、记忆、反馈、耦合、滞回、数值收敛 7 个用例。

## Stage 1：dl360gen9 源码级

- 主机：`dl360gen9`（PVE，x86_64，Go `1.27.1`）。
- 源码包：仅 `go.mod/go.sum`、`api`、`internal`、`extensions/federation`、`prism-lib`、`ssam-lib`。
- 解压路径：`/root/t6/t28-verify`。
- 命令与结果：

```text
go test -v ./internal/topology -run 'TestDepth|TestPartialPolicyUnknown'
  PASS TestDepthExhaustionIsProbable
  PASS TestDepthSufficientReachable
  PASS TestPartialPolicyUnknownBySubnet

go test -v ./internal/srddyn
  PASS TestIndependentStateChangesTrajectory
  PASS TestDebtHasMemoryAndDecays
  PASS TestCollapseFeedbackChangesPosture
  PASS TestNeighborCouplingChangesContagion
  PASS TestHysteresisStatePersistsAfterStress
  PASS TestRK4FiniteAndBounded
  PASS TestRK4TimestepConvergence

go test -tags federation,engine ./extensions/federation -run 'TestMerge|TestBuildMerged'
  ok
```

**结论**：拓扑 P0（2.1/3.1/3.4/1.4 子网范围）与 SRD-DYN 核心原型在目标主机上可复现通过。

## Stage 2：dl360gen9 小拓扑（T1/T3 实测）

### 启动状态

- 启动 `qm 910`（asc-kernel-vm）；
- 启动 CT `920`（domC-router）、`921`（domA-web）、`922`（domA-db）、`923`（domB-web）；
- 四个 CT 的 `asscor-agent` 均为 active；
- 用当前源码构建的 proc kernel 替换 `/home/asc/asscor/bin/kernel`，重启 `asscor-kernel`；
- 本地/远端二进制 SHA256 一致：

```text
c8de33848ecb52852637a6e7f1042f0077bbaccb048a14f3fe94149e9054247e
```

### 实测查询

通过 `/opt/asscor/asscor-cli.sock` 执行 `srd check`：

```text
srd check domA-web domA-db
  verdict : reachable   (paths=2)
  path    : domA-web -> domA-db
  layers  : hosts=3 subnets=5 vlans=0 policies=5 forwarding=1

srd check domA-web domB-web
  verdict : blocked   (paths=1)
  path    : domA-web -> domC-router -> domB-web
  blocked : domC-router
  reason  : policy deny 172.22.10.1/24->172.23.10.1/24
  layers  : hosts=4 subnets=5 vlans=0 policies=5 forwarding=1
```

结论：

- T1 域内可达性正常，且返回多路径计数（`paths=2`）；
- 跨域 T3 被 router 的显式策略阻断，阻断点/原因可解释；这是当前拓扑策略的预期结果，不是代码回归；
- 深度耗尽、部分 unknown、allow/deny 冲突三项在实验拓扑里没有自然实例，仍以 Stage 0/1 的定向用例为准。

### 待继续

- 若要验证跨域可达，需要调整 920 的跨域 allow 策略（属于实验配置变更，不是模型代码）；
- 深度耗尽可用更长的链式拓扑（≥5 跳）验证；
- 部分 unknown/冲突可在联邦节点上报中注入（下一轮）。

