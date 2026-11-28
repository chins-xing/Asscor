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

## Stage 2：dl360gen9 小拓扑（待执行）

现状：

- `pct list` 中拓扑容器（920–927）与 federation 节点（930–932）全部 `stopped`；
- `qm 910`（asc-kernel-vm）配置缺失，不能直接启动；
- 因此 Stage 2 需要先恢复 kernel 运行位置与最小拓扑启动脚本，不在本轮盲目拉起 30 个容器。

建议顺序：

1. 只启动 T1 相关容器（`920/921/922`）+ 一个 kernel 实例；
2. 用导出的 topology JSON 跑 `HostReachable` 的三类断言：深度耗尽、冲突、部分 unknown；
3. 再扩到 923–927（T2/T3），最后才恢复 930–932 federation 节点；
4. 每步保留 `pct status`、kernel 日志、判定 JSON。

## 备注

- Stage 1 使用源码包而非远端陈旧 `/root/t6/argus`（其 HEAD 停在 `0a05b7d`），避免“测到旧二进制”。
- SRD-DYN 原型尚未实现 EKF/参数回收/时间外预测，因此不能据此宣称完整 v0.0.1 验收；见 `SRD-DYN.md` 第 13 节。
