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
  PASS TestFilterCovarianceShrinksAndTracksObservation
  PASS TestFilterFiniteUnderNoise

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

### T3 正向验证（临时 ACL）

在 920 上临时插入 `eth0`↔`eth1` accept（备份原 nft 规则），重启 agent 后：

```text
srd check domA-web domB-web
  verdict : reachable   (paths=1)
  path    : domA-web -> domC-router -> domB-web
  layers  : hosts=4 subnets=5 vlans=0 policies=7 forwarding=1
```

随后删除临时规则（handle 9/10）并重启 agent，恢复到原始 deny 策略，避免实验环境长期漂移。

### 待继续

- 若要验证跨域可达，需要调整 920 的跨域 allow 策略（属于实验配置变更，不是模型代码）；
- 深度耗尽可用更长的链式拓扑（≥5 跳）验证；
- 部分 unknown/冲突可在联邦节点上报中注入（下一轮）。


## Stage 3：dl360gen9 联邦注入（冲突 / 部分 unknown）

> 关键发现：`federation check` 的合并逻辑在 **federation-mod 子进程**，只换 kernel 不够；本轮重新构建并替换了 `federation-mod`。

### 3.1 allow/deny 冲突

向 master `POST /federation/report` 注入两个节点（`p0-nk1` allow、`p0-nk2` deny），查询：

```json
{
  "src": "p0-A", "dst": "p0-B",
  "verdict": "probable",
  "conflicts": [{
    "from": "10.9.1.0/24", "to": "10.9.2.0/24",
    "allow_sources": ["p0-nk1"], "deny_sources": ["p0-nk2"]
  }],
  "stats": {"policies": 2, "hosts": 3}
}
```

- 冲突不再静默选边，判 `probable`；
- `allow_sources/deny_sources` 可回溯；
- 路径步骤 reason 当前显示 `policy partially unknown`（`sessionVerdict` 对 probable 的通用文案），不影响 verdict 与冲突字段。

### 3.2 部分策略 unknown

注入 `policy_known=false` 的 `p0-nk3`（`p0-U`/`p0-GW2`/`p0-V`），查询：

```json
{
  "src": "p0-U", "dst": "p0-V",
  "verdict": "probable",
  "unknowns": ["policy"]
}
```

- 仅该节点的子网被标 unknown，其它已知子网仍保持 known；
- 跨 unknown 子网判 `probable`，符合 1.4 目标。


### 3.4 host 级 inbound/outbound 冲突（真实注入）

重新构建并部署含 host 级冲突的 `federation-mod`（sha256 `8fe847ec…1859`），注入两个报告：
`hk1` 对 HA 的 inbound allow、`hk2` 对 HA 的 inbound deny。

```json
{
  "src": "HX", "dst": "HA",
  "verdict": "probable",
  "unknowns": ["policy_conflict"],
  "conflicts": [{
    "host": "HA", "direction": "inbound",
    "from": "10.9.9.0/24", "to": "10.9.9.0/24",
    "allow_sources": ["hk1"], "deny_sources": ["hk2"]
  }]
}
```

- host 级冲突不再由首条匹配静默决定；
- `PolicyConflict.Host/Direction` 在真实 API 输出中可见；
- 验证后重启 kernel 清空注入报告，`/federation/nodes` 回到 `count=0`。

### 3.3 环境清理

注入报告只存在 master 内存；验证后重启 `asscor-kernel` 清空测试节点，agent 自动重连，T1/T3 原有拓扑恢复。


## Stage 4：SRD-DYN 参数回收（dl360gen9）

- 新增 `RecoverParams`：合成全状态观测 + 坐标下降；
- 真值 `Alpha=0.20/Delta=0.05/Lambda=0.35`，初值扰动后回收，±20% 内通过；
- dl360gen9 结果：

```text
PASS TestRecoverParamsFromFullState
PASS TestRecoverParamsUnknownName
ok github.com/chins-xing/asscor/internal/srddyn
```

限制：观测为**全状态 oracle**，只证明优化器与合成可辨识链路；仅观测 s 的部分可辨识性、Fisher/Sobol、时间外预测仍未做。


## Stage 5：SRD-DYN Fisher 信息（s-only）

- 新增 `FisherInformation`：s-only 观测、数值灵敏度、标量观测方差；
- 检查矩阵对称、对角为正、有限；
- dl360gen9：

```text
PASS TestFisherInformationSOnly
PASS TestFisherUnknownParameter
ok github.com/chins-xing/asscor/internal/srddyn
```

限制：仅证明 Fisher 计算链路，尚未做剖面似然/Sobol/仅 s 参数回收。


## Stage 6：长链深度耗尽（32 节点 + 12 节点实机）

### 32 节点模型回归

`internal/topology/layers_longchain_test.go`：

```text
PASS TestLongChainDepthExhaustion
```

- 32 节点链，`maxHops=5` → `probable` + `max_hops_exhausted`；
- `maxHops=31` → `reachable`；
- 已在 dl360gen9 源码级复跑通过。

### 12 节点实机注入

向 federation master 注入 `CH0…CH11` 链（每相邻主机共享一个独立 /24，中间节点 forward=true），查询：

```text
CH5  reachable   paths=1
CH6  probable    unknowns=['max_hops_exhausted'] paths=1
CH11 probable    unknowns=['max_hops_exhausted'] paths=1
```

与预期一致：5 跳可达；6/11 跳被深度截断，但返回 unknown 而不是误报 blocked。

### 清理

重启 kernel 清空注入报告，`/federation/nodes` 回到 `count=0`；T1 复查 `reachable (paths=2)`。

