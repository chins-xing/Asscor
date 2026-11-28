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


## Stage 7：SRD-DYN 仅 s 观测参数回收

- 新增 `RecoverParamsSObserved`（初值 `S/D/C/H` 已知，之后只观测 `s`）；
- 激励：失败脉冲 + 邻居态势切换；
- dl360gen9：

```text
PASS TestRecoverParamsSObserved
  Alpha s-only recovered 0.2 (truth 0.2)
  Lambda s-only recovered 0.3 (truth 0.35)
ok github.com/chins-xing/asscor/internal/srddyn
```

- `Alpha` 精确；`Lambda` 偏差约 14%；
- 坐标下降对 `Delta=0.05` 落入局部极小（未回收）；后续剖面似然表明这是优化器问题，不是弱可辨识。


## Stage 8：Delta 剖面似然

- 新增 `ProfileLikelihoodSObserved`：固定 `Delta` 网格，重拟合 `Alpha/Lambda`；
- dl360gen9：

```text
PASS TestProfileLikelihoodDeltaMinimum
  Delta profile min SSE=0 at Delta=0.05 (truth=0.05)
```

结论：在“初值隐状态已知 + 激励充分”的合成场景下，`Delta` 在真值处有明确全局最小；此前坐标下降失败是局部极小，不应写成“弱可辨识”。初值隐状态未知时的一般部分观测可辨识性仍未证明。


## Stage 9：SRD-DYN 合成验收总跑

新增并验证：

| 能力 | 测试 |
|---|---|
| 事件跳变 | `TestApplyEventJump` |
| Sobol 一阶/总指数 | `TestSobolIndicesAdditive` |
| CRPS/Brier/AUC/RMSE | `TestProperScoringMetrics` |
| 预测优于持久性基线 | `TestForecastBeatsPersistence` |

dl360gen9：

```text
go test -v ./internal/srddyn
19 tests PASS
ok github.com/chins-xing/asscor/internal/srddyn
```

覆盖的验收子项：A1 独立状态、A2 演化、A3 记忆、A4 反馈、A5 耦合、A6 滞回、A7 滤波、A8 参数回收（合成）、A9 预测（合成）、A10 可复现。
**未覆盖**：真实数据校准、初值隐状态未知的部分观测可辨识性、Sobol 置信区间。


## Stage 10：Sobol CI + 未知初值联合恢复

```text
PASS TestSobolBootstrapCI
PASS TestRecoverUnknownInitialSObserved
unknown-initial fit SSE 0.343753 -> 1.14023e-06
```

- Sobol 指数补 5/95% bootstrap 区间；
- 初值 `D/C/H` 未知时联合估计，SSE 从 0.344 降到 1.1e-6；
- `H0` 在该场景仍弱可辨识（恢复 0.1 vs 真值 0.2 但 SSE 近零），需先验/固定策略。


## Stage 11：L4 协议/端口

- `PolicyRule/PolicyFact` 增加 `Protocol/SrcPort/DstPort`；
- 新增 `HostReachableFlow(from,to,maxHops,flow)`，旧 `HostReachable` 保持 any-flow 兼容；
- federation 合并/冲突键包含 L4，不同端口不再误报 allow/deny 冲突；
- dl360gen9：

```text
PASS TestHostReachableFlowPorts
PASS TestDifferentPortsDoNotConflict
```


### 11.1 Agent 上报链路

- `apiv1.PolicyRule`、`TopoPolicyRule`、`PolicyFact` 全链路传递 L4；
- agent nft：解析 `tcp/udp sport/dport`、`ip protocol`；
- agent iptables：解析 `-p/--dport/--sport`，允许 `-m tcp/udp`，其它模块继续跳过（不猜）；
- 本地测试：

```text
PASS TestParseNftL4Ports
PASS TestParseIptablesL4Ports
PASS TestParseIptablesSkipsComplexModules
```

- dl360gen9：补传 `x/crypto@v0.57.0`、`x/sys@v0.48.0` 模块缓存后，agent 解析测试远端通过：

```text
PASS TestParseNftL4Ports
PASS TestParseIptablesL4Ports
```


## Stage 12：NodeReport 语义校验

- 新增 `ValidateNodeReport`：node_id、host id、IP/CIDR、协议、端口、事实上限；
- master `/federation/report` 在合并前校验，非法报告返回 400；
- dl360gen9：

```text
PASS TestValidateNodeReportValid
PASS TestValidateNodeReportRejectsMalformed
```

覆盖：空 node_id、坏 IP、坏 CIDR、端口越界、未知协议、空 host id、超限主机数。


## Stage 13：事实时间轴与置信度

- `HostFacts/PolicyRule/HostFact/PolicyFact` 增加 `ObservedAt/ValidUntil/Confidence`；
- `BuildLayeredGraphAt` 过滤过期主机/策略；
- federation merge 保留最新观测时间、最早过期时间、最小正置信度；
- dl360gen9：

```text
PASS TestExpiredHostAndPolicyAreFiltered
PASS TestConfidencePreserved
PASS TestMergePreservesMetadata
```

限制：置信度目前只做保留/展示，尚未参与 `reachable/probable` 判定；agent 也尚未填充这些元数据。


## Stage 14：置信度接入判定

- `LayeredGraph.confidenceThreshold`（默认 0.5，`SetConfidenceThreshold` 可调）；
- `0 < Confidence < threshold` 的主机/策略降级为 `probable`：
  - `low_confidence`（主机）
  - `low_confidence_policy`（host inbound/outbound）
  - `low confidence policy`（全局 PolicyRule）
- 低置信 deny 不再直接 `blocked`。
- dl360gen9：

```text
PASS TestLowConfidenceHostDowngrades
PASS TestLowConfidencePolicyDoesNotBlock
```


### 14.1 Agent 元数据

- nft/iptables 解析出的策略统一 `stampRuleMetadata`：
  - `ObservedAt = now`（未提供时）；
  - `Confidence = 1.0`（显式解析规则的基础置信度）。
- dl360gen9：

```text
PASS TestParseNftL4Ports
PASS TestParseIptablesL4Ports
```


## Stage 15：上报截断可见

- `NodeReport` 增加 `truncated/dropped_hosts/dropped_policies`；
- `collectFacts` 计算丢弃数量，不再静默切片；
- 同时修复 local facts 丢失 L4/元数据的问题；
- dl360gen9：

```text
PASS TestCollectFactsTruncationVisible
PASS TestCollectFactsPreservesL4AndMetadata
```


## Stage 16：NAT 外部别名（DNAT 原型）

- `topology.HostFacts.NAT`、federation `HostFact.NAT`；
- 构建图时 `External` 作为主机别名子网，使外部地址可达；
- dl360gen9：

```text
PASS TestNATExternalAliasReachable
ok github.com/chins-xing/asscor/extensions/federation
```

范围：仅 DNAT 外部别名。SNAT、双向 NAT、地址转换后的策略重写未实现，不能据此声称完整 NAT。


### 14.2 Host 级元数据

- `TopoNode` 增加 `ObservedAt/ValidUntil/Confidence`；
- `RecordNetworkFacts` 在心跳写入时打点 `ObservedAt=now`、基础 `Confidence=1.0`；
- `hostFactFromTopo` 把元数据带到 federation `HostFact`；
- dl360gen9：

```text
PASS TestRecordNetworkFactsMetadata
PASS TestHostFactFromTopoMetadata
```


## Stage 17：conntrack invalid 状态

- `Flow.State` 支持 `new/established/related/invalid`；
- `HostFacts.StatefulInvalidDrop` 时，invalid 流量在入/出向被阻断；
- dl360gen9：

```text
PASS TestInvalidStateDropped
```

范围：查询模型原型。agent 尚未采集 `ct state invalid drop`；会话超时与 related 生命周期仍未建模。

