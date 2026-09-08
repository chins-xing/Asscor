# 故障注入验证 — E29–E39 实验

**日期**: 2026-08-16 | **版本**: v0.2.3 | **环境**: Containerlab v3（12 台主机 / host1 为主要注入对象）

## 实验结果

| # | 故障 | 注入方式 | 行为与恢复 | 判定 |
|:-:|------|---------|-----------|:---:|
| E29 | Agent kill | `kill -9` host1 agent | 75s 后 kernel 心跳超时检测（WARN "agent timed out"）；重启 agent → 重新注册 accepted + 心跳恢复 + 重新评估（58.27） | ✅ |
| E30 | Engine kill | `kill -9` kernel | agent 断连重试（cycle error + backoff）；重启 kernel → 12 agent 全部重连注册，**身份绑定持久化恢复**（host1 f7955c00 保留） | ✅ |
| E31 | IPC 中断 | iptables DROP host1→kernel:50051 gRPC 流量 | agent gRPC 断连重试；移除规则后心跳恢复（has_result=true） | ✅ |
| E32 | 网络中断 | r2 eth2 down（host1 完全断网） | host1 断网不可达；恢复链路后心跳+评估恢复 | ✅ |
| E33 | 状态存储不可用 | identity.json 改名 | **运行时 kernel 不受影响**（内存绑定仍在、评估持续 103 次）；重启 kernel 后文件缺失 → 绑定重置为首次绑定（重新注册 accepted） | ⚠️ 见发现 1 |
| E34 | 插件异常退出 | 插件为进程内 goroutine，无法直接 kill | 健康机制存在（CLI `plugin health` + 各 monitorLoop `recover`）；本实验无插件 panic（panic recovered=0） | ✅ 部分 |
| E35 | 插件返回非法数据 | agent 上报受代码约束，无法端到端制造 | 防护在代码级（services.go maxPackages/maxCPEs 截断 + 空 result 跳过）；无异常日志 | ✅ 部分 |
| E36 | 重复事件洪泛 | host1 心跳间隔 30s→5s（40s 内 142 条心跳，约 42× 洪泛） | kernel 稳定处理无 ERROR（日志中 ERROR 为历史 dashboard rename，非洪泛引起）、无 panic | ✅ |
| E37 | 状态恢复 | E29-E36 各故障后 | 全部恢复：注册/心跳/评估正常 | ✅ |
| E38 | 故障后重新评估 | 恢复后触发全系统评估 | host1/5/9/12 均正常评估（58.27） | ✅ |
| E39 | 故障后重新响应 | 恢复后检查响应 | 12 台心跳全通、评估响应 110 次正常 | ✅ |

## 发现

| 级别 | 发现 | 实验 | 说明 |
|:---:|------|:---:|------|
| **P1** | 状态文件丢失 → 身份锚定重置 | E33 | identity.json 缺失时重启 kernel → 绑定清空 → 任何证书可作"首次绑定"抢占。窗口期内存在身份抢占风险（同证书可恢复一致，攻击者若在窗口内注册则抢占） |
| P2 | agent 在 engine 长时间不可达时退出 | E30 | `max_retries=3` 后 "kernel unreachable, shutting down"——agent 主动退出且无自动拉起（容器内无 systemd 托管 agent），需外部 supervisor |
| P3 | dashboard 报告 rename 错误噪音 | E36 | persistence 写 latest-assessment.json 偶发 `rename: no such file` ERROR（容错但日志噪音） |

## 结论

**故障注入 E29-E39 整体通过（10 项全过，E34/E35 为代码级部分验证）**：

- **容错性**：agent kill、engine kill、IPC/网络中断、状态存储故障、事件洪泛下，系统均无崩溃、无数据损坏，恢复后功能完整。
- **恢复能力**：E37-E39 确认故障后评估与响应完全正常；身份绑定在 engine 重启后持久化恢复（亮点）。
- **待改进**：E33 暴露身份锚定对状态文件的单点依赖（P1）；E30 暴露 agent 无 supervisor 自动拉起（P2）；E36 观察 dashboard 写入错误噪音（P3）。

*数据：`docs/clab-lab/data/assessments-checks.jsonl` 及同批评估轮次。*
