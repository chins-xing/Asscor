# 扩展点执行清单（2026-11-27）

> 目的：回答“89 个扩展点实际被谁执行”这一旧问题（复核后实际为 96 点）。统计口径：`Name:` 静态注册 + `engine.*` 8 个动态阶段 + 6 个 kernel 生命周期；
> 执行点来自非测试代码的 `Extensions().Execute(...)` 调用。

## 1. 结论

- **实际注册点：96**（平台 90 + kernel 生命周期 6）
- **有执行者：90**；**仅注册未执行：6**
- 旧文档写的 **89** 是漏算了 `engine.*` 动态注册（占位符只算 1 个）

## 2. 仅注册未执行（预留或待接）

| 扩展点 | 建议 |
|---|---|
| `extension.enable_failed` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |
| `extension.execution_error` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |
| `extension.install_failed` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |
| `recaller.candidates` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |
| `recaller.dropped` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |
| `recaller.filtered` | 若下个版本仍无订阅者，删除或标注“预留”；当前保留会让人误以为可用 |

## 3. 全量清单（按名称排序）

| # | 扩展点 | 状态 | 执行处（最多 3 个） |
|---|---|---|---|
| 1 | `adapter.post_fetch` | ✅ 1 处 | `internal\kernel\adapter_integration.go:143` |
| 2 | `adapter.pre_fetch` | ✅ 1 处 | `internal\kernel\adapter_integration.go:124` |
| 3 | `agent.log_uploaded` | ✅ 1 处 | `internal\collector\collector.go:213` |
| 4 | `archive.post_write` | ✅ 1 处 | `internal\persistence\persistence.go:317` |
| 5 | `archive.pre_write` | ✅ 1 处 | `internal\persistence\persistence.go:308` |
| 6 | `archive.rotation` | ✅ 2 处 | `internal\persistence\persistence.go:550`<br>`internal\persistence\persistence.go:638` |
| 7 | `assessor.outbound` | ✅ 2 处 | `internal\assessor\assessor.go:421`<br>`internal\assessor\assessor.go:539` |
| 8 | `assessor.post_evaluate` | ✅ 2 处 | `internal\assessor\assessor.go:400`<br>`internal\assessor\assessor.go:518` |
| 9 | `assessor.pre_evaluate` | ✅ 2 处 | `internal\assessor\assessor.go:364`<br>`internal\assessor\assessor.go:448` |
| 10 | `assessor.pre_score` | ✅ 1 处 | `internal\assessor\assessor.go:388` |
| 11 | `assessor.report_generated` | ✅ 2 处 | `internal\assessor\assessor.go:426`<br>`internal\assessor\assessor.go:544` |
| 12 | `attck.apt.attribution` | ✅ 1 处 | `internal\attck\attck.go:510` |
| 13 | `attck.apt.chain_detected` | ✅ 1 处 | `internal\attck\attck_apt_chain.go:97` |
| 14 | `attck.apt.hunt_confirmed` | ✅ 1 处 | `internal\attck\attck_apt_hunt.go:166` |
| 15 | `attck.apt.matched` | ✅ 2 处 | `internal\attck\attck.go:480`<br>`internal\attck\attck.go:1278` |
| 16 | `attck.apt.report_generated` | ✅ 1 处 | `internal\attck\attck_apt_attribution.go:437` |
| 17 | `attck.assessment.complete` | ✅ 1 处 | `internal\attck\attck_assessment.go:147` |
| 18 | `attck.behavioral.alert` | ✅ 1 处 | `internal\attck\attck_apt_detect.go:170` |
| 19 | `attck.behavioral.beacon` | ✅ 1 处 | `internal\attck\attck_apt_detect.go:290` |
| 20 | `attck.coverage.complete` | ✅ 2 处 | `internal\attck\attck.go:461`<br>`internal\attck\attck.go:1165` |
| 21 | `attck.detection.alert` | ✅ 2 处 | `internal\attck\attck.go:615`<br>`internal\attck\attck_detection.go:143` |
| 22 | `attck.detection.anomaly` | ✅ 1 处 | `internal\attck\attck_detection.go:229` |
| 23 | `attck.emulation.complete` | ✅ 1 处 | `internal\attck\attck_emulation.go:359` |
| 24 | `attck.risk.predicted` | ✅ 2 处 | `internal\attck\attck.go:526`<br>`internal\attck\attck.go:1351` |
| 25 | `block.confirmed` | ✅ 1 处 | `internal\kernel\lifecycle.go:327` |
| 26 | `block.post_apply` | ✅ 1 处 | `internal\kernel\lifecycle.go:325` |
| 27 | `block.pre_apply` | ✅ 1 处 | `internal\kernel\lifecycle.go:321` |
| 28 | `breaker.state_changed` | ✅ 1 处 | `internal\kernel\circuitbreaker.go:67` |
| 29 | `cli.command.register` | ✅ 1 处 | `internal\cli\module.go:683` |
| 30 | `commander.command_expired` | ✅ 1 处 | `internal\commander\commander.go:283` |
| 31 | `commander.key_rotated` | ✅ 1 处 | `internal\commander\commander.go:202` |
| 32 | `config.load_error` | ✅ 1 处 | `internal\kernel\config_watcher.go:267` |
| 33 | `config.post_reload` | ✅ 1 处 | `internal\kernel\config_watcher.go:292` |
| 34 | `config.pre_reload` | ✅ 1 处 | `internal\kernel\config_watcher.go:252` |
| 35 | `cti.coefficient_changed` | ✅ 1 处 | `internal\cti\cti.go:362` |
| 36 | `cti.post_update` | ✅ 1 处 | `internal\cti\cti.go:183` |
| 37 | `cti.pre_update` | ✅ 1 处 | `internal\cti\cti.go:161` |
| 38 | `engine.post_check` | ✅ 2 处 | `internal\assessor\assessor.go:384`<br>`internal\assessor\assessor.go:487` |
| 39 | `engine.post_edge` | ✅ 1 处 | `internal\assessor\assessor.go:387` |
| 40 | `engine.post_report` | ✅ 2 处 | `internal\assessor\assessor.go:427`<br>`internal\assessor\assessor.go:545` |
| 41 | `engine.post_score` | ✅ 2 处 | `internal\assessor\assessor.go:385`<br>`internal\assessor\assessor.go:505` |
| 42 | `engine.pre_check` | ✅ 2 处 | `internal\assessor\assessor.go:379`<br>`internal\assessor\assessor.go:449` |
| 43 | `engine.pre_edge` | ✅ 1 处 | `internal\assessor\assessor.go:386` |
| 44 | `engine.pre_report` | ✅ 2 处 | `internal\assessor\assessor.go:423`<br>`internal\assessor\assessor.go:541` |
| 45 | `engine.pre_score` | ✅ 2 处 | `internal\assessor\assessor.go:380`<br>`internal\assessor\assessor.go:501` |
| 46 | `extension.config_changed` | ✅ 1 处 | `internal\kernel\config_watcher.go:296` |
| 47 | `extension.enable_failed` | 仅注册 | — |
| 48 | `extension.execution_error` | 仅注册 | — |
| 49 | `extension.install_failed` | 仅注册 | — |
| 50 | `guide.completed` | ✅ 1 处 | `internal\kernel\lifecycle.go:299` |
| 51 | `guide.confirmed` | ✅ 1 处 | `internal\kernel\lifecycle.go:304` |
| 52 | `heartbeat.agent_pruned` | ✅ 1 处 | `internal\heartbeat\heartbeat.go:636` |
| 53 | `heartbeat.agent_reconnected` | ✅ 1 处 | `internal\heartbeat\heartbeat.go:261` |
| 54 | `heartbeat.agent_timeout` | ✅ 1 处 | `internal\heartbeat\heartbeat.go:595` |
| 55 | `kernel.post_init` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:64` |
| 56 | `kernel.post_start` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:75` |
| 57 | `kernel.post_stop` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:109` |
| 58 | `kernel.pre_init` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:33` |
| 59 | `kernel.pre_start` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:66` |
| 60 | `kernel.pre_stop` | ✅ 1 处 | `internal\kernel\kernel_lifecycle.go:84` |
| 61 | `lifecycle.completed` | ✅ 1 处 | `internal\kernel\lifecycle.go:384` |
| 62 | `lifecycle.phase_entered` | ✅ 1 处 | `internal\kernel\lifecycle.go:242` |
| 63 | `lifecycle.phase_exited` | ✅ 1 处 | `internal\kernel\lifecycle.go:248` |
| 64 | `lifecycle.repeat` | ✅ 1 处 | `internal\kernel\lifecycle.go:365` |
| 65 | `locate.completed` | ✅ 1 处 | `internal\kernel\lifecycle.go:278` |
| 66 | `locate.threat_active` | ✅ 1 处 | `internal\kernel\lifecycle.go:350` |
| 67 | `log.entry_received` | ✅ 1 处 | `internal\collector\collector.go:174` |
| 68 | `persistence.dashboard_written` | ✅ 1 处 | `internal\persistence\persistence.go:350` |
| 69 | `persistence.post_append` | ✅ 1 处 | `internal\persistence\persistence.go:282` |
| 70 | `persistence.pre_append` | ✅ 1 处 | `internal\persistence\persistence.go:266` |
| 71 | `persistence.record_written` | ✅ 1 处 | `internal\persistence\persistence.go:322` |
| 72 | `policy.action_decided` | ✅ 1 处 | `internal\policy\policy.go:152` |
| 73 | `policy.notify` | ✅ 1 处 | `internal\policy\policy.go:159` |
| 74 | `policy.status_changed` | ✅ 1 处 | `internal\policy\policy.go:141` |
| 75 | `ratelimit.limit_exceeded` | ✅ 1 处 | `internal\kernel\ratelimit.go:139` |
| 76 | `recaller.candidates` | 仅注册 | — |
| 77 | `recaller.dropped` | 仅注册 | — |
| 78 | `recaller.filtered` | 仅注册 | — |
| 79 | `remediation.action_resolved` | ✅ 1 处 | `internal\commander\commander.go:381` |
| 80 | `remediation.post_apply` | ✅ 1 处 | `internal\commander\commander.go:374` |
| 81 | `remediation.pre_apply` | ✅ 1 处 | `internal\commander\commander.go:324` |
| 82 | `siem.post_push` | ✅ 1 处 | `internal\assessor\assessor.go:179` |
| 83 | `siem.pre_push` | ✅ 1 处 | `internal\assessor\assessor.go:165` |
| 84 | `siem.push_failure` | ✅ 1 处 | `internal\assessor\assessor.go:172` |
| 85 | `source.post_deploy` | ✅ 1 处 | `internal\sourcemanager\sourcemanager.go:152` |
| 86 | `source.pre_deploy` | ✅ 1 处 | `internal\sourcemanager\sourcemanager.go:99` |
| 87 | `source.pre_disable` | ✅ 1 处 | `internal\sourcemanager\sourcemanager.go:253` |
| 88 | `source.pre_enable` | ✅ 1 处 | `internal\sourcemanager\sourcemanager.go:208` |
| 89 | `spc.cve_updated` | ✅ 1 处 | `internal\spc\spc_fetch.go:83` |
| 90 | `spc.post_calculate` | ✅ 1 处 | `internal\spc\spc.go:665` |
| 91 | `spc.pre_calculate` | ✅ 1 处 | `internal\spc\spc.go:423` |
| 92 | `srd.result_processed` | ✅ 1 处 | `internal\srdwrapper\srd_wrapper.go:148` |
| 93 | `verify.post_check` | ✅ 2 处 | `internal\assessor\assessor.go:402`<br>`internal\assessor\assessor.go:520` |
| 94 | `verify.pre_check` | ✅ 2 处 | `internal\assessor\assessor.go:365`<br>`internal\assessor\assessor.go:450` |
| 95 | `verify.status_changed` | ✅ 2 处 | `internal\assessor\assessor.go:411`<br>`internal\assessor\assessor.go:529` |
| 96 | `workerpool.task_timed_out` | ✅ 1 处 | `internal\kernel\workerpool.go:257` |

## 4. 修复建议

1. 更新 README/白皮书里的 89 → **96**（90 平台 + 6 生命周期）。
2. 6 个未执行点（`extension.enable_failed`/`execution_error`/`install_failed`、`recaller.*`）要么在对应失败/召回路径补 Execute，要么从注册表移除并记录为预留。
3. 保留 `engine.*` 动态注册说明，避免再次被静态计数漏算。

