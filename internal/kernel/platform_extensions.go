package kernel

// RegisterAllExtensionPoints defines every extension point on the ASSCOR platform.
// Modules fire events via Extensions().Execute() but CANNOT define extension points.
// The *ExtensionRegistry is only accessible at the platform layer (cmd/kernel/main.go),
// not through the KernelContext exposed to plugins.
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
	r.RegisterPoint(ExtensionPoint{
		Name: "assessor.pre_evaluate", Description: "Called before each host assessment", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "assessor.pre_score", Description: "Called before scoring engine runs — orchestrator plugins intercept here", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "assessor.post_evaluate", Description: "Called after each host assessment completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "assessor.report_generated", Description: "Called after console/dashboard report is generated", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "assessor.outbound", Description: "Called after assessment completes — plugins can push to SIEM/webhook/SOAR", Version: "1.0",
	})

	// Engine phase bridge — connects engine.HookRegistry (8 phases) to kernel Extension Points.
	// Plugins can subscribe to these to hook into engine pipeline phases:
	//   pre_check, post_check, pre_score, post_score, pre_edge, post_edge, pre_report, post_report
	for _, phase := range []string{"pre_check", "post_check", "pre_score", "post_score", "pre_edge", "post_edge", "pre_report", "post_report"} {
		r.RegisterPoint(ExtensionPoint{
			Name: "engine." + phase, Description: "Engine assessment pipeline phase — bridges engine.HookRegistry to kernel extension points", Version: "1.0",
		})
	}

	r.RegisterPoint(ExtensionPoint{
		Name: "spc.pre_calculate", Description: "Called before SPC calculation", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "spc.post_calculate", Description: "Called after SPC calculation completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "spc.cve_updated", Description: "Called when CVE cache is refreshed", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.coverage.complete", Description: "Called after coverage analysis completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.detection.alert", Description: "Called when a detection alert is triggered", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.detection.anomaly", Description: "Called when a high-score anomaly is detected", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.behavioral.alert", Description: "Called when a behavioral alert is triggered", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.behavioral.beacon", Description: "Called when C2 beaconing is detected", Version: "1.0",
	})

	r.RegisterPoint(ExtensionPoint{
		Name: "policy.action_decided", Description: "Called when a policy action is decided", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "policy.notify", Description: "Called to dispatch notifications for policy actions", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "policy.status_changed", Description: "Called when host policy status changes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.emulation.complete", Description: "Called after adversary emulation completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.apt.hunt_confirmed", Description: "Called when threat hunt hypothesis is confirmed", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.apt.chain_detected", Description: "Called when APT attack chain is reconstructed", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.apt.matched", Description: "Called when APT group match is detected", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.apt.attribution", Description: "Called when APT attribution is performed", Version: "1.0",
	})

	r.RegisterPoint(ExtensionPoint{
		Name: "attck.risk.predicted", Description: "Called after predictive risk assessment", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.assessment.complete", Description: "Called after gap analysis assessment completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "attck.apt.report_generated", Description: "Called when APT analysis report is generated", Version: "1.0",
	})

	r.RegisterPoint(ExtensionPoint{
		Name: "remediation.pre_apply", Description: "Called before a remediation command is enqueued", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "remediation.post_apply", Description: "Called after agent acknowledges remediation", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "remediation.action_resolved", Description: "Called when remediation action is resolved", Version: "1.0",
	})

	r.RegisterPoint(ExtensionPoint{
		Name: "verify.pre_check", Description: "Called before verification re-assessment", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "verify.post_check", Description: "Called after verification re-assessment (prev_score, new_score, delta)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "verify.status_changed", Description: "Called when host verification status transitions", Version: "1.0",
	})

	r.RegisterPoint(ExtensionPoint{
		Name: "archive.pre_write", Description: "Called before writing to archive", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "archive.post_write", Description: "Called after archive write succeeds", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "archive.rotation", Description: "Called when archive rotation executes (snapshots/daily)", Version: "1.0",
	})

	// ── Extensibility 阶段 (platform self-extension) ──
	r.RegisterPoint(ExtensionPoint{
		Name: "cli.command.register", Description: "Register custom CLI commands from plugins", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "webui.route.register", Description: "Register additional HTTP routes on the web server", Version: "1.0",
	})

	// ── 探测辅助: 心跳/Agent生命周期 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "heartbeat.agent_timeout", Description: "Called when agent heartbeat times out", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "heartbeat.agent_reconnected", Description: "Called when agent reconnects after timeout", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "heartbeat.agent_pruned", Description: "Called when dead agent is pruned from registry", Version: "1.0",
	})

	// ── 探测辅助: 适配器管线 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "adapter.pre_fetch", Description: "Called before external adapter pipeline executes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "adapter.post_fetch", Description: "Called after external adapter pipeline completes", Version: "1.0",
	})

	// ── 探测辅助: CTI威胁情报 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "cti.pre_update", Description: "Called before CTI feed update cycle", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "cti.post_update", Description: "Called after CTI feed update cycle completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "cti.coefficient_changed", Description: "Called when CTI threat coefficient changes", Version: "1.0",
	})

	// ── 响应辅助: 配置热加载 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "config.pre_reload", Description: "Called before configuration is reloaded (SIGHUP/poll)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "config.post_reload", Description: "Called after configuration reload completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "config.load_error", Description: "Called when configuration reload fails", Version: "1.0",
	})

	// ── 报告辅助: 日志收集 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "log.entry_received", Description: "Called when agent log entry is received — plugins can forward to external systems", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "agent.log_uploaded", Description: "Called when agent uploads log batch to kernel", Version: "1.0",
	})

	// ── 报告辅助: SIEM推送 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "siem.pre_push", Description: "Called before SIEM event push", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "siem.post_push", Description: "Called after SIEM push succeeds", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "siem.push_failure", Description: "Called when SIEM push fails", Version: "1.0",
	})

	// ── 修复辅助: 命令过期 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "commander.command_expired", Description: "Called when a pending command TTL expires without ack", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "commander.key_rotated", Description: "Called when HMAC command signing key rotates", Version: "1.0",
	})

	// ── 修复辅助: Source管理器 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "source.pre_deploy", Description: "Called before source deployment", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "source.post_deploy", Description: "Called after source deployment completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "source.pre_enable", Description: "Called before a source is enabled", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "source.pre_disable", Description: "Called before a source is disabled", Version: "1.0",
	})

	// ── 归档辅助: 通用持久化 ──
	r.RegisterPoint(ExtensionPoint{
		Name: "persistence.pre_append", Description: "Called before appending to any data file", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "persistence.post_append", Description: "Called after data append succeeds", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "persistence.dashboard_written", Description: "Called after dashboard report is atomically written", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "persistence.record_written", Description: "Called after each assessment record is appended to JSONL", Version: "1.0",
	})

	// ── 扩展管理器生命周期 (extmgr) ──
	r.RegisterPoint(ExtensionPoint{
		Name: "extension.install_failed", Description: "Called when extension install fails", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "extension.enable_failed", Description: "Called when extension enable fails (dependency/validation)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "extension.execution_error", Description: "Called when extension execution returns an error", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "extension.config_changed", Description: "Called when kernel configuration is reloaded — plugins should refresh", Version: "1.0",
	})

	// ── 基础设施扩展点 (breaker, workerpool) ──
	r.RegisterPoint(ExtensionPoint{
		Name: "breaker.state_changed", Description: "Called when circuit breaker changes state (closed→open→half_open)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "workerpool.task_timed_out", Description: "Called when a worker pool task exceeds its timeout", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "ratelimit.limit_exceeded", Description: "Called when a rate limit threshold is exceeded", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "srd.result_processed", Description: "Called after SRD pipeline processes an external tool result", Version: "1.0",
	})

	// ── 黑盒召回层 (可选扩展, 白盒主路径不变) ──
	// 黑盒阵列作为辅助召回层, 仅发布候选信号; 白盒确定性验证兜底.
	// 黑盒输出视为不可信输入, 经白盒复核后才进入决策.
	r.RegisterPoint(ExtensionPoint{
		Name: "recaller.candidates", Description: "Called when black-box recaller array publishes candidate risk signals (untrusted input)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "recaller.filtered", Description: "Called after white-box arbitration retains validated candidate signals", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "recaller.dropped", Description: "Called when all black-box models unanimously drop a signal (audit trail)", Version: "1.0",
	})

	// ── 自动化全链路生命周期 (探测→定位→响应→报告→阻断→修复→验证→定位→归档→重复) ──
	// 定位 (Locate): 攻击者定位聚合
	r.RegisterPoint(ExtensionPoint{
		Name: "locate.completed", Description: "Called when attacker location aggregation completes", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "locate.threat_active", Description: "Called when attacker activity is detected (loop continuation condition)", Version: "1.0",
	})

	// 阻断 (Block): 主动阻断执行
	r.RegisterPoint(ExtensionPoint{
		Name: "block.pre_apply", Description: "Called before a blocking action is executed", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "block.post_apply", Description: "Called after a blocking action is executed", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "block.confirmed", Description: "Called when a blocking action is confirmed effective", Version: "1.0",
	})

	// 生命周期编排 (Lifecycle): 状态机阶段转换 + 循环
	r.RegisterPoint(ExtensionPoint{
		Name: "lifecycle.phase_entered", Description: "Called when the lifecycle state machine enters a phase", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "lifecycle.phase_exited", Description: "Called when the lifecycle state machine exits a phase", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "lifecycle.repeat", Description: "Called when the lifecycle loops back (attacker activity persists)", Version: "1.0",
	})
	r.RegisterPoint(ExtensionPoint{
		Name: "lifecycle.completed", Description: "Called when the full lifecycle chain completes", Version: "1.0",
	})
}
