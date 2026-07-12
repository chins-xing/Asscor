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
		Name: "assessor.post_evaluate", Description: "Called after each host assessment completes", Version: "1.0",
	})
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
}
