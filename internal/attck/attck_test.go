//go:build attck_ext

package attck

import (
	"context"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

type mockKernelContext struct{}

func (m *mockKernelContext) Container() *kernel.Container               { return kernel.NewContainer() }
func (m *mockKernelContext) Bus() *kernel.Bus                           { return kernel.NewBus(512) }
func (m *mockKernelContext) Extensions() kernel.ModuleExtensions        { return kernel.NewExtensionRegistry() }
func (m *mockKernelContext) Context() context.Context                   { return context.Background() }
func (m *mockKernelContext) Config() map[string]string                  { return make(map[string]string) }
func (m *mockKernelContext) SetConfig(key, value string)                {}
func (m *mockKernelContext) GetConfigObj() *config.Config               { return nil }
func (m *mockKernelContext) SetConfigObj(c *config.Config)              {}
func (m *mockKernelContext) GetPlugin(name string) (kernel.Plugin, bool) { return nil, false }
func (m *mockKernelContext) ListPlugins() []kernel.PluginInfo           { return nil }
func (m *mockKernelContext) HealthCheck(ctx context.Context) []kernel.PluginHealthStatus {
	return nil
}

func newTestATTACKModule() *Module {
	m := New()
	kc := &mockKernelContext{}
	m.kc = kc
	m.loadDefaultMatrix()
	m.loadDefaultAPTProfiles()
	m.buildTransitionMatrix()
	m.loadDefaultDetectionRules()
	m.loadDefaultThreatActors()
	m.loadDefaultScenarios()
	m.loadDefaultBehavioralIndicators()
	return m
}

func TestATTACKModule_DetectionRuleCRUD(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-TEST-001", Name: "Test Rule", Description: "Test detection rule",
		TechniqueID: "T1110", TacticIDs: []string{"TA0006"}, Severity: "high",
		LogSources: []string{"auth"}, Query: "failed", Enabled: true,
	}

	if err := m.RegisterDetectionRule(rule); err != nil {
		t.Fatalf("RegisterDetectionRule failed: %v", err)
	}

	got := m.GetDetectionRule("DET-TEST-001")
	if got == nil {
		t.Fatal("GetDetectionRule returned nil")
	}
	if got.Name != "Test Rule" {
		t.Errorf("expected Name=Test Rule, got %s", got.Name)
	}

	rules := m.ListDetectionRules("T1110", true)
	if len(rules) == 0 {
		t.Fatal("ListDetectionRules returned empty for T1110")
	}

	if !m.DeleteDetectionRule("DET-TEST-001") {
		t.Fatal("DeleteDetectionRule returned false")
	}

	if m.GetDetectionRule("DET-TEST-001") != nil {
		t.Fatal("rule should be deleted")
	}
}

func TestATTACKModule_DetectionRuleValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.RegisterDetectionRule(DetectionRule{}); err == nil {
		t.Fatal("expected error for empty ID")
	}

	if err := m.RegisterDetectionRule(DetectionRule{ID: "X"}); err == nil {
		t.Fatal("expected error for empty technique ID")
	}
}

func TestATTACKModule_EvaluateDetectionRule(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-EVAL-001", Name: "Eval Rule", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "failed password", Enabled: true,
	}
	m.RegisterDetectionRule(rule)

	alert, err := m.EvaluateDetectionRule("DET-EVAL-001", "host-1", "Failed password for root", nil)
	if err != nil {
		t.Fatalf("EvaluateDetectionRule failed: %v", err)
	}
	if alert == nil {
		t.Fatal("expected alert for matching log")
	}
	if alert.HostID != "host-1" {
		t.Errorf("expected host-1, got %s", alert.HostID)
	}

	alert2, err := m.EvaluateDetectionRule("DET-EVAL-001", "host-1", "normal log entry", nil)
	if err != nil {
		t.Fatalf("EvaluateDetectionRule failed: %v", err)
	}
	if alert2 != nil {
		t.Fatal("expected nil alert for non-matching log")
	}
}

func TestATTACKModule_EvaluateDisabledRule(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-DIS-001", Name: "Disabled Rule", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "test", Enabled: false,
	}
	m.RegisterDetectionRule(rule)

	_, err := m.EvaluateDetectionRule("DET-DIS-001", "host-1", "test log", nil)
	if err == nil {
		t.Fatal("expected error for disabled rule")
	}
}

func TestATTACKModule_Alerts(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-ALERT-001", Name: "Alert Rule", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "critical", Query: "attack", Enabled: true,
	}
	m.RegisterDetectionRule(rule)

	m.EvaluateDetectionRule("DET-ALERT-001", "host-1", "attack detected", nil)
	m.EvaluateDetectionRule("DET-ALERT-001", "host-2", "attack detected again", nil)

	alerts := m.GetAlerts("", "", 0)
	if len(alerts) < 2 {
		t.Fatalf("expected at least 2 alerts, got %d", len(alerts))
	}

	host1Alerts := m.GetAlerts("host-1", "", 0)
	if len(host1Alerts) != 1 {
		t.Fatalf("expected 1 alert for host-1, got %d", len(host1Alerts))
	}

	criticalAlerts := m.GetAlerts("", "critical", 0)
	if len(criticalAlerts) < 1 {
		t.Fatal("expected at least 1 critical alert")
	}

	if !m.AcknowledgeAlert(alerts[0].ID) {
		t.Fatal("AcknowledgeAlert returned false")
	}
}

func TestATTACKModule_Anomaly(t *testing.T) {
	m := newTestATTACKModule()

	event := AnomalyEvent{
		HostID: "host-1", EventType: "process_anomaly",
		Description: "Unusual process detected", TechniqueID: "T1059",
		Score: 0.85, Baseline: 0.1, Deviation: 0.75,
	}
	m.RecordAnomaly(event)

	anomalies := m.GetAnomalies("host-1", 0.5, 10)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Score != 0.85 {
		t.Errorf("expected score 0.85, got %f", anomalies[0].Score)
	}

	anomaliesFiltered := m.GetAnomalies("host-1", 0.9, 10)
	if len(anomaliesFiltered) != 0 {
		t.Fatal("expected 0 anomalies above 0.9 threshold")
	}
}

func TestATTACKModule_Correlation(t *testing.T) {
	m := newTestATTACKModule()

	rule1 := DetectionRule{
		ID: "DET-CORR-001", Name: "Brute Force", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "failed", Enabled: true,
	}
	rule2 := DetectionRule{
		ID: "DET-CORR-002", Name: "Credential Dump", TechniqueID: "T1003",
		TacticIDs: []string{"TA0006"}, Severity: "critical", Query: "procdump", Enabled: true,
	}
	m.RegisterDetectionRule(rule1)
	m.RegisterDetectionRule(rule2)

	m.EvaluateDetectionRule("DET-CORR-001", "host-1", "failed login", nil)
	m.EvaluateDetectionRule("DET-CORR-002", "host-1", "procdump lsass", nil)

	results := m.CorrelateAlerts("host-1")
	if len(results) == 0 {
		t.Fatal("expected correlation results")
	}
}

func TestATTACKModule_DetectionSummary(t *testing.T) {
	m := newTestATTACKModule()

	summary := m.GetDetectionSummary()
	if summary.TotalRules == 0 {
		t.Fatal("expected non-zero total rules")
	}
	if summary.ActiveRules == 0 {
		t.Fatal("expected non-zero active rules")
	}
}

func TestATTACKModule_IOCCRUD(t *testing.T) {
	m := newTestATTACKModule()

	ioc := IOCEntry{
		Type: "ip", Value: "192.168.1.100", Source: "test",
		TechniqueIDs: []string{"T1071"}, Confidence: 0.9,
	}
	if err := m.AddIOC(ioc); err != nil {
		t.Fatalf("AddIOC failed: %v", err)
	}

	iocs := m.GetIOCs("ip", "", 0)
	if len(iocs) == 0 {
		t.Fatal("expected at least 1 IOC")
	}

	searched := m.SearchIOC("192.168.1.100")
	if len(searched) == 0 {
		t.Fatal("SearchIOC returned empty")
	}

	if !m.DeleteIOC(iocs[0].ID) {
		t.Fatal("DeleteIOC returned false")
	}
}

func TestATTACKModule_IOCValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.AddIOC(IOCEntry{}); err == nil {
		t.Fatal("expected error for empty IOC")
	}
}

func TestATTACKModule_IOCExpire(t *testing.T) {
	m := newTestATTACKModule()

	ioc := IOCEntry{
		Type: "domain", Value: "evil.example.com", Source: "test",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	m.AddIOC(ioc)

	expired := m.ExpireIOCs()
	if expired != 1 {
		t.Fatalf("expected 1 expired IOC, got %d", expired)
	}

	remaining := m.GetIOCs("domain", "", 0)
	if len(remaining) != 0 {
		t.Fatal("expected 0 remaining IOCs after expiry")
	}
}

func TestATTACKModule_ThreatActor(t *testing.T) {
	m := newTestATTACKModule()

	actors := m.ListThreatActors()
	if len(actors) == 0 {
		t.Fatal("expected default threat actors")
	}

	actor := m.GetThreatActor("TA-APT29")
	if actor == nil {
		t.Fatal("expected APT29 actor")
	}
	if actor.Country != "Russia" {
		t.Errorf("expected Russia, got %s", actor.Country)
	}

	newActor := ThreatActorProfile{
		ID: "TA-TEST", Name: "TestActor", Country: "Test",
		Motivation: "test", TargetSectors: []string{"test"},
		Techniques: map[string]float64{"T1566": 0.5},
	}
	if err := m.UpsertThreatActor(newActor); err != nil {
		t.Fatalf("UpsertThreatActor failed: %v", err)
	}

	got := m.GetThreatActor("TA-TEST")
	if got == nil {
		t.Fatal("expected to find upserted actor")
	}
}

func TestATTACKModule_TTPTrack(t *testing.T) {
	m := newTestATTACKModule()

	track := TTPTrack{
		TechniqueID: "T1566", TacticID: "TA0001",
		ActorID: "TA-APT29", Description: "Spear phishing observed",
		Evidence: []string{"email_log"}, Confidence: 0.8,
	}
	if err := m.AddTTPTrack(track); err != nil {
		t.Fatalf("AddTTPTrack failed: %v", err)
	}

	tracks := m.GetTTPTracks("TA-APT29", "")
	if len(tracks) == 0 {
		t.Fatal("expected TTP tracks for actor")
	}

	tracksByTech := m.GetTTPTracks("", "T1566")
	if len(tracksByTech) == 0 {
		t.Fatal("expected TTP tracks for technique")
	}
}

func TestATTACKModule_TTPValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.AddTTPTrack(TTPTrack{}); err == nil {
		t.Fatal("expected error for empty technique ID")
	}
}

func TestATTACKModule_EnrichAlert(t *testing.T) {
	m := newTestATTACKModule()

	ioc := IOCEntry{
		Type: "ip", Value: "10.0.0.1", Source: "test",
		TechniqueIDs: []string{"T1071"}, Confidence: 0.8,
	}
	m.AddIOC(ioc)

	rule := DetectionRule{
		ID: "DET-ENRICH-001", Name: "C2 Beacon", TechniqueID: "T1071",
		TacticIDs: []string{"TA0011"}, Severity: "high", Query: "beacon", Enabled: true,
	}
	m.RegisterDetectionRule(rule)

	alert, _ := m.EvaluateDetectionRule("DET-ENRICH-001", "host-1", "beacon detected", nil)
	if alert == nil {
		t.Fatal("expected alert")
	}

	_, enrichment := m.EnrichAlertWithTI(alert.ID)
	if enrichment == nil {
		t.Fatal("expected enrichment data")
	}
	if _, ok := enrichment["related_iocs"]; !ok {
		t.Error("expected related_iocs in enrichment")
	}
}

func TestATTACKModule_TISummary(t *testing.T) {
	m := newTestATTACKModule()

	summary := m.GetTISummary()
	if summary == nil {
		t.Fatal("expected TI summary")
	}
	if summary["attck_version"] != "v19" {
		t.Errorf("expected v19, got %v", summary["attck_version"])
	}
}

func TestATTACKModule_ScenarioCRUD(t *testing.T) {
	m := newTestATTACKModule()

	scenario := EmulationScenario{
		ID: "EMU-TEST-001", Name: "Test Scenario",
		Description: "Test emulation scenario", Objective: "Test objective",
		Phases: []EmulationPhase{
			{
				Order: 1, Name: "Phase 1", TacticID: "TA0001", TechniqueID: "T1566",
				Description: "Initial access", RiskLevel: "high",
				Commands: []EmulationCommand{
					{ID: "cmd-1", Description: "Test cmd", Platform: "linux", Executor: "shell", Command: "echo test", SafeMode: true},
				},
			},
		},
		Difficulty: "basic",
	}

	if err := m.CreateScenario(scenario); err != nil {
		t.Fatalf("CreateScenario failed: %v", err)
	}

	got := m.GetScenario("EMU-TEST-001")
	if got == nil {
		t.Fatal("GetScenario returned nil")
	}
	if got.Name != "Test Scenario" {
		t.Errorf("expected Test Scenario, got %s", got.Name)
	}

	scenarios := m.ListScenarios("")
	if len(scenarios) == 0 {
		t.Fatal("ListScenarios returned empty")
	}

	if !m.DeleteScenario("EMU-TEST-001") {
		t.Fatal("DeleteScenario returned false")
	}
}

func TestATTACKModule_ScenarioValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.CreateScenario(EmulationScenario{}); err == nil {
		t.Fatal("expected error for empty ID")
	}

	if err := m.CreateScenario(EmulationScenario{ID: "X", Name: "X"}); err == nil {
		t.Fatal("expected error for no phases")
	}
}

func TestATTACKModule_GenerateScenarioFromActor(t *testing.T) {
	m := newTestATTACKModule()

	scenario, err := m.GenerateScenarioFromActor("TA-APT29")
	if err != nil {
		t.Fatalf("GenerateScenarioFromActor failed: %v", err)
	}
	if scenario == nil {
		t.Fatal("expected scenario")
	}
	if scenario.ActorProfile != "TA-APT29" {
		t.Errorf("expected TA-APT29, got %s", scenario.ActorProfile)
	}
	if len(scenario.Phases) == 0 {
		t.Fatal("expected at least one phase")
	}
}

func TestATTACKModule_GenerateScenarioFromAPTGroup(t *testing.T) {
	m := newTestATTACKModule()

	scenario, err := m.GenerateScenarioFromActor("G0016")
	if err != nil {
		t.Fatalf("GenerateScenarioFromActor with APT group failed: %v", err)
	}
	if scenario == nil {
		t.Fatal("expected scenario from APT group")
	}
}

func TestATTACKModule_GenerateScenarioInvalidActor(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.GenerateScenarioFromActor("INVALID")
	if err == nil {
		t.Fatal("expected error for invalid actor")
	}
}

func TestATTACKModule_RunEmulation(t *testing.T) {
	m := newTestATTACKModule()

	scenario := EmulationScenario{
		ID: "EMU-RUN-001", Name: "Run Test",
		Phases: []EmulationPhase{
			{
				Order: 1, Name: "Phase 1", TacticID: "TA0001", TechniqueID: "T1566",
				Description: "Test", RiskLevel: "high",
				Commands: []EmulationCommand{
					{ID: "cmd-1", Description: "Test", Platform: "linux", Executor: "shell", Command: "echo test", SafeMode: true},
				},
				ExpectedDetections: []string{"DET-001"},
			},
		},
	}
	m.CreateScenario(scenario)

	result, err := m.RunEmulation("EMU-RUN-001", "host-1", true)
	if err != nil {
		t.Fatalf("RunEmulation failed: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("expected completed, got %s", result.Status)
	}
	if result.TotalTechniques != 1 {
		t.Errorf("expected 1 technique, got %d", result.TotalTechniques)
	}

	results := m.GetEmulationResults("EMU-RUN-001", 10)
	if len(results) == 0 {
		t.Fatal("expected emulation results")
	}
}

func TestATTACKModule_RunEmulationInvalidScenario(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.RunEmulation("INVALID", "host-1", true)
	if err == nil {
		t.Fatal("expected error for invalid scenario")
	}
}

func TestATTACKModule_GapAnalysis(t *testing.T) {
	m := newTestATTACKModule()

	report, err := m.PerformGapAnalysis("host-1")
	if err != nil {
		t.Fatalf("PerformGapAnalysis failed: %v", err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
	if report.TotalTechniques == 0 {
		t.Fatal("expected non-zero total techniques")
	}
	if report.Framework != "MITRE ATT&CK" {
		t.Errorf("expected MITRE ATT&CK, got %s", report.Framework)
	}
	if report.Version != "v19" {
		t.Errorf("expected v19, got %s", report.Version)
	}
	if len(report.ControlMaps) == 0 {
		t.Fatal("expected control mappings")
	}
}

func TestATTACKModule_ControlMapping(t *testing.T) {
	m := newTestATTACKModule()

	mapping := m.GetControlMapping("T1566")
	if mapping == nil {
		t.Fatal("expected control mapping for T1566")
	}
	if mapping.TechniqueID != "T1566" {
		t.Errorf("expected T1566, got %s", mapping.TechniqueID)
	}
	if mapping.CoverageLevel == "" {
		t.Error("expected non-empty coverage level")
	}

	missingMapping := m.GetControlMapping("INVALID")
	if missingMapping != nil {
		t.Fatal("expected nil for invalid technique")
	}
}

func TestATTACKModule_AssessmentReports(t *testing.T) {
	m := newTestATTACKModule()

	m.PerformGapAnalysis("host-1")
	m.PerformGapAnalysis("host-2")

	reports := m.GetAssessmentReports("", 10)
	if len(reports) < 2 {
		t.Fatalf("expected at least 2 reports, got %d", len(reports))
	}

	host1Reports := m.GetAssessmentReports("host-1", 10)
	if len(host1Reports) != 1 {
		t.Fatalf("expected 1 report for host-1, got %d", len(host1Reports))
	}
}

func TestATTACKModule_ImprovementTrack(t *testing.T) {
	m := newTestATTACKModule()

	track := ImprovementTrack{
		ID: "IMP-001", Name: "Improve Detection Coverage",
		Description: "Track to improve detection coverage", BaselineScore: 0.3,
		CurrentScore: 0.3, TargetScore: 0.7,
		Actions: []ImprovementAction{
			{ID: "ACT-001", Description: "Add detection for T1566", TechniqueIDs: []string{"T1566"}, Status: "open"},
			{ID: "ACT-002", Description: "Add detection for T1190", TechniqueIDs: []string{"T1190"}, Status: "open"},
		},
	}

	if err := m.CreateImprovementTrack(track); err != nil {
		t.Fatalf("CreateImprovementTrack failed: %v", err)
	}

	got := m.GetImprovementTrack("IMP-001")
	if got == nil {
		t.Fatal("expected improvement track")
	}

	tracks := m.ListImprovementTracks()
	if len(tracks) == 0 {
		t.Fatal("expected improvement tracks")
	}

	if err := m.UpdateImprovementAction("IMP-001", "ACT-001", "completed"); err != nil {
		t.Fatalf("UpdateImprovementAction failed: %v", err)
	}

	progress, err := m.CalculateImprovementProgress("IMP-001")
	if err != nil {
		t.Fatalf("CalculateImprovementProgress failed: %v", err)
	}
	if progress != 0.5 {
		t.Errorf("expected 0.5 progress, got %f", progress)
	}
}

func TestATTACKModule_ImprovementTrackValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.CreateImprovementTrack(ImprovementTrack{}); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestATTACKModule_ImprovementTrackInvalidAction(t *testing.T) {
	m := newTestATTACKModule()

	track := ImprovementTrack{
		ID: "IMP-VAL", Name: "Test",
		Actions: []ImprovementAction{{ID: "A1", Description: "Test", Status: "open"}},
	}
	m.CreateImprovementTrack(track)

	if err := m.UpdateImprovementAction("IMP-VAL", "INVALID", "completed"); err == nil {
		t.Fatal("expected error for invalid action")
	}

	if err := m.UpdateImprovementAction("INVALID", "A1", "completed"); err == nil {
		t.Fatal("expected error for invalid track")
	}
}

func TestATTACKModule_CalculateImprovementProgressInvalid(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.CalculateImprovementProgress("INVALID")
	if err == nil {
		t.Fatal("expected error for invalid track")
	}
}

func TestATTACKModule_EmptyImprovementProgress(t *testing.T) {
	m := newTestATTACKModule()

	track := ImprovementTrack{ID: "IMP-EMPTY", Name: "Empty"}
	m.CreateImprovementTrack(track)

	progress, err := m.CalculateImprovementProgress("IMP-EMPTY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if progress != 0 {
		t.Errorf("expected 0 progress, got %f", progress)
	}
}

func TestATTACKModule_DefaultDetectionRules(t *testing.T) {
	m := newTestATTACKModule()

	rules := m.ListDetectionRules("", true)
	if len(rules) == 0 {
		t.Fatal("expected default detection rules")
	}

	det001 := m.GetDetectionRule("DET-001")
	if det001 == nil {
		t.Fatal("expected DET-001 default rule")
	}
	if det001.TechniqueID != "T1110" {
		t.Errorf("expected T1110, got %s", det001.TechniqueID)
	}
}

func TestATTACKModule_DefaultScenarios(t *testing.T) {
	m := newTestATTACKModule()

	scenario := m.GetScenario("EMU-DEFAULT-001")
	if scenario == nil {
		t.Fatal("expected default scenario")
	}
	if len(scenario.Phases) == 0 {
		t.Fatal("expected phases in default scenario")
	}
}

func TestATTACKModule_DefaultThreatActors(t *testing.T) {
	m := newTestATTACKModule()

	actors := m.ListThreatActors()
	if len(actors) < 3 {
		t.Fatalf("expected at least 3 default threat actors, got %d", len(actors))
	}
}

func TestATTACKModule_MatchThreatActor(t *testing.T) {
	m := newTestATTACKModule()

	results := m.MatchThreatActor([]string{"T1566", "T1071", "T1003"})
	if len(results) == 0 {
		t.Fatal("expected threat actor matches")
	}
}

func TestATTACKModule_Priority(t *testing.T) {
	m := New()
	if m.Priority() != 21 {
		t.Errorf("expected priority 21, got %d", m.Priority())
	}
}

func TestATTACKModule_Version(t *testing.T) {
	m := New()
	if m.Version() != "v19" {
		t.Errorf("expected v19, got %s", m.Version())
	}
}

func TestATTACKModule_Info(t *testing.T) {
	m := New()
	info := m.Info()
	if info.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", info.Version)
	}
	if info.Name != "attck" {
		t.Errorf("expected name attck, got %s", info.Name)
	}
}

func TestATTACKModule_InitAndLifecycle(t *testing.T) {
	m := New()

	kc := &mockKernelContext{}
	err := m.Init(context.Background(), kc)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if m.State() != kernel.PluginInitialized {
		t.Errorf("expected initialized, got %s", m.State())
	}

	err = m.Start(context.Background())
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if m.State() != kernel.PluginStarted {
		t.Errorf("expected started, got %s", m.State())
	}

	err = m.Stop(context.Background())
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if m.State() != kernel.PluginStopped {
		t.Errorf("expected stopped, got %s", m.State())
	}
}

func TestATTACKModule_BehavioralIndicatorCRUD(t *testing.T) {
	m := newTestATTACKModule()

	indicators := m.ListBehavioralIndicators("")
	if len(indicators) == 0 {
		t.Fatal("expected default behavioral indicators")
	}

	filtered := m.ListBehavioralIndicators("T1110")
	if len(filtered) == 0 {
		t.Fatal("expected indicators for T1110")
	}

	custom := BehavioralIndicator{
		ID: "BI-CUSTOM-001", Name: "Custom Indicator", TechniqueID: "T1059",
		TacticIDs: []string{"TA0002"}, Category: "process", Metric: "custom_metric",
		Operator: "gt", Threshold: 100, Window: 5 * time.Minute, Severity: "high",
		Description: "Custom test indicator", Enabled: true,
	}
	if err := m.RegisterBehavioralIndicator(custom); err != nil {
		t.Fatalf("RegisterBehavioralIndicator failed: %v", err)
	}

	if !m.DeleteBehavioralIndicator("BI-CUSTOM-001") {
		t.Fatal("DeleteBehavioralIndicator returned false")
	}
}

func TestATTACKModule_BehavioralIndicatorValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.RegisterBehavioralIndicator(BehavioralIndicator{ID: "X"}); err == nil {
		t.Fatal("expected error for empty technique ID")
	}

	if err := m.RegisterBehavioralIndicator(BehavioralIndicator{ID: "X", TechniqueID: "T"}); err == nil {
		t.Fatal("expected error for empty metric")
	}

	if err := m.RegisterBehavioralIndicator(BehavioralIndicator{ID: "X", TechniqueID: "T", Metric: "m", Operator: "invalid"}); err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestATTACKModule_Baseline(t *testing.T) {
	m := newTestATTACKModule()

	m.UpdateBaseline("host-1", map[string]float64{"failed_login_count": 5, "process_spawn_rate": 20})

	baseline := m.GetBaseline("host-1")
	if baseline == nil {
		t.Fatal("expected baseline for host-1")
	}
	if baseline.Metrics["failed_login_count"] != 5 {
		t.Errorf("expected 5, got %f", baseline.Metrics["failed_login_count"])
	}

	m.UpdateBaseline("host-1", map[string]float64{"failed_login_count": 15})
	updated := m.GetBaseline("host-1")
	if updated == nil {
		t.Fatal("expected updated baseline")
	}
	if updated.SampleCount != 2 {
		t.Errorf("expected 2 samples, got %d", updated.SampleCount)
	}

	missing := m.GetBaseline("host-999")
	if missing != nil {
		t.Fatal("expected nil for missing host")
	}
}

func TestATTACKModule_EvaluateBehavioralIndicators(t *testing.T) {
	m := newTestATTACKModule()

	m.UpdateBaseline("host-1", map[string]float64{"failed_login_count": 3})

	alerts := m.EvaluateBehavioralIndicators("host-1", map[string]float64{"failed_login_count": 50})
	if len(alerts) == 0 {
		t.Fatal("expected behavioral alerts for high failed login count")
	}

	if alerts[0].TechniqueID != "T1110" {
		t.Errorf("expected T1110, got %s", alerts[0].TechniqueID)
	}

	noAlerts := m.EvaluateBehavioralIndicators("host-1", map[string]float64{"failed_login_count": 2})
	if len(noAlerts) != 0 {
		t.Fatal("expected no alerts for low failed login count")
	}
}

func TestATTACKModule_BehavioralAlerts(t *testing.T) {
	m := newTestATTACKModule()

	m.UpdateBaseline("host-1", map[string]float64{"failed_login_count": 3})
	m.EvaluateBehavioralIndicators("host-1", map[string]float64{"failed_login_count": 50})

	alerts := m.GetBehavioralAlerts("host-1", 10)
	if len(alerts) == 0 {
		t.Fatal("expected behavioral alerts")
	}

	allAlerts := m.GetBehavioralAlerts("", 0)
	if len(allAlerts) == 0 {
		t.Fatal("expected all behavioral alerts")
	}
}

func TestATTACKModule_BeaconDetection(t *testing.T) {
	m := newTestATTACKModule()

	now := time.Now()
	events := make([]TimeSeriesPoint, 20)
	for i := 0; i < 20; i++ {
		events[i] = TimeSeriesPoint{
			Timestamp: now.Add(time.Duration(i*60) * time.Second),
			Value:     1.0,
		}
	}

	detections := m.DetectBeaconing("host-1", events)
	if len(detections) == 0 {
		t.Fatal("expected beacon detection for regular intervals")
	}
	if detections[0].Score < 0.5 {
		t.Errorf("expected high beacon score, got %f", detections[0].Score)
	}

	irregularEvents := make([]TimeSeriesPoint, 20)
	for i := 0; i < 20; i++ {
		irregularEvents[i] = TimeSeriesPoint{
			Timestamp: now.Add(time.Duration(i*i*10) * time.Second),
			Value:     1.0,
		}
	}
	irregularDetections := m.DetectBeaconing("host-2", irregularEvents)
	if len(irregularDetections) > 0 && irregularDetections[0].Score > 0.7 {
		t.Error("expected low score for irregular intervals")
	}
}

func TestATTACKModule_BeaconDetectionInsufficientData(t *testing.T) {
	m := newTestATTACKModule()

	events := []TimeSeriesPoint{
		{Timestamp: time.Now(), Value: 1.0},
		{Timestamp: time.Now().Add(time.Second), Value: 1.0},
	}

	detections := m.DetectBeaconing("host-1", events)
	if len(detections) != 0 {
		t.Fatal("expected no beacon detection for insufficient data")
	}
}

func TestATTACKModule_AttackChainReconstruction(t *testing.T) {
	m := newTestATTACKModule()

	rule1 := DetectionRule{
		ID: "DET-CHAIN-001", Name: "Brute Force", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "failed", Enabled: true,
	}
	rule2 := DetectionRule{
		ID: "DET-CHAIN-002", Name: "Credential Dump", TechniqueID: "T1003",
		TacticIDs: []string{"TA0006"}, Severity: "critical", Query: "procdump", Enabled: true,
	}
	rule3 := DetectionRule{
		ID: "DET-CHAIN-003", Name: "Lateral Movement", TechniqueID: "T1021",
		TacticIDs: []string{"TA0008"}, Severity: "high", Query: "ssh", Enabled: true,
	}
	m.RegisterDetectionRule(rule1)
	m.RegisterDetectionRule(rule2)
	m.RegisterDetectionRule(rule3)

	m.EvaluateDetectionRule("DET-CHAIN-001", "host-1", "failed login", nil)
	m.EvaluateDetectionRule("DET-CHAIN-002", "host-1", "procdump lsass", nil)
	m.EvaluateDetectionRule("DET-CHAIN-003", "host-1", "ssh lateral", nil)

	chain, err := m.ReconstructAttackChain([]string{"host-1"})
	if err != nil {
		t.Fatalf("ReconstructAttackChain failed: %v", err)
	}
	if chain == nil {
		t.Fatal("expected attack chain")
	}
	if len(chain.Stages) == 0 {
		t.Fatal("expected at least one stage")
	}
	if chain.Severity == "" {
		t.Error("expected non-empty severity")
	}
	if chain.Status != "active" {
		t.Errorf("expected active status, got %s", chain.Status)
	}

	chains := m.GetAttackChains("host-1", 10)
	if len(chains) == 0 {
		t.Fatal("expected stored attack chains")
	}
}

func TestATTACKModule_AttackChainEmptyHosts(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.ReconstructAttackChain([]string{})
	if err == nil {
		t.Fatal("expected error for empty host IDs")
	}
}

func TestATTACKModule_AttackChainNoEvidence(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.ReconstructAttackChain([]string{"host-unknown"})
	if err == nil {
		t.Fatal("expected error for no evidence")
	}
}

func TestATTACKModule_MultiIndicatorCorrelation(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-MIC-001", Name: "C2 Traffic", TechniqueID: "T1071",
		TacticIDs: []string{"TA0011"}, Severity: "high", Query: "beacon", Enabled: true,
	}
	m.RegisterDetectionRule(rule)
	m.EvaluateDetectionRule("DET-MIC-001", "host-1", "beacon detected", nil)

	m.RecordAnomaly(AnomalyEvent{
		HostID: "host-1", EventType: "network_anomaly", Description: "Unusual traffic",
		TechniqueID: "T1071", Score: 0.8, Baseline: 0.1, Deviation: 0.7,
	})

	m.AddIOC(IOCEntry{
		Type: "ip", Value: "10.0.0.1", Source: "test",
		TechniqueIDs: []string{"T1071"}, Confidence: 0.9,
	})

	correlations := m.CorrelateMultiIndicator([]string{"host-1"})
	if len(correlations) == 0 {
		t.Fatal("expected multi-indicator correlations")
	}
}

func TestATTACKModule_Attribution(t *testing.T) {
	m := newTestATTACKModule()

	rule1 := DetectionRule{
		ID: "DET-ATTR-001", Name: "Spear Phish", TechniqueID: "T1566",
		TacticIDs: []string{"TA0001"}, Severity: "high", Query: "phish", Enabled: true,
	}
	rule2 := DetectionRule{
		ID: "DET-ATTR-002", Name: "C2 Channel", TechniqueID: "T1071",
		TacticIDs: []string{"TA0011"}, Severity: "high", Query: "c2", Enabled: true,
	}
	rule3 := DetectionRule{
		ID: "DET-ATTR-003", Name: "Credential Dump", TechniqueID: "T1003",
		TacticIDs: []string{"TA0006"}, Severity: "critical", Query: "procdump", Enabled: true,
	}
	m.RegisterDetectionRule(rule1)
	m.RegisterDetectionRule(rule2)
	m.RegisterDetectionRule(rule3)

	m.EvaluateDetectionRule("DET-ATTR-001", "host-1", "phish email", nil)
	m.EvaluateDetectionRule("DET-ATTR-002", "host-1", "c2 traffic", nil)
	m.EvaluateDetectionRule("DET-ATTR-003", "host-1", "procdump lsass", nil)

	chain, err := m.ReconstructAttackChain([]string{"host-1"})
	if err != nil {
		t.Fatalf("ReconstructAttackChain failed: %v", err)
	}

	attribution, err := m.PerformAttribution(chain.ID)
	if err != nil {
		t.Fatalf("PerformAttribution failed: %v", err)
	}
	if attribution == nil {
		t.Fatal("expected attribution result")
	}
	if attribution.Methodology != "multi_source_fusion" {
		t.Errorf("expected multi_source_fusion, got %s", attribution.Methodology)
	}
}

func TestATTACKModule_AttributionInvalidChain(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.PerformAttribution("invalid-chain-id")
	if err == nil {
		t.Fatal("expected error for invalid chain ID")
	}
}

func TestATTACKModule_APTAnalysisReport(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-REPORT-001", Name: "Brute Force", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "failed", Enabled: true,
	}
	m.RegisterDetectionRule(rule)
	m.EvaluateDetectionRule("DET-REPORT-001", "host-1", "failed login", nil)

	m.UpdateBaseline("host-1", map[string]float64{"failed_login_count": 3})
	m.EvaluateBehavioralIndicators("host-1", map[string]float64{"failed_login_count": 50})

	report, err := m.GenerateAPTAnalysisReport([]string{"host-1"})
	if err != nil {
		t.Fatalf("GenerateAPTAnalysisReport failed: %v", err)
	}
	if report == nil {
		t.Fatal("expected APT analysis report")
	}
	if report.RiskLevel == "" {
		t.Error("expected non-empty risk level")
	}
	if report.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestATTACKModule_APTAnalysisReportEmptyHosts(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.GenerateAPTAnalysisReport([]string{})
	if err == nil {
		t.Fatal("expected error for empty host IDs")
	}
}

func TestATTACKModule_HuntHypothesisCRUD(t *testing.T) {
	m := newTestATTACKModule()

	hypothesis := HuntHypothesis{
		ID: "HUNT-001", Name: "Test Hunt", Description: "Test hypothesis",
		TechniqueID: "T1071", TacticIDs: []string{"TA0011"},
		DataSource: "network", Query: "c2_traffic", Priority: "high",
	}

	if err := m.CreateHuntHypothesis(hypothesis); err != nil {
		t.Fatalf("CreateHuntHypothesis failed: %v", err)
	}

	got := m.GetHuntHypothesis("HUNT-001")
	if got == nil {
		t.Fatal("expected hunt hypothesis")
	}

	hypotheses := m.ListHuntHypotheses("", "active")
	if len(hypotheses) == 0 {
		t.Fatal("expected active hypotheses")
	}

	if !m.DeleteHuntHypothesis("HUNT-001") {
		t.Fatal("DeleteHuntHypothesis returned false")
	}
}

func TestATTACKModule_HuntHypothesisValidation(t *testing.T) {
	m := newTestATTACKModule()

	if err := m.CreateHuntHypothesis(HuntHypothesis{}); err == nil {
		t.Fatal("expected error for empty ID")
	}

	if err := m.CreateHuntHypothesis(HuntHypothesis{ID: "X"}); err == nil {
		t.Fatal("expected error for empty name")
	}

	if err := m.CreateHuntHypothesis(HuntHypothesis{ID: "X", Name: "X"}); err == nil {
		t.Fatal("expected error for empty technique ID")
	}
}

func TestATTACKModule_ExecuteHunt(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-HUNT-001", Name: "C2 Traffic", TechniqueID: "T1071",
		TacticIDs: []string{"TA0011"}, Severity: "high", Query: "beacon", Enabled: true,
	}
	m.RegisterDetectionRule(rule)
	m.EvaluateDetectionRule("DET-HUNT-001", "host-1", "beacon detected", nil)

	hypothesis := HuntHypothesis{
		ID: "HUNT-EXEC-001", Name: "Find C2", Description: "Hunt for C2 activity",
		TechniqueID: "T1071", TacticIDs: []string{"TA0011"},
		DataSource: "network", Query: "c2_traffic", Priority: "high",
	}
	m.CreateHuntHypothesis(hypothesis)

	result, err := m.ExecuteHunt("HUNT-EXEC-001", "host-1")
	if err != nil {
		t.Fatalf("ExecuteHunt failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected hunt result")
	}
	if !result.Confirmed {
		t.Error("expected confirmed hunt result")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected hunt findings")
	}

	results := m.GetHuntResults("host-1", 10)
	if len(results) == 0 {
		t.Fatal("expected stored hunt results")
	}
}

func TestATTACKModule_ExecuteHuntInvalidHypothesis(t *testing.T) {
	m := newTestATTACKModule()

	_, err := m.ExecuteHunt("INVALID", "host-1")
	if err == nil {
		t.Fatal("expected error for invalid hypothesis")
	}
}

func TestATTACKModule_AutoGenerateHypotheses(t *testing.T) {
	m := newTestATTACKModule()

	rule := DetectionRule{
		ID: "DET-AUTO-001", Name: "Brute Force", TechniqueID: "T1110",
		TacticIDs: []string{"TA0006"}, Severity: "high", Query: "failed", Enabled: true,
	}
	m.RegisterDetectionRule(rule)
	m.EvaluateDetectionRule("DET-AUTO-001", "host-1", "failed login", nil)

	hypotheses, err := m.AutoGenerateHypotheses("host-1")
	if err != nil {
		t.Fatalf("AutoGenerateHypotheses failed: %v", err)
	}

	_ = hypotheses
}

func TestATTACKModule_DefaultBehavioralIndicators(t *testing.T) {
	m := newTestATTACKModule()

	indicators := m.ListBehavioralIndicators("")
	if len(indicators) < 5 {
		t.Fatalf("expected at least 5 default behavioral indicators, got %d", len(indicators))
	}

	bi001 := m.ListBehavioralIndicators("T1110")
	if len(bi001) == 0 {
		t.Fatal("expected BI-001 indicator for T1110")
	}
}
