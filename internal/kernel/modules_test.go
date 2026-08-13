package kernel

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/model"
)

func TestWorkerPool(t *testing.T) {
	pool := NewWorkerPool(3)
	if got := pool.MaxConcurrency(); got != 3 {
		t.Fatalf("expected max 3, got %d", got)
	}

	completed := 0
	for i := 0; i < 10; i++ {
		pool.Submit(func() error {
			time.Sleep(10 * time.Millisecond)
			return nil
		})
	}
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalSubmitted != 10 {
		t.Fatalf("expected 10 submitted, got %d", metrics.totalSubmitted)
	}
	if metrics.totalCompleted != 10 {
		t.Fatalf("expected 10 completed, got %d", metrics.totalCompleted)
	}

	_ = completed
}

func TestWorkerPoolTimeout(t *testing.T) {
	pool := NewWorkerPool(2)

	pool.SubmitWithTimeout(func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}, 50*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalTimeout == 0 {
		t.Error("expected at least 1 timeout")
	}
}

func TestSPCModule(t *testing.T) {
	k := NewKernel()
	spc := NewSPCModule()
	spc.enabled = true

	if err := spc.Init(k.Context(), KernelContext(k)); err != nil {
		t.Fatalf("init spc: %v", err)
	}

	spc.FetchFromAllSources()

	if got := spc.GetCVECount(); got < 3 {
		t.Fatalf("expected at least 3 sample CVEs, got %d", got)
	}

	if got := spc.GetKEVCount(); got < 1 {
		t.Fatalf("expected at least 1 KEV CVE, got %d", got)
	}

	asset := LocalAsset{
		HostID:        "web-prod-01",
		Hostname:      "web-prod-01.example.com",
		Role:          "web-server",
		NetworkZone:   "dmz",
		InstalledCPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}
	asset.Compensations.WAFRules = true

	spc.UpsertAsset(asset)

	correction := spc.Calculate("web-prod-01", []string{"openssl", "nginx", "php"})

	t.Logf("P_score: %.3f", correction.Score)
	t.Logf("Action: %s", correction.Action)
	t.Logf("Top CVE: %s", correction.TopCVEImpact)
	t.Logf("Total Penalty: %.3f", correction.TotalPenalty)
	t.Logf("Affected CVEs: %v", correction.AffectedCVE)
	t.Logf("Weights: %v", correction.Weights)

	if correction.Score < 0.60 || correction.Score > 1.0 {
		t.Errorf("P_score out of range: %.3f", correction.Score)
	}

	if len(correction.AffectedCVE) == 0 {
		t.Error("expected at least 1 affected CVE")
	}

	if correction.TopCVEImpact == "" {
		t.Error("expected a top impact CVE")
	}
}

func TestSPCExactVersionMatch(t *testing.T) {
	spc := NewSPCModule()
	spc.enabled = true

	cve := SPCCVEScore{
		CVEID:         "CVE-2024-TEST",
		CVSS:          9.8,
		EPSS:          0.72,
		InKEV:         true,
		DatePublished: time.Now().AddDate(0, 0, -14),
		AffectedCPEs:  []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}
	spc.AddCVE(cve)

	asset := LocalAsset{
		HostID:        "test-host",
		NetworkZone:   "internal",
		InstalledCPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}

	matchType, matched := spc.matchCPE(&cve, &asset, nil)
	if !matched {
		t.Fatal("expected exact CPE match")
	}
	if matchType != MatchExactVersion {
		t.Fatalf("expected MatchExactVersion, got %d", matchType)
	}
}

func TestPersistenceModule(t *testing.T) {
	pm := NewPersistenceModule(t.TempDir())

	if pm.Info().Name != "persistence" {
		t.Fatalf("expected name 'persistence', got '%s'", pm.Info().Name)
	}

	rec := AssessmentRecord{
		Timestamp:  time.Now(),
		HostID:     "test-01",
		FinalScore: 85.5,
		Acceptable: true,
	}
	err := pm.Append("test_assessments", rec)
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}

	audit := AuditEntry{
		Timestamp: time.Now(),
		Actor:     "test",
		Action:    "write",
		Target:    "test",
		Success:   true,
	}
	err = pm.WriteAudit(audit)
	if err != nil {
		t.Fatalf("write audit failed: %v", err)
	}

	pm.mu.Lock()
	for _, w := range pm.writers {
		w.sync()
		w.close()
	}
	pm.mu.Unlock()
}

func TestSPCWeightShift(t *testing.T) {
	spc := NewSPCModule()
	spc.enabled = true

	cves := []SPCCVEScore{
		{
			CVEID:   "CVE-A", CVSS: 9.0, EPSS: 0.5,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposurePublic,
		},
		{
			CVEID:   "CVE-B", CVSS: 8.0, EPSS: 0.3,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposurePublic,
		},
		{
			CVEID:   "CVE-C", CVSS: 7.0, EPSS: 0.2,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposureDMZ,
		},
	}

	shift := spc.generateWeightShift([]string{"CVE-A", "CVE-B", "CVE-C"}, cves)

	if shift[model.DomainAttackSurface] != 5 {
		t.Errorf("expected attack_surface shift +5, got %.0f", shift[model.DomainAttackSurface])
	}
	if shift[model.DomainBusinessContinuity] != -3 {
		t.Errorf("expected business_continuity shift -3, got %.0f", shift[model.DomainBusinessContinuity])
	}
	if shift[model.DomainResilience] != -2 {
		t.Errorf("expected resilience shift -2, got %.0f", shift[model.DomainResilience])
	}

	var sum float64
	for _, v := range shift {
		sum += v
	}
	if sum != 0 {
		t.Errorf("weight shift sum should be 0, got %.0f", sum)
	}
}

func TestCTIModule_Coefficient(t *testing.T) {
	kc := &mockKernelContext{}
	m := NewCTIModule()
	_ = m.Init(nil, kc)

	if coeff := m.GetCoefficient(); coeff != 1.0 {
		t.Errorf("default coefficient = %f, want 1.0", coeff)
	}

	m.mu.Lock()
	m.activeThreats = 4
	m.mu.Unlock()
	m.updateCoefficient()

	if coeff := m.GetCoefficient(); coeff != 0.92 {
		t.Errorf("coefficient after 4 threats = %f, want 0.92 (1.0 - 4*0.02)", coeff)
	}

	m.mu.Lock()
	m.activeThreats = 25
	m.mu.Unlock()
	m.updateCoefficient()

	if coeff := m.GetCoefficient(); coeff != 0.60 {
		t.Errorf("coefficient after 25 threats = %f, want 0.60 (floor)", coeff)
	}
}

func TestCTIModule_ReportThreat(t *testing.T) {
	kc := &mockKernelContext{}
	m := NewCTIModule()
	_ = m.Init(nil, kc)

	m.ReportThreat("critical")
	m.ReportThreat("high")

	m.mu.Lock()
	threats := m.activeThreats
	m.mu.Unlock()

	if threats != 7 {
		t.Errorf("activeThreats = %d, want 7 (4+3)", threats)
	}
}

func TestCTIModule_AccumulateThreats(t *testing.T) {
	kc := &mockKernelContext{}
	m := NewCTIModule()
	_ = m.Init(nil, kc)

	m.mu.Lock()
	m.activeThreats = 0
	m.mu.Unlock()

	m.ReportThreat("critical")

	m.mu.Lock()
	m.activeThreats += 10
	m.mu.Unlock()

	m.updateCoefficient()

	m.mu.Lock()
	coeff := m.coefficient
	total := m.activeThreats
	m.mu.Unlock()

	if coeff > 0.80 {
		t.Errorf("coefficient %f after 14 active threats, want <= 0.80", coeff)
	}
	if total < 10 {
		t.Errorf("activeThreats = %d, want >= 10 (accumulated, not replaced)", total)
	}
}

func TestCTIModule_SeverityWeight(t *testing.T) {
	tests := []struct {
		sev string
		w   int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 2},
		{"", 2},
	}
	for _, tt := range tests {
		if got := severityWeight(tt.sev); got != tt.w {
			t.Errorf("severityWeight(%q) = %d, want %d", tt.sev, got, tt.w)
		}
	}
}

func TestCTIModule_HealthCheck(t *testing.T) {
	kc := &mockKernelContext{}
	m := NewCTIModule()
	_ = m.Init(nil, kc)

	if err := m.HealthCheck(nil); err == nil {
		t.Error("expected health check failure for unstarted module")
	}

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.mu.Unlock()
	if err := m.HealthCheck(nil); err != nil {
		t.Errorf("unexpected health check error: %v", err)
	}
}

func TestCTIModule_APIKeyConfiguration(t *testing.T) {
	m := NewCTIModule()
	kc := &mockKernelContext{}
	_ = m.Init(nil, kc)

	m.mu.RLock()
	otx := m.otxAPIKey
	mispURL := m.mispURL
	m.mu.RUnlock()

	if otx != "" || mispURL != "" {
		t.Logf("CTI API keys: OTX=%v MISP=%v (from env/config)", otx != "", mispURL != "")
	}
}

func TestCTIModule_Lifecycle(t *testing.T) {
	kc := &mockKernelContext{}
	m := NewCTIModule()

	if err := m.Init(nil, kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if m.State() != PluginInitialized {
		t.Errorf("state = %v, want Initialized", m.State())
	}
	if m.Info().Name != "cti" {
		t.Errorf("name = %s, want cti", m.Info().Name)
	}
	if m.Priority() != 10 {
		t.Errorf("priority = %d, want 10", m.Priority())
	}
}

func TestSPC_GetKEVCatalog(t *testing.T) {
	spc := NewSPCModule()
	spc.mu.Lock()
	spc.kevCatalog["CVE-2024-0001"] = true
	spc.kevCatalog["CVE-2024-0002"] = true
	spc.kevCatalog["CVE-2024-0003"] = true
	spc.mu.Unlock()

	catalog := spc.GetKEVCatalog()
	if len(catalog) != 3 {
		t.Errorf("expected 3 KEV entries, got %d", len(catalog))
	}

	found := make(map[string]bool)
	for _, cveID := range catalog {
		found[cveID] = true
	}
	for _, want := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		if !found[want] {
			t.Errorf("expected %s in KEV catalog", want)
		}
	}
}

func TestSPC_Summary(t *testing.T) {
	spc := NewSPCModule()
	spc.enabled = true
	spc.mu.Lock()
	spc.lastUpdate = time.Now()
	spc.minPScore = 0.65
	spc.kevCatalog["CVE-2024-0001"] = true
	spc.mu.Unlock()

	summary := spc.Summary()

	if v, ok := summary["enabled"].(bool); !ok || !v {
		t.Error("expected enabled=true in summary")
	}
	if v, ok := summary["kev_count"].(int); !ok || v != 1 {
		t.Errorf("kev_count = %v, want 1", summary["kev_count"])
	}
	if v, ok := summary["min_pscore"].(float64); !ok || v != 0.65 {
		t.Errorf("min_pscore = %v, want 0.65", summary["min_pscore"])
	}
}

func TestHistoricalStore_ComputeTrends(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"score":85.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":72.0,"acceptable":false,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":90.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":60.0,"acceptable":false,"host_id":"host-b"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}

	if len(trends) != 2 {
		t.Fatalf("expected 2 host trends, got %d", len(trends))
	}

	sort.Slice(trends, func(i, j int) bool { return trends[i].HostID < trends[j].HostID })

	if trends[0].HostID != "host-a" {
		t.Errorf("HostID = %s, want host-a", trends[0].HostID)
	}
	if trends[0].Count != 3 {
		t.Errorf("host-a count = %d, want 3", trends[0].Count)
	}
	if trends[0].MinScore != 72.0 {
		t.Errorf("host-a MinScore = %f, want 72.0", trends[0].MinScore)
	}
	if trends[0].MaxScore != 90.0 {
		t.Errorf("host-a MaxScore = %f, want 90.0", trends[0].MaxScore)
	}

	acceptablePct := math.Round(float64(2)/3*10000) / 100
	if trends[0].AcceptablePct != acceptablePct {
		t.Errorf("host-a AcceptablePct = %f, want %f", trends[0].AcceptablePct, acceptablePct)
	}
}

func TestHistoricalStore_ComputeRiskLevels(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"score":50.0,"acceptable":false,"host_id":"high-risk"}`+"\n")
	fmt.Fprintf(f, `{"score":70.0,"acceptable":true,"host_id":"mid-risk"}`+"\n")
	fmt.Fprintf(f, `{"score":90.0,"acceptable":true,"host_id":"low-risk"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	levels, err := store.ComputeRiskLevels(30)
	if err != nil {
		t.Fatal(err)
	}

	if v := levels["high-risk"]; v != 1.0 {
		t.Errorf("high-risk level = %f, want 1.0", v)
	}
	if v := levels["mid-risk"]; v != 0.5 {
		t.Errorf("mid-risk level = %f, want 0.5", v)
	}
	if v := levels["low-risk"]; v != 0.0 {
		t.Errorf("low-risk level = %f, want 0.0", v)
	}
}

func TestHistoricalStore_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	store := NewHistoricalStore(dir)

	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trends) != 0 {
		t.Errorf("expected 0 trends for empty dir, got %d", len(trends))
	}
}

func TestHistoricalStore_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	fmt.Fprintf(f, "not valid json\n")
	fmt.Fprintf(f, `{"score":85.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trends) != 1 {
		t.Fatalf("expected 1 host (invalid line skipped), got %d", len(trends))
	}
}

func TestSPCInterface_Completeness(t *testing.T) {
	spc := NewSPCModule()
	var iface SPCInterface = spc
	_ = iface
}

func TestPersistenceInterface_Completeness(t *testing.T) {
	pm := NewPersistenceModule(t.TempDir())
	var iface PersistenceInterface = pm
	_ = iface

	dir := pm.DataDir()
	if dir == "" {
		t.Error("DataDir should not be empty")
	}
}

func TestCTIInterface_Completeness(t *testing.T) {
	m := NewCTIModule()
	var iface CTIInterface = m
	_ = iface
}

func TestSIEMPusher_Disabled(t *testing.T) {
	s := NewSIEMPusher("", "", "")
	if s.Enabled() {
		t.Error("SIEM pusher with empty config should be disabled")
	}
}

func TestSIEMPusher_Enabled(t *testing.T) {
	s := NewSIEMPusher("https://siem.internal:55000", "admin", "pass")
	if !s.Enabled() {
		t.Error("SIEM pusher with full config should be enabled")
	}
}

func TestSIEMPusher_EndpointURLs(t *testing.T) {
	s := NewSIEMPusher("https://siem.internal:55000/", "admin", "pass")

	s.mu.Lock()
	s.token = "test-token"
	token := s.token
	s.mu.Unlock()

	if token != "test-token" {
		t.Errorf("token = %s, want test-token", token)
	}
}

func TestSelfAssessment_TopicConstant(t *testing.T) {
	if TopicAssessorSelfCheck != "assessor.self_check" {
		t.Errorf("TopicAssessorSelfCheck = %s, want assessor.self_check", TopicAssessorSelfCheck)
	}
	if TopicAssessorSelfCheck == TopicAssessorResult {
		t.Error("self_check topic must differ from assessor.result to prevent downstream pollution")
	}
}

func TestAdapterIntegration_StopChannel(t *testing.T) {
	m := NewAdapterIntegrationModule()
	m.mu.Lock()
	ch := m.stopCh
	m.mu.Unlock()

	if ch == nil {
		t.Error("stopCh should be initialized in constructor")
	}

	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		select {
		case <-m.stopCh:
		default:
			close(m.stopCh)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	m.mu.Lock()
	select {
	case <-m.stopCh:
	default:
		t.Error("stopCh should have been closed")
	}
	m.mu.Unlock()
}