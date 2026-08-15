//go:build cti

package cti

import (
	"context"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

type mockKC struct{}

func (m *mockKC) Container() *kernel.Container                { return kernel.NewContainer() }
func (m *mockKC) Bus() *kernel.Bus                            { return kernel.NewBus(512) }
func (m *mockKC) Extensions() kernel.ModuleExtensions         { return kernel.NewExtensionRegistry() }
func (m *mockKC) Context() context.Context                    { return context.Background() }
func (m *mockKC) Config() map[string]string                   { return make(map[string]string) }
func (m *mockKC) SetConfig(key, value string)                 {}
func (m *mockKC) GetConfigObj() *config.Config                { return nil }
func (m *mockKC) SetConfigObj(c *config.Config)               {}
func (m *mockKC) GetPlugin(name string) (kernel.Plugin, bool) { return nil, false }
func (m *mockKC) ListPlugins() []kernel.PluginInfo            { return nil }
func (m *mockKC) HealthCheck(ctx context.Context) []kernel.PluginHealthStatus {
	return nil
}

func TestCTIGetCoefficient(t *testing.T) {
	m := &Module{coefficient: 1.0}

	if got := m.GetCoefficient(); got != 1.0 {
		t.Errorf("GetCoefficient() = %.2f, want 1.0", got)
	}
}

func TestCTIReportAndClearThreat(t *testing.T) {
	m := &Module{coefficient: 1.0, activeThreats: 0}

	m.ReportThreat("critical")
	if m.activeThreats != 4 {
		t.Errorf("activeThreats = %d, want 4 (critical=weight 4)", m.activeThreats)
	}

	m.ReportThreat("high")
	if m.activeThreats != 7 {
		t.Errorf("activeThreats = %d, want 7 (high=weight 3)", m.activeThreats)
	}

	m.ClearThreat()
	if m.activeThreats != 6 {
		t.Errorf("activeThreats = %d, want 6 after clear", m.activeThreats)
	}

	for i := 0; i < 6; i++ {
		m.ClearThreat()
	}
	if m.activeThreats != 0 {
		t.Errorf("activeThreats = %d, want 0 after clears", m.activeThreats)
	}
}

func TestCTIUpdateCoefficient(t *testing.T) {
	m := &Module{coefficient: 1.0}

	m.activeThreats = 0
	m.updateCoefficient()
	if m.coefficient != 1.0 {
		t.Errorf("coeff with 0 threats = %.2f, want 1.0", m.coefficient)
	}

	m.activeThreats = 5
	m.updateCoefficient()
	if m.coefficient > 1.0 || m.coefficient < 0.60 {
		t.Errorf("coeff = %.2f, expected between 0.60 and 1.0", m.coefficient)
	}

	m.activeThreats = 50
	m.updateCoefficient()
	if m.coefficient != 0.60 {
		t.Errorf("coeff with 50 threats = %.2f, want 0.60 (floor)", m.coefficient)
	}
}

func TestCTIClearThreatAtZero(t *testing.T) {
	m := &Module{coefficient: 1.0, activeThreats: 0}

	m.ClearThreat()
	if m.activeThreats != 0 {
		t.Errorf("ClearThreat at 0 should stay 0, got %d", m.activeThreats)
	}
}

func TestCTIModule_Coefficient(t *testing.T) {
	kc := &mockKC{}
	m := New()
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
	kc := &mockKC{}
	m := New()
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
	kc := &mockKC{}
	m := New()
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
	kc := &mockKC{}
	m := New()
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
	m := New()
	kc := &mockKC{}
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
	kc := &mockKC{}
	m := New()

	if err := m.Init(nil, kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if m.State() != kernel.PluginInitialized {
		t.Errorf("state = %v, want Initialized", m.State())
	}
	if m.Info().Name != "cti" {
		t.Errorf("name = %s, want cti", m.Info().Name)
	}
	if m.Priority() != 10 {
		t.Errorf("priority = %d, want 10", m.Priority())
	}
}

func TestCTIInterface_Completeness(t *testing.T) {
	m := New()
	var iface kernel.CTIInterface = m
	_ = iface
}
