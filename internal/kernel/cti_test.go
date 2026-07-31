package kernel

import (
	"testing"
)

func TestCTIGetCoefficient(t *testing.T) {
	m := &CTIModule{coefficient: 1.0}

	if got := m.GetCoefficient(); got != 1.0 {
		t.Errorf("GetCoefficient() = %.2f, want 1.0", got)
	}
}

func TestCTIReportAndClearThreat(t *testing.T) {
	m := &CTIModule{coefficient: 1.0, activeThreats: 0}

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
	m := &CTIModule{coefficient: 1.0}

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
	m := &CTIModule{coefficient: 1.0, activeThreats: 0}

	m.ClearThreat()
	if m.activeThreats != 0 {
		t.Errorf("ClearThreat at 0 should stay 0, got %d", m.activeThreats)
	}
}
