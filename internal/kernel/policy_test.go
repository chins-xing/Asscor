package kernel

import (
	"testing"

	"github.com/asscor/asscor/internal/config"
)

func TestHostStatusString(t *testing.T) {
	tests := []struct {
		status HostStatus
		want   string
	}{
		{HostOK, "OK"},
		{HostWarning, "Warning"},
		{HostCritical, "Critical"},
		{HostIsolated, "Isolated"},
		{HostStatus(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("HostStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestPolicyEvaluateOK(t *testing.T) {
	m := &PolicyModule{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]HostStatus),
	}

	status, actions := m.EvaluateHost("host-01", 85.0)

	if status != HostOK {
		t.Errorf("expected HostOK, got %s", status)
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for OK, got %d", len(actions))
	}
}

func TestPolicyEvaluateWarning(t *testing.T) {
	m := &PolicyModule{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]HostStatus),
	}

	status, actions := m.EvaluateHost("host-02", 75.0)

	if status != HostWarning {
		t.Errorf("expected HostWarning, got %s", status)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Action != "notify_admin" {
		t.Errorf("expected notify_admin action, got %s", actions[0].Action)
	}
}

func TestPolicyEvaluateCritical(t *testing.T) {
	m := &PolicyModule{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]HostStatus),
	}

	status, actions := m.EvaluateHost("host-03", 55.0)

	if status != HostCritical {
		t.Errorf("expected HostCritical, got %s", status)
	}
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 actions, got %d", len(actions))
	}
	hasIncrease := false
	for _, a := range actions {
		if a.Action == "increase_assessment" {
			hasIncrease = true
		}
	}
	if !hasIncrease {
		t.Error("expected increase_assessment action for critical")
	}
}

func TestPolicyEvaluateIsolated(t *testing.T) {
	m := &PolicyModule{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]HostStatus),
	}

	status, actions := m.EvaluateHost("host-04", 30.0)

	if status != HostIsolated {
		t.Errorf("expected HostIsolated, got %s", status)
	}
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 actions for isolated, got %d", len(actions))
	}
	hasIsolate := false
	for _, a := range actions {
		if a.Action == "isolate_host" {
			hasIsolate = true
		}
	}
	if !hasIsolate {
		t.Error("expected isolate_host action")
	}
}

func TestPolicyThresholdBoundary(t *testing.T) {
	m := &PolicyModule{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]HostStatus),
	}

	if s, _ := m.EvaluateHost("h", 80.0); s != HostOK {
		t.Errorf("score=80 (==threshold) should be OK, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 79.0); s != HostWarning {
		t.Errorf("score=79 should be Warning, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 70.0); s != HostWarning {
		t.Errorf("score=70 should be Warning (threshold-10 inclusive), got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 69.0); s != HostCritical {
		t.Errorf("score=69 should be Critical, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 49.0); s != HostIsolated {
		t.Errorf("score=49 should be Isolated, got %s", s)
	}
}
