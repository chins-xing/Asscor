//go:build policy

package policy

import (
	"testing"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

func TestPolicyEvaluateOK(t *testing.T) {
	m := &Module{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]kernel.HostStatus),
	}

	status, actions := m.EvaluateHost("host-01", 85.0)

	if status != kernel.HostOK {
		t.Errorf("expected HostOK, got %s", status)
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for OK, got %d", len(actions))
	}
}

func TestPolicyEvaluateWarning(t *testing.T) {
	m := &Module{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]kernel.HostStatus),
	}

	status, actions := m.EvaluateHost("host-02", 75.0)

	if status != kernel.HostWarning {
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
	m := &Module{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]kernel.HostStatus),
	}

	status, actions := m.EvaluateHost("host-03", 55.0)

	if status != kernel.HostCritical {
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
	m := &Module{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]kernel.HostStatus),
	}

	status, actions := m.EvaluateHost("host-04", 30.0)

	if status != kernel.HostIsolated {
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
	m := &Module{
		cfg:        &config.Config{Threshold: 80},
		hostStatus: make(map[string]kernel.HostStatus),
	}

	if s, _ := m.EvaluateHost("h", 80.0); s != kernel.HostOK {
		t.Errorf("score=80 (==threshold) should be OK, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 79.0); s != kernel.HostWarning {
		t.Errorf("score=79 should be Warning, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 70.0); s != kernel.HostWarning {
		t.Errorf("score=70 should be Warning (threshold-10 inclusive), got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 69.0); s != kernel.HostCritical {
		t.Errorf("score=69 should be Critical, got %s", s)
	}
	if s, _ := m.EvaluateHost("h", 49.0); s != kernel.HostIsolated {
		t.Errorf("score=49 should be Isolated, got %s", s)
	}
}
