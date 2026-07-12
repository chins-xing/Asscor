package kernel

import (
	"context"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
)

type mockAssessorForService struct {
	lastResult *model.AssessmentResult
}

func (m *mockAssessorForService) Evaluate(hostID string) *model.AssessmentResult { return nil }
func (m *mockAssessorForService) EvaluateFromResults(hostID, hostname string, checks []model.CheckResult) *model.AssessmentResult {
	r := &model.AssessmentResult{HostID: hostID, Hostname: hostname, FinalScore: 85, Acceptable: true, Checks: checks}
	m.lastResult = r
	return r
}
func (m *mockAssessorForService) GetResult(hostID string) *model.AssessmentResult {
	return m.lastResult
}
func (m *mockAssessorForService) ListResults() []*model.AssessmentResult {
	if m.lastResult != nil {
		return []*model.AssessmentResult{m.lastResult}
	}
	return nil
}
func (m *mockAssessorForService) ReloadConfig(_ *config.Config) {}

func TestHeartbeat_ProcessesCheckResults(t *testing.T) {
	ma := &mockAssessorForService{}
	svc := &KernelServiceImpl{
		assessor: ma,
	}

	req := &apiv1.HeartbeatRequest{
		HostId: "test-host",
		Result: &apiv1.AssessmentResult{
			Checks: []*apiv1.CheckResult{
				{CheckId: "AS-001", Domain: "attack_surface", Name: "test", Passed: true},
				{CheckId: "OT-001", Domain: "operation_trust", Name: "test", Passed: false, Delta: -10},
			},
		},
	}

	resp, err := svc.Heartbeat(context.Background(), req)
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if resp == nil || !resp.Ok {
		t.Fatal("expected Heartbeat to return Ok=true")
	}
}

func TestHeartbeat_EmptyResultReturnsOk(t *testing.T) {
	svc := &KernelServiceImpl{}
	req := &apiv1.HeartbeatRequest{HostId: "empty-host"}

	resp, err := svc.Heartbeat(context.Background(), req)
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if resp == nil || !resp.Ok {
		t.Fatal("expected Ok=true even with empty result")
	}
}
