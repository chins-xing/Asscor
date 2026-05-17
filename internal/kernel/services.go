package kernel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	apiv1 "github.com/argus-security/argus/api/v1"
	"github.com/argus-security/argus/internal/model"
)

type KernelServiceImpl struct {
	heartbeat   HeartbeatInterface
	commander   CommanderInterface
	cti         CTIInterface
	assessor    AssessorInterface
	persistence PersistenceInterface
}

func NewKernelServiceImpl(
	heartbeat HeartbeatInterface,
	commander CommanderInterface,
	cti CTIInterface,
	assessor AssessorInterface,
	persistence PersistenceInterface,
) *KernelServiceImpl {
	return &KernelServiceImpl{
		heartbeat:   heartbeat,
		commander:   commander,
		cti:         cti,
		assessor:    assessor,
		persistence: persistence,
	}
}

func (s *KernelServiceImpl) Register(ctx context.Context, req *apiv1.RegisterRequest) (*apiv1.RegisterResponse, error) {
	log.Printf("kernel: register request from %s (%s) v%s", req.HostId, req.Hostname, req.Version)

	if s.heartbeat == nil {
		return nil, fmt.Errorf("heartbeat service not available")
	}

	s.heartbeat.RegisterAgent(req.HostId, req.Hostname, req.Version)

	return &apiv1.RegisterResponse{
		Accepted:  true,
		SessionId: "sess-" + req.HostId + "-" + randomSessionSuffix(),
	}, nil
}

func (s *KernelServiceImpl) Heartbeat(ctx context.Context, req *apiv1.HeartbeatRequest) (*apiv1.HeartbeatResponse, error) {
	log.Printf("kernel: heartbeat from %s (result=%v, assessor=%v)", req.HostId, req.Result != nil, s.assessor != nil)

	if s.heartbeat != nil {
		s.heartbeat.RecordHeartbeat(req.HostId)
	}

	var assessmentResult *apiv1.AssessmentResult

	if req.Result != nil && s.assessor != nil {
		log.Printf("kernel: processing %d check results from %s", len(req.Result.Checks), req.HostId)

		checkResults := make([]model.CheckResult, 0, len(req.Result.Checks))
		for _, c := range req.Result.Checks {
			checkResults = append(checkResults, model.CheckResult{
				CheckID:       c.CheckId,
				Domain:        c.Domain,
				Name:          c.Name,
				Passed:        c.Passed,
				Delta:         c.Delta,
				Detail:        c.Detail,
				ComplianceRef: c.ComplianceRef,
			})
		}

		hostname := req.HostId
		if s.heartbeat != nil {
			if agent := s.heartbeat.GetAgent(req.HostId); agent != nil {
				hostname = agent.Hostname
			}
		}

		result := s.assessor.EvaluateFromResults(req.HostId, hostname, checkResults)
		log.Printf("kernel: assessment result for %s: score=%.2f acceptable=%v checks=%d",
			req.HostId, result.FinalScore, result.Acceptable, len(result.Checks))

		assessmentResult = convertAssessmentResult(result)
	}

	var pendingCmds []*apiv1.Command
	if s.commander != nil {
		pendingCmds = s.commander.DequeueCommands(req.HostId)
	}

	var threatCoeff float64 = 1.0
	if s.cti != nil {
		threatCoeff = s.cti.GetCoefficient()
	}

	return &apiv1.HeartbeatResponse{
		Ok:                true,
		ThreatCoefficient: threatCoeff,
		PendingCommands:   pendingCmds,
		AssessmentResult:  assessmentResult,
	}, nil
}

func convertAssessmentResult(r *model.AssessmentResult) *apiv1.AssessmentResult {
	if r == nil {
		return nil
	}

	domainScores := map[string]float64{
		"attack_surface":      r.DomainScores.AttackSurface,
		"business_continuity": r.DomainScores.BusinessContinuity,
		"operation_trust":     r.DomainScores.OperationTrust,
		"resilience":          r.DomainScores.Resilience,
		"kernel_security":     r.DomainScores.KernelSecurity,
	}

	edgeFactors := map[string]float64{
		"two_factor_failure": r.EdgeFactors.TwoFactorFailure,
	}

	checks := make([]*apiv1.CheckResult, 0, len(r.Checks))
	for _, c := range r.Checks {
		checks = append(checks, &apiv1.CheckResult{
			CheckId:       c.CheckID,
			Domain:        c.Domain,
			Name:          c.Name,
			Passed:        c.Passed,
			Delta:         c.Delta,
			Detail:        c.Detail,
			ComplianceRef: c.ComplianceRef,
		})
	}

	return &apiv1.AssessmentResult{
		FinalScore:   r.FinalScore,
		Acceptable:   r.Acceptable,
		DomainScores: domainScores,
		EdgeFactors:  edgeFactors,
		ThreatCoeff:  r.ThreatCoeff,
		SpcScore:     r.SPCScore,
		Checks:       checks,
	}
}

type AgentServiceImpl struct {
	assessor   AssessorInterface
	commander  CommanderInterface
	logCollect LogCollectorInterface
}

func NewAgentServiceImpl(
	assessor AssessorInterface,
	commander CommanderInterface,
	logCollect LogCollectorInterface,
) *AgentServiceImpl {
	return &AgentServiceImpl{
		assessor:   assessor,
		commander:  commander,
		logCollect: logCollect,
	}
}

func (s *AgentServiceImpl) GetSnapshot(ctx context.Context, req *apiv1.SnapshotRequest) (*apiv1.SnapshotResponse, error) {
	var result *apiv1.AssessmentResult
	if s.assessor != nil {
		ar := s.assessor.Evaluate(req.HostId)
		if ar != nil {
			checks := make([]*apiv1.CheckResult, len(ar.Checks))
			for i, c := range ar.Checks {
				checks[i] = &apiv1.CheckResult{
					CheckId:       c.CheckID,
					Domain:        c.Domain,
					Name:          c.Name,
					Passed:        c.Passed,
					Delta:         c.Delta,
					Detail:        c.Detail,
					ComplianceRef: c.ComplianceRef,
				}
			}
			result = &apiv1.AssessmentResult{
				FinalScore: ar.FinalScore,
				Acceptable: ar.Acceptable,
				DomainScores: map[string]float64{
					"attack_surface":      ar.DomainScores.AttackSurface,
					"business_continuity": ar.DomainScores.BusinessContinuity,
					"operation_trust":     ar.DomainScores.OperationTrust,
					"resilience":          ar.DomainScores.Resilience,
					"kernel_security":     ar.DomainScores.KernelSecurity,
				},
				Checks: checks,
			}
		}
	}

	return &apiv1.SnapshotResponse{
		HostId: req.HostId,
		Result: result,
	}, nil
}

func (s *AgentServiceImpl) ExecuteCommand(ctx context.Context, req *apiv1.CommandRequest) (*apiv1.CommandResponse, error) {
	if s.commander != nil {
		s.commander.AckCommand(req.HostId, req.CommandId, true, "")
	}

	return &apiv1.CommandResponse{
		CommandId: req.CommandId,
		Success:   true,
	}, nil
}

func (s *AgentServiceImpl) StreamLogs(ctx context.Context, req *apiv1.StreamLogsRequest) (*apiv1.Ack, error) {
	if s.logCollect == nil {
		return &apiv1.Ack{Ok: false}, fmt.Errorf("log collector not available")
	}

	if len(req.Entries) == 0 {
		return &apiv1.Ack{Ok: true}, nil
	}

	if err := s.logCollect.AppendBatch(req.Entries); err != nil {
		return &apiv1.Ack{Ok: false}, err
	}

	return &apiv1.Ack{Ok: true}, nil
}

func randomSessionSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}