package kernel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/resilience"
)

var (
	hostIDPattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	cpePattern       = regexp.MustCompile(`^cpe:2\.3:[aoh]:[^:]*:[^:]*:[^:]*:.*$`)
	maxPackages      = 50000
	maxCPEs          = 50000
	maxPackageLen    = 256
)

type KernelServiceImpl struct {
	heartbeat   HeartbeatInterface
	commander   CommanderInterface
	cti         CTIInterface
	assessor    AssessorInterface
	persistence PersistenceInterface
	spc         SPCInterface
}

func NewKernelServiceImpl(
	heartbeat HeartbeatInterface,
	commander CommanderInterface,
	cti CTIInterface,
	assessor AssessorInterface,
	persistence PersistenceInterface,
	spc SPCInterface,
) *KernelServiceImpl {
	return &KernelServiceImpl{
		heartbeat:   heartbeat,
		commander:   commander,
		cti:         cti,
		assessor:    assessor,
		persistence: persistence,
		spc:         spc,
	}
}

func (s *KernelServiceImpl) Register(ctx context.Context, req *apiv1.RegisterRequest) (*apiv1.RegisterResponse, error) {
	logger.WithComponent("kernel").Info("register request", "host_id", req.HostId, "hostname", req.Hostname, "version", req.Version)

	if req.HostId == "" {
		return &apiv1.RegisterResponse{
			Accepted:  false,
			SessionId: "",
		}, fmt.Errorf("host_id is required")
	}
	if len(req.HostId) > 128 {
		return &apiv1.RegisterResponse{
			Accepted:  false,
			SessionId: "",
		}, fmt.Errorf("host_id too long (max 128 characters)")
	}
	if !hostIDPattern.MatchString(req.HostId) {
		return &apiv1.RegisterResponse{
			Accepted:  false,
			SessionId: "",
		}, fmt.Errorf("host_id contains invalid characters (allowed: a-z, A-Z, 0-9, ._-)")
	}
	if req.Version == "" {
		return &apiv1.RegisterResponse{
			Accepted:  false,
			SessionId: "",
		}, fmt.Errorf("version is required")
	}

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
	logger.WithComponent("kernel").Info("heartbeat received", "host_id", req.HostId, "has_result", req.Result != nil, "has_assessor", s.assessor != nil)

	if s.heartbeat != nil {
		s.heartbeat.RecordHeartbeat(req.HostId)
	}

	if s.spc != nil && s.spc.Enabled() && len(req.Packages) > 0 {
		if len(req.Packages) > maxPackages {
			logger.WithComponent("kernel").Warn("heartbeat packages exceed limit, truncating", "host_id", req.HostId, "count", len(req.Packages), "max", maxPackages)
			req.Packages = req.Packages[:maxPackages]
		}
		if len(req.InstalledCPEs) > maxCPEs {
			logger.WithComponent("kernel").Warn("heartbeat CPEs exceed limit, truncating", "host_id", req.HostId, "count", len(req.InstalledCPEs), "max", maxCPEs)
			req.InstalledCPEs = req.InstalledCPEs[:maxCPEs]
		}

		for i := range req.Packages {
			if len(req.Packages[i]) > maxPackageLen {
				req.Packages[i] = req.Packages[i][:maxPackageLen]
			}
		}

		validCPEs := make([]string, 0, len(req.InstalledCPEs))
		for _, cpeStr := range req.InstalledCPEs {
			if cpePattern.MatchString(cpeStr) {
				validCPEs = append(validCPEs, cpeStr)
			}
		}
		req.InstalledCPEs = validCPEs

		asset := s.spc.GetAsset(req.HostId)
		if asset == nil {
			asset = &LocalAsset{
				HostID:        req.HostId,
				Packages:      req.Packages,
				InstalledCPEs: req.InstalledCPEs,
			}
		} else {
			asset.Packages = req.Packages
			if len(req.InstalledCPEs) > 0 {
				asset.InstalledCPEs = req.InstalledCPEs
			}
		}
		s.spc.UpsertAsset(*asset)
		logger.WithComponent("kernel").Debug("SPC asset updated from heartbeat", "host_id", req.HostId, "packages", len(req.Packages), "cpes", len(asset.InstalledCPEs))
	}

	if req.Result != nil && s.assessor != nil {
		logger.WithComponent("kernel").Info("processing check results", "count", len(req.Result.Checks), "host_id", req.HostId)

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

		resilience.GuardGo("kernel.heartbeat", "evaluate", func() {
			result := s.assessor.EvaluateFromResults(req.HostId, hostname, checkResults)
			logger.WithComponent("kernel").Info("assessment result", "host_id", req.HostId, "score", result.FinalScore, "acceptable", result.Acceptable, "checks", len(result.Checks))
		})
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
		"two_factor_failure":  r.EdgeFactors.TwoFactorFailure,
		"syn_cookie_disabled": r.EdgeFactors.SYNCookieDisabled,
		"selinux_disabled":    r.EdgeFactors.SELinuxDisabled,
		"apparmor_disabled":   r.EdgeFactors.AppArmorDisabled,
		"no_siem":             r.EdgeFactors.NoSIEM,
		"no_ids":              r.EdgeFactors.NoIDS,
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

	spcCVEs := make([]apiv1.SPCCVEInfo, 0, len(r.SPCCVEs))
	for _, c := range r.SPCCVEs {
		spcCVEs = append(spcCVEs, apiv1.SPCCVEInfo{
			CVEID:   c.CVEID,
			CVSS:    c.CVSS,
			EPSS:    c.EPSS,
			InKEV:   c.InKEV,
			HasPoC:  c.HasPoC,
			Penalty: c.Penalty,
			Product: c.Product,
		})
	}

	return &apiv1.AssessmentResult{
		FinalScore:   r.FinalScore,
		Acceptable:   r.Acceptable,
		DomainScores: domainScores,
		EdgeFactors:  edgeFactors,
		ThreatCoeff:  r.ThreatCoeff,
		SpcScore:     r.SPCScore,
		SpcCVEs:      spcCVEs,
		Checks:       checks,

		ATTACKCoverage:      convertATTACKCoverage(r.ATTACKCoverage),
		ATTACKKillChain:     convertATTACKKillChain(r.ATTACKKillChain),
		ATTACKAPTMatches:    convertATTACKAPTMatch(r.ATTACKAPTMatches),
		ATTACKPredictedRisk: convertATTACKPredictedRisk(r.ATTACKPredictedRisk),
		ATTACKFailedTechs:   r.ATTACKFailedTechs,
	}
}

func convertATTACKCoverage(src []model.ATTACKCoverageInfo) []apiv1.ATTACKCoverageInfo {
	if len(src) == 0 {
		return nil
	}
	dst := make([]apiv1.ATTACKCoverageInfo, 0, len(src))
	for _, c := range src {
		dst = append(dst, apiv1.ATTACKCoverageInfo{
			TacticID:        c.TacticID,
			TacticName:      c.TacticName,
			TotalTechniques: c.TotalTechniques,
			CoveredDet:      c.CoveredDet,
			CoverageDet:     c.CoverageDet,
			CoveragePrev:    c.CoveragePrev,
			CoverageComp:    c.CoverageComp,
			RiskLevel:       c.RiskLevel,
		})
	}
	return dst
}

func convertATTACKKillChain(src *model.ATTACKKillChainInfo) *apiv1.ATTACKKillChainInfo {
	if src == nil {
		return nil
	}
	stages := make([]apiv1.ATTACKKillChainStage, 0, len(src.Stages))
	for _, s := range src.Stages {
		stages = append(stages, apiv1.ATTACKKillChainStage{
			Name:         s.Name,
			Score:        s.Score,
			Status:       s.Status,
			ChecksPassed: s.ChecksPassed,
			ChecksTotal:  s.ChecksTotal,
		})
	}
	return &apiv1.ATTACKKillChainInfo{
		Stages:       stages,
		OverallScore: src.OverallScore,
		WeakestStage: src.WeakestStage,
	}
}

func convertATTACKAPTMatch(src []model.ATTACKAPTMatchInfo) []apiv1.ATTACKAPTMatchInfo {
	if len(src) == 0 {
		return nil
	}
	dst := make([]apiv1.ATTACKAPTMatchInfo, 0, len(src))
	for _, m := range src {
		overlap := make([]string, len(m.OverlapTech))
		copy(overlap, m.OverlapTech)
		dst = append(dst, apiv1.ATTACKAPTMatchInfo{
			GroupID:     m.GroupID,
			GroupName:   m.GroupName,
			Similarity:  m.Similarity,
			Confidence:  m.Confidence,
			OverlapTech: overlap,
		})
	}
	return dst
}

func convertATTACKPredictedRisk(src *model.ATTACKPredictedRiskInfo) *apiv1.ATTACKPredictedRiskInfo {
	if src == nil {
		return nil
	}
	recs := make([]string, len(src.Recommendations))
	copy(recs, src.Recommendations)
	return &apiv1.ATTACKPredictedRiskInfo{
		MaxRiskScore:    src.MaxRiskScore,
		EnhancedThreat:  src.EnhancedThreat,
		PredictedPaths:  src.PredictedPaths,
		Recommendations: recs,
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
				EdgeFactors: map[string]float64{
					"two_factor_failure":  ar.EdgeFactors.TwoFactorFailure,
					"syn_cookie_disabled": ar.EdgeFactors.SYNCookieDisabled,
					"selinux_disabled":    ar.EdgeFactors.SELinuxDisabled,
					"apparmor_disabled":   ar.EdgeFactors.AppArmorDisabled,
					"no_siem":             ar.EdgeFactors.NoSIEM,
					"no_ids":              ar.EdgeFactors.NoIDS,
				},
				Checks: checks,
				ATTACKCoverage:      convertATTACKCoverage(ar.ATTACKCoverage),
				ATTACKKillChain:     convertATTACKKillChain(ar.ATTACKKillChain),
				ATTACKAPTMatches:    convertATTACKAPTMatch(ar.ATTACKAPTMatches),
				ATTACKPredictedRisk: convertATTACKPredictedRisk(ar.ATTACKPredictedRisk),
				ATTACKFailedTechs:   ar.ATTACKFailedTechs,
			}
		}
	}

	return &apiv1.SnapshotResponse{
		HostId: req.HostId,
		Result: result,
	}, nil
}

func (s *AgentServiceImpl) ExecuteCommand(ctx context.Context, req *apiv1.CommandRequest) (*apiv1.CommandResponse, error) {
	if req.CommandId == "" || req.HostId == "" {
		return &apiv1.CommandResponse{
			CommandId: req.CommandId,
			Success:   false,
		}, fmt.Errorf("command_id and host_id are required")
	}

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
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		logger.WithComponent("kernel").Error("crypto/rand read failed for session suffix", "error", err)
		for i := range b {
			b[i] = byte(i)
		}
	}
	return hex.EncodeToString(b)
}