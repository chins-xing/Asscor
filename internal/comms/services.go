//go:build comms

package comms

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
	"github.com/asscor/asscor/internal/topology"
	"regexp"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/resilience"
)

var (
	hostIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	cpePattern    = regexp.MustCompile(`^cpe:2\.3:[aoh]:[^:]*:[^:]*:[^:]*:.*$`)
	maxPackages   = 50000
	maxCPEs       = 50000
	maxPackageLen = 256
)

type KernelServiceImpl struct {
	heartbeat   kernel.HeartbeatInterface
	commander   kernel.CommanderInterface
	cti         kernel.CTIInterface
	assessor    kernel.AssessorInterface
	persistence kernel.PersistenceInterface
	spc         kernel.SPCInterface
	// cfg is the kernel configuration; its [user_check.*] and [check_deltas]
	// sections are synced to agents via heartbeat (check_config). Nil disables
	// syncing (agent keeps its local bootstrap config).
	cfg *config.Config
	// secureMode is the secure-mode controller; its SecretRegistry records
	// agent ephemeral passwords keyed on the mTLS certificate fingerprint
	// (spec §10.1). Nil when the securemode build tag is off.
	secureMode *securemode.Controller
}

func NewKernelServiceImpl(
	heartbeat kernel.HeartbeatInterface,
	commander kernel.CommanderInterface,
	cti kernel.CTIInterface,
	assessor kernel.AssessorInterface,
	persistence kernel.PersistenceInterface,
	spc kernel.SPCInterface,
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

// SetConfig wires the kernel configuration into the service so heartbeat
// responses can sync check-item configuration (user checks + delta overrides)
// to agents. Call before serving; nil disables syncing.
func (s *KernelServiceImpl) SetConfig(cfg *config.Config) {
	s.cfg = cfg
}

// SetSecureMode wires the secure-mode controller into the service so heartbeat
// responses can register agent ephemeral passwords (spec §10.1). Call before
// serving; nil disables registration (the securemode build tag is off).
func (s *KernelServiceImpl) SetSecureMode(ctrl *securemode.Controller) {
	s.secureMode = ctrl
}

// buildAgentCheckConfig extracts the check-item configuration to sync to
// agents from the kernel's config: the [user_check.*] sections (as flattened
// keys), the [check_deltas] overrides, and the [commands] extra whitelist.
// Returns nil when nothing is configured, so agents keep their local
// bootstrap config unchanged.
func (s *KernelServiceImpl) buildAgentCheckConfig() *apiv1.AgentCheckConfig {
	if s.cfg == nil {
		return nil
	}

	var userChecks map[string]string
	for k, v := range s.cfg.AdapterConfig {
		if strings.HasPrefix(k, "user_check.") {
			if userChecks == nil {
				userChecks = make(map[string]string)
			}
			userChecks[k] = v
		}
	}

	var checkDeltas map[string]float64
	if len(s.cfg.CheckDeltas) > 0 {
		checkDeltas = make(map[string]float64, len(s.cfg.CheckDeltas))
		for id, d := range s.cfg.CheckDeltas {
			checkDeltas[id] = d
		}
	}

	// [commands] extra_whitelist: comma/space-separated command names appended
	// to the agent's execution allowlist (deduplicated, trimmed).
	var allowedCommands []string
	if v := s.cfg.AdapterConfig["commands.extra_whitelist"]; v != "" {
		seen := make(map[string]bool)
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				allowedCommands = append(allowedCommands, part)
			}
		}
	}

	if len(userChecks) == 0 && len(checkDeltas) == 0 && len(allowedCommands) == 0 {
		return nil
	}

	return &apiv1.AgentCheckConfig{
		UserChecks:      userChecks,
		CheckDeltas:     checkDeltas,
		AllowedCommands: allowedCommands,
		Version:         agentCheckConfigVersion(userChecks, checkDeltas, allowedCommands),
	}
}

// agentCheckConfigVersion computes a stable content fingerprint so agents can
// skip reapplying unchanged configuration.
func agentCheckConfigVersion(userChecks map[string]string, checkDeltas map[string]float64, allowedCommands []string) string {
	h := sha256.New()
	if len(userChecks) > 0 {
		keys := make([]string, 0, len(userChecks))
		for k := range userChecks {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(h, "u:%s=%s\n", k, userChecks[k])
		}
	}
	if len(checkDeltas) > 0 {
		ids := make([]string, 0, len(checkDeltas))
		for id := range checkDeltas {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(h, "d:%s=%s\n", id, strconv.FormatFloat(checkDeltas[id], 'f', -1, 64))
		}
	}
	for _, c := range allowedCommands {
		fmt.Fprintf(h, "c:%s\n", c)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
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

	// Identity hardening (audit I-01): bind the presenting mTLS certificate
	// fingerprint to this host_id on first registration. A legal certificate
	// cannot impersonate a different host, and one certificate maps to one
	// identity. Empty fingerprint (no mTLS, development) skips binding.
	fp := kernel.PeerCertFingerprintFromContext(ctx)
	// Identity hardening (audit I-03): a revoked certificate must not
	// register, even for a host it was previously bound to.
	if s.heartbeat.IsCertRevoked(fp) {
		logger.WithComponent("identity").Warn("registration rejected: certificate revoked",
			"host_id", req.HostId, "fingerprint", truncateFingerprint(fp))
		return &apiv1.RegisterResponse{Accepted: false}, fmt.Errorf("certificate revoked: fingerprint %q", truncateFingerprint(fp))
	}
	if !s.heartbeat.BindAgentCert(req.HostId, fp) {
		logger.WithComponent("identity").Warn("registration rejected: certificate identity mismatch",
			"host_id", req.HostId, "fingerprint", truncateFingerprint(fp))
		return &apiv1.RegisterResponse{Accepted: false}, fmt.Errorf("certificate identity conflict: host %q is bound to a different certificate", req.HostId)
	}

	s.heartbeat.RegisterAgent(req.HostId, req.Hostname, req.Version)

	// Identity event (audit I-02): unified registration record.
	logger.WithComponent("identity").Info("identity: agent registered",
		"host_id", req.HostId, "fingerprint", truncateFingerprint(fp), "action", "register", "result", "accepted")

	return &apiv1.RegisterResponse{
		Accepted:  true,
		SessionId: "sess-" + req.HostId + "-" + randomSessionSuffix(),
	}, nil
}

// truncateFingerprint shortens a cert fingerprint for logging (full value in
// structured fields when needed). Empty input stays empty.
func truncateFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "..."
}

func (s *KernelServiceImpl) Heartbeat(ctx context.Context, req *apiv1.HeartbeatRequest) (*apiv1.HeartbeatResponse, error) {
	logger.WithComponent("kernel").Info("heartbeat received", "host_id", req.HostId, "has_result", req.Result != nil, "has_assessor", s.assessor != nil)

	// Identity hardening (audit I-01): verify the presenting certificate
	// matches the one bound to this host_id at registration.
	if s.heartbeat != nil {
		fp := kernel.PeerCertFingerprintFromContext(ctx)
		if !s.heartbeat.VerifyAgentCert(req.HostId, fp) {
			logger.WithComponent("identity").Warn("heartbeat rejected: certificate identity mismatch",
				"host_id", req.HostId, "fingerprint", truncateFingerprint(fp))
			return &apiv1.HeartbeatResponse{Ok: false}, fmt.Errorf("certificate identity mismatch for host %q", req.HostId)
		}
		s.heartbeat.RecordHeartbeat(req.HostId)
	}

	// Secure Mode: agent ephemeral-password reporting AND locked-agent unlock
	// (kernel-managed, spec §10.1). The fingerprint comes from the mTLS
	// transport layer — a forged agent_id with an unknown/mismatched
	// fingerprint was already rejected by VerifyAgentCert above. An EMPTY
	// fingerprint (no mTLS, development) cannot be keyed, so the unlock and
	// registration paths are skipped with a warning instead of failing the
	// heartbeat (the agent would otherwise retry forever).
	var secureModeUnlock *apiv1.SecureModeUnlock
	var secureModeNoSecret bool
	if s.secureMode != nil {
		fp := kernel.PeerCertFingerprintFromContext(ctx)
		switch {
		case req.SecureMode != nil && req.SecureMode.Locked:
			// Run-mode restart: the agent declares itself locked (it has no
			// password to report and no hmac_key to verify a pending command
			// with — review I-1/I-2). Hand the registered password back over
			// the already-authenticated mTLS heartbeat channel.
			if fp == "" {
				logger.WithComponent("identity").Warn("secure-mode unlock skipped: no mTLS fingerprint (development mode)")
				break
			}
			if sec, ok := s.secureMode.Secrets.Lookup(fp); ok && sec.Password != "" {
				secureModeUnlock = &apiv1.SecureModeUnlock{Password: sec.Password}
				logger.WithComponent("identity").Info("secure-mode unlock issued to locked agent", "host_id", req.HostId)
			} else {
				logger.WithComponent("identity").Warn("secure-mode unlock skipped: no registered secret for this fingerprint", "host_id", req.HostId)
				// I-2 (spec §8.2): tell the locked agent there is NO
				// registration so it self-recovers immediately (fresh password
				// + re-encrypt + re-report) instead of polling forever.
				secureModeNoSecret = true
			}
		case req.SecureMode != nil && req.SecureMode.Password != "":
			if fp == "" {
				logger.WithComponent("identity").Warn("secure-mode registration skipped: no mTLS fingerprint (development mode)")
			} else if err := s.secureMode.Secrets.Register(fp, req.HostId, req.SecureMode.Password); err != nil {
				logger.WithComponent("identity").Warn("secure-mode registration rejected",
					"host_id", req.HostId, "error", err.Error())
				return &apiv1.HeartbeatResponse{Ok: false}, fmt.Errorf("secure mode registration rejected: %v", err)
			} else if err := s.secureMode.PersistSecrets(); err != nil {
				// P0-1 durability (spec §10.1): the registry is written
				// encrypted under the kernel run-mode password after every
				// registration/rotation so a later kernel restart can recover
				// it. In default mode PersistSecrets is a no-op (nothing to
				// persist); in run mode a failure only degrades crash-recovery
				// durability — the in-memory registration stays correct and
				// the next registration retries the persist.
				logger.WithComponent("identity").Warn("secure-mode registry persist failed (in-memory registration kept; will retry on next registration)",
					"host_id", req.HostId, "error", err.Error())
			}
		case req.SecureMode == nil:
			// I-2 derived (review reason 3): any heartbeat whose certificate
			// fingerprint has NO secure-mode registration carries the signal —
			// an already-unlocked run-mode agent whose registration was lost
			// (kernel restarted with an unrecoverable registry) then re-arms
			// its password report and re-registers on the next heartbeat.
			// Ordinary agents ignore it (they have no password to re-report).
			if fp != "" {
				if _, ok := s.secureMode.Secrets.Lookup(fp); !ok {
					secureModeNoSecret = true
				}
			}
		}
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
			asset = &kernel.LocalAsset{
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

	if req.NetworkInfo != nil {
		if s.spc != nil && s.spc.Enabled() {
			asset := s.spc.GetAsset(req.HostId)
			if asset == nil {
				asset = &kernel.LocalAsset{HostID: req.HostId}
			}
			if req.NetworkInfo.NetworkZone != "" && asset.NetworkZone == "" {
				asset.NetworkZone = req.NetworkInfo.NetworkZone
				s.spc.UpsertAsset(*asset)
			}
		}
		if len(req.NetworkInfo.Subnets) > 0 {
			subnets := req.NetworkInfo.Subnets
			// M1 网段过滤 (audit P0-2/T4): 排除管理/虚拟网段, 避免全互达
			// 假传播 (config.ini [topology] exclude_cidrs)。
			if s.cfg != nil && len(s.cfg.TopologyExcludeCIDRs) > 0 {
				subnets = topology.FilterExcludedSubnets(subnets, s.cfg.TopologyExcludeCIDRs)
			}
			if len(subnets) > 0 {
				topology.RecordTopology(req.HostId, subnets)
			}
		}
		logger.WithComponent("kernel").Debug("network info received", "host_id", req.HostId,
			"zone", req.NetworkInfo.NetworkZone, "ips", len(req.NetworkInfo.LocalIPs), "subnets", len(req.NetworkInfo.Subnets))
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
				Source:        model.CheckSource(c.Source),
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
		Ok:                 true,
		ThreatCoefficient:  threatCoeff,
		PendingCommands:    pendingCmds,
		CheckConfig:        s.buildAgentCheckConfig(),
		SecureModeUnlock:   secureModeUnlock,
		SecureModeNoSecret: secureModeNoSecret,
	}, nil
}

func convertAssessmentResult(r *model.AssessmentResult) *apiv1.AssessmentResult {
	if r == nil {
		return nil
	}

	domainScores := r.DomainScores.GetAllDomainScores()

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
			Source:        string(c.Source),
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
	assessor   kernel.AssessorInterface
	commander  kernel.CommanderInterface
	logCollect kernel.LogCollectorInterface
}

func NewAgentServiceImpl(
	assessor kernel.AssessorInterface,
	commander kernel.CommanderInterface,
	logCollect kernel.LogCollectorInterface,
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
					Source:        string(c.Source),
				}
			}
			result = &apiv1.AssessmentResult{
				FinalScore:   ar.FinalScore,
				Acceptable:   ar.Acceptable,
				DomainScores: ar.DomainScores.GetAllDomainScores(),
				EdgeFactors: map[string]float64{
					"two_factor_failure":  ar.EdgeFactors.TwoFactorFailure,
					"syn_cookie_disabled": ar.EdgeFactors.SYNCookieDisabled,
					"selinux_disabled":    ar.EdgeFactors.SELinuxDisabled,
					"apparmor_disabled":   ar.EdgeFactors.AppArmorDisabled,
					"no_siem":             ar.EdgeFactors.NoSIEM,
					"no_ids":              ar.EdgeFactors.NoIDS,
				},
				Checks:              checks,
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

	// Identity event (audit I-02): command confirmation attributed to the
	// connecting agent's certificate identity.
	logger.WithComponent("identity").Info("identity: command acknowledged",
		"host_id", req.HostId, "fingerprint", truncateFingerprint(kernel.PeerCertFingerprintFromContext(ctx)),
		"command_id", req.CommandId, "action", "command_ack", "result", "accepted")

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
