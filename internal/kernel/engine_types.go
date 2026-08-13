package kernel

import (
	"context"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
)

// This file holds the assessor engine CONTRACT types (interfaces + shared data
// types). It is owned by the microkernel so that the kernel and always-compiled
// modules (extmgr, cli) can depend on them without importing the engine
// implementation package (which is a build-tag optional module //go:build engine).

// AssessorEngine is the unified scoring engine interface owned by ASSCOR.
// Algorithm implementations (SSAM, SRD, custom) depend on ASSCOR and implement
// this contract. ASSCOR itself has zero dependency on any specific algorithm.
type AssessorEngine interface {
	ComputeScore(ctx context.Context, result *model.AssessmentResult) error
	Name() string
	ReloadWeights(cfg *config.Config)
}

// SPCProvider is the Security Posture Calculation provider contract.
type SPCProvider interface {
	Enabled() bool
	GetAsset(hostID string) *SPCLocalAsset
	UpsertAsset(asset SPCLocalAsset)
	Calculate(hostID string, assetPackages []string) SPCCorrection
}

// ATTACKProvider is the MITRE ATT&CK analysis provider contract.
type ATTACKProvider interface {
	IsEnabled() bool
	Version() string
	CalculateCoverage(checkResults map[string]bool) []ATTACKCoverageResult
	AssessKillChain(hostID string, checkResults map[string]bool) ATTACKKillChainResult
	MatchAPTGroup(detectedTechniques []string) []ATTACKAPTMatch
	PredictRisk(hostID string, detectedTechniques []string, maxDepth int) ATTACKPredictedRisk
	GetAllTactics() []ATTACKTacticInfo
}

// ATTACKCoverageResult reports tactic coverage from ATT&CK analysis.
type ATTACKCoverageResult struct {
	TacticID        string
	TacticName      string
	TotalTechniques int
	CoveredDet      int
	CoverageDet     float64
	CoveragePrev    float64
	CoverageComp    float64
	RiskLevel       string
}

// ATTACKKillChainResult is the kill-chain weakness analysis result.
type ATTACKKillChainResult struct {
	OverallScore float64
	WeakestStage string
	Stages       []ATTACKKillChainStage
}

// ATTACKKillChainStage is a single kill-chain stage score.
type ATTACKKillChainStage struct {
	Name         string
	Score        float64
	Status       string
	ChecksPassed int
	ChecksTotal  int
}

// ATTACKAPTMatch is an APT group attribution match.
type ATTACKAPTMatch struct {
	GroupID     string
	GroupName   string
	Similarity  float64
	Confidence  string
	OverlapTech []string
}

// ATTACKPredictedRisk is the predicted future risk from ATT&CK analysis.
type ATTACKPredictedRisk struct {
	MaxRiskScore    float64
	EnhancedThreat  float64
	PredictedPaths  int
	Recommendations []string
}

// ATTACKTacticInfo describes a tactic and its techniques.
type ATTACKTacticInfo struct {
	ID         string
	Name       string
	Techniques []ATTACKTechniqueInfo
}

// ATTACKTechniqueInfo describes a technique and its ASSCOR check mappings.
type ATTACKTechniqueInfo struct {
	ID           string
	Name         string
	AsscorChecks []string
}

// SPCLocalAsset is the SPC view of a local host asset.
type SPCLocalAsset struct {
	HostID        string
	NetworkZone   string
	Role          string
	Packages      []string
	InstalledCPEs []string
	Compensations SPCCompensations
}

// SPCCompensations records deployed compensating controls.
type SPCCompensations struct {
	VirtualPatch bool
	WAFRules     bool
	IPSRules     bool
	AppWhitelist bool
}

// SPCCorrection is defined in spc_types.go (shared with the SPC module).

// AssessmentPhase is a phase in the assessment pipeline where a hook fires.
type AssessmentPhase string

// Assessment pipeline phases.
const (
	PhasePreCheck   AssessmentPhase = "pre_check"
	PhasePostCheck  AssessmentPhase = "post_check"
	PhasePreScore   AssessmentPhase = "pre_score"
	PhasePostScore  AssessmentPhase = "post_score"
	PhasePreEdge    AssessmentPhase = "pre_edge"
	PhasePostEdge   AssessmentPhase = "post_edge"
	PhasePreReport  AssessmentPhase = "pre_report"
	PhasePostReport AssessmentPhase = "post_report"
)

// AssessmentHook is a function invoked at a specific assessment phase.
type AssessmentHook func(ctx context.Context, result *model.AssessmentResult) error

// HookRegistrar is the hook registration contract implemented by the engine.
// extmgr depends on this interface (not the concrete engine.Assessor) so the
// extension manager stays decoupled from the gated engine implementation.
type HookRegistrar interface {
	RegisterHook(id string, phase AssessmentPhase, hook AssessmentHook, priority int)
	UnregisterHook(id string)
}
