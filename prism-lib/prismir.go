package prism

import (
	"encoding/json"
	"fmt"
	"time"
)

// ----------------------------------------------------------
// Prism IR — Intermediate Representation
// ----------------------------------------------------------
// PrismIR is the standardized JSON output format for Prism
// risk dynamics results. It follows the same Meta/Input/Output
// pattern as SSAM IR, enabling downstream SIEM/SOC consumption.
//
// The IR is self-describing: given a PrismIR document, one can
// fully reproduce the risk dynamics computation without the
// original code.

type PrismIR struct {
	PrismIRVersion string       `json:"prismir_version"`
	Meta           PrismIRMeta  `json:"meta"`
	Input          PrismIRInput `json:"input"`
	Output         PrismIROutput `json:"output"`
}

// ----------------------------------------------------------
// Meta
// ----------------------------------------------------------

type PrismIRMeta struct {
	Version     string `json:"version"`
	Engine      string `json:"engine"`
	Timestamp   string `json:"timestamp"`
	HorizonDays int    `json:"horizon_days"`
}

// ----------------------------------------------------------
// Input
// ----------------------------------------------------------

type PrismIRInput struct {
	HostID            string                `json:"host_id"`
	SSAMScore         float64               `json:"ssam_score"`
	FailedChecks      []IRCheckFailure      `json:"failed_checks"`
	PropagationEdges  []IRPropagationEdge   `json:"propagation_edges,omitempty"`
	Config            IRPrismConfig         `json:"config"`
}

type IRCheckFailure struct {
	CheckID string  `json:"check_id"`
	Delta   float64 `json:"delta"`
	FailAt  int64   `json:"fail_at"`
}

type IRPropagationEdge struct {
	Source           string  `json:"source"`
	Target           string  `json:"target"`
	RiskTransmission float64 `json:"risk_transmission"`
}

type IRPrismConfig struct {
	DebtAlpha    float64 `json:"debt_alpha"`
	PropCap      float64 `json:"prop_cap"`
	DebtCap      float64 `json:"debt_cap"`
	DebtNormDays float64 `json:"debt_norm_days"`
	ScoreFloor   float64 `json:"score_floor"`
	MaxPathDepth int     `json:"max_path_depth"`
}

// ----------------------------------------------------------
// Output
// ----------------------------------------------------------

type PrismIROutput struct {
	Core      IRCoreLayer      `json:"core"`
	Semantic  IRSemanticLayer  `json:"semantic"`
	Inference IRInferenceLayer `json:"inference"`
}

// Core Layer

type IRCoreLayer struct {
	PrismScore       float64 `json:"prism_score"`
	ExternalRisk     float64 `json:"external_risk"`
	PropagatedRisk   float64 `json:"propagated_risk"`
	PropPenalty      float64 `json:"prop_penalty"`
	DebtRaw          float64 `json:"debt_raw"`
	DebtPenalty      float64 `json:"debt_penalty"`
	CollapseModifier float64 `json:"collapse_modifier"`
	RiskVelocity     float64 `json:"risk_velocity"`
}

// Semantic Layer

type IRSemanticLayer struct {
	StateVector  [4]float64    `json:"state_vector"`
	DominantState string       `json:"dominant_state"`
	Membership    IRMembership `json:"membership"`
}

type IRMembership struct {
	Stable    float64 `json:"stable"`
	Degraded  float64 `json:"degraded"`
	Untrusted float64 `json:"untrusted"`
	Collapse  float64 `json:"collapse"`
}

// Inference Layer

type IRInferenceLayer struct {
	HorizonDays  int       `json:"horizon_days"`
	FutureVector [4]float64 `json:"future_vector"`
	Confidence   float64   `json:"confidence"`
	Trend        string    `json:"trend"`
	CollapseRisk float64   `json:"collapse_risk"`
	Model        string    `json:"model"`
}

// ----------------------------------------------------------
// Constructor
// ----------------------------------------------------------

// NewIR constructs a full PrismIR from the three-layer computation results.
//
// Parameters:
//   - node: the input node state (host ID, SSAM score, failed checks)
//   - edges: incoming propagation edges
//   - cfg: the Prism configuration used for computation
//   - core: Core Layer output (AssetRiskResult)
//   - sem: Semantic Layer output (SemanticRiskReport)
//   - inf: Inference Layer output (FutureRiskReport)
//   - modelName: the inference model identifier (e.g., "MarkovChain")
func NewIR(
	node NodeState,
	edges []EdgeState,
	cfg PrismConfig,
	core AssetRiskResult,
	sem SemanticRiskReport,
	inf FutureRiskReport,
	modelName string,
) PrismIR {
	// Failed checks
	failedChecks := make([]IRCheckFailure, len(node.FailedChecks))
	for i, fc := range node.FailedChecks {
		failedChecks[i] = IRCheckFailure{
			CheckID: fc.CheckID,
			Delta:   fc.Delta,
			FailAt:  fc.FailUnix,
		}
	}

	// Propagation edges
	propEdges := make([]IRPropagationEdge, len(edges))
	for i, e := range edges {
		propEdges[i] = IRPropagationEdge{
			Source:           e.Source,
			Target:           e.Target,
			RiskTransmission: e.RiskTransmission,
		}
	}

	return PrismIR{
		PrismIRVersion: "1.0",
		Meta: PrismIRMeta{
			Version:     "1.0",
			Engine:      "prism",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			HorizonDays: inf.HorizonDays,
		},
		Input: PrismIRInput{
			HostID:           node.HostID,
			SSAMScore:        node.SSAMScore,
			FailedChecks:     failedChecks,
			PropagationEdges: propEdges,
			Config: IRPrismConfig{
				DebtAlpha:    cfg.DebtAlpha,
				PropCap:      cfg.PropCap,
				DebtCap:      cfg.DebtCap,
				DebtNormDays: cfg.DebtNormDays,
				ScoreFloor:   cfg.ScoreFloor,
				MaxPathDepth: cfg.MaxPathDepth,
			},
		},
		Output: PrismIROutput{
			Core: IRCoreLayer{
				PrismScore:       core.PrismScore,
				ExternalRisk:     core.ExternalRisk,
				PropagatedRisk:   core.PropagatedRisk,
				PropPenalty:      core.PropPenalty,
				DebtRaw:          core.DebtRaw,
				DebtPenalty:      core.DebtPenalty,
				CollapseModifier: core.CollapseModifier,
				RiskVelocity:     core.RiskVelocity,
			},
			Semantic: IRSemanticLayer{
				StateVector:   sem.StateVector,
				DominantState: sem.CurrentState,
				Membership: IRMembership{
					Stable:    sem.StableMembership,
					Degraded:  sem.DegradedMembership,
					Untrusted: sem.UntrustedMembership,
					Collapse:  sem.CollapseMembership,
				},
			},
			Inference: IRInferenceLayer{
				HorizonDays:  inf.HorizonDays,
				FutureVector: [4]float64{inf.StableProb, inf.DegradedProb, inf.UntrustedProb, inf.CollapseProb},
				Confidence:   inf.Confidence,
				Trend:        inf.Trend,
				CollapseRisk: inf.CollapseRisk,
				Model:        modelName,
			},
		},
	}
}

// ----------------------------------------------------------
// Serialization
// ----------------------------------------------------------

// MarshalJSON serializes the PrismIR to indented JSON.
// Uses type alias to avoid infinite recursion.
func (ir PrismIR) MarshalJSON() ([]byte, error) {
	type Alias PrismIR
	return json.MarshalIndent(Alias(ir), "", "  ")
}

// UnmarshalIR deserializes a PrismIR from JSON bytes.
func UnmarshalIR(data []byte) (PrismIR, error) {
	var ir PrismIR
	if err := json.Unmarshal(data, &ir); err != nil {
		return PrismIR{}, fmt.Errorf("prismir: unmarshal failed: %w", err)
	}
	return ir, nil
}

// ----------------------------------------------------------
// Validation
// ----------------------------------------------------------

// Validate checks the PrismIR for required fields and value ranges.
func (ir PrismIR) Validate() error {
	if ir.PrismIRVersion == "" {
		return fmt.Errorf("prismir: prismir_version must not be empty")
	}
	if ir.Meta.Version == "" {
		return fmt.Errorf("prismir: meta.version must not be empty")
	}
	if ir.Meta.Engine == "" {
		return fmt.Errorf("prismir: meta.engine must not be empty")
	}
	if ir.Meta.Timestamp == "" {
		return fmt.Errorf("prismir: meta.timestamp must not be empty")
	}
	if ir.Meta.HorizonDays <= 0 {
		return fmt.Errorf("prismir: meta.horizon_days must be positive, got %d", ir.Meta.HorizonDays)
	}
	if ir.Input.HostID == "" {
		return fmt.Errorf("prismir: input.host_id must not be empty")
	}
	if ir.Input.SSAMScore < 0 || ir.Input.SSAMScore > 100 {
		return fmt.Errorf("prismir: input.ssam_score must be in [0, 100], got %f", ir.Input.SSAMScore)
	}
	if ir.Output.Core.PrismScore < 0 || ir.Output.Core.PrismScore > 100 {
		return fmt.Errorf("prismir: output.core.prism_score must be in [0, 100], got %f", ir.Output.Core.PrismScore)
	}
	if ir.Output.Semantic.DominantState == "" {
		return fmt.Errorf("prismir: output.semantic.dominant_state must not be empty")
	}
	validStates := map[string]bool{"Stable": true, "Degraded": true, "Untrusted": true, "Collapse": true}
	if !validStates[ir.Output.Semantic.DominantState] {
		return fmt.Errorf("prismir: output.semantic.dominant_state must be one of Stable/Degraded/Untrusted/Collapse, got %q", ir.Output.Semantic.DominantState)
	}
	validTrends := map[string]bool{"improving": true, "stable": true, "degrading": true, "collapsing": true}
	if !validTrends[ir.Output.Inference.Trend] {
		return fmt.Errorf("prismir: output.inference.trend must be one of improving/stable/degrading/collapsing, got %q", ir.Output.Inference.Trend)
	}
	if ir.Output.Inference.Model == "" {
		return fmt.Errorf("prismir: output.inference.model must not be empty")
	}
	return nil
}