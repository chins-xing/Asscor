//go:build engine

package ssam

import (
	"context"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	"github.com/chins-xing/asscor/internal/model"
)

// EngineAdapter wraps ssam.Engine to implement engine.AssessorEngine.
// This is the bridge that makes SSAM into an ASSCOR plugin.
// Dependency direction: ssam → ASSCOR (not ASSCOR → ssam).
type EngineAdapter struct {
	engine *Engine
	// confCfg retains the kernel config used for confidence resolution
	// (per-check rule lookup happens right before each ComputeScore, so it
	// reflects hot-reloaded [confidence] rules via ReloadWeights).
	confCfg *config.Config
}

// NewEngineAdapter creates a new SSAM adapter that satisfies engine.AssessorEngine.
// Pass the returned value to Assessor.SetPluginEngine().
func NewEngineAdapter(cfg *config.Config) *EngineAdapter {
	e := NewEngine()
	if cfg != nil {
		e.SetWeights(ConfigToWeights(cfg))
		e.SetEdgeFactors(ConfigToEdgeFactors(cfg))
		e.SetConfidencePolicy(ConfigToConfidencePolicy(cfg))
	}
	e.InitializeDefaults(nil, nil)
	return &EngineAdapter{engine: e, confCfg: cfg}
}

// confCfgPtr returns the retained config (may be nil).
func (a *EngineAdapter) confCfgPtr() *config.Config { return a.confCfg }

func (a *EngineAdapter) ComputeScore(ctx context.Context, result *model.AssessmentResult) error {
	// Confidence-native: fill per-check confidences from the kernel rule
	// table before mapping into the library input (design §3). Results that
	// already carry an explicit upstream confidence are preserved.
	ResolveCheckConfidence(a.confCfgPtr(), result)

	input := &AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Threshold:   result.Threshold,
		Checks:      CheckResultsToInputs(result.Checks),
		ThreatCoeff: result.ThreatCoeff,
		SPCScore:    result.SPCScore,
	}
	output, err := a.engine.ComputeScore(ctx, input)
	if err != nil {
		return err
	}
	OutputToModel(output, result)
	return nil
}

func (a *EngineAdapter) Name() string {
	return "ssam_v2.0"
}

func (a *EngineAdapter) ReloadWeights(cfg *config.Config) {
	if cfg == nil {
		return
	}
	a.confCfg = cfg
	a.engine.SetWeights(ConfigToWeights(cfg))
	a.engine.SetEdgeFactors(ConfigToEdgeFactors(cfg))
	a.engine.SetConfidencePolicy(ConfigToConfidencePolicy(cfg))
}

var _ engine.AssessorEngine = (*EngineAdapter)(nil)
