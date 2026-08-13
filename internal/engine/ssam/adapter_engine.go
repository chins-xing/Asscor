//go:build engine

package ssam

import (
	"context"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/model"
)

// EngineAdapter wraps ssam.Engine to implement engine.AssessorEngine.
// This is the bridge that makes SSAM into an ASSCOR plugin.
// Dependency direction: ssam → ASSCOR (not ASSCOR → ssam).
type EngineAdapter struct {
	engine *Engine
}

// NewEngineAdapter creates a new SSAM adapter that satisfies engine.AssessorEngine.
// Pass the returned value to Assessor.SetPluginEngine().
func NewEngineAdapter(cfg *config.Config) *EngineAdapter {
	e := NewEngine()
	if cfg != nil {
		e.SetWeights(ConfigToWeights(cfg))
		e.SetEdgeFactors(ConfigToEdgeFactors(cfg))
	}
	e.InitializeDefaults(nil, nil)
	return &EngineAdapter{engine: e}
}

func (a *EngineAdapter) ComputeScore(ctx context.Context, result *model.AssessmentResult) error {
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
	a.engine.SetWeights(ConfigToWeights(cfg))
	a.engine.SetEdgeFactors(ConfigToEdgeFactors(cfg))
}

var _ engine.AssessorEngine = (*EngineAdapter)(nil)
