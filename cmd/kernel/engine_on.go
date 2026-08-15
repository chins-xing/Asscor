//go:build engine

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	ascorprism "github.com/asscor/asscor/internal/engine/prism"
	"github.com/asscor/asscor/internal/engine/ssam"
	"github.com/asscor/asscor/internal/kernel"
)

// newSSAMEngineAdapter returns the SSAM algorithm engine adapter, or nil when
// the engine build tag is disabled.
func newSSAMEngineAdapter(cfg *config.Config) kernel.AssessorEngine {
	return ssam.NewEngineAdapter(cfg)
}

// newPrismEngine returns the Prism risk-dynamics engine, or nil when the
// engine build tag is disabled.
func newPrismEngine() kernel.PrismEngineProvider {
	return ascorprism.NewEngine()
}

// newEngineScorer returns the concrete scoring engine implementation injected
// into the assessor module. It lives in this engine-tagged file so the
// assessor module itself never imports the engine package.
func newEngineScorer(cfg *config.Config) kernel.EngineScorer {
	return engine.NewAssessor(cfg)
}
