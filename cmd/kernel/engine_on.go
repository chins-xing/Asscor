//go:build engine

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	ascorprism "github.com/asscor/asscor/internal/engine/prism"
	"github.com/asscor/asscor/internal/engine/ssam"
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
