//go:build assessor

package main

import (
	"github.com/asscor/asscor/internal/assessor"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

// newAssessor returns the assessor module, or nil when the assessor build tag
// is disabled (kernel zero-bloat).
func newAssessor() kernel.AssessorInterface {
	return assessor.New()
}

// newScoringEngine returns the scoring engine provider plugin, or nil when the
// assessor build tag is disabled.
func newScoringEngine(cfg *config.Config) kernel.ScoringEngineProvider {
	return assessor.NewScoringEngine(cfg)
}
