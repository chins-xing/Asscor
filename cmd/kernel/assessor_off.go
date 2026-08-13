//go:build !assessor

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

func newAssessor() kernel.AssessorInterface { return nil }

func newScoringEngine(cfg *config.Config) kernel.ScoringEngineProvider { return nil }
