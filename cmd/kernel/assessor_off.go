//go:build !assessor

package main

import (
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
)

func newAssessor() kernel.AssessorInterface { return nil }

func newScoringEngine(cfg *config.Config) kernel.ScoringEngineProvider { return nil }
