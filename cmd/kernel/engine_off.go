//go:build !engine

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

func newSSAMEngineAdapter(cfg *config.Config) kernel.AssessorEngine { return nil }

func newPrismEngine() kernel.PrismEngineProvider { return nil }

func newEngineScorer(cfg *config.Config) kernel.EngineScorer { return nil }
