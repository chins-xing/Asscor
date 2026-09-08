//go:build attck_ext && engine

package main

import (
	"github.com/asscor/asscor/internal/attck"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
)

func init() {
	registeredASSCOrATTACKInit = func(assessor *engine.Assessor, cfg *config.Config) {
		attckMod := attck.New()
		attckMod.ConfigureFromConfig(cfg)
		assessor.SetATTACKProvider(attckMod.AsEngineProvider())
	}
}
