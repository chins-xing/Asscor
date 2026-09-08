//go:build spc && engine

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/spc"
)

type spcAdapter struct {
	module *spc.Module
}

func (a *spcAdapter) Enabled() bool {
	return a.module.Enabled()
}

func (a *spcAdapter) GetAsset(hostID string) *engine.SPCLocalAsset {
	asset := a.module.GetAsset(hostID)
	if asset == nil {
		return nil
	}
	return &engine.SPCLocalAsset{
		HostID:        asset.HostID,
		NetworkZone:   asset.NetworkZone,
		Role:          asset.Role,
		Packages:      asset.Packages,
		InstalledCPEs: asset.InstalledCPEs,
		Compensations: engine.SPCCompensations{
			VirtualPatch: asset.Compensations.VirtualPatch,
			WAFRules:     asset.Compensations.WAFRules,
			IPSRules:     asset.Compensations.IPSRules,
			AppWhitelist: asset.Compensations.AppWhitelist,
		},
	}
}

func (a *spcAdapter) UpsertAsset(asset engine.SPCLocalAsset) {
	la := kernel.LocalAsset{
		HostID:        asset.HostID,
		NetworkZone:   asset.NetworkZone,
		Role:          asset.Role,
		Packages:      asset.Packages,
		InstalledCPEs: asset.InstalledCPEs,
	}
	la.Compensations.VirtualPatch = asset.Compensations.VirtualPatch
	la.Compensations.WAFRules = asset.Compensations.WAFRules
	la.Compensations.IPSRules = asset.Compensations.IPSRules
	la.Compensations.AppWhitelist = asset.Compensations.AppWhitelist
	a.module.UpsertAsset(la)
}

func (a *spcAdapter) Calculate(hostID string, assetPackages []string) engine.SPCCorrection {
	correction := a.module.Calculate(hostID, assetPackages)
	return engine.SPCCorrection{
		Score:          correction.Score,
		Weights:        correction.Weights,
		Action:         correction.Action,
		AffectedCVE:    correction.AffectedCVE,
		TopCVEImpact:   correction.TopCVEImpact,
		TotalPenalty:   correction.TotalPenalty,
		KillChainScore: correction.KillChainScore,
	}
}

func attachSPC(cfg *config.Config, assessor *engine.Assessor) {
	if !cfg.SPC.Enabled {
		return
	}
	spcModule := spc.New()
	spcModule.ConfigureFromConfig(cfg)
	spcModule.FetchFromAllSources()
	assessor.SetSPCProvider(&spcAdapter{module: spcModule})
	logger.WithComponent("main").Info("SPC module initialized and attached to assessor")
}
