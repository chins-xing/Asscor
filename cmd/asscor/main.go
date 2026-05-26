package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"

	_ "github.com/asscor/asscor/internal/checks"
)

type spcAdapter struct {
	module *kernel.SPCModule
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
		Score:        correction.Score,
		Weights:      correction.Weights,
		Action:       correction.Action,
		AffectedCVE:  correction.AffectedCVE,
		TopCVEImpact: correction.TopCVEImpact,
		TotalPenalty: correction.TotalPenalty,
		KillChainScore: correction.KillChainScore,
	}
}

func main() {
	configPath := flag.String("config", "config.ini", "配置文件路径")
	jsonOutput := flag.Bool("json", false, "以JSON格式输出")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法加载配置文件 %s: %v\n使用默认配置\n", *configPath, err)
		cfg = config.Default()
	}

	assessor := engine.NewAssessor(cfg)

	if cfg.SPC.Enabled {
		spcModule := kernel.NewSPCModule()
		spcModule.ConfigureFromConfig(cfg)
		spcModule.FetchFromAllSources()
		assessor.SetSPCProvider(&spcAdapter{module: spcModule})
		logger.WithComponent("main").Info("SPC module initialized and attached to assessor")
	}

	result := assessor.Assess("", "")

	if *jsonOutput {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Print(assessor.PrintReport(result))
	}

	if !result.Acceptable {
		os.Exit(1)
	}
}
