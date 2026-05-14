package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/argus-security/argus/internal/model"
)

type Config struct {
	Weights      model.Weights
	Threshold    float64
	EdgeFactors  model.EdgeFactors
	ThreatCoeff  float64
	SPCEnabled   bool
	ComplianceFramework string

	ACINetworkSegmentation float64
	ACILAPSEnabled        float64
	ACIOfflineBackup      float64
	ACIEDRRunning         float64
	ACIRemoteLogging      float64
	ACIAppWhitelist       float64
	ACIDLPMeasures        float64

	CheckDeltas map[string]float64
}

func Default() *Config {
	return &Config{
		Weights: model.Weights{
			AttackSurface:      35,
			BusinessContinuity: 25,
			OperationTrust:     25,
			Resilience:         15,
		},
		Threshold:   80.0,
		ThreatCoeff: 1.0,
		SPCEnabled:  false,
		EdgeFactors: model.EdgeFactors{
			TwoFactorFailure: 1.0,
		},
		ACINetworkSegmentation: -15,
		ACILAPSEnabled:        -10,
		ACIOfflineBackup:      -20,
		ACIEDRRunning:         -10,
		ACIRemoteLogging:      -10,
		ACIAppWhitelist:       -10,
		ACIDLPMeasures:        -5,
		CheckDeltas:           make(map[string]float64),
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(string(data))
}

func Parse(content string) (*Config, error) {
	cfg := Default()
	sections := parseSections(content)

	if sec, ok := sections["weights"]; ok {
		for k, v := range sec {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "attack_surface":
				cfg.Weights.AttackSurface = f
			case "business_continuity":
				cfg.Weights.BusinessContinuity = f
			case "operation_trust":
				cfg.Weights.OperationTrust = f
			case "resilience":
				cfg.Weights.Resilience = f
			}
		}
	}

	if sec, ok := sections["acceptability"]; ok {
		for k, v := range sec {
			switch k {
			case "threshold":
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					cfg.Threshold = f
				}
			case "compliance_framework":
				cfg.ComplianceFramework = v
			}
		}
	}

	if sec, ok := sections["edge_factors"]; ok {
		for k, v := range sec {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "two_factor_failure":
				cfg.EdgeFactors.TwoFactorFailure = f
			}
		}
	}

	if sec, ok := sections["edge_factors.level4_override"]; ok {
		for k, v := range sec {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "two_factor_failure":
				cfg.EdgeFactors.TwoFactorFailure = f
			}
		}
	}

	if sec, ok := sections["threat"]; ok {
		if v, ok := sec["coefficient"]; ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.ThreatCoeff = f
			}
		}
		if v, ok := sec["spc_enabled"]; ok {
			cfg.SPCEnabled = strings.EqualFold(v, "true") || v == "1"
		}
	}

	if sec, ok := sections["resilience"]; ok {
		for k, v := range sec {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "aci_network_segmentation":
				cfg.ACINetworkSegmentation = f
			case "aci_laps_enabled":
				cfg.ACILAPSEnabled = f
			case "aci_offline_backup":
				cfg.ACIOfflineBackup = f
			case "aci_edr_running":
				cfg.ACIEDRRunning = f
			case "aci_remote_logging":
				cfg.ACIRemoteLogging = f
			case "aci_app_whitelist":
				cfg.ACIAppWhitelist = f
			case "aci_dlp_measures":
				cfg.ACIDLPMeasures = f
			}
		}
	}

	if sec, ok := sections["check_deltas"]; ok {
		for k, v := range sec {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.CheckDeltas[k] = f
			}
		}
	}

	cfg.Weights.Normalize()

	return cfg, nil
}

func parseSections(content string) map[string]map[string]string {
	sections := make(map[string]map[string]string)
	var currentSection string

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sections[currentSection] == nil {
				sections[currentSection] = make(map[string]string)
			}
			continue
		}
		if currentSection == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])
		sections[currentSection][key] = val
	}
	return sections
}
