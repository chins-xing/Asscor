package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
)

type Config struct {
	Weights      model.Weights
	Threshold    float64
	EdgeFactors       model.EdgeFactors
	EdgeFactorsCustom map[string]float64
	ThreatCoeff  float64
	SPCEnabled   bool
	ComplianceFramework string
	DataDir      string

	ACINetworkSegmentation float64
	ACILAPSEnabled        float64
	ACIOfflineBackup      float64
	ACIEDRRunning         float64
	ACIRemoteLogging      float64
	ACIAppWhitelist       float64
	ACIDLPMeasures        float64

	CheckDeltas map[string]float64

	SPC model.SPCConfig

	Extensions       map[string]bool
	ExtensionWeights map[string]float64

	AdapterConfig map[string]string

	ExtMgrCfg ExtMgrConfig

	HotloadEnabled bool
	HotloadIntervalS int
}

type ExtMgrConfig struct {
	Enabled          bool
	ExtensionsDir    string
	StateDir         string
	AutoEnable       bool
	AllowPreRelease  bool
	ExecutionPolicy  string
	ExecutionTimeout int
	Repositories     []string
	WhitelistCmds    []string
	WorkingDir       string
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
			SYNCookieDisabled: 0.75,
			SELinuxDisabled:  0.80,
			AppArmorDisabled: 0.82,
			NoSIEM:           0.90,
			NoIDS:            0.88,
		},
		ACINetworkSegmentation: -15,
		ACILAPSEnabled:        -10,
		ACIOfflineBackup:      -20,
		ACIEDRRunning:         -10,
		ACIRemoteLogging:      -10,
		ACIAppWhitelist:       -10,
		ACIDLPMeasures:        -5,
		CheckDeltas:           make(map[string]float64),
		Extensions:            make(map[string]bool),
		ExtensionWeights:      make(map[string]float64),
		AdapterConfig:         make(map[string]string),
		SPC: model.SPCConfig{
			Enabled:            false,
			MinPScore:          0.60,
			CacheRetentionDays: 365,
			FetchIntervalH:     1,
			NVD: model.NVConfig{
				BaseURL:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
				APIKey:         "",
				SyncIntervalH:  6,
				UseLastMod:     false,
				NoRejected:     true,
			},
			EPSS: model.EPSSConfig{
				Enabled:       true,
				DataURL:       "https://epss.cyentia.com/epss_scores-current.csv.gz",
				SyncIntervalH: 24,
			},
			CISAKEV: model.CISAKEVConfig{
				Enabled:       true,
				CatalogURL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
				SyncIntervalH: 24,
			},
			MISP: model.MISPConfig{
				BaseURL:        "",
				APIKey:         "",
				VerifyTLS:      true,
				SyncIntervalH:  1,
				TLPFilter:      "white",
			},
			OSCAL: model.OSCALConfig{
				Enabled:     false,
				InputFormat: "json",
				ResultsPath: "./oscal_results/",
				PlanPath:    "./oscal_plan/",
			},
			CNNVD: model.CNNVDConfig{
				Enabled:       false,
				BaseURL:       "https://www.cnnvd.org.cn/home/data",
				APIKey:        "",
				SyncIntervalH: 24,
			},
			CNVD: model.CNVDConfig{
				Enabled:       false,
				BaseURL:       "https://www.cnvd.org.cn/shareData",
				SyncIntervalH: 24,
			},
		},
		ExtMgrCfg: ExtMgrConfig{
			Enabled:          true,
			ExtensionsDir:    "./extensions",
			StateDir:         "./extensions/state",
			AutoEnable:       false,
			AllowPreRelease:  false,
			ExecutionPolicy:  "whitelist",
			ExecutionTimeout: 30,
			WorkingDir:       "./extensions/runtime",
		},
		HotloadEnabled:   false,
		HotloadIntervalS: 30,
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
			case "data_dir":
				cfg.DataDir = v
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
			case "syn_cookie_disabled":
				cfg.EdgeFactors.SYNCookieDisabled = f
			case "selinux_disabled":
				cfg.EdgeFactors.SELinuxDisabled = f
			case "apparmor_disabled":
				cfg.EdgeFactors.AppArmorDisabled = f
			case "no_siem":
				cfg.EdgeFactors.NoSIEM = f
			case "no_ids":
				cfg.EdgeFactors.NoIDS = f
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

	if sec, ok := sections["check_deltas.ks"]; ok {
		for k, v := range sec {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.CheckDeltas[k] = f
			}
		}
	}

	if sec, ok := sections["extensions"]; ok {
		for k, v := range sec {
			cfg.Extensions[k] = strings.EqualFold(v, "on") || strings.EqualFold(v, "true") || v == "1"
		}
	}

	if sec, ok := sections["extension_weights"]; ok {
		for k, v := range sec {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.ExtensionWeights[k] = f
			}
		}
	}

	if sec, ok := sections["spc"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "min_pscore":
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					cfg.SPC.MinPScore = f
				}
			case "cache_retention_days":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.CacheRetentionDays = i
				}
			case "fetch_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.FetchIntervalH = i
				}
			}
		}
	}

	if sec, ok := sections["spc.nvd"]; ok {
		for k, v := range sec {
			switch k {
			case "base_url":
				cfg.SPC.NVD.BaseURL = v
			case "api_key":
				cfg.SPC.NVD.APIKey = v
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.NVD.SyncIntervalH = i
				}
			case "use_last_mod":
				cfg.SPC.NVD.UseLastMod = strings.EqualFold(v, "true") || v == "1"
			case "no_rejected":
				cfg.SPC.NVD.NoRejected = strings.EqualFold(v, "true") || v == "1"
			}
		}
		if envKey := os.Getenv("NVD_API_KEY"); envKey != "" {
			cfg.SPC.NVD.APIKey = envKey
			logger.WithComponent("config").Info("NVD API key loaded from environment variable", "source", "NVD_API_KEY")
		} else if cfg.SPC.NVD.APIKey != "" {
			logger.WithComponent("config").Info("NVD API key loaded from configuration file", "key_length", len(cfg.SPC.NVD.APIKey))
		}
	}

	if sec, ok := sections["spc.epss"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.EPSS.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "data_url":
				cfg.SPC.EPSS.DataURL = v
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.EPSS.SyncIntervalH = i
				}
			}
		}
	}

	if sec, ok := sections["spc.cisa_kev"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.CISAKEV.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "catalog_url":
				cfg.SPC.CISAKEV.CatalogURL = v
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.CISAKEV.SyncIntervalH = i
				}
			}
		}
	}

	if sec, ok := sections["spc.misp"]; ok {
		for k, v := range sec {
			switch k {
			case "base_url":
				cfg.SPC.MISP.BaseURL = v
			case "api_key":
				cfg.SPC.MISP.APIKey = v
			case "verify_tls":
				cfg.SPC.MISP.VerifyTLS = strings.EqualFold(v, "true") || v == "1"
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.MISP.SyncIntervalH = i
				}
			case "tlp_filter":
				cfg.SPC.MISP.TLPFilter = v
			}
		}
		if envKey := os.Getenv("MISP_API_KEY"); envKey != "" {
			cfg.SPC.MISP.APIKey = envKey
			logger.WithComponent("config").Info("MISP API key loaded from environment variable", "source", "MISP_API_KEY")
		} else if cfg.SPC.MISP.APIKey != "" {
			logger.WithComponent("config").Info("MISP API key loaded from configuration file", "key_length", len(cfg.SPC.MISP.APIKey))
		}
	}

	if sec, ok := sections["spc.oscal"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.OSCAL.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "input_format":
				cfg.SPC.OSCAL.InputFormat = v
			case "results_path":
				cfg.SPC.OSCAL.ResultsPath = v
			case "plan_path":
				cfg.SPC.OSCAL.PlanPath = v
			}
		}
	}

	if sec, ok := sections["spc.cnnvd"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.CNNVD.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "base_url":
				cfg.SPC.CNNVD.BaseURL = v
			case "api_key":
				cfg.SPC.CNNVD.APIKey = v
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.CNNVD.SyncIntervalH = i
				}
			}
		}
		if envKey := os.Getenv("CNNVD_API_KEY"); envKey != "" {
			cfg.SPC.CNNVD.APIKey = envKey
		}
	}

	if sec, ok := sections["spc.cnvd"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.SPC.CNVD.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "base_url":
				cfg.SPC.CNVD.BaseURL = v
			case "sync_interval_h":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.SPC.CNVD.SyncIntervalH = i
				}
			}
		}
	}

	cfg.Weights.Normalize()

	if sec, ok := sections["edge_factors.custom"]; ok {
		if cfg.EdgeFactorsCustom == nil {
			cfg.EdgeFactorsCustom = make(map[string]float64)
		}
		for k, v := range sec {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 1.0 {
				model.SetEdgeFactorValue(k, f)
				model.SetEdgeFactorActive(k, false)
				cfg.EdgeFactorsCustom[k] = f
			}
		}
	}

	if sec, ok := sections["domain_registry"]; ok {
		for domain, status := range sec {
			if strings.EqualFold(status, "on") || status == "1" {
				if _, exists := model.GetDomainMeta(domain); !exists {
					model.RegisterDomain(model.DomainMeta{
						ID:            domain,
						Label:         domain,
						Category:      model.CategoryExtension,
						DefaultWeight: 5,
					})
				}
			}
		}
	}

	if sec, ok := sections["extension_manager"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.ExtMgrCfg.Enabled = strings.EqualFold(v, "true") || v == "1"
			case "extensions_dir":
				cfg.ExtMgrCfg.ExtensionsDir = v
			case "state_dir":
				cfg.ExtMgrCfg.StateDir = v
			case "auto_enable":
				cfg.ExtMgrCfg.AutoEnable = strings.EqualFold(v, "true") || v == "1"
			case "allow_prerelease":
				cfg.ExtMgrCfg.AllowPreRelease = strings.EqualFold(v, "true") || v == "1"
			case "execution_policy":
				cfg.ExtMgrCfg.ExecutionPolicy = v
			case "execution_timeout_s":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.ExtMgrCfg.ExecutionTimeout = i
				}
			}
		}
	}

	if sec, ok := sections["extension_manager.repositories"]; ok {
		for _, v := range sec {
			cfg.ExtMgrCfg.Repositories = append(cfg.ExtMgrCfg.Repositories, v)
		}
	}

	if sec, ok := sections["extension_manager.whitelist"]; ok {
		for _, v := range sec {
			cfg.ExtMgrCfg.WhitelistCmds = append(cfg.ExtMgrCfg.WhitelistCmds, v)
		}
	}

	if sec, ok := sections["extension_manager.execution"]; ok {
		for k, v := range sec {
			switch k {
			case "policy":
				cfg.ExtMgrCfg.ExecutionPolicy = v
			case "timeout_s":
				if i, err := strconv.Atoi(v); err == nil {
					cfg.ExtMgrCfg.ExecutionTimeout = i
				}
			case "working_dir":
				cfg.ExtMgrCfg.WorkingDir = v
			}
		}
	}

	if sec, ok := sections["weights_hotload"]; ok {
		for k, v := range sec {
			switch k {
			case "enabled":
				cfg.HotloadEnabled = strings.EqualFold(v, "true") || v == "1"
			case "interval_s":
				if i, err := strconv.Atoi(v); err == nil && i > 0 {
					cfg.HotloadIntervalS = i
				}
			}
		}
	}

	cfg.buildAdapterConfig(sections)

	return cfg, nil
}

func (cfg *Config) buildAdapterConfig(sections map[string]map[string]string) {
	adapterSections := map[string]bool{
		"adapters": true, "adapter_paths": true,
		"trivy": true, "nuclei": true, "lynis": true,
		"openscap": true, "wazuh_agent": true, "suricata": true,
		"falco": true, "clamav": true, "osv_scanner": true,
		"aide": true, "nikto": true,
		"management_adapters": true,
		"ansible": true, "netbox": true, "snipe_it": true,
		"freeipa": true, "keycloak": true, "wazuh_siem": true,
		"rundeck": true, "jira": true, "terraform": true, "opentofu": true,
		"interceptor": true,
		"grpc": true, "log": true,
	}

	for sectionName, kv := range sections {
		if !adapterSections[sectionName] {
			continue
		}
		switch sectionName {
		case "adapters", "management_adapters":
			for k, v := range kv {
				cfg.AdapterConfig[k] = v
			}
		case "adapter_paths":
			for k, v := range kv {
				cfg.AdapterConfig["adapter_paths."+k] = v
			}
		default:
			for k, v := range kv {
				cfg.AdapterConfig[sectionName+"."+k] = v
			}
		}
	}
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
