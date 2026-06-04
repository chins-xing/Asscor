package spc

import (
	"net/http"
	"time"
)

const maxHTTPBodySize = 1 << 20

const DefaultEPSSDataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
const DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const DefaultKEVCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type MatchType int

const (
	MatchNone       MatchType = iota
	MatchCPEVendor            = 1
	MatchCPEProduct           = 2
	MatchVersionRange         = 3
	MatchExactVersion         = 4
)

func (m MatchType) Factor() float64 {
	switch m {
	case MatchExactVersion:
		return 1.0
	case MatchVersionRange:
		return 0.7
	case MatchCPEProduct:
		return 0.3
	case MatchCPEVendor:
		return 0.15
	default:
		return 0.0
	}
}

type ExposureLevel int

const (
	ExposureLocalhost ExposureLevel = iota
	ExposureInternal
	ExposureDMZ
	ExposurePublic
)

func (e ExposureLevel) Factor() float64 {
	switch e {
	case ExposurePublic:
		return 1.0
	case ExposureDMZ:
		return 0.7
	case ExposureInternal:
		return 0.4
	case ExposureLocalhost:
		return 0.1
	default:
		return 0.4
	}
}

func (e ExposureLevel) String() string {
	switch e {
	case ExposurePublic:
		return "public"
	case ExposureDMZ:
		return "dmz"
	case ExposureInternal:
		return "internal"
	case ExposureLocalhost:
		return "localhost"
	default:
		return "unknown"
	}
}

type ControlLevel int

const (
	ControlNone       ControlLevel = 0
	ControlPartial                 = 1
	ControlEffective               = 2
)

func (c ControlLevel) Factor() float64 {
	switch c {
	case ControlNone:
		return 1.0
	case ControlPartial:
		return 0.5
	case ControlEffective:
		return 0.2
	default:
		return 1.0
	}
}

type SPCAction int

const (
	ActionNone     SPCAction = iota
	ActionWarn
	ActionPatch
	ActionPriority
	ActionIsolate
)

func (a SPCAction) String() string {
	switch a {
	case ActionNone:
		return "none"
	case ActionWarn:
		return "notify_admin"
	case ActionPatch:
		return "patch_recommended"
	case ActionPriority:
		return "priority_fix"
	case ActionIsolate:
		return "isolate_host"
	default:
		return "none"
	}
}

func ClassifyAction(pscore float64) SPCAction {
	switch {
	case pscore >= 0.95:
		return ActionNone
	case pscore >= 0.85:
		return ActionWarn
	case pscore >= 0.75:
		return ActionPatch
	case pscore >= 0.65:
		return ActionPriority
	default:
		return ActionIsolate
	}
}

type CVESource string

const (
	SourceNVD   CVESource = "nvd"
	SourceKEV   CVESource = "kev"
	SourceEPSS  CVESource = "epss"
	SourceMISP  CVESource = "misp"
	SourceCNNVD CVESource = "cnnvd"
	SourceCNVD  CVESource = "cnvd"
	SourceOSCAL CVESource = "oscal"
)

var cveSourcePriority = map[CVESource]int{
	SourceNVD:   100,
	SourceKEV:   90,
	SourceEPSS:  80,
	SourceMISP:  70,
	SourceCNNVD: 60,
	SourceCNVD:  50,
	SourceOSCAL: 40,
}

func (s CVESource) Priority() int {
	if p, ok := cveSourcePriority[s]; ok {
		return p
	}
	return 0
}

type SPCCVEScore struct {
	CVEID              string       `json:"cve_id"`
	Description        string       `json:"description"`
	CVSS               float64      `json:"cvss_score"`
	CVSSVector         string       `json:"cvss_vector"`
	EPSS               float64      `json:"epss_score"`
	EPSSPercent        float64      `json:"epss_percentile"`
	InKEV              bool         `json:"in_kev"`
	HasPublicPoC       bool         `json:"has_public_poc"`
	DatePublished      time.Time    `json:"date_published"`
	DateModified       time.Time    `json:"date_modified"`
	AffectedCPEs       []string     `json:"affected_cpes"`
	AttckTechniques    []string     `json:"attck_techniques"`
	MISPGalaxyTags     []string     `json:"misp_galaxy_tags"`
	OSCALFindingUUID   string       `json:"oscal_finding_uuid,omitempty"`
	APTGroupAssoc      []string     `json:"apt_group_assoc,omitempty"`
	CWEs               []string     `json:"cwes,omitempty"`
	Source             CVESource    `json:"source,omitempty"`
	Matched            bool         `json:"matched"`
	MatchType          MatchType    `json:"match_type"`
	Exposure           ExposureLevel `json:"exposure"`
	ControlLevel       ControlLevel  `json:"control_level"`
}

type SPCVulnerabilityRecord struct {
	CVEID              string   `json:"cve_id"`
	Description        string   `json:"description"`
	CVSSScore          float64  `json:"cvss_score"`
	CVSSVector         string   `json:"cvss_vector"`
	EPSSScore          float64  `json:"epss_score"`
	EPSSPercent        float64  `json:"epss_percentile"`
	InKEV              bool     `json:"in_kev"`
	DatePublished      string   `json:"date_published"`
	DateModified       string   `json:"date_modified"`
	AffectedCPEs       []string `json:"affected_cpes"`
	AttckTechniques    []string `json:"attck_techniques"`
	MISPGalaxyTags     []string `json:"misp_galaxy_tags"`
	OSCALFindingUUID   string   `json:"oscal_finding_uuid,omitempty"`
	APTGroupAssoc      []string `json:"apt_group_assoc,omitempty"`
}

type SPCCorrection struct {
	Score              float64            `json:"p_score"`
	Weights            map[string]float64 `json:"p_weight"`
	Action             string             `json:"p_action"`
	AffectedCVE        []string           `json:"affected_cve"`
	TopCVEImpact       string             `json:"top_cve_impact"`
	TotalPenalty       float64            `json:"total_penalty"`
	PenaltyBreakdown   []CVEPenalty       `json:"penalty_breakdown,omitempty"`
	KillChainScore     float64            `json:"kill_chain_score,omitempty"`
}

type CVEPenalty struct {
	CVEID       string  `json:"cve_id"`
	CVSS        float64 `json:"cvss"`
	EPSS        float64 `json:"epss"`
	InKEV       bool    `json:"in_kev"`
	HasPoC      bool    `json:"has_poc"`
	Impact      float64 `json:"impact"`
	CVSSFactor  float64 `json:"cvss_factor"`
	EPSSFactor  float64 `json:"epss_factor"`
	KEVFactor   float64 `json:"kev_factor"`
	LocalFactor float64 `json:"local_factor"`
	TimeFactor  float64 `json:"time_factor"`
	Penalty     float64 `json:"penalty"`
	Products    string  `json:"products,omitempty"`
}

type LocalAsset struct {
	HostID          string   `json:"host_id"`
	Hostname        string   `json:"hostname"`
	Role            string   `json:"role"`
	Packages        []string `json:"packages"`
	InstalledCPEs   []string `json:"installed_cpes"`
	Services        []string `json:"services"`
	Ports           []int    `json:"ports"`
	NetworkZone     string   `json:"network_zone"`
	Compensations   struct {
		WAFRules       bool `json:"waf_rules"`
		IPSRules       bool `json:"ips_rules"`
		AppWhitelist   bool `json:"app_whitelist"`
		VirtualPatch   bool `json:"virtual_patch"`
	} `json:"compensations"`
}

type SPCFetchResult struct {
	Source      string        `json:"source"`
	CVEAdded    int           `json:"cve_added"`
	CVEUpdated  int           `json:"cve_updated"`
	Duration    time.Duration `json:"duration_ms"`
	Error       string        `json:"error,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
}

type SPCMISPConfig struct {
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
	VerifyTLS   bool   `json:"verify_tls"`
	SyncHours   int    `json:"sync_interval_h"`
	TLPFilter   string `json:"tlp_filter"`
}

type SPCMISPClient struct {
	config   SPCMISPConfig
	client   *http.Client
	lastSync time.Time
}

type SPCNVDConfig struct {
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
	SyncHours   int    `json:"sync_interval_h"`
	UseLastMod  bool   `json:"use_last_mod"`
	NoRejected  bool   `json:"no_rejected"`
}

type SPCOSCALConfig struct {
	Enabled       bool   `json:"enabled"`
	InputFormat   string `json:"input_format"`
	ResultsPath   string `json:"results_path"`
	PlanPath      string `json:"plan_path"`
}

type SPCEPSSConfig struct {
	Enabled         bool   `json:"enabled"`
	DataURL         string `json:"data_url"`
	SyncIntervalH   int    `json:"sync_interval_h"`
}

type SPCKEVConfig struct {
	Enabled         bool   `json:"enabled"`
	CatalogURL      string `json:"catalog_url"`
	SyncIntervalH   int    `json:"sync_interval_h"`
}

type SPCCNNVDConfig struct {
	Enabled         bool   `json:"enabled"`
	BaseURL         string `json:"base_url"`
	APIKey          string `json:"api_key"`
	SyncIntervalH   int    `json:"sync_interval_h"`
}

type SPCCNVDConfig struct {
	Enabled         bool   `json:"enabled"`
	BaseURL         string `json:"base_url"`
	SyncIntervalH   int    `json:"sync_interval_h"`
}
