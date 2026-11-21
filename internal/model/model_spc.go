package model

type SPCCVEInfo struct {
	CVEID   string  `json:"cve_id"`
	CVSS    float64 `json:"cvss"`
	EPSS    float64 `json:"epss"`
	InKEV   bool    `json:"in_kev"`
	HasPoC  bool    `json:"has_poc"`
	Penalty float64 `json:"penalty"`
	Product string  `json:"product,omitempty"`
}

type SPCConfig struct {
	Enabled   bool
	MinPScore float64
	// Impact formula weights (audit A16; defaults 0.20/0.50/0.30).
	ImpactCVSSWeight float64
	ImpactEPSSWeight float64
	ImpactKEVWeight  float64
	// Amplifiers per sub-technique / APT association (defaults 0.1 / 0.2)
	// and the KEV substitute factor for public PoC (default 0.3).
	SubTechGrowth      float64
	APTGrowth          float64
	PoCFactor          float64
	CacheRetentionDays int
	FetchIntervalH     int
	MaxCacheSize       int
	NVD                NVConfig
	EPSS               EPSSConfig
	CISAKEV            CISAKEVConfig
	MISP               MISPConfig
	OSCAL              OSCALConfig
	CNNVD              CNNVDConfig
	CNVD               CNVDConfig
}

type NVConfig struct {
	BaseURL       string
	APIKey        string
	SyncIntervalH int
	UseLastMod    bool
	NoRejected    bool
}

type EPSSConfig struct {
	Enabled       bool
	DataURL       string
	SyncIntervalH int
}

type CISAKEVConfig struct {
	Enabled       bool
	CatalogURL    string
	SyncIntervalH int
}

type MISPConfig struct {
	BaseURL       string
	APIKey        string
	VerifyTLS     bool
	SyncIntervalH int
	TLPFilter     string
}

type OSCALConfig struct {
	Enabled     bool
	InputFormat string
	ResultsPath string
	PlanPath    string
}

type CNNVDConfig struct {
	Enabled       bool
	BaseURL       string
	APIKey        string
	SyncIntervalH int
}

type CNVDConfig struct {
	Enabled       bool
	BaseURL       string
	SyncIntervalH int
}
