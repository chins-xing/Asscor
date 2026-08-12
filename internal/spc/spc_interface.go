package spc

import "time"

type SPCInterface interface {
	SPCCalculator
	SPCFetcher
	SPCAssetManager
	SPCCacheManager
}

// SPCCalculator groups assessment calculation and CVE data operations.
type SPCCalculator interface {
	Calculate(hostID string, assetPackages []string) SPCCorrection
	AddCVE(score SPCCVEScore)
	AddCVEs(scores []SPCCVEScore)
	MergeCVEs(cves []SPCCVEScore) (added int, updated int)
	GetCVEs() []SPCCVEScore
	GetCVECount() int
}

// SPCFetcher groups data source fetching and status operations.
type SPCFetcher interface {
	FetchFromAllSources() []SPCFetchResult
	FetchFromEPSS() SPCFetchResult
	FetchFromCISAKEV() SPCFetchResult
	ImportOSCAL(data []byte, format string) (int, error)
	Enabled() bool
	SetEnabled(v bool)
	LastUpdate() time.Time
}

// SPCAssetManager groups asset and MISP configuration operations.
type SPCAssetManager interface {
	UpsertAsset(asset LocalAsset)
	GetAsset(hostID string) *LocalAsset
	ConfigureMISP(baseURL, apiKey string) error
}

// SPCCacheManager groups cache management and KEV catalog operations.
type SPCCacheManager interface {
	GetKEVCount() int
	GetKEVCatalog() []string
	Summary() map[string]interface{}
	ClearCache()
}
