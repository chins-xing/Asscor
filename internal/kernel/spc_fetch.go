package kernel

import (
	"sort"
	"time"

	"github.com/asscor/asscor/internal/common"
)

func (m *SPCModule) FetchFromAllSources() []SPCFetchResult {
	sourceCount := 1 // NVD
	if m.epssConfig.Enabled {
		sourceCount++
	}
	if m.kevConfig.Enabled {
		sourceCount++
	}
	if m.mispConfig.BaseURL != "" {
		sourceCount++
	}
	if m.cnnvdConfig.Enabled {
		sourceCount++
	}
	if m.cnvdConfig.Enabled {
		sourceCount++
	}

	results := make([]SPCFetchResult, 0, sourceCount)

	mp := common.NewMultiProgress()

	overallBar := mp.AddBar("spc_overall", int64(sourceCount), "SPC Sync")

	result := m.FetchFromNVD()
	results = append(results, result)
	overallBar.Increment()

	if m.epssConfig.Enabled {
		resultEPSS := m.FetchFromEPSS()
		results = append(results, resultEPSS)
		overallBar.Increment()
	}

	if m.kevConfig.Enabled {
		resultKEV := m.FetchFromCISAKEV()
		results = append(results, resultKEV)
		overallBar.Increment()
	}

	result2 := m.FetchFromMISP()
	results = append(results, result2)
	if m.mispConfig.BaseURL != "" {
		overallBar.Increment()
	}

	if m.cnnvdConfig.Enabled {
		resultCNNVD := m.FetchFromCNNVD()
		results = append(results, resultCNNVD)
		overallBar.Increment()
	}

	if m.cnvdConfig.Enabled {
		resultCNVD := m.FetchFromCNVD()
		results = append(results, resultCNVD)
		overallBar.Increment()
	}

	overallBar.Finish()
	mp.FinishAll()

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.fetchResults = append(m.fetchResults, results...)
	if len(m.fetchResults) > 100 {
		m.fetchResults = m.fetchResults[len(m.fetchResults)-100:]
	}
	m.mu.Unlock()

	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "spc.cve_updated", results)
	}

	if m.kernel != nil {
		if persister, ok := m.kernel.Container().ResolveNamed("persistence"); ok {
		if pi, ok2 := persister.(PersistenceInterface); ok2 {
			topCVEs := make([]string, 0, 10)
			m.mu.RLock()
			sorted := make([]SPCCVEScore, len(m.cveCache))
			copy(sorted, m.cveCache)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].CVSS > sorted[j].CVSS
			})
			for i := 0; i < len(sorted) && i < 10; i++ {
				topCVEs = append(topCVEs, sorted[i].CVEID)
			}
			kevCount := 0
			highCount := 0
			for _, cve := range m.cveCache {
				if cve.InKEV {
					kevCount++
				}
				if cve.CVSS >= 7.0 {
					highCount++
				}
			}
			m.mu.RUnlock()

			pi.WriteCVECache(CVECacheRecord{
				Timestamp:  time.Now(),
				TotalCount: len(m.cveCache),
				HighCount:  highCount,
				KEVCount:   kevCount,
				TopCVEs:    topCVEs,
				Sources: map[string]interface{}{
					"nvd":  result,
					"misp": result2,
				},
			})
		}
	}
	}

	return results
}
