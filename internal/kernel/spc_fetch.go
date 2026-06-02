package kernel

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
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

func (m *SPCModule) FetchFromNVD() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "nvd",
		Timestamp: time.Now(),
	}

	m.mu.Lock()
	m.lastNVDFetch = time.Now()
	baseURL := m.nvdConfig.BaseURL
	apiKey := m.nvdConfig.APIKey
	since := m.lastUpdate
	m.mu.Unlock()

	if baseURL == "" {
		baseURL = defaultNVDBaseURL
	}

	if since.IsZero() {
		since = time.Now().AddDate(0, 0, -120)
		m.mu.Lock()
		m.nvdConfig.UseLastMod = false
		m.nvdConfig.NoRejected = true
		m.mu.Unlock()
		logger.WithComponent("spc").Info("NVD initial sync, fetching last 120 days", "since", since.Format("2006-01-02"))
	} else {
		m.mu.Lock()
		m.nvdConfig.UseLastMod = true
		m.nvdConfig.NoRejected = true
		m.mu.Unlock()
		logger.WithComponent("spc").Info("NVD incremental sync", "since", since.Format("2006-01-02"))
	}

	cves, err := m.fetchNVDAPI(baseURL, apiKey, since)
	if err != nil {
		result.Error = err.Error()
		logger.WithComponent("spc").Warn("NVD API fetch failed, falling back to sample data", "error", err)
		cves = m.generateSampleCVEs()
	} else if len(cves) == 0 && m.lastUpdate.IsZero() {
		logger.WithComponent("spc").Warn("NVD API returned 0 CVEs on initial sync, falling back to sample data")
		cves = m.generateSampleCVEs()
	}

	logger.WithComponent("spc").Info("NVD API returned CVEs",
		"count", len(cves),
		"error", err,
		"since", since.Format("2006-01-02"),
	)

	m.mu.Lock()
	for _, cve := range cves {
		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			m.mergeCVEInPlace(idx, cve)
			result.CVEUpdated++
		} else {
			if len(m.cveCache) >= m.maxCacheSize {
				logger.WithComponent("spc").Warn("CVE cache reached max size", "max", m.maxCacheSize)
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.WithComponent("spc").Info("NVD fetch completed", "duration", result.Duration, "added", result.CVEAdded, "updated", result.CVEUpdated)
	return result
}

type nvdAPIResponse struct {
	TotalResults int              `json:"totalResults"`
	ResultsPerPage int            `json:"resultsPerPage"`
	StartIndex int                `json:"startIndex"`
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []nvdLangStr   `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Weaknesses     []nvdWeakness   `json:"weaknesses"`
	Configurations []nvdConfig     `json:"configurations"`
	References     []nvdReference  `json:"references"`
}

type nvdLangStr struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	Source   string     `json:"source"`
	Type     string     `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type nvdCVSSData struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
}

type nvdCVSSMetricV2 struct {
	Source       string       `json:"source"`
	Type         string       `json:"type"`
	CVSSData     nvdCVSSDataV2 `json:"cvssData"`
	BaseSeverity string       `json:"baseSeverity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type nvdCVSSDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Source          string        `json:"source"`
	Type            string        `json:"type"`
	Description     []nvdLangStr  `json:"description"`
}

type nvdConfig struct {
	Operator string      `json:"operator"`
	Nodes    []nvdNode   `json:"nodes"`
}

type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdReference struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Tags   []string `json:"tags"`
}

func (m *SPCModule) fetchNVDAPI(baseURL, apiKey string, since time.Time) ([]SPCCVEScore, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	maxRetries := 3

	useLastMod := m.nvdConfig.UseLastMod
	noRejected := m.nvdConfig.NoRejected

	startDate := since.UTC()
	finalEndDate := time.Now().UTC()

	maxRangeDays := 120

	nvdProgress := common.NewProgressBar(0, "NVD Fetch")
	nvdProgress.SetStyle(common.StyleSpinner)
	defer nvdProgress.Finish()

	totalDays := int(finalEndDate.Sub(startDate).Hours() / 24)
	if totalDays <= 0 {
		totalDays = 1
	}

	concurrency := 1
	chunkDays := maxRangeDays
	if apiKey == "" && totalDays > 30 {
		chunkDays = 30
		concurrency = 4
	} else if apiKey != "" && totalDays > 60 {
		chunkDays = 60
		concurrency = 2
	}

	var windows []struct {
		start time.Time
		end   time.Time
	}
	windowStart := startDate
	for {
		windowEnd := windowStart.AddDate(0, 0, chunkDays)
		if windowEnd.After(finalEndDate) {
			windowEnd = finalEndDate
		}
		windows = append(windows, struct {
			start time.Time
			end   time.Time
		}{windowStart, windowEnd})
		if windowEnd.Equal(finalEndDate) || windowEnd.After(finalEndDate) {
			break
		}
		windowStart = windowEnd
	}

	if concurrency > len(windows) {
		concurrency = len(windows)
	}

	logger.WithComponent("spc").Info("NVD fetch plan",
		"windows", len(windows),
		"concurrency", concurrency,
		"chunk_days", chunkDays,
		"has_api_key", apiKey != "",
		"total_days", totalDays,
	)

	type windowResult struct {
		cves []SPCCVEScore
		err  error
		idx  int
	}

	results := make([]windowResult, len(windows))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, w := range windows {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, start, end time.Time) {
			defer wg.Done()
			defer func() { <-sem }()

			startIdx := 0
			retryCount := 0
			cves, err := m.fetchNVDWindow(client, baseURL, apiKey, start, end, useLastMod, noRejected, &startIdx, &retryCount, maxRetries, nvdProgress)
			results[idx] = windowResult{cves: cves, err: err, idx: idx}
		}(i, w.start, w.end)
	}

	wg.Wait()

	var allCVEs []SPCCVEScore
	var firstErr error
	for _, r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		allCVEs = append(allCVEs, r.cves...)
	}

	if firstErr != nil && len(allCVEs) == 0 {
		return nil, firstErr
	}

	logger.WithComponent("spc").Info("NVD API fetched CVEs", "count", len(allCVEs), "since", since.Format("2006-01-02"))
	return allCVEs, nil
}

func (m *SPCModule) fetchNVDWindow(client *http.Client, baseURL, apiKey string, startDate, endDate time.Time, useLastMod, noRejected bool, startIdx *int, retryCount *int, maxRetries int, prog *common.ProgressBar) ([]SPCCVEScore, error) {
	var allCVEs []SPCCVEScore

	formatNVDDate := func(t time.Time) string {
		return t.Format("2006-01-02T15:04:05.000") + "Z"
	}

	for {
		var params []string
		if useLastMod {
			params = append(params, fmt.Sprintf("lastModStartDate=%s", url.QueryEscape(formatNVDDate(startDate))))
			params = append(params, fmt.Sprintf("lastModEndDate=%s", url.QueryEscape(formatNVDDate(endDate))))
		} else {
			params = append(params, fmt.Sprintf("pubStartDate=%s", url.QueryEscape(formatNVDDate(startDate))))
			params = append(params, fmt.Sprintf("pubEndDate=%s", url.QueryEscape(formatNVDDate(endDate))))
		}
		if noRejected {
			params = append(params, "noRejected")
		}
		params = append(params, fmt.Sprintf("startIndex=%d", *startIdx))

		reqURL := baseURL + "?" + strings.Join(params, "&")

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("NVD request creation: %w", err)
		}

		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		m.nvdLimiter <- struct{}{}
		t := time.AfterFunc(6*time.Second, func() {
			<-m.nvdLimiter
		})
		m.mu.Lock()
		m.nvdTimers = append(m.nvdTimers, t)
		m.mu.Unlock()

		prog.SetDesc(fmt.Sprintf("NVD Fetch (%d CVEs) requesting...", len(allCVEs)))

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				*retryCount++
				if *retryCount > maxRetries {
					return allCVEs, fmt.Errorf("NVD API timeout after %d retries (collected %d CVEs)", maxRetries, len(allCVEs))
				}
				backoff := time.Duration(1<<uint(*retryCount-1)) * 15 * time.Second
				prog.SetDesc(fmt.Sprintf("NVD Fetch timeout, retry %d/%d in %vs...", *retryCount, maxRetries, backoff.Seconds()))
				logger.WithComponent("spc").Warn("NVD API request timeout, retrying",
					"retry", *retryCount, "backoff", backoff)
				m.waitWithProgress(prog, backoff, "NVD retry wait")
				continue
			}
			return allCVEs, fmt.Errorf("NVD API call: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			cancel()
			*retryCount++
			if *retryCount > maxRetries {
				return allCVEs, fmt.Errorf("NVD API rate limited after %d retries (collected %d CVEs)", maxRetries, len(allCVEs))
			}
			backoff := time.Duration(10+1<<uint(*retryCount-1)*10) * time.Second
			prog.SetDesc(fmt.Sprintf("NVD 429 rate-limited, retry %d/%d in %vs...", *retryCount, maxRetries, backoff.Seconds()))
			logger.WithComponent("spc").Warn("NVD API rate limited (429), retrying",
				"retry", *retryCount, "backoff", backoff)
			m.waitWithProgress(prog, backoff, "NVD 429 wait")
			continue
		}

		cancel()

		*retryCount = 0

		logger.WithComponent("spc").Info("NVD API response received",
			"status", resp.StatusCode,
			"collected_so_far", len(allCVEs),
		)

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
			logger.WithComponent("spc").Error("NVD API non-200 response",
				"status", resp.StatusCode,
				"body_preview", truncateString(string(body), 500),
			)
			return allCVEs, fmt.Errorf("NVD API returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var apiResp nvdAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			logger.WithComponent("spc").Error("NVD response decode failed", "error", err, "collected", len(allCVEs))
			return allCVEs, fmt.Errorf("NVD response decode: %w", err)
		}

		logger.WithComponent("spc").Debug("NVD API response",
			"totalResults", apiResp.TotalResults,
			"resultsPerPage", apiResp.ResultsPerPage,
			"startIndex", apiResp.StartIndex,
			"vulnerabilities_in_page", len(apiResp.Vulnerabilities),
		)

		for _, vuln := range apiResp.Vulnerabilities {
			cve := m.parseNVDCVE(vuln.CVE)
			allCVEs = append(allCVEs, cve)
		}

		if apiResp.StartIndex+apiResp.ResultsPerPage >= apiResp.TotalResults {
			prog.SetDesc(fmt.Sprintf("NVD Fetch complete (%d CVEs)", apiResp.TotalResults))
			prog.SetCurrent(int64(apiResp.TotalResults))
			prog.SetTotal(int64(apiResp.TotalResults))
			break
		}
		*startIdx += apiResp.ResultsPerPage

		prog.SetDesc(fmt.Sprintf("NVD Fetch (%d/%d CVEs)", *startIdx, apiResp.TotalResults))
		prog.SetCurrent(int64(*startIdx))
		prog.SetTotal(int64(apiResp.TotalResults))

		if apiKey != "" {
			time.Sleep(600 * time.Millisecond)
		}
	}

	return allCVEs, nil
}

func (m *SPCModule) waitWithProgress(prog *common.ProgressBar, duration time.Duration, label string) {
	interval := 2 * time.Second
	if duration < interval {
		interval = duration
	}
	elapsed := time.Duration(0)
	for elapsed < duration {
		remaining := duration - elapsed
		if remaining < interval {
			interval = remaining
		}

		if m.kernel != nil {
			select {
			case <-m.kernel.Context().Done():
				return
			case <-time.After(interval):
			}
		} else {
			time.Sleep(interval)
		}

		elapsed += interval
		prog.SetDesc(fmt.Sprintf("%s %vs/%vs", label, elapsed.Seconds(), duration.Seconds()))
	}
}

func (m *SPCModule) parseNVDCVE(cve nvdCVE) SPCCVEScore {
	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(cve.Descriptions) > 0 {
		desc = cve.Descriptions[0].Value
	}

	var cvssScore float64
	var cvssVector string
	if len(cve.Metrics.CVSSMetricV40) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV40[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV40[0].CVSSData.VectorString
	} else if len(cve.Metrics.CVSSMetricV31) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV31[0].CVSSData.VectorString
	} else if len(cve.Metrics.CVSSMetricV30) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV30[0].CVSSData.VectorString
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV2[0].CVSSData.VectorString
	}

	var affectedCPEs []string
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if match.Vulnerable && match.Criteria != "" {
					cpeStr := match.Criteria
					if match.VersionStartIncluding != "" || match.VersionEndIncluding != "" ||
						match.VersionStartExcluding != "" || match.VersionEndExcluding != "" {
						parts := []string{}
						if match.VersionStartIncluding != "" {
							parts = append(parts, "vsi="+match.VersionStartIncluding)
						}
						if match.VersionStartExcluding != "" {
							parts = append(parts, "vse="+match.VersionStartExcluding)
						}
						if match.VersionEndIncluding != "" {
							parts = append(parts, "vei="+match.VersionEndIncluding)
						}
						if match.VersionEndExcluding != "" {
							parts = append(parts, "vee="+match.VersionEndExcluding)
						}
						cpeStr += "|" + strings.Join(parts, ",")
					}
					affectedCPEs = append(affectedCPEs, cpeStr)
				}
			}
		}
	}

	pubDate, err := time.Parse("2006-01-02T15:04:05.000", cve.Published)
	if err != nil {
		logger.WithComponent("spc").Debug("failed to parse published date", "cve_id", cve.ID, "error", err)
	}
	modDate, _ := time.Parse("2006-01-02T15:04:05.000", cve.LastModified)
	if pubDate.IsZero() {
		pubDate, _ = time.Parse(time.RFC3339, cve.Published)
	}
	if modDate.IsZero() {
		modDate, _ = time.Parse(time.RFC3339, cve.LastModified)
	}

	var attckTechs []string
	for _, ref := range cve.References {
		for _, tag := range ref.Tags {
			if strings.HasPrefix(tag, "ATT&CK:") {
				tech := strings.TrimPrefix(tag, "ATT&CK:")
				attckTechs = append(attckTechs, tech)
			} else if strings.HasPrefix(tag, "MITRE ATT&CK:") {
				tech := strings.TrimPrefix(tag, "MITRE ATT&CK:")
				attckTechs = append(attckTechs, tech)
			}
		}
	}

	return SPCCVEScore{
		CVEID:          cve.ID,
		Description:    desc,
		CVSS:           cvssScore,
		CVSSVector:     cvssVector,
		AffectedCPEs:   affectedCPEs,
		AttckTechniques: attckTechs,
		DatePublished:  pubDate,
		DateModified:   modDate,
	}
}

func (m *SPCModule) FetchFromEPSS() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "epss",
		Timestamp: start,
	}

	epssProgress := common.NewSpinner("EPSS Fetch")
	defer epssProgress.Finish()

	if !m.epssConfig.Enabled {
		result.Error = "EPSS data source disabled"
		return result
	}

	dataURL := m.epssConfig.DataURL
	if dataURL == "" {
		dataURL = defaultEPSSDataURL
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(dataURL)
	if err != nil {
		result.Error = fmt.Sprintf("EPSS fetch failed: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Error("EPSS fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("EPSS returned HTTP %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(dataURL, ".gz") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("EPSS gzip decompress failed: %v", err)
			result.Duration = time.Since(start)
			return result
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	parsed := 0
	epssUpdates := make(map[string][2]float64, 50000)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "model") || strings.HasPrefix(line, "cve") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}

		cveID := strings.TrimSpace(fields[0])
		epssStr := strings.TrimSpace(fields[1])
		percentileStr := strings.TrimSpace(fields[2])

		if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
			continue
		}

		epssVal, err := strconv.ParseFloat(epssStr, 64)
		if err != nil {
			logger.WithComponent("spc").Debug("failed to parse EPSS value", "cve_id", cveID, "raw", epssStr, "error", err)
			continue
		}
		percentileVal, err := strconv.ParseFloat(percentileStr, 64)
		if err != nil {
			logger.WithComponent("spc").Debug("failed to parse EPSS percentile", "cve_id", cveID, "raw", percentileStr, "error", err)
			continue
		}
		parsed++
		epssUpdates[cveID] = [2]float64{epssVal, percentileVal}

		if parsed%50000 == 0 {
			epssProgress.SetDesc(fmt.Sprintf("EPSS Parse (%d records)", parsed))
			epssProgress.SetCurrent(int64(parsed))
		}
	}

	if err := scanner.Err(); err != nil {
		result.Error = fmt.Sprintf("EPSS parse error: %v", err)
	}

	updated := 0
	created := 0

	m.mu.Lock()
	for cveID, vals := range epssUpdates {
		epssVal := vals[0]
		percentileVal := vals[1]
		if idx, exists := m.cveIndex[cveID]; exists && idx < len(m.cveCache) {
			m.cveCache[idx].EPSS = epssVal
			m.cveCache[idx].EPSSPercent = percentileVal
			updated++
		} else if len(m.cveCache) < m.maxCacheSize {
			m.cveIndex[cveID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, SPCCVEScore{
				CVEID:       cveID,
				EPSS:        epssVal,
				EPSSPercent: percentileVal,
			})
			created++
		}
	}
	m.mu.Unlock()

	result.CVEAdded = created
	result.CVEUpdated = updated
	result.Duration = time.Since(start)

	logger.WithComponent("spc").Info("EPSS data fetched",
		"parsed", parsed,
		"created", created,
		"updated", updated,
		"duration_ms", result.Duration.Milliseconds())

	return result
}

func (m *SPCModule) FetchFromCISAKEV() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "cisa_kev",
		Timestamp: start,
	}

	kevProgress := common.NewSpinner("CISA KEV Fetch")
	defer kevProgress.Finish()

	if !m.kevConfig.Enabled {
		result.Error = "CISA KEV data source disabled"
		return result
	}

	catalogURL := m.kevConfig.CatalogURL
	if catalogURL == "" {
		catalogURL = defaultKEVCatalogURL
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(catalogURL)
	if err != nil {
		result.Error = fmt.Sprintf("CISA KEV fetch failed: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Error("CISA KEV fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("CISA KEV returned HTTP %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	var kevCatalog struct {
		Title           string `json:"title"`
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVEID                       string   `json:"cveID"`
			VendorProject               string   `json:"vendorProject"`
			Product                     string   `json:"product"`
			VulnerabilityName           string   `json:"vulnerabilityName"`
			DateAdded                   string   `json:"dateAdded"`
			ShortDescription            string   `json:"shortDescription"`
			RequiredAction              string   `json:"requiredAction"`
			DueDate                     string   `json:"dueDate"`
			KnownRansomwareCampaignUse  string   `json:"knownRansomwareCampaignUse"`
			Notes                       string   `json:"notes"`
			CWEs                        []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&kevCatalog); err != nil {
		result.Error = fmt.Sprintf("CISA KEV decode failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	newKEV := make(map[string]bool)
	kevUpdated := 0
	kevCreated := 0

	type kevEntry struct {
		CVEID       string
		Ransomware  bool
		CWEs        []string
		Description string
	}
	var entries = make([]kevEntry, 0, len(kevCatalog.Vulnerabilities))
	for _, vuln := range kevCatalog.Vulnerabilities {
		cveID := strings.TrimSpace(vuln.CVEID)
		if cveID == "" {
			continue
		}
		newKEV[cveID] = true
		entries = append(entries, kevEntry{
			CVEID:       cveID,
			Ransomware:  strings.EqualFold(vuln.KnownRansomwareCampaignUse, "known"),
			CWEs:        vuln.CWEs,
			Description: vuln.ShortDescription,
		})
	}

	m.mu.Lock()
	for _, entry := range entries {
		if idx, exists := m.cveIndex[entry.CVEID]; exists && idx < len(m.cveCache) {
			m.cveCache[idx].InKEV = true
			if entry.Ransomware {
				m.cveCache[idx].APTGroupAssoc = appendUnique(m.cveCache[idx].APTGroupAssoc, "ransomware")
			}
			if len(entry.CWEs) > 0 && len(m.cveCache[idx].CWEs) == 0 {
				m.cveCache[idx].CWEs = entry.CWEs
			}
			kevUpdated++
		} else if len(m.cveCache) < m.maxCacheSize {
			m.cveIndex[entry.CVEID] = len(m.cveCache)
			aptAssoc := []string{}
			if entry.Ransomware {
				aptAssoc = []string{"ransomware"}
			}
			m.cveCache = append(m.cveCache, SPCCVEScore{
				CVEID:          entry.CVEID,
				InKEV:          true,
				APTGroupAssoc:  aptAssoc,
				CWEs:           entry.CWEs,
				Description:    entry.Description,
			})
			kevCreated++
		}
	}
	m.kevCatalog = newKEV
	m.mu.Unlock()

	result.CVEAdded = kevCreated
	result.CVEUpdated = kevUpdated
	result.Duration = time.Since(start)

	logger.WithComponent("spc").Info("CISA KEV catalog fetched",
		"total_kev", len(newKEV),
		"created", kevCreated,
		"updated", kevUpdated,
		"catalog_version", kevCatalog.CatalogVersion,
		"duration_ms", result.Duration.Milliseconds())

	return result
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func (m *SPCModule) isInKEVCatalog(cveID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kevCatalog[cveID]
}

func (m *SPCModule) FetchFromCNNVD() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "cnnvd",
		Timestamp: time.Now(),
	}

	if !m.cnnvdConfig.Enabled {
		result.Duration = time.Since(start)
		return result
	}

	baseURL := m.cnnvdConfig.BaseURL
	apiKey := m.cnnvdConfig.APIKey

	if baseURL == "" {
		result.Error = "CNNVD base URL not configured"
		result.Duration = time.Since(start)
		return result
	}

	logger.WithComponent("spc").Info("CNNVD fetch starting", "base_url", baseURL)

	client := &http.Client{Timeout: 45 * time.Second}

	reqURL := baseURL

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("CNNVD request creation: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("CNNVD API call: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNNVD fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
		result.Error = fmt.Sprintf("CNNVD API returned HTTP %d: %s", resp.StatusCode, truncateString(string(body), 500))
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNNVD non-200 response", "status", resp.StatusCode)
		return result
	}

	type cnnvdResponse struct {
		Data []struct {
			CveID      string `json:"cve_id"`
			CnnvdID    string `json:"cnnvd_id"`
			Name       string `json:"name"`
			Severity   string `json:"severity"`
			TypeName   string `json:"type_name"`
			ProductName string `json:"product"`
			VendorName  string `json:"vendor"`
			PublishDate string `json:"publish_date"`
			UpdateDate  string `json:"update_date"`
			Href       string `json:"href"`
		} `json:"data"`
	}

	var cnnvdResp cnnvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&cnnvdResp); err != nil {
		result.Error = fmt.Sprintf("CNNVD decode failed: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNNVD response decode failed", "error", err)
		return result
	}

	var cves = make([]SPCCVEScore, 0, len(cnnvdResp.Data))
	for _, item := range cnnvdResp.Data {
		cveID := strings.TrimSpace(item.CveID)
		if cveID == "" {
			continue
		}

		cvss := 0.0
		switch strings.ToLower(item.Severity) {
		case "critical", "严重":
			cvss = 9.0
		case "high", "高危", "高":
			cvss = 7.5
		case "medium", "中危", "中":
			cvss = 5.0
		case "low", "低危", "低":
			cvss = 2.5
		}

		desc := item.Name
		if desc == "" {
			desc = item.TypeName
		}

		var affectedCPEs []string
		if item.VendorName != "" && item.ProductName != "" {
			affectedCPEs = append(affectedCPEs, fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*",
				strings.ToLower(item.VendorName), strings.ToLower(item.ProductName)))
		}

		pubDate := time.Now()
		if item.PublishDate != "" {
			if t, err := time.Parse("2006-01-02", item.PublishDate); err == nil {
				pubDate = t
			} else if t, err := time.Parse("2006-01-02T15:04:05", item.PublishDate); err == nil {
				pubDate = t
			}
		}

		cve := SPCCVEScore{
			CVEID:         cveID,
			Description:   desc,
			CVSS:          cvss,
			DatePublished: pubDate,
			AffectedCPEs:  affectedCPEs,
		}

		cves = append(cves, cve)
	}

	m.mu.Lock()
	for _, cve := range cves {
		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			if cve.CVSS > m.cveCache[idx].CVSS {
				m.cveCache[idx].CVSS = cve.CVSS
			}
			if len(cve.AffectedCPEs) > 0 && len(m.cveCache[idx].AffectedCPEs) == 0 {
				m.cveCache[idx].AffectedCPEs = cve.AffectedCPEs
			}
			result.CVEUpdated++
		} else {
			if len(m.cveCache) >= m.maxCacheSize {
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.WithComponent("spc").Info("CNNVD fetch completed", "added", result.CVEAdded, "updated", result.CVEUpdated, "duration", result.Duration)
	return result
}

func (m *SPCModule) FetchFromCNVD() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "cnvd",
		Timestamp: time.Now(),
	}

	if !m.cnvdConfig.Enabled {
		result.Duration = time.Since(start)
		return result
	}

	baseURL := m.cnvdConfig.BaseURL

	if baseURL == "" {
		result.Error = "CNVD base URL not configured"
		result.Duration = time.Since(start)
		return result
	}

	logger.WithComponent("spc").Info("CNVD fetch starting", "base_url", baseURL)

	client := &http.Client{Timeout: 45 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("CNVD request creation: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("CNVD API call: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNVD fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
		result.Error = fmt.Sprintf("CNVD API returned HTTP %d: %s", resp.StatusCode, truncateString(string(body), 500))
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNVD non-200 response", "status", resp.StatusCode)
		return result
	}

	type cnvdResponse struct {
		Data []struct {
			CnvdID      string `json:"cnvd_id"`
			CveID       string `json:"cve_id"`
			Title       string `json:"title"`
			Severity    string `json:"severity"`
			ProductName string `json:"product"`
			VendorName  string `json:"vendor"`
			PublishDate string `json:"publish_date"`
			UpdateDate  string `json:"update_date"`
		} `json:"data"`
	}

	var cnvdResp cnvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&cnvdResp); err != nil {
		result.Error = fmt.Sprintf("CNVD decode failed: %v", err)
		result.Duration = time.Since(start)
		logger.WithComponent("spc").Warn("CNVD response decode failed", "error", err)
		return result
	}

	var cves = make([]SPCCVEScore, 0, len(cnvdResp.Data))
	for _, item := range cnvdResp.Data {
		cveID := strings.TrimSpace(item.CveID)
		if cveID == "" {
			cnvdID := strings.TrimSpace(item.CnvdID)
			if cnvdID == "" {
				continue
			}
			cveID = cnvdID
		}

		cvss := 0.0
		switch strings.ToLower(item.Severity) {
		case "critical", "严重":
			cvss = 9.0
		case "high", "高危", "高":
			cvss = 7.5
		case "medium", "中危", "中":
			cvss = 5.0
		case "low", "低危", "低":
			cvss = 2.5
		}

		desc := item.Title

		var affectedCPEs []string
		if item.VendorName != "" && item.ProductName != "" {
			affectedCPEs = append(affectedCPEs, fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*",
				strings.ToLower(item.VendorName), strings.ToLower(item.ProductName)))
		}

		pubDate := time.Now()
		if item.PublishDate != "" {
			if t, err := time.Parse("2006-01-02", item.PublishDate); err == nil {
				pubDate = t
			} else if t, err := time.Parse("2006-01-02T15:04:05", item.PublishDate); err == nil {
				pubDate = t
			}
		}

		cve := SPCCVEScore{
			CVEID:         cveID,
			Description:   desc,
			CVSS:          cvss,
			DatePublished: pubDate,
			AffectedCPEs:  affectedCPEs,
		}

		cves = append(cves, cve)
	}

	m.mu.Lock()
	for _, cve := range cves {
		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			if cve.CVSS > m.cveCache[idx].CVSS {
				m.cveCache[idx].CVSS = cve.CVSS
			}
			if len(cve.AffectedCPEs) > 0 && len(m.cveCache[idx].AffectedCPEs) == 0 {
				m.cveCache[idx].AffectedCPEs = cve.AffectedCPEs
			}
			result.CVEUpdated++
		} else {
			if len(m.cveCache) >= m.maxCacheSize {
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.WithComponent("spc").Info("CNVD fetch completed", "added", result.CVEAdded, "updated", result.CVEUpdated, "duration", result.Duration)
	return result
}

func (m *SPCModule) FetchFromMISP() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "misp",
		Timestamp: time.Now(),
	}

	m.mu.RLock()
	client := m.mispClient
	m.mu.RUnlock()

	if client == nil || client.config.BaseURL == "" {
		result.Duration = time.Since(start)
		return result
	}

	cves := m.fetchMISPEvents(client)

	m.mu.Lock()
	for _, cve := range cves {
		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			m.mergeCVEInPlace(idx, cve)
			result.CVEUpdated++
		} else {
			if len(m.cveCache) >= m.maxCacheSize {
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	m.mu.Lock()
	if client != nil {
		client.lastSync = time.Now()
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.WithComponent("spc").Info("MISP fetch completed", "duration", result.Duration, "added", result.CVEAdded, "updated", result.CVEUpdated)
	return result
}

type mispEventSearchRequest struct {
	ReturnFormat  string   `json:"returnFormat"`
	Type         []string `json:"type"`
	Category     []string `json:"category"`
	Tags         []string `json:"tags,omitempty"`
	DateFrom     string   `json:"date,omitempty"`
	Published    bool     `json:"published"`
	EnforceWarninglist bool `json:"enforceWarninglist"`
	Limit        int      `json:"limit"`
	Page         int      `json:"page"`
}

type mispEventResponse struct {
	Response []mispEventItem `json:"response"`
}

type mispEventItem struct {
	Event mispEvent `json:"Event"`
}

type mispEvent struct {
	ID          string          `json:"id"`
	Info        string          `json:"info"`
	ThreatLevel string          `json:"threat_level_id"`
	Published   bool            `json:"published"`
	Date        string          `json:"date"`
	Tags        []mispTag       `json:"Tag"`
	Galaxy      []mispGalaxy    `json:"Galaxy"`
	Attribute   []mispAttribute `json:"Attribute"`
}

type mispTag struct {
	Name  string `json:"name"`
	Color string `json:"colour"`
}

type mispGalaxy struct {
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	Cluster  []mispGalaxyCluster `json:"GalaxyCluster"`
}

type mispGalaxyCluster struct {
	Value   string   `json:"value"`
	TagName string   `json:"tag_name"`
	Meta    struct {
		Synonyms []string `json:"synonyms"`
	} `json:"meta"`
}

type mispAttribute struct {
	Type       string `json:"type"`
	Category   string `json:"category"`
	Value      string `json:"value"`
	ToIDS      bool   `json:"to_ids"`
	Comment    string `json:"comment"`
}

func (m *SPCModule) fetchMISPEvents(client *SPCMISPClient) []SPCCVEScore {
	searchReq := mispEventSearchRequest{
		ReturnFormat: "json",
		Type:        []string{"vulnerability"},
		Category:    []string{"External analysis"},
		Published:   true,
		EnforceWarninglist: true,
		Limit:       100,
		Page:        1,
	}

	if client.config.TLPFilter != "" {
		tlps := strings.Split(client.config.TLPFilter, ",")
		for _, tlp := range tlps {
			tlp = strings.TrimSpace(tlp)
			if tlp == "" {
				continue
			}
			if strings.HasPrefix(tlp, "!") {
				searchReq.Tags = append(searchReq.Tags, "!tlp:"+tlp[1:])
			} else {
				searchReq.Tags = append(searchReq.Tags, "tlp:"+tlp)
			}
		}
	}

	since := m.lastUpdate
	if since.IsZero() {
		since = time.Now().AddDate(0, 0, -7)
	}
	searchReq.DateFrom = since.Format("2006-01-02")

	body, err := json.Marshal(searchReq)
	if err != nil {
		logger.WithComponent("spc").Error("MISP request marshal failed", "error", err)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	const mispMaxRetries = 3

	req, err := http.NewRequestWithContext(ctx, "POST", client.config.BaseURL+"/events/restSearch",
		strings.NewReader(string(body)))
	if err != nil {
		logger.WithComponent("spc").Error("MISP request creation failed", "error", err)
		return nil
	}

	req.Header.Set("Authorization", client.config.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	var lastErr error
	for attempt := 0; attempt <= mispMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 10 * time.Second
			logger.WithComponent("spc").Warn("MISP API retrying",
				"attempt", attempt, "backoff", backoff)
			time.Sleep(backoff)
		}

		resp, err := client.client.Do(req)
		if err != nil {
			lastErr = err
			logger.WithComponent("spc").Error("MISP API call failed", "error", err, "attempt", attempt+1)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = fmt.Errorf("MISP API rate limited (429)")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = fmt.Errorf("MISP API returned status %d: %s", resp.StatusCode, string(body))
			continue
		}

		var eventResp mispEventResponse
		if err := json.NewDecoder(resp.Body).Decode(&eventResp); err != nil {
			resp.Body.Close()
			lastErr = err
			logger.WithComponent("spc").Error("MISP response decode failed", "error", err, "attempt", attempt+1)
			continue
		}
		resp.Body.Close()

		var cves []SPCCVEScore
		for _, item := range eventResp.Response {
			parsed := m.parseMISPEvent(item.Event)
			cves = append(cves, parsed...)
		}

		logger.WithComponent("spc").Info("MISP fetched events", "events", len(eventResp.Response), "cves", len(cves))
		return cves
	}

	logger.WithComponent("spc").Error("MISP fetch failed after all retries", "error", lastErr)
	return nil
}

func (m *SPCModule) parseMISPEvent(event mispEvent) []SPCCVEScore {
	var cveIDs []string
	var descriptions []string

	for _, attr := range event.Attribute {
		if attr.Type == "vulnerability" {
			if strings.HasPrefix(strings.ToUpper(attr.Value), "CVE-") {
				cveIDs = append(cveIDs, attr.Value)
			}
		}
		if attr.Category == "External analysis" && attr.Comment != "" {
			descriptions = append(descriptions, attr.Comment)
		}
	}

	var galaxyTags []string
	var attckTechs []string
	var aptGroups []string

	for _, g := range event.Galaxy {
		for _, cluster := range g.Cluster {
			galaxyTags = append(galaxyTags, cluster.TagName)
			if strings.HasPrefix(g.Type, "mitre-attack-pattern") {
				tech := extractATTCKTechnique(cluster.TagName)
				if tech != "" {
					attckTechs = append(attckTechs, tech)
				}
			}
			if strings.HasPrefix(g.Type, "threat-actor") || strings.HasPrefix(g.Type, "microsoft-activity-group") {
				aptGroups = append(aptGroups, cluster.Value)
			}
		}
	}

	for _, tag := range event.Tags {
		if strings.HasPrefix(tag.Name, "misp-galaxy:mitre-attack-pattern") {
			tech := extractATTCKTechnique(tag.Name)
			if tech != "" {
				attckTechs = append(attckTechs, tech)
			}
		}
		if strings.HasPrefix(tag.Name, "misp-galaxy:threat-actor") {
			parts := strings.Split(tag.Name, "=\"")
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[1], "\"")
				aptGroups = append(aptGroups, name)
			}
		}
	}

	desc := event.Info
	if len(descriptions) > 0 {
		desc = descriptions[0]
	}

	pubDate, _ := time.Parse("2006-01-02", event.Date)

	var results = make([]SPCCVEScore, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		results = append(results, SPCCVEScore{
			CVEID:          cveID,
			Description:    desc,
			DatePublished:  pubDate,
			DateModified:   time.Now(),
			AttckTechniques: attckTechs,
			MISPGalaxyTags:  galaxyTags,
			APTGroupAssoc:   aptGroups,
		})
	}

	return results
}

func extractATTCKTechnique(tagName string) string {
	upper := strings.ToUpper(tagName)
	idx := strings.Index(upper, "T1")
	if idx < 0 {
		return ""
	}
	tech := tagName[idx:]
	var result strings.Builder
	for _, ch := range tech {
		if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			result.WriteRune(ch)
		} else {
			break
		}
	}
	s := result.String()
	if len(s) < 4 {
		return ""
	}
	return s
}

func (m *SPCModule) ConfigureMISP(baseURL, apiKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if baseURL == "" || apiKey == "" {
		return fmt.Errorf("MISP base URL and API key are required")
	}

	m.mispConfig.BaseURL = baseURL
	m.mispConfig.APIKey = apiKey

	client := &http.Client{Timeout: 30 * time.Second}
	if !m.mispConfig.VerifyTLS {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	mispCtx, mispCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer mispCancel()

	req, err := http.NewRequestWithContext(mispCtx, "GET", baseURL+"/users/view/me", nil)
	if err != nil {
		return fmt.Errorf("MISP test request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("MISP connection test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MISP authentication failed: HTTP %d (expected 200)", resp.StatusCode)
	}

	m.mispClient = &SPCMISPClient{
		config:   m.mispConfig,
		client:   client,
		lastSync: time.Now(),
	}

	logger.WithComponent("spc").Info("MISP connection verified", "url", baseURL)
	return nil
}

func (m *SPCModule) ImportOSCAL(data []byte, format string) (int, error) {
	var records []SPCVulnerabilityRecord

	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(data, &records); err != nil {
			var wrapper struct {
				Findings []SPCVulnerabilityRecord `json:"findings"`
			}
			if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
				return 0, err
			}
			records = wrapper.Findings
		}
	case "yaml", "yml":
		parsed, err := parseOSCALYAML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL YAML parse: %w", err)
		}
		records = parsed
	case "xml":
		parsed, err := parseOSCALXML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL XML parse: %w", err)
		}
		records = parsed
	default:
		return 0, fmt.Errorf("unknown OSCAL format: %s (supported: json, yaml, xml)", format)
	}

	added := 0
	updated := 0
	m.mu.Lock()
	for _, rec := range records {
		if len(m.cveCache) >= m.maxCacheSize {
			logger.WithComponent("spc").Warn("CVE cache reached max size during OSCAL import", "max", m.maxCacheSize, "imported", added)
			break
		}
		pubDate, _ := time.Parse("2006-01-02", rec.DatePublished)
		modDate, _ := time.Parse("2006-01-02", rec.DateModified)

		cve := SPCCVEScore{
			CVEID:          rec.CVEID,
			Description:    rec.Description,
			CVSS:           rec.CVSSScore,
			CVSSVector:     rec.CVSSVector,
			EPSS:           rec.EPSSScore,
			EPSSPercent:    rec.EPSSPercent,
			InKEV:          rec.InKEV,
			DatePublished:  pubDate,
			DateModified:   modDate,
			AffectedCPEs:   rec.AffectedCPEs,
			AttckTechniques: rec.AttckTechniques,
			MISPGalaxyTags:  rec.MISPGalaxyTags,
			OSCALFindingUUID: rec.OSCALFindingUUID,
			APTGroupAssoc:   rec.APTGroupAssoc,
		}

		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			m.mergeCVEInPlace(idx, cve)
			updated++
		} else {
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			added++
		}
	}
	m.mu.Unlock()

	logger.WithComponent("spc").Info("OSCAL import completed", "format", format, "added", added, "updated", updated)
	return added, nil
}

func parseOSCALYAML(data []byte) ([]SPCVulnerabilityRecord, error) {
	var records []SPCVulnerabilityRecord
	text := strings.TrimSpace(string(data))

	if strings.HasPrefix(text, "---") {
		text = strings.TrimPrefix(text, "---")
		text = strings.TrimSpace(text)
	}

	lines := strings.Split(text, "\n")
	var currentRecord *SPCVulnerabilityRecord
	var inFindings bool
	var inFinding bool
	var listKey string
	var listItems []string

	flushRecord := func() {
		if currentRecord != nil && currentRecord.CVEID != "" {
			switch listKey {
			case "affected_cpes":
				currentRecord.AffectedCPEs = listItems
			case "attck_techniques":
				currentRecord.AttckTechniques = listItems
			case "misp_galaxy_tags":
				currentRecord.MISPGalaxyTags = listItems
			case "apt_group_assoc":
				currentRecord.APTGroupAssoc = listItems
			}
			records = append(records, *currentRecord)
		}
		currentRecord = nil
		listKey = ""
		listItems = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := 0
		for _, ch := range line {
			if ch == ' ' {
				indent++
			} else {
				break
			}
		}

		if indent == 0 && strings.HasPrefix(trimmed, "findings:") {
			inFindings = true
			inFinding = false
			continue
		}

		if indent == 0 && !strings.HasPrefix(trimmed, "findings:") {
			inFindings = false
			inFinding = false
			flushRecord()
			continue
		}

		if inFindings && indent == 2 && strings.HasSuffix(trimmed, ":") {
			flushRecord()
			currentRecord = &SPCVulnerabilityRecord{}
			inFinding = true
			listKey = ""
			listItems = nil
			continue
		}

		if inFinding && currentRecord != nil {
			if strings.HasPrefix(trimmed, "- ") {
				item := strings.TrimPrefix(trimmed, "- ")
				item = strings.Trim(item, "\"")
				if listKey != "" {
					listItems = append(listItems, item)
				}
				continue
			}

			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"")

				if listKey != "" && key != listKey {
					switch listKey {
					case "affected_cpes":
						currentRecord.AffectedCPEs = listItems
					case "attck_techniques":
						currentRecord.AttckTechniques = listItems
					case "misp_galaxy_tags":
						currentRecord.MISPGalaxyTags = listItems
					case "apt_group_assoc":
						currentRecord.APTGroupAssoc = listItems
					}
					listKey = ""
					listItems = nil
				}

				if val == "" {
					switch key {
					case "affected_cpes", "attck_techniques", "misp_galaxy_tags", "apt_group_assoc":
						listKey = key
						listItems = nil
					}
					continue
				}

				switch key {
				case "cve_id":
					currentRecord.CVEID = val
				case "description":
					currentRecord.Description = val
				case "cvss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.CVSSScore = f
					}
				case "cvss_vector":
					currentRecord.CVSSVector = val
				case "epss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSScore = f
					}
				case "epss_percentile":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSPercent = f
					}
				case "in_kev":
					currentRecord.InKEV = strings.EqualFold(val, "true") || val == "1"
				case "date_published":
					currentRecord.DatePublished = val
				case "date_modified":
					currentRecord.DateModified = val
				case "oscal_finding_uuid":
					currentRecord.OSCALFindingUUID = val
				}
			}
		}
	}

	flushRecord()

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in YAML")
	}

	return records, nil
}

func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	return strconv.ParseFloat(s, 64)
}

type oscalXMLRoot struct {
	XMLName  struct{}          `xml:"oscal"`
	Findings oscalXMLFindings  `xml:"findings"`
}

type oscalXMLFindings struct {
	Finding []oscalXMLFinding `xml:"finding"`
}

type oscalXMLFinding struct {
	CVEID          string   `xml:"cve_id"`
	Description    string   `xml:"description"`
	CVSSScore      float64  `xml:"cvss_score"`
	CVSSVector     string   `xml:"cvss_vector"`
	EPSSScore      float64  `xml:"epss_score"`
	EPSSPercent    float64  `xml:"epss_percentile"`
	InKEV          bool     `xml:"in_kev"`
	DatePublished  string   `xml:"date_published"`
	DateModified   string   `xml:"date_modified"`
	AffectedCPEs   struct {
		CPE []string `xml:"cpe"`
	} `xml:"affected_cpes"`
	AttckTechniques struct {
		Technique []string `xml:"technique"`
	} `xml:"attck_techniques"`
	MISPGalaxyTags struct {
		Tag []string `xml:"tag"`
	} `xml:"misp_galaxy_tags"`
	OSCALFindingUUID string `xml:"oscal_finding_uuid"`
	APTGroupAssoc    struct {
		Group []string `xml:"group"`
	} `xml:"apt_group_assoc"`
}

func parseOSCALXML(data []byte) ([]SPCVulnerabilityRecord, error) {
	var root oscalXMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var records []SPCVulnerabilityRecord
	for _, f := range root.Findings.Finding {
		rec := SPCVulnerabilityRecord{
			CVEID:           f.CVEID,
			Description:     f.Description,
			CVSSScore:       f.CVSSScore,
			CVSSVector:      f.CVSSVector,
			EPSSScore:       f.EPSSScore,
			EPSSPercent:     f.EPSSPercent,
			InKEV:           f.InKEV,
			DatePublished:   f.DatePublished,
			DateModified:    f.DateModified,
			AffectedCPEs:    f.AffectedCPEs.CPE,
			AttckTechniques: f.AttckTechniques.Technique,
			MISPGalaxyTags:  f.MISPGalaxyTags.Tag,
			OSCALFindingUUID: f.OSCALFindingUUID,
			APTGroupAssoc:   f.APTGroupAssoc.Group,
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in XML")
	}

	return records, nil
}

