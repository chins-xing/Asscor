//go:build spc

package spc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) FetchFromNVD() kernel.SPCFetchResult {
	start := time.Now()
	result := kernel.SPCFetchResult{
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
		baseURL = kernel.DefaultNVDBaseURL
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
	TotalResults    int           `json:"totalResults"`
	ResultsPerPage  int           `json:"resultsPerPage"`
	StartIndex      int           `json:"startIndex"`
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string         `json:"id"`
	SourceIdentifier string         `json:"sourceIdentifier"`
	Published        string         `json:"published"`
	LastModified     string         `json:"lastModified"`
	Descriptions     []nvdLangStr   `json:"descriptions"`
	Metrics          nvdMetrics     `json:"metrics"`
	Weaknesses       []nvdWeakness  `json:"weaknesses"`
	Configurations   []nvdConfig    `json:"configurations"`
	References       []nvdReference `json:"references"`
}

type nvdLangStr struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetric   `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetric   `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric   `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            nvdCVSSData `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSMetricV2 struct {
	Source              string        `json:"source"`
	Type                string        `json:"type"`
	CVSSData            nvdCVSSDataV2 `json:"cvssData"`
	BaseSeverity        string        `json:"baseSeverity"`
	ExploitabilityScore float64       `json:"exploitabilityScore"`
	ImpactScore         float64       `json:"impactScore"`
}

type nvdCVSSDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []nvdLangStr `json:"description"`
}

type nvdConfig struct {
	Operator string    `json:"operator"`
	Nodes    []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
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
	Source string   `json:"source"`
	URL    string   `json:"url"`
	Tags   []string `json:"tags"`
}

func (m *Module) fetchNVDAPI(baseURL, apiKey string, since time.Time) ([]kernel.SPCCVEScore, error) {
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
		cves []kernel.SPCCVEScore
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
			defer func() {
				if r := recover(); r != nil {
					logger.WithComponent("spc").Error("NVD fetch goroutine panicked", "window", idx, "panic", r)
				}
			}()

			startIdx := 0
			retryCount := 0
			cves, err := m.fetchNVDWindow(client, baseURL, apiKey, start, end, useLastMod, noRejected, &startIdx, &retryCount, maxRetries, nvdProgress)
			results[idx] = windowResult{cves: cves, err: err, idx: idx}
		}(i, w.start, w.end)
	}

	wg.Wait()

	var allCVEs []kernel.SPCCVEScore
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

func (m *Module) fetchNVDWindow(client *http.Client, baseURL, apiKey string, startDate, endDate time.Time, useLastMod, noRejected bool, startIdx *int, retryCount *int, maxRetries int, prog *common.ProgressBar) ([]kernel.SPCCVEScore, error) {
	var allCVEs []kernel.SPCCVEScore

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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, kernel.MaxHTTPBodySize))
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

func (m *Module) waitWithProgress(prog *common.ProgressBar, duration time.Duration, label string) {
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

		if m.kc != nil {
			select {
			case <-m.kc.Context().Done():
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

func (m *Module) parseNVDCVE(cve nvdCVE) kernel.SPCCVEScore {
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

	return kernel.SPCCVEScore{
		CVEID:           cve.ID,
		Description:     desc,
		CVSS:            cvssScore,
		CVSSVector:      cvssVector,
		AffectedCPEs:    affectedCPEs,
		AttckTechniques: attckTechs,
		DatePublished:   pubDate,
		DateModified:    modDate,
	}
}
