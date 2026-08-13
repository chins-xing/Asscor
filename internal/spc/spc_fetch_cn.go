//go:build spc

package spc

import (
	"github.com/asscor/asscor/internal/kernel"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) FetchFromCNNVD() kernel.SPCFetchResult {
	start := time.Now()
	result := kernel.SPCFetchResult{
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, kernel.MaxHTTPBodySize))
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

	var cves = make([]kernel.SPCCVEScore, 0, len(cnnvdResp.Data))
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

		cve := kernel.SPCCVEScore{
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

func (m *Module) FetchFromCNVD() kernel.SPCFetchResult {
	start := time.Now()
	result := kernel.SPCFetchResult{
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, kernel.MaxHTTPBodySize))
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

	var cves = make([]kernel.SPCCVEScore, 0, len(cnvdResp.Data))
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

		cve := kernel.SPCCVEScore{
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
