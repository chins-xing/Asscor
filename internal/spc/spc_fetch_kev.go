//go:build spc

package spc

import (
	"encoding/json"
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"net/http"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) FetchFromCISAKEV() kernel.SPCFetchResult {
	start := time.Now()
	result := kernel.SPCFetchResult{
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
		catalogURL = kernel.DefaultKEVCatalogURL
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
			CVEID                      string   `json:"cveID"`
			VendorProject              string   `json:"vendorProject"`
			Product                    string   `json:"product"`
			VulnerabilityName          string   `json:"vulnerabilityName"`
			DateAdded                  string   `json:"dateAdded"`
			ShortDescription           string   `json:"shortDescription"`
			RequiredAction             string   `json:"requiredAction"`
			DueDate                    string   `json:"dueDate"`
			KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
			Notes                      string   `json:"notes"`
			CWEs                       []string `json:"cwes"`
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
			m.cveCache = append(m.cveCache, kernel.SPCCVEScore{
				CVEID:         entry.CVEID,
				InKEV:         true,
				APTGroupAssoc: aptAssoc,
				CWEs:          entry.CWEs,
				Description:   entry.Description,
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

func (m *Module) isInKEVCatalog(cveID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kevCatalog[cveID]
}
