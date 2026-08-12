package spc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

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
