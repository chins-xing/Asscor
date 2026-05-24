package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/argus-security/argus/internal/logger"
)

func (m *SPCModule) AddCVE(score SPCCVEScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.cveIndex[score.CVEID]; exists {
		return
	}
	if len(m.cveCache) >= m.maxCacheSize {
		logger.WithComponent("spc").Warn("CVE cache reached max size in AddCVE", "max", m.maxCacheSize)
		return
	}
	m.cveIndex[score.CVEID] = len(m.cveCache)
	m.cveCache = append(m.cveCache, score)
}

func (m *SPCModule) AddCVEs(scores []SPCCVEScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, score := range scores {
		if _, exists := m.cveIndex[score.CVEID]; exists {
			continue
		}
		if len(m.cveCache) >= m.maxCacheSize {
			logger.WithComponent("spc").Warn("CVE cache reached max size in AddCVEs", "max", m.maxCacheSize, "added_so_far", len(m.cveCache))
			break
		}
		m.cveIndex[score.CVEID] = len(m.cveCache)
		m.cveCache = append(m.cveCache, score)
	}
}

func (m *SPCModule) GetCVEs() []SPCCVEScore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]SPCCVEScore, len(m.cveCache))
	copy(result, m.cveCache)
	return result
}

func (m *SPCModule) GetCVECount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cveCache)
}

func (m *SPCModule) GetKEVCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, cve := range m.cveCache {
		if cve.InKEV {
			count++
		}
	}
	return count
}

func (m *SPCModule) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cveCache = m.cveCache[:0]
	m.cveIndex = make(map[string]int)
}

func (m *SPCModule) cacheFilePath() string {
	dataDir := "./data"
	if m.kernel != nil {
		if cfg := m.kernel.GetConfigObj(); cfg != nil && cfg.DataDir != "" {
			dataDir = cfg.DataDir
		}
	}
	return filepath.Join(dataDir, "spc_cache.json")
}

func (m *SPCModule) saveCacheToDisk() {
	m.mu.RLock()
	cacheCopy := make([]SPCCVEScore, len(m.cveCache))
	copy(cacheCopy, m.cveCache)
	lastUpd := m.lastUpdate
	m.mu.RUnlock()

	if len(cacheCopy) == 0 {
		return
	}

	path := m.cacheFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.WithComponent("spc").Error("failed to create cache directory", "error", err)
		return
	}

	payload := struct {
		SavedAt    time.Time     `json:"saved_at"`
		LastUpdate time.Time     `json:"last_update"`
		CVECount   int           `json:"cve_count"`
		CVEs       []SPCCVEScore `json:"cves"`
	}{
		SavedAt:    time.Now(),
		LastUpdate: lastUpd,
		CVECount:   len(cacheCopy),
		CVEs:       cacheCopy,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logger.WithComponent("spc").Error("failed to marshal cache", "error", err)
		return
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		logger.WithComponent("spc").Error("failed to write cache file", "error", err)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		logger.WithComponent("spc").Error("failed to rename cache file", "error", err)
		return
	}

	logger.WithComponent("spc").Info("SPC cache saved to disk", "path", path, "cve_count", len(cacheCopy))
}

func (m *SPCModule) loadCacheFromDisk() {
	path := m.cacheFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		logger.WithComponent("spc").Debug("no SPC cache file found, starting fresh", "error", err)
		return
	}

	var payload struct {
		SavedAt    time.Time     `json:"saved_at"`
		LastUpdate time.Time     `json:"last_update"`
		CVECount   int           `json:"cve_count"`
		CVEs       []SPCCVEScore `json:"cves"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		logger.WithComponent("spc").Warn("failed to parse SPC cache file", "error", err)
		return
	}

	m.mu.Lock()
	m.cveCache = payload.CVEs
	m.cveIndex = make(map[string]int, len(m.cveCache))
	for i, cve := range m.cveCache {
		m.cveIndex[cve.CVEID] = i
	}
	m.lastUpdate = payload.LastUpdate
	m.mu.Unlock()

	logger.WithComponent("spc").Info("SPC cache loaded from disk", "cve_count", len(m.cveCache), "last_update", payload.LastUpdate.Format(time.RFC3339))
}

func (m *SPCModule) LastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

func (m *SPCModule) generateSampleCVEs() []SPCCVEScore {
	logger.WithComponent("spc").Warn("USING SAMPLE CVE DATA — not suitable for production; configure NVD API key for real data")
	now := time.Now()
	return []SPCCVEScore{
		{
			CVEID:          "CVE-2024-1234",
			Description:    "OpenSSL Remote Code Execution in TLS handshake",
			CVSS:           9.8,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			EPSS:           0.72,
			EPSSPercent:    0.95,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -28),
			AffectedCPEs:   []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1190", "T1210"},
			MISPGalaxyTags:  []string{"misp-galaxy:mitre-attck-pattern"},
			APTGroupAssoc:   []string{"APT29", "Lazarus"},
		},
		{
			CVEID:          "CVE-2024-5678",
			Description:    "Nginx HTTP/3 Denial of Service via malformed QUIC frames",
			CVSS:           7.5,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			EPSS:           0.15,
			EPSSPercent:    0.62,
			InKEV:          false,
			HasPublicPoC:   false,
			DatePublished:  now.AddDate(0, 0, -54),
			AffectedCPEs:   []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1499"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2024-9012",
			Description:    "PHP Information Disclosure via crafted multipart form data",
			CVSS:           5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			EPSS:           0.03,
			EPSSPercent:    0.38,
			InKEV:          false,
			HasPublicPoC:   false,
			DatePublished:  now.AddDate(0, 0, -163),
			AffectedCPEs:   []string{"cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1592"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2024-3094",
			Description:    "XZ Utils backdoor in liblzma allowing remote code execution via SSH",
			CVSS:           10.0,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			EPSS:           0.97,
			EPSSPercent:    0.99,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -60),
			AffectedCPEs:   []string{"cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", "cpe:2.3:a:tukaani:xz_utils:5.6.0:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1195", "T1195.002", "T1078"},
			MISPGalaxyTags:  []string{"misp-galaxy:mitre-attck-pattern"},
			APTGroupAssoc:   []string{"UNC5765"},
		},
		{
			CVEID:          "CVE-2024-6387",
			Description:    "OpenSSH regreSSHion Remote Code Execution via race condition in sshd",
			CVSS:           8.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			EPSS:           0.56,
			EPSSPercent:    0.88,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -45),
			AffectedCPEs:   []string{"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", "cpe:2.3:a:openbsd:openssh:9.5p1:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1190", "T1068"},
			MISPGalaxyTags:  []string{"misp-galaxy:mitre-attck-pattern"},
			APTGroupAssoc:   []string{},
		},
		{
			CVEID:          "CVE-2023-44487",
			Description:    "HTTP/2 Rapid Reset Attack DDoS vulnerability",
			CVSS:           7.5,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			EPSS:           0.82,
			EPSSPercent:    0.97,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -200),
			AffectedCPEs:   []string{"cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1499", "T1498"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2024-21626",
			Description:    "runc Container Breakout via leaked file descriptor",
			CVSS:           8.6,
			CVSSVector:     "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
			EPSS:           0.34,
			EPSSPercent:    0.75,
			InKEV:          false,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -90),
			AffectedCPEs:   []string{"cpe:2.3:a:opencontainers:runc:1.1.11:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1611", "T1068"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2023-4911",
			Description:    "Glibc Looney Tunables buffer overflow in ld.so leading to privilege escalation",
			CVSS:           7.8,
			CVSSVector:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			EPSS:           0.45,
			EPSSPercent:    0.82,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -180),
			AffectedCPEs:   []string{"cpe:2.3:a:gnu:glibc:2.37:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1068"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2024-1086",
			Description:    "Linux Kernel netfilter use-after-free leading to privilege escalation",
			CVSS:           7.8,
			CVSSVector:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			EPSS:           0.61,
			EPSSPercent:    0.90,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -120),
			AffectedCPEs:   []string{"cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1068"},
			MISPGalaxyTags:  []string{"misp-galaxy:mitre-attck-pattern"},
			APTGroupAssoc:   []string{},
		},
		{
			CVEID:          "CVE-2024-2961",
			Description:    "Glibc iconv buffer overflow in ISO-2022-CN-EXT encoding",
			CVSS:           8.8,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			EPSS:           0.38,
			EPSSPercent:    0.79,
			InKEV:          false,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -70),
			AffectedCPEs:   []string{"cpe:2.3:a:gnu:glibc:2.39:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1190"},
			MISPGalaxyTags:  []string{},
		},
	}
}
