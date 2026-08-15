//go:build spc

package spc

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) FetchFromEPSS() kernel.SPCFetchResult {
	start := time.Now()
	result := kernel.SPCFetchResult{
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
		dataURL = kernel.DefaultEPSSDataURL
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
			m.cveCache = append(m.cveCache, kernel.SPCCVEScore{
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
