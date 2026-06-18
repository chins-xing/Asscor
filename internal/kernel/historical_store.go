package kernel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type HostTrend struct {
	HostID    string    `json:"host_id"`
	Date      string    `json:"date"`
	AvgScore  float64   `json:"avg_score"`
	MinScore  float64   `json:"min_score"`
	MaxScore  float64   `json:"max_score"`
	Count     int       `json:"count"`
	AcceptablePct float64 `json:"acceptable_pct"`
}

type HistoricalStore struct {
	dataDir    string
	enabled    bool
}

func NewHistoricalStore(dataDir string) *HistoricalStore {
	return &HistoricalStore{
		dataDir: dataDir,
		enabled: true,
	}
}

func (s *HistoricalStore) ComputeTrends(days int) ([]HostTrend, error) {
	if !s.enabled {
		return nil, nil
	}

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return nil, fmt.Errorf("read data dir: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	hostEntries := make(map[string][]float64)
	hostAcceptable := make(map[string]int)

	type logEntry struct {
		FinalScore float64 `json:"score"`
		Acceptable bool    `json:"acceptable"`
		HostID     string  `json:"host_id"`
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}

		info, err := entry.Info()
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}

		path := filepath.Join(s.dataDir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 2*1024*1024)
		for scanner.Scan() {
			var le logEntry
			if err := json.Unmarshal(scanner.Bytes(), &le); err != nil {
				continue
			}
			if le.HostID == "" {
				continue
			}
			hostEntries[le.HostID] = append(hostEntries[le.HostID], le.FinalScore)
			if le.Acceptable {
				hostAcceptable[le.HostID]++
			}
		}
		if err := scanner.Err(); err != nil {
			logger.WithComponent("historical_store").Warn("scanner error reading file",
				"path", path, "error", err)
		}
		f.Close()
	}

	var trends []HostTrend
	for hostID, scores := range hostEntries {
		if len(scores) == 0 {
			continue
		}

		sort.Float64s(scores)
		var sum float64
		for _, s := range scores {
			sum += s
		}

		trends = append(trends, HostTrend{
			HostID:    hostID,
			AvgScore:  math.Round(sum/float64(len(scores))*100) / 100,
			MinScore:  scores[0],
			MaxScore:  scores[len(scores)-1],
			Count:     len(scores),
			AcceptablePct: math.Round(float64(hostAcceptable[hostID])/float64(len(scores))*10000) / 100,
			Date:      time.Now().Format("2006-01-02"),
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		return trends[i].AvgScore < trends[j].AvgScore
	})

	logger.WithComponent("historical_store").Info("trends computed",
		"hosts", len(trends), "days", days, "total_entries", len(hostEntries))
	return trends, nil
}

func (s *HistoricalStore) ComputeRiskLevels(days int) (map[string]float64, error) {
	if !s.enabled {
		return nil, nil
	}

	trends, err := s.ComputeTrends(days)
	if err != nil {
		return nil, err
	}

	correlation := make(map[string]float64)
	for _, t := range trends {
		var risk float64
		if t.AvgScore < 60 {
			risk = 1.0
		} else if t.AvgScore < 80 {
			risk = 0.5
		} else {
			risk = 0.0
		}
		correlation[t.HostID] = risk
	}

	return correlation, nil
}
