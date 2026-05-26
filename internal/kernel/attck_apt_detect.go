package kernel

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *ATTACKModule) RegisterBehavioralIndicator(indicator BehavioralIndicator) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if indicator.ID == "" || indicator.TechniqueID == "" {
		return fmt.Errorf("behavioral indicator ID and technique ID must not be empty")
	}

	if indicator.Metric == "" {
		return fmt.Errorf("behavioral indicator metric must not be empty")
	}

	validOps := map[string]bool{"gt": true, "lt": true, "gte": true, "lte": true, "eq": true, "neq": true}
	if !validOps[indicator.Operator] {
		return fmt.Errorf("invalid operator: %s (must be gt/lt/gte/lte/eq/neq)", indicator.Operator)
	}

	for i, bi := range m.behavioralIndicators {
		if bi.ID == indicator.ID {
			m.behavioralIndicators[i] = indicator
			logger.WithComponent("attck.behavioral").Info("updated behavioral indicator", "id", indicator.ID, "technique", indicator.TechniqueID)
			return nil
		}
	}

	m.behavioralIndicators = append(m.behavioralIndicators, indicator)
	logger.WithComponent("attck.behavioral").Info("registered behavioral indicator", "id", indicator.ID, "technique", indicator.TechniqueID, "metric", indicator.Metric)
	return nil
}

func (m *ATTACKModule) ListBehavioralIndicators(techniqueID string) []BehavioralIndicator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BehavioralIndicator
	for _, bi := range m.behavioralIndicators {
		if techniqueID != "" && bi.TechniqueID != techniqueID {
			continue
		}
		result = append(result, bi)
	}
	return result
}

func (m *ATTACKModule) DeleteBehavioralIndicator(indicatorID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, bi := range m.behavioralIndicators {
		if bi.ID == indicatorID {
			m.behavioralIndicators = append(m.behavioralIndicators[:i], m.behavioralIndicators[i+1:]...)
			return true
		}
	}
	return false
}

func (m *ATTACKModule) UpdateBaseline(hostID string, metrics map[string]float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	baseline, ok := m.baselines[hostID]
	if !ok {
		baseline = BehavioralBaseline{
			HostID:     hostID,
			Metrics:    make(map[string]float64),
			Period:     24 * time.Hour,
			ComputedAt: time.Now(),
		}
	}

	alpha := 0.3
	for k, v := range metrics {
		if old, ok := baseline.Metrics[k]; ok {
			baseline.Metrics[k] = alpha*v + (1-alpha)*old
		} else {
			baseline.Metrics[k] = v
		}
	}

	baseline.SampleCount++
	baseline.ComputedAt = time.Now()
	m.baselines[hostID] = baseline

	logger.WithComponent("attck.behavioral").Info("baseline updated", "host", hostID, "metrics", len(metrics), "samples", baseline.SampleCount)
}

func (m *ATTACKModule) GetBaseline(hostID string) *BehavioralBaseline {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if b, ok := m.baselines[hostID]; ok {
		return &b
	}
	return nil
}

func (m *ATTACKModule) EvaluateBehavioralIndicators(hostID string, metrics map[string]float64) []BehavioralAlert {
	m.mu.Lock()
	defer m.mu.Unlock()

	var alerts []BehavioralAlert

	baseline, hasBaseline := m.baselines[hostID]

	for _, indicator := range m.behavioralIndicators {
		if !indicator.Enabled {
			continue
		}

		observed, ok := metrics[indicator.Metric]
		if !ok {
			continue
		}

		var baselineValue float64
		if hasBaseline {
			baselineValue = baseline.Metrics[indicator.Metric]
		} else {
			baselineValue = indicator.Threshold
		}

		triggered := m.evaluateOperator(observed, indicator.Operator, indicator.Threshold)
		if !triggered {
			continue
		}

		deviation := 0.0
		if baselineValue > 0 {
			deviation = math.Abs(observed-baselineValue) / baselineValue
		} else if observed > 0 {
			deviation = observed
		}

		alert := BehavioralAlert{
			ID:            fmt.Sprintf("ba-%d", time.Now().UnixNano()),
			IndicatorID:   indicator.ID,
			IndicatorName: indicator.Name,
			TechniqueID:   indicator.TechniqueID,
			HostID:        hostID,
			ObservedValue: observed,
			BaselineValue: baselineValue,
			Deviation:     math.Round(deviation*1000) / 1000,
			Severity:      indicator.Severity,
			Timestamp:     time.Now(),
		}

		alerts = append(alerts, alert)
		m.behavioralAlerts = append(m.behavioralAlerts, alert)
	}

	if len(alerts) > 0 {
		logger.WithComponent("attck.behavioral").Info("behavioral alerts triggered", "host", hostID, "count", len(alerts))
	}

	return alerts
}

func (m *ATTACKModule) evaluateOperator(observed float64, operator string, threshold float64) bool {
	switch operator {
	case "gt":
		return observed > threshold
	case "lt":
		return observed < threshold
	case "gte":
		return observed >= threshold
	case "lte":
		return observed <= threshold
	case "eq":
		return observed == threshold
	case "neq":
		return observed != threshold
	default:
		return false
	}
}

func (m *ATTACKModule) GetBehavioralAlerts(hostID string, limit int) []BehavioralAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BehavioralAlert
	for i := len(m.behavioralAlerts) - 1; i >= 0; i-- {
		a := m.behavioralAlerts[i]
		if hostID != "" && a.HostID != hostID {
			continue
		}
		result = append(result, a)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) DetectBeaconing(hostID string, events []TimeSeriesPoint) []BeaconDetection {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(events) < 10 {
		return nil
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	intervals := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		interval := events[i].Timestamp.Sub(events[i-1].Timestamp).Seconds()
		if interval > 0 {
			intervals = append(intervals, interval)
		}
	}

	if len(intervals) < 5 {
		return nil
	}

	meanInterval := m.mean(intervals)
	stdInterval := m.stdDev(intervals)

	if meanInterval == 0 {
		return nil
	}

	jitter := 0.0
	if meanInterval > 0 {
		jitter = stdInterval / meanInterval
	}

	score := 0.0
	switch {
	case jitter < 0.1:
		score = 0.95
	case jitter < 0.2:
		score = 0.85
	case jitter < 0.3:
		score = 0.7
	case jitter < 0.5:
		score = 0.5
	default:
		return nil
	}

	destination := ""
	if len(events) > 0 {
		destination = fmt.Sprintf("host-%s-endpoint", hostID)
	}

	detection := BeaconDetection{
		ID:          fmt.Sprintf("beacon-%d", time.Now().UnixNano()),
		HostID:      hostID,
		Destination: destination,
		Interval:    math.Round(meanInterval*100) / 100,
		Jitter:      math.Round(jitter*1000) / 1000,
		Score:       score,
		TechniqueID: "T1071.001",
		DataPoints:  len(events),
		FirstSeen:   events[0].Timestamp,
		LastSeen:    events[len(events)-1].Timestamp,
	}

	m.beaconDetections = append(m.beaconDetections, detection)

	logger.WithComponent("attck.behavioral").Info("beaconing detected",
		"host", hostID, "interval", detection.Interval, "jitter", detection.Jitter, "score", score)

	return []BeaconDetection{detection}
}

func (m *ATTACKModule) GetBeaconDetections(hostID string, limit int) []BeaconDetection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BeaconDetection
	for i := len(m.beaconDetections) - 1; i >= 0; i-- {
		d := m.beaconDetections[i]
		if hostID != "" && d.HostID != hostID {
			continue
		}
		result = append(result, d)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (m *ATTACKModule) stdDev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	avg := m.mean(values)
	var sum float64
	for _, v := range values {
		diff := v - avg
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)))
}

func (m *ATTACKModule) loadDefaultBehavioralIndicators() {
	m.behavioralIndicators = []BehavioralIndicator{
		{
			ID: "BI-001", Name: "High Failed Login Rate", TechniqueID: "T1110",
			TacticIDs: []string{"TA0006"}, Category: "authentication", Metric: "failed_login_count",
			Operator: "gt", Threshold: 10, Window: 5 * time.Minute, Severity: "high",
			Description: "Failed login attempts exceed threshold within time window", Enabled: true,
		},
		{
			ID: "BI-002", Name: "Unusual Process Count", TechniqueID: "T1059",
			TacticIDs: []string{"TA0002"}, Category: "process", Metric: "process_spawn_rate",
			Operator: "gt", Threshold: 50, Window: 1 * time.Minute, Severity: "medium",
			Description: "Process spawn rate exceeds baseline", Enabled: true,
		},
		{
			ID: "BI-003", Name: "Excessive Network Connections", TechniqueID: "T1071",
			TacticIDs: []string{"TA0011"}, Category: "network", Metric: "outbound_conn_count",
			Operator: "gt", Threshold: 100, Window: 10 * time.Minute, Severity: "medium",
			Description: "Outbound connection count exceeds threshold", Enabled: true,
		},
		{
			ID: "BI-004", Name: "Large Data Transfer", TechniqueID: "T1048",
			TacticIDs: []string{"TA0010"}, Category: "network", Metric: "outbound_bytes",
			Operator: "gt", Threshold: 104857600, Window: 1 * time.Hour, Severity: "high",
			Description: "Outbound data volume exceeds 100MB threshold", Enabled: true,
		},
		{
			ID: "BI-005", Name: "Privilege Escalation Attempts", TechniqueID: "T1548",
			TacticIDs: []string{"TA0004"}, Category: "authentication", Metric: "priv_escalation_count",
			Operator: "gt", Threshold: 3, Window: 10 * time.Minute, Severity: "high",
			Description: "Privilege escalation attempts exceed threshold", Enabled: true,
		},
		{
			ID: "BI-006", Name: "File Permission Changes", TechniqueID: "T1222",
			TacticIDs: []string{"TA0005"}, Category: "file", Metric: "permission_change_count",
			Operator: "gt", Threshold: 20, Window: 30 * time.Minute, Severity: "medium",
			Description: "File permission modifications exceed threshold", Enabled: true,
		},
		{
			ID: "BI-007", Name: "Scheduled Task Creation", TechniqueID: "T1053",
			TacticIDs: []string{"TA0003"}, Category: "persistence", Metric: "scheduled_task_create_count",
			Operator: "gt", Threshold: 5, Window: 1 * time.Hour, Severity: "high",
			Description: "Scheduled task creation rate exceeds threshold", Enabled: true,
		},
		{
			ID: "BI-008", Name: "DNS Query Volume Anomaly", TechniqueID: "T1071.004",
			TacticIDs: []string{"TA0011"}, Category: "network", Metric: "dns_query_count",
			Operator: "gt", Threshold: 500, Window: 5 * time.Minute, Severity: "medium",
			Description: "DNS query volume exceeds threshold", Enabled: true,
		},
	}
}
