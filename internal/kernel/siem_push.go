package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

type SIEMPusher struct {
	mu       sync.Mutex
	apiURL   string
	username string
	password string
	token    string
	client   *http.Client
	enabled  bool
}

func NewSIEMPusher(apiURL, username, password string) *SIEMPusher {
	return &SIEMPusher{
		apiURL:   strings.TrimRight(apiURL, "/"),
		username: username,
		password: password,
		client:   &http.Client{Timeout: 15 * time.Second},
		enabled:  apiURL != "" && username != "" && password != "",
	}
}

func (s *SIEMPusher) Enabled() bool {
	return s.enabled
}

func (s *SIEMPusher) authenticate(ctx context.Context) error {
	s.mu.Lock()
	token := s.token
	s.mu.Unlock()

	if token != "" {
		return nil
	}

	url := s.apiURL + "/security/user/authenticate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.username, s.password)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("siem auth returned status %d", resp.StatusCode)
	}

	var authResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
		Error int `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("siem auth parse: %w", err)
	}
	if authResp.Error != 0 || authResp.Data.Token == "" {
		return fmt.Errorf("siem auth failed with error code %d", authResp.Error)
	}

	s.mu.Lock()
	s.token = authResp.Data.Token
	s.mu.Unlock()
	return nil
}

type siemAlertPayload struct {
	Description string            `json:"description"`
	Severity    int               `json:"severity"`
	Level       string            `json:"level"`
	AgentName   string            `json:"agent_name"`
	Fields      map[string]string `json:"fields"`
}

func (s *SIEMPusher) PushAssessment(ctx context.Context, result *model.AssessmentResult) {
	if !s.enabled || result == nil {
		return
	}

	if err := s.authenticate(ctx); err != nil {
		logger.WithComponent("siem").Warn("auth failed, cannot push", "error", err)
		return
	}

	severity := siemSeverity(result.FinalScore)
	payload := siemAlertPayload{
		Description: fmt.Sprintf("ASSCOR assessment: %s scored %.1f (acceptable: %v)",
			result.HostID, result.FinalScore, result.Acceptable),
		Severity:  severity,
		Level:     siemLevel(severity),
		AgentName: result.HostID,
		Fields: map[string]string{
			"asscor.score":      fmt.Sprintf("%.2f", result.FinalScore),
			"asscor.acceptable": fmt.Sprintf("%v", result.Acceptable),
			"asscor.spc_score":  fmt.Sprintf("%.2f", result.SPCScore),
			"asscor.threat":     fmt.Sprintf("%.2f", result.ThreatCoeff),
		},
	}

	payload.Fields["asscor.domain_as"] = fmt.Sprintf("%.2f", result.DomainScores.AttackSurface)
	payload.Fields["asscor.domain_bc"] = fmt.Sprintf("%.2f", result.DomainScores.BusinessContinuity)
	payload.Fields["asscor.domain_ot"] = fmt.Sprintf("%.2f", result.DomainScores.OperationTrust)
	payload.Fields["asscor.domain_rs"] = fmt.Sprintf("%.2f", result.DomainScores.Resilience)

	body, _ := json.Marshal(payload)
	url := s.apiURL + "/events"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logger.WithComponent("siem").Warn("build request failed", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		logger.WithComponent("siem").Warn("push to SIEM failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
		if err := s.authenticate(ctx); err == nil {
			s.pushRetry(ctx, payload)
		}
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.WithComponent("siem").Info("pushed assessment to SIEM",
			"host_id", result.HostID, "score", result.FinalScore, "severity", payload.Level)
	} else {
		logger.WithComponent("siem").Warn("SIEM push returned non-200",
			"status", resp.StatusCode, "host_id", result.HostID)
	}
}

func (s *SIEMPusher) pushRetry(ctx context.Context, payload siemAlertPayload) {
	s.mu.Lock()
	token := s.token
	s.mu.Unlock()

	body, _ := json.Marshal(payload)
	url := s.apiURL + "/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.WithComponent("siem").Info("SIEM retry succeeded")
	} else {
		logger.WithComponent("siem").Warn("SIEM retry failed", "status", resp.StatusCode)
	}
}

func siemSeverity(score float64) int {
	switch {
	case score >= 80:
		return 2
	case score >= 60:
		return 5
	case score >= 40:
		return 10
	default:
		return 15
	}
}

func siemLevel(severity int) string {
	if severity <= 2 {
		return "low"
	}
	if severity <= 5 {
		return "medium"
	}
	if severity <= 10 {
		return "high"
	}
	return "critical"
}
