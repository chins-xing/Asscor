package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

// ===== FreeIPA Adapter (MG-004, P1) =====

type FreeIPAAdapter struct {
	adapter.BaseAdapter
}

func NewFreeIPAAdapter() *FreeIPAAdapter {
	return &FreeIPAAdapter{
		BaseAdapter: adapter.NewBaseAdapter("freeipa", "FreeIPA", "management", "P1", "1.0"),
	}
}

func (f *FreeIPAAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	ipaPath := config["adapter_paths.freeipa"]
	if ipaPath == "" {
		ipaPath = "ipa"
	}
	cmd := exec.CommandContext(ctx, ipaPath, "user-find", "--sizelimit=100")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("freeipa fetch failed: %w", err)
	}
	return out, nil
}

func (f *FreeIPAAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
	text := string(raw)
	lines := strings.Split(text, "\n")

	var findings []*adapter.NormalizedFinding
	var currentUser string
	var disabledUsers []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "User login:") {
			currentUser = strings.TrimSpace(strings.TrimPrefix(line, "User login:"))
			continue
		}
		if currentUser != "" && strings.Contains(line, "Account disabled: True") {
			disabledUsers = append(disabledUsers, currentUser)
		}
		if currentUser != "" && strings.HasPrefix(line, "UID:") {
			findings = append(findings, &adapter.NormalizedFinding{
				ID:          "FREEIPA-USER-" + currentUser,
				Source:      "freeipa",
				ToolName:    "FreeIPA",
				Timestamp:   now,
				FindingType: adapter.FindingIdentity,
				Severity:    adapter.SeverityInfo,
				Title:       "FreeIPA User: " + currentUser,
				Passed:      true,
				Detail:      fmt.Sprintf("User %s found in FreeIPA directory", currentUser),
				Domain:      model.DomainOperationTrust,
				DelegatedTo: "freeipa",
				Metadata:    map[string]string{"username": currentUser},
			})
		}
	}
	for i := range findings {
		adapter.ApplyDelegation(findings[i], "freeipa")
	}

		if len(findings) == 0 {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "FREEIPA-USERS",
			Source:      "freeipa",
			ToolName:    "FreeIPA",
			Timestamp:   now,
			FindingType: adapter.FindingIdentity,
			Severity:    adapter.SeverityMedium,
			Title:       "FreeIPA Identity Source",
			Passed:      false,
			Detail:      "FreeIPA directory accessible, no users found",
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "freeipa",
		})
	}

	for _, du := range disabledUsers {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "FREEIPA-DISABLED-" + du,
			Source:      "freeipa",
			ToolName:    "FreeIPA",
			Timestamp:   now,
			FindingType: adapter.FindingIdentity,
			Severity:    adapter.SeverityMedium,
			Title:       "FreeIPA Disabled Account: " + du,
			Passed:      false,
			Detail:      fmt.Sprintf("User %s is disabled in FreeIPA — should be deprovisioned", du),
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "freeipa",
		})
	}

	for i := range findings {
		adapter.ApplyDelegation(findings[i], "freeipa")
	}

	return findings, nil
}

func (f *FreeIPAAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (f *FreeIPAAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Keycloak Adapter (MG-005, P1) =====

type KeycloakAdapter struct {
	adapter.BaseAdapter
}

func NewKeycloakAdapter() *KeycloakAdapter {
	return &KeycloakAdapter{
		BaseAdapter: adapter.NewBaseAdapter("keycloak", "Keycloak", "management", "P1", "1.0"),
	}
}

func (k *KeycloakAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["keycloak.api_url"]
	if apiURL == "" {
		apiURL = "https://keycloak.internal"
	}

	url := strings.TrimRight(apiURL, "/") + "/admin/realms"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keycloak read: %w", err)
	}
	return body, nil
}

func (k *KeycloakAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	type keycloakRealm struct {
		ID      string `json:"id"`
		Realm   string `json:"realm"`
		Enabled bool   `json:"enabled"`
	}

	var realms []keycloakRealm
	if err := json.Unmarshal(raw, &realms); err != nil {
		result := &adapter.NormalizedFinding{
			ID:          "KEYCLOAK-STATUS",
			Source:      "keycloak",
			ToolName:    "Keycloak",
			Timestamp:   now,
			FindingType: adapter.FindingIdentity,
			Title:       "Keycloak Identity Provider",
			Passed:      false,
			Detail:      fmt.Sprintf("Keycloak API unreachable or invalid response: %v", err),
		}
		adapter.ApplyDelegation(result, "keycloak")
		return []*adapter.NormalizedFinding{result}, nil
	}

	var findings []*adapter.NormalizedFinding
	for _, realm := range realms {
		passed := realm.Enabled
		detail := fmt.Sprintf("Realm %s (%s)", realm.Realm, realm.ID)
		if !realm.Enabled {
			detail += " — DISABLED"
		}
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "KEYCLOAK-REALM-" + realm.ID,
			Source:      "keycloak",
			ToolName:    "Keycloak",
			Timestamp:   now,
			FindingType: adapter.FindingIdentity,
			Title:       "Keycloak Realm: " + realm.Realm,
			Passed:      passed,
			Detail:      detail,
			Metadata:    map[string]string{"realm_id": realm.ID, "realm": realm.Realm},
		})
	}
	for i := range findings {
		adapter.ApplyDelegation(findings[i], "keycloak")
	}

	if len(findings) == 0 {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "KEYCLOAK-STATUS",
			Source:      "keycloak",
			ToolName:    "Keycloak",
			Timestamp:   now,
			FindingType: adapter.FindingIdentity,
			Title:       "Keycloak Identity Provider",
			Passed:      true,
			Detail:      "Keycloak API accessible, no realms configured",
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "keycloak",
		})
	}

	return findings, nil
}

func (k *KeycloakAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (k *KeycloakAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Wazuh SIEM Adapter (MG-006, P1) =====

type WazuhSIEMAdapter struct {
	adapter.BaseAdapter
}

func NewWazuhSIEMAdapter() *WazuhSIEMAdapter {
	return &WazuhSIEMAdapter{
		BaseAdapter: adapter.NewBaseAdapter("wazuh_siem", "Wazuh SIEM", "management", "P1", "1.0"),
	}
}

func (w *WazuhSIEMAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["wazuh_siem.api_url"]
	if apiURL == "" {
		apiURL = "https://wazuh.internal:55000"
	}

	username := config["wazuh_siem.username"]
	password := config["wazuh_siem.password"]

	url := strings.TrimRight(apiURL, "/") + "/security/user/authenticate"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("wazuh siem request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username, password)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wazuh siem API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wazuh siem read: %w", err)
	}
	return body, nil
}

func (w *WazuhSIEMAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	type wazuhAuthResponse struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
		Error int `json:"error"`
	}

	var authResp wazuhAuthResponse
	if err := json.Unmarshal(raw, &authResp); err != nil || authResp.Error != 0 {
		return []*adapter.NormalizedFinding{{
			ID:          "WAZUH-SIEM-STATUS",
			Source:      "wazuh_siem",
			ToolName:    "Wazuh SIEM",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Title:       "Wazuh SIEM Integration",
			Passed:      false,
			Detail:      "Wazuh SIEM API authentication failed",
			Severity:    adapter.SeverityHigh,
			Domain:      model.DomainResilience,
			DelegatedTo: "wazuh_siem",
		}}, nil
	}

	var findings []*adapter.NormalizedFinding
	findings = append(findings, &adapter.NormalizedFinding{
		ID:          "WAZUH-SIEM-STATUS",
		Source:      "wazuh_siem",
		ToolName:    "Wazuh SIEM",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "Wazuh SIEM Integration",
		Passed:      true,
		Detail:      "Wazuh SIEM API authenticated successfully",
		Severity:    adapter.SeverityInfo,
		Domain:      model.DomainResilience,
		DelegatedTo: "wazuh_siem",
		Metadata:    map[string]string{"auth_status": "ok"},
	})

	return findings, nil
}

func (w *WazuhSIEMAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (w *WazuhSIEMAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Rundeck Adapter (MG-007, P1) =====

type RundeckAdapter struct {
	adapter.BaseAdapter
}

func NewRundeckAdapter() *RundeckAdapter {
	return &RundeckAdapter{
		BaseAdapter: adapter.NewBaseAdapter("rundeck", "Rundeck", "management", "P1", "1.0"),
	}
}

func (r *RundeckAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["rundeck.api_url"]
	if apiURL == "" {
		apiURL = "https://rundeck.internal"
	}
	apiToken := config["rundeck.api_token"]

	url := strings.TrimRight(apiURL, "/") + "/api/41/system/info"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("rundeck request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if apiToken != "" {
		req.Header.Set("X-Rundeck-Auth-Token", apiToken)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rundeck API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rundeck read: %w", err)
	}
	return body, nil
}

func (r *RundeckAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	type rundeckSystemInfo struct {
		System struct {
			Timestamp struct {
				Epoch int64  `json:"epoch"`
				Date  string `json:"date"`
			} `json:"timestamp"`
			Rundeck struct {
				Version  string `json:"version"`
				NodeName string `json:"node"`
			} `json:"rundeck"`
			Executions struct {
				Active bool `json:"active"`
			} `json:"executions"`
		} `json:"system"`
	}

	var info rundeckSystemInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return []*adapter.NormalizedFinding{{
			ID:          "RUNDECK-STATUS",
			Source:      "rundeck",
			ToolName:    "Rundeck",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Title:       "Rundeck Job Orchestrator",
			Passed:      false,
			Detail:      fmt.Sprintf("Rundeck API unreachable: %v", err),
			Severity:    adapter.SeverityMedium,
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "rundeck",
		}}, nil
	}

	findings := []*adapter.NormalizedFinding{{
		ID:          "RUNDECK-STATUS",
		Source:      "rundeck",
		ToolName:    "Rundeck",
		Timestamp:   now,
		FindingType: adapter.FindingConfigState,
		Title:       "Rundeck Job Orchestrator",
		Passed:      info.System.Executions.Active,
		Detail:      fmt.Sprintf("Rundeck %s (node: %s), executor %s", info.System.Rundeck.Version, info.System.Rundeck.NodeName, map[bool]string{true: "active", false: "inactive"}[info.System.Executions.Active]),
		Severity:    adapter.SeverityInfo,
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "rundeck",
		Metadata: map[string]string{
			"version":  info.System.Rundeck.Version,
			"node":     info.System.Rundeck.NodeName,
			"executor": fmt.Sprintf("%v", info.System.Executions.Active),
		},
	}}

	return findings, nil
}

func (r *RundeckAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (r *RundeckAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
