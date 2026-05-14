package management

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/argus-security/argus/internal/adapter"
	"github.com/argus-security/argus/internal/model"
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
	usersFound := strings.Count(text, "User login:")

	return []*adapter.NormalizedFinding{{
		ID:          "FREEIPA-USERS",
		Source:      "freeipa",
		ToolName:    "FreeIPA",
		Timestamp:   now,
		FindingType: adapter.FindingIdentity,
		Severity:    adapter.SeverityInfo,
		Title:       "FreeIPA Identity Source",
		Passed:      usersFound > 0,
		Detail:      fmt.Sprintf("FreeIPA directory accessible, %d users found", usersFound),
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "freeipa",
	}}, nil
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
	accessible := len(raw) > 0 && raw[0] == '['

	return []*adapter.NormalizedFinding{{
		ID:          "KEYCLOAK-STATUS",
		Source:      "keycloak",
		ToolName:    "Keycloak",
		Timestamp:   now,
		FindingType: adapter.FindingIdentity,
		Title:       "Keycloak Identity Provider",
		Passed:      accessible,
		Detail:      fmt.Sprintf("Keycloak API %s", map[bool]string{true: "accessible", false: "not accessible"}[accessible]),
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "keycloak",
	}}, nil
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
	accessible := strings.Contains(string(raw), "token")

	return []*adapter.NormalizedFinding{{
		ID:          "WAZUH-SIEM-STATUS",
		Source:      "wazuh_siem",
		ToolName:    "Wazuh SIEM",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "Wazuh SIEM Integration",
		Passed:      accessible,
		Detail:      fmt.Sprintf("Wazuh SIEM API %s", map[bool]string{true: "authenticated", false: "unreachable"}[accessible]),
		Domain:      model.DomainResilience,
		DelegatedTo: "wazuh_siem",
	}}, nil
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
	accessible := strings.Contains(string(raw), "system")

	return []*adapter.NormalizedFinding{{
		ID:          "RUNDECK-STATUS",
		Source:      "rundeck",
		ToolName:    "Rundeck",
		Timestamp:   now,
		FindingType: adapter.FindingConfigState,
		Title:       "Rundeck Job Orchestrator",
		Passed:      accessible,
		Detail:      fmt.Sprintf("Rundeck API %s", map[bool]string{true: "accessible", false: "not accessible"}[accessible]),
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "rundeck",
	}}, nil
}

func (r *RundeckAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (r *RundeckAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
