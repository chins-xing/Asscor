//go:build adapter

package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type tfResource struct {
	Mode string `json:"mode"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type tfState struct {
	Version   int          `json:"version"`
	Resources []tfResource `json:"resources"`
}

// ===== Jira Adapter (MG-008, P2) =====

type JiraAdapter struct {
	adapter.BaseAdapter
}

func NewJiraAdapter() *JiraAdapter {
	return &JiraAdapter{
		BaseAdapter: adapter.NewBaseAdapter("jira", "Jira", "management", "P2", "1.0"),
	}
}

func (j *JiraAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["jira.api_url"]
	if apiURL == "" {
		apiURL = "https://jira.internal"
	}
	username := config["jira.username"]
	apiToken := config["jira.api_token"]

	url := strings.TrimRight(apiURL, "/") + "/rest/api/2/myself"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("jira request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if username != "" && apiToken != "" {
		req.SetBasicAuth(username, apiToken)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("jira read: %w", err)
	}
	return body, nil
}

func (j *JiraAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	type jiraUser struct {
		Self        string `json:"self"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Active      bool   `json:"active"`
		Email       string `json:"emailAddress"`
	}

	var user jiraUser
	if err := json.Unmarshal(raw, &user); err != nil {
		return []*adapter.NormalizedFinding{{
			ID:          "JIRA-STATUS",
			Source:      "jira",
			ToolName:    "Jira",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Title:       "Jira Issue Tracker",
			Passed:      false,
			Detail:      fmt.Sprintf("Jira API unreachable: %v", err),
			Severity:    adapter.SeverityMedium,
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "jira",
		}}, nil
	}

	return []*adapter.NormalizedFinding{{
		ID:          "JIRA-STATUS",
		Source:      "jira",
		ToolName:    "Jira",
		Timestamp:   now,
		FindingType: adapter.FindingConfigState,
		Title:       "Jira Issue Tracker",
		Passed:      user.Active,
		Detail:      fmt.Sprintf("Jira API accessible (user: %s, active: %v)", user.DisplayName, user.Active),
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "jira",
		Metadata:    map[string]string{"display_name": user.DisplayName, "email": user.Email},
	}}, nil
}

func (j *JiraAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (j *JiraAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Terraform Adapter (MG-009, P2) =====

type TerraformAdapter struct {
	adapter.BaseAdapter
}

func NewTerraformAdapter() *TerraformAdapter {
	return &TerraformAdapter{
		BaseAdapter: adapter.NewBaseAdapter("terraform", "Terraform", "management", "P2", "1.0"),
	}
}

func (t *TerraformAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	tfPath := config["adapter_paths.terraform"]
	if tfPath == "" {
		tfPath = "terraform"
	}

	planDir := config["terraform.plan_dir"]
	if planDir == "" {
		planDir = "."
	}

	cmd := exec.CommandContext(ctx, tfPath, "show", "-json", filepath.Join(planDir, "terraform.tfstate"))
	out, err := cmd.Output()
	if err != nil {
		cmd2 := exec.CommandContext(ctx, tfPath, "version")
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return nil, fmt.Errorf("terraform not available: %w", err)
		}
		return out2, nil
	}
	return out, nil
}

func (t *TerraformAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var state tfState
	if err := json.Unmarshal(raw, &state); err != nil {
		text := string(raw)
		hasResources := strings.Contains(text, "resources")
		resourcesCount := 0
		if hasResources {
			resourcesCount = strings.Count(text, `"mode"`) / 2
		}
		return []*adapter.NormalizedFinding{{
			ID:          "TERRAFORM-STATE",
			Source:      "terraform",
			ToolName:    "Terraform",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Severity:    adapter.SeverityInfo,
			Title:       "Terraform Infrastructure as Code",
			Passed:      true,
			Detail:      fmt.Sprintf("Terraform accessible (non-JSON output, %d resources detected)", resourcesCount),
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "terraform",
		}}, nil
	}

	var findings []*adapter.NormalizedFinding
	resourcesByType := make(map[string]int)
	for _, r := range state.Resources {
		resourcesByType[r.Type]++
	}

	for resType, count := range resourcesByType {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "TERRAFORM-RESOURCE-" + resType,
			Source:      "terraform",
			ToolName:    "Terraform",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Severity:    adapter.SeverityInfo,
			Title:       "Terraform Resource: " + resType,
			Passed:      true,
			Detail:      fmt.Sprintf("%d × %s resources managed by Terraform", count, resType),
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "terraform",
			Metadata:    map[string]string{"resource_type": resType, "count": fmt.Sprintf("%d", count)},
		})
	}

	return findings, nil
}

func (t *TerraformAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (t *TerraformAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== OpenTofu Adapter (MG-010, P2) =====

type OpenTofuAdapter struct {
	adapter.BaseAdapter
}

func NewOpenTofuAdapter() *OpenTofuAdapter {
	return &OpenTofuAdapter{
		BaseAdapter: adapter.NewBaseAdapter("opentofu", "OpenTofu", "management", "P2", "1.0"),
	}
}

func (o *OpenTofuAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	tofuPath := config["adapter_paths.opentofu"]
	if tofuPath == "" {
		tofuPath = "tofu"
	}

	planDir := config["opentofu.plan_dir"]
	if planDir == "" {
		planDir = "."
	}

	stateFile := filepath.Join(planDir, "terraform.tfstate")
	if _, err := os.Stat(stateFile); err != nil {
		cmd := exec.CommandContext(ctx, tofuPath, "version")
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("opentofu not available: %w", err)
		}
		return out, nil
	}

	cmd := exec.CommandContext(ctx, tofuPath, "show", "-json", stateFile)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("opentofu show failed: %w", err)
	}
	return out, nil
}

func (o *OpenTofuAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var state tfState
	if err := json.Unmarshal(raw, &state); err != nil {
		text := string(raw)
		hasResources := strings.Contains(text, "resources")
		resourcesCount := 0
		if hasResources {
			resourcesCount = strings.Count(text, `"mode"`) / 2
		}
		return []*adapter.NormalizedFinding{{
			ID:          "OPENTOFU-STATE",
			Source:      "opentofu",
			ToolName:    "OpenTofu",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Severity:    adapter.SeverityInfo,
			Title:       "OpenTofu Infrastructure as Code",
			Passed:      true,
			Detail:      fmt.Sprintf("OpenTofu accessible (non-JSON output, %d resources detected)", resourcesCount),
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "opentofu",
		}}, nil
	}

	var findings []*adapter.NormalizedFinding
	resourcesByType := make(map[string]int)
	for _, r := range state.Resources {
		resourcesByType[r.Type]++
	}

	for resType, count := range resourcesByType {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "OPENTOFU-RESOURCE-" + resType,
			Source:      "opentofu",
			ToolName:    "OpenTofu",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Severity:    adapter.SeverityInfo,
			Title:       "OpenTofu Resource: " + resType,
			Passed:      true,
			Detail:      fmt.Sprintf("%d × %s resources managed by OpenTofu", count, resType),
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "opentofu",
			Metadata:    map[string]string{"resource_type": resType, "count": fmt.Sprintf("%d", count)},
		})
	}

	return findings, nil
}

func (o *OpenTofuAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (o *OpenTofuAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
