//go:build adapter

package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type snipeITAsset struct {
	ID              int                `json:"id"`
	Name            string             `json:"name"`
	AssetTag        string             `json:"asset_tag"`
	Serial          string             `json:"serial"`
	Model           snipeITRef         `json:"model"`
	Category        snipeITRef         `json:"category"`
	StatusLabel     snipeITStatusLabel `json:"status_label"`
	AssignedTo      *snipeITRef        `json:"assigned_to"`
	Location        *snipeITRef        `json:"location"`
	PurchaseDate    *snipeITDate       `json:"purchase_date"`
	WarrantyExpires *snipeITDate       `json:"warranty_expires"`
	Notes           string             `json:"notes"`
}

type snipeITRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type snipeITStatusLabel struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	StatusType string `json:"status_type"`
	StatusMeta string `json:"status_meta"`
}

type snipeITDate struct {
	Date      string `json:"date"`
	Formatted string `json:"formatted"`
}

type snipeITResponse struct {
	Total int            `json:"total"`
	Rows  []snipeITAsset `json:"rows"`
}

type SnipeITAdapter struct {
	adapter.BaseAdapter
}

func NewSnipeITAdapter() *SnipeITAdapter {
	return &SnipeITAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"snipe_it",
			"Snipe-IT",
			"management",
			"P0",
			"1.0",
		),
	}
}

func (s *SnipeITAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["snipe_it.api_url"]
	if apiURL == "" {
		apiURL = "https://snipeit.internal"
	}
	apiToken := config["snipe_it.api_token"]

	url := strings.TrimRight(apiURL, "/") + "/api/v1/hardware?limit=1000"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("snipe-it request create: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("snipe-it API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("snipe-it read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("snipe-it API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (s *SnipeITAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	var resp snipeITResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("snipe-it json parse: %w", err)
	}

	var findings []*adapter.NormalizedFinding
	now := time.Now()

	for _, asset := range resp.Rows {
		sev := adapter.SeverityInfo
		passed := true

		statusType := strings.ToLower(asset.StatusLabel.StatusType)
		switch statusType {
		case "deployed", "pending", "archived":
			sev = adapter.SeverityInfo
		case "undeployable", "broken":
			sev = adapter.SeverityCritical
			passed = false
		case "ready to deploy":
			sev = adapter.SeverityLow
		default:
			sev = adapter.SeverityMedium
			passed = false
		}

		assignedTo := "unassigned"
		if asset.AssignedTo != nil {
			assignedTo = asset.AssignedTo.Name
		}

		location := "unknown"
		if asset.Location != nil {
			location = asset.Location.Name
		}

		f := &adapter.NormalizedFinding{
			ID:          fmt.Sprintf("SNIPEIT-ASSET-%d", asset.ID),
			Source:      "snipe_it",
			ToolName:    "Snipe-IT",
			Timestamp:   now,
			FindingType: adapter.FindingAsset,
			Severity:    sev,
			Title:       fmt.Sprintf("Asset %s (%s)", asset.Name, asset.AssetTag),
			Description: fmt.Sprintf("Model: %s, Category: %s", asset.Model.Name, asset.Category.Name),
			Resource:    asset.Name,
			Passed:      passed,
			Detail:      fmt.Sprintf("Asset %s (tag: %s) status: %s, assigned to: %s", asset.Name, asset.AssetTag, asset.StatusLabel.Name, assignedTo),
			Domain:      model.DomainBusinessContinuity,
			Metadata: map[string]string{
				"snipeit_id":  fmt.Sprintf("%d", asset.ID),
				"asset_tag":   asset.AssetTag,
				"serial":      asset.Serial,
				"model":       asset.Model.Name,
				"category":    asset.Category.Name,
				"status":      asset.StatusLabel.Name,
				"status_type": statusType,
				"assigned_to": assignedTo,
				"location":    location,
			},
		}

		if asset.WarrantyExpires != nil {
			f.Metadata["warranty_expires"] = asset.WarrantyExpires.Formatted
		}

		adapter.ApplyDelegation(f, "snipe_it")
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []*adapter.NormalizedFinding{{
			ID:          "SNIPEIT-NO-ASSETS",
			Source:      "snipe_it",
			ToolName:    "Snipe-IT",
			Timestamp:   now,
			FindingType: adapter.FindingAsset,
			Severity:    adapter.SeverityMedium,
			Title:       "No assets found in Snipe-IT",
			Passed:      false,
			Detail:      "Snipe-IT inventory returned zero assets",
			Domain:      model.DomainBusinessContinuity,
			DelegatedTo: "snipe_it",
		}}, nil
	}

	return findings, nil
}

func (s *SnipeITAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (s *SnipeITAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
