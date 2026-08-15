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

type netboxDevice struct {
	ID           int                    `json:"id"`
	Name         string                 `json:"name"`
	DisplayName  string                 `json:"display_name"`
	DeviceType   netboxRef              `json:"device_type"`
	DeviceRole   netboxRef              `json:"device_role"`
	Site         netboxRef              `json:"site"`
	Status       netboxStatus           `json:"status"`
	PrimaryIP    netboxIP               `json:"primary_ip"`
	Serial       string                 `json:"serial"`
	AssetTag     string                 `json:"asset_tag"`
	Comments     string                 `json:"comments"`
	CustomFields map[string]interface{} `json:"custom_fields"`
}

type netboxRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type netboxStatus struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type netboxIP struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
}

type netboxResponse struct {
	Count    int            `json:"count"`
	Next     string         `json:"next"`
	Previous string         `json:"previous"`
	Results  []netboxDevice `json:"results"`
}

type NetBoxAdapter struct {
	adapter.BaseAdapter
}

func NewNetBoxAdapter() *NetBoxAdapter {
	return &NetBoxAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"netbox",
			"NetBox",
			"management",
			"P0",
			"1.0",
		),
	}
}

func (n *NetBoxAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	apiURL := config["netbox.api_url"]
	if apiURL == "" {
		apiURL = "https://netbox.internal"
	}
	apiToken := config["netbox.api_token"]

	url := strings.TrimRight(apiURL, "/") + "/api/dcim/devices/?limit=1000"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("netbox request create: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if apiToken != "" {
		req.Header.Set("Authorization", "Token "+apiToken)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("netbox API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("netbox read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("netbox API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (n *NetBoxAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	var resp netboxResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("netbox json parse: %w", err)
	}

	var findings []*adapter.NormalizedFinding
	now := time.Now()

	for _, dev := range resp.Results {
		criticality := "normal"
		if cf, ok := dev.CustomFields["criticality"]; ok {
			if s, ok := cf.(string); ok {
				criticality = strings.ToLower(s)
			}
		}

		sev := adapter.SeverityInfo
		switch criticality {
		case "critical":
			sev = adapter.SeverityCritical
		case "high":
			sev = adapter.SeverityHigh
		case "medium":
			sev = adapter.SeverityMedium
		case "low":
			sev = adapter.SeverityLow
		}

		passed := dev.Status.Value == "active"

		f := &adapter.NormalizedFinding{
			ID:          fmt.Sprintf("NETBOX-DEV-%d", dev.ID),
			Source:      "netbox",
			ToolName:    "NetBox",
			Timestamp:   now,
			FindingType: adapter.FindingAsset,
			Severity:    sev,
			Title:       fmt.Sprintf("Device %s (%s)", dev.Name, dev.DeviceRole.Name),
			Description: fmt.Sprintf("Site: %s, Role: %s, Status: %s", dev.Site.Name, dev.DeviceRole.Name, dev.Status.Label),
			Resource:    dev.Name,
			Passed:      passed,
			Detail:      fmt.Sprintf("Asset %s (role: %s) at site %s, status: %s", dev.Name, dev.DeviceRole.Name, dev.Site.Name, dev.Status.Label),
			Domain:      model.DomainBusinessContinuity,
			Metadata: map[string]string{
				"netbox_id":   fmt.Sprintf("%d", dev.ID),
				"site":        dev.Site.Name,
				"role":        dev.DeviceRole.Name,
				"status":      dev.Status.Value,
				"criticality": criticality,
				"serial":      dev.Serial,
				"asset_tag":   dev.AssetTag,
			},
		}

		if dev.PrimaryIP.Address != "" {
			f.Metadata["primary_ip"] = dev.PrimaryIP.Address
		}

		adapter.ApplyDelegation(f, "netbox")
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []*adapter.NormalizedFinding{{
			ID:          "NETBOX-NO-DEVICES",
			Source:      "netbox",
			ToolName:    "NetBox",
			Timestamp:   now,
			FindingType: adapter.FindingAsset,
			Severity:    adapter.SeverityMedium,
			Title:       "No devices found in NetBox",
			Passed:      false,
			Detail:      "NetBox inventory returned zero devices",
			Domain:      model.DomainBusinessContinuity,
			DelegatedTo: "netbox",
		}}, nil
	}

	return findings, nil
}

func (n *NetBoxAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	for _, f := range findings {
		if f.Severity == adapter.SeverityCritical {
			f.Passed = false
			f.Detail += " (CRITICAL asset)"
		}
	}
	return findings
}

func (n *NetBoxAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
