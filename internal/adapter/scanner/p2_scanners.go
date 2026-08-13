//go:build adapter

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type osvResult struct {
	Results []osvPackageResult `json:"results"`
}

type osvPackageResult struct {
	Package      osvPackage      `json:"package"`
	Source       osvSource       `json:"source"`
	Vulnerabilities []osvVuln    `json:"vulnerabilities"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvVuln struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
	Aliases []string `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVScannerAdapter struct {
	adapter.BaseAdapter
}

func NewOSVScannerAdapter() *OSVScannerAdapter {
	return &OSVScannerAdapter{
		BaseAdapter: adapter.NewBaseAdapter("osv_scanner", "OSV-Scanner", "scanner", "P2", "1.0"),
	}
}

func (o *OSVScannerAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	osvPath := config["adapter_paths.osv_scanner"]
	if osvPath == "" {
		osvPath = "osv-scanner"
	}

	scanPath := config["osv_scanner.scan_path"]
	if scanPath == "" {
		scanPath = "."
	}

	cmd := exec.CommandContext(ctx, osvPath, "--json", scanPath)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return out, nil
		}
		return nil, fmt.Errorf("osv-scanner execution failed: %w", err)
	}
	return out, nil
}

func (o *OSVScannerAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var result osvResult
	if err := json.Unmarshal(raw, &result); err != nil {
		hasOutput := len(raw) > 0
		vulnCount := 0
		if hasOutput {
			vulnCount = strings.Count(strings.ToLower(string(raw)), `"id":`)
		}
		return []*adapter.NormalizedFinding{{
			ID:          "OSV-SCANNER-RESULT",
			Source:      "osv_scanner",
			ToolName:    "OSV-Scanner",
			Timestamp:   now,
			FindingType: adapter.FindingVulnerability,
			Severity:    map[bool]adapter.Severity{true: adapter.SeverityInfo, false: adapter.SeverityHigh}[vulnCount == 0],
			Title:       "OSV-Scanner dependency scan",
			Passed:      vulnCount == 0,
			Detail:      fmt.Sprintf("OSV-Scanner completed, %d vulnerabilities found", vulnCount),
			Domain:      model.DomainAttackSurface,
			DelegatedTo: "osv_scanner",
		}}, nil
	}

	totalVulns := 0
	var findings []*adapter.NormalizedFinding

	for _, pkg := range result.Results {
		for _, vuln := range pkg.Vulnerabilities {
			totalVulns++

			cveID := vuln.ID
			for _, alias := range vuln.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					cveID = alias
					break
				}
			}

			sev := adapter.SeverityMedium
			for _, s := range vuln.Severity {
				if strings.HasPrefix(s.Type, "CVSS") {
					if strings.Contains(s.Score, "CRITICAL") {
						sev = adapter.SeverityCritical
					} else if strings.Contains(s.Score, "HIGH") {
						sev = adapter.SeverityHigh
					}
				}
			}

			findings = append(findings, &adapter.NormalizedFinding{
				ID:          vuln.ID,
				Source:      "osv_scanner",
				ToolName:    "OSV-Scanner",
				Timestamp:   now,
				FindingType: adapter.FindingVulnerability,
				Severity:    sev,
				Title:       vuln.Summary,
				Description: vuln.Details,
				Resource:    fmt.Sprintf("%s@%s (%s)", pkg.Package.Name, pkg.Package.Version, pkg.Package.Ecosystem),
				CVE:         cveID,
				Reference:   vuln.DatabaseSpecific.URL,
				Passed:      false,
				Detail:      fmt.Sprintf("Vulnerability %s in %s@%s", vuln.ID, pkg.Package.Name, pkg.Package.Version),
				Domain:      model.DomainAttackSurface,
				DelegatedTo: "osv_scanner",
			})
		}
	}

	if totalVulns == 0 {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "OSV-SCANNER-RESULT",
			Source:      "osv_scanner",
			ToolName:    "OSV-Scanner",
			Timestamp:   now,
			FindingType: adapter.FindingVulnerability,
			Severity:    adapter.SeverityInfo,
			Title:       "OSV-Scanner dependency scan",
			Passed:      true,
			Detail:      "OSV-Scanner completed, no vulnerabilities found",
			Domain:      model.DomainAttackSurface,
			DelegatedTo: "osv_scanner",
		})
	}

	return findings, nil
}

func (o *OSVScannerAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (o *OSVScannerAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== AIDE Adapter (SC-010, P2) =====

type AIDEAdapter struct {
	adapter.BaseAdapter
}

func NewAIDEAdapter() *AIDEAdapter {
	return &AIDEAdapter{
		BaseAdapter: adapter.NewBaseAdapter("aide", "AIDE", "scanner", "P2", "1.0"),
	}
}

func (a *AIDEAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	aidePath := config["adapter_paths.aide"]
	if aidePath == "" {
		aidePath = "aide"
	}
	cmd := exec.CommandContext(ctx, aidePath, "--check")
	out, err := cmd.Output()
	if err != nil {
		return out, nil
	}
	return out, nil
}

func (a *AIDEAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
	text := string(raw)
	changes := strings.Count(text, "\n")
	passed := !strings.Contains(strings.ToLower(text), "changed") &&
		!strings.Contains(strings.ToLower(text), "added") &&
		!strings.Contains(strings.ToLower(text), "removed")

	return []*adapter.NormalizedFinding{{
		ID:          "AIDE-CHECK",
		Source:      "aide",
		ToolName:    "AIDE",
		Timestamp:   now,
		FindingType: adapter.FindingCompliance,
		Severity:    map[bool]adapter.Severity{true: adapter.SeverityInfo, false: adapter.SeverityHigh}[passed],
		Title:       "AIDE File Integrity Check",
		Passed:      passed,
		Detail:      fmt.Sprintf("AIDE integrity check: %s (%d lines changed)", map[bool]string{true: "clean", false: "changes detected"}[passed], changes),
		Domain:      model.DomainOperationTrust,
		DelegatedTo: "aide",
	}}, nil
}

func (a *AIDEAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (a *AIDEAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Nikto Adapter (SC-011, P2) =====

type NiktoAdapter struct {
	adapter.BaseAdapter
}

func NewNiktoAdapter() *NiktoAdapter {
	return &NiktoAdapter{
		BaseAdapter: adapter.NewBaseAdapter("nikto", "Nikto", "scanner", "P2", "1.0"),
	}
}

func (n *NiktoAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	niktoPath := config["adapter_paths.nikto"]
	if niktoPath == "" {
		niktoPath = "nikto"
	}

	target := config["nikto.target"]
	if target == "" {
		target = "localhost"
	}

	cmd := exec.CommandContext(ctx, niktoPath, "-h", target, "-Format", "txt")
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return out, nil
		}
		return nil, fmt.Errorf("nikto execution failed: %w", err)
	}
	return out, nil
}

func (n *NiktoAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
	text := string(raw)
	hasFindings := strings.Contains(strings.ToLower(text), "vulnerab") ||
		strings.Contains(strings.ToLower(text), "warning") ||
		strings.Contains(strings.ToLower(text), "interesting")

	return []*adapter.NormalizedFinding{{
		ID:          "NIKTO-SCAN",
		Source:      "nikto",
		ToolName:    "Nikto",
		Timestamp:   now,
		FindingType: adapter.FindingVulnerability,
		Severity:    map[bool]adapter.Severity{true: adapter.SeverityHigh, false: adapter.SeverityInfo}[hasFindings],
		Title:       "Nikto Web Server Scan",
		Passed:      !hasFindings,
		Detail:      fmt.Sprintf("Nikto scan %s", map[bool]string{true: "found issues", false: "clean"}[hasFindings]),
		Domain:      model.DomainAttackSurface,
		DelegatedTo: "nikto",
	}}, nil
}

func (n *NiktoAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (n *NiktoAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
