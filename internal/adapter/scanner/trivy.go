//go:build adapter

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type trivyResult struct {
	Results []trivyScanResult `json:"Results"`
}

type trivyScanResult struct {
	Target          string              `json:"Target"`
	Type            string              `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfig  `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string  `json:"VulnerabilityID"`
	PkgName          string  `json:"PkgName"`
	Severity         string  `json:"Severity"`
	Title            string  `json:"Title"`
	Description      string  `json:"Description"`
	FixedVersion     string  `json:"FixedVersion"`
	PrimaryURL       string  `json:"PrimaryURL"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
}

type trivyCVSS struct {
	V3Score float64 `json:"V3Score"`
	V3Vector string `json:"V3Vector"`
}

type trivyMisconfig struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
	PrimaryURL  string `json:"PrimaryURL"`
}

type TrivyAdapter struct {
	adapter.BaseAdapter
}

func NewTrivyAdapter() *TrivyAdapter {
	return &TrivyAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"trivy",
			"Trivy",
			"scanner",
			"P0",
			"1.0",
		),
	}
}

func (t *TrivyAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	trivyPath := config["adapter_paths.trivy"]
	if trivyPath == "" {
		trivyPath = "trivy"
	}

	args := []string{"image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM,LOW"}

	targetImages := config["trivy.target_images"]
	if targetImages != "" {
		for _, img := range strings.Split(targetImages, ",") {
			args = append(args, strings.TrimSpace(img))
		}
	} else {
		hostname, _ := os.Hostname()
		args = append(args, hostname)
	}

	cmd := exec.CommandContext(ctx, trivyPath, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}
	return out, nil
}

func (t *TrivyAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	var result trivyResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("trivy json parse: %w", err)
	}

	var findings []*adapter.NormalizedFinding
	now := time.Now()

	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			f := &adapter.NormalizedFinding{
				ID:          v.VulnerabilityID,
				Source:      "trivy",
				ToolName:    "Trivy",
				Timestamp:   now,
				FindingType: adapter.FindingVulnerability,
				Severity:    adapter.ParseSeverity(v.Severity),
				Title:       v.Title,
				Description: v.Description,
				Resource:    fmt.Sprintf("%s/%s", r.Target, v.PkgName),
				CVE:         v.VulnerabilityID,
				FixVersion:  v.FixedVersion,
				Reference:   v.PrimaryURL,
				Passed:      false,
				Detail:      fmt.Sprintf("CVE-%s in %s (package %s)", v.VulnerabilityID, r.Target, v.PkgName),
			}

			if cvss, ok := v.CVSS["nvd"]; ok {
				f.CVSEScore = cvss.V3Score
				f.CVSSVector = cvss.V3Vector
			}

			adapter.ApplyDelegation(f, "trivy")
			findings = append(findings, f)
		}

		for _, m := range r.Misconfigurations {
			f := &adapter.NormalizedFinding{
				ID:          m.ID,
				Source:      "trivy",
				ToolName:    "Trivy",
				Timestamp:   now,
				FindingType: adapter.FindingMisconfig,
				Severity:    adapter.ParseSeverity(m.Severity),
				Title:       m.Title,
				Description: m.Description,
				Resource:    r.Target,
				Reference:   m.PrimaryURL,
				Passed:      false,
				Detail:      fmt.Sprintf("Misconfig %s: %s", m.ID, m.Title),
				Domain:      model.DomainOperationTrust,
				CheckID:     "OT-099-T",
				DelegatedTo: "trivy",
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func (t *TrivyAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	for _, f := range findings {
		if f.Severity == adapter.SeverityNone && f.CVSEScore >= 9.0 {
			f.Severity = adapter.SeverityCritical
		} else if f.Severity == adapter.SeverityNone && f.CVSEScore >= 7.0 {
			f.Severity = adapter.SeverityHigh
		}
		if f.Title == "" && f.CVE != "" {
			f.Title = f.CVE
		}
		f.Passed = false
	}
	return findings
}

func (t *TrivyAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
