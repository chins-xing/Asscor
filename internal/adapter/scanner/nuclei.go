package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/argus-security/argus/internal/adapter"
	"github.com/argus-security/argus/internal/model"
)

type nucleiResultItem struct {
	TemplateID  string      `json:"template-id"`
	TemplateURL string      `json:"template-url"`
	Info        nucleiInfo   `json:"info"`
	Type        string      `json:"type"`
	Host        string      `json:"host"`
	MatchedAt   string      `json:"matched-at"`
	Severity    string      `json:"severity"`
	Timestamp   string      `json:"timestamp"`
	MatcherName string      `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	IP          string      `json:"ip"`
	CurlCommand string      `json:"curl-command"`
}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Author      []string `json:"author"`
	Description string   `json:"description"`
	Reference   []string `json:"reference"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
	Classification nucleiClassification `json:"classification"`
}

type nucleiClassification struct {
	CVEScore float64  `json:"cvss-score"`
	CVEID    []string `json:"cve-id"`
	CVEMap   map[string]string `json:"cve-map"`
}

type NucleiAdapter struct {
	adapter.BaseAdapter
}

func NewNucleiAdapter() *NucleiAdapter {
	return &NucleiAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"nuclei",
			"Nuclei",
			"scanner",
			"P0",
			"1.0",
		),
	}
}

func (n *NucleiAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	nucleiPath := config["adapter_paths.nuclei"]
	if nucleiPath == "" {
		nucleiPath = "nuclei"
	}

	args := []string{"-jsonl", "-silent", "-severity", "critical,high,medium,low,info"}

	templates := config["nuclei.templates"]
	if templates != "" {
		args = append(args, "-t", templates)
	}

	target := config["nuclei.target"]
	if target != "" {
		args = append(args, "-u", target)
	} else {
		args = append(args, "-host")
	}

	cmd := exec.CommandContext(ctx, nucleiPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return out, nil
		}
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}
	return out, nil
}

func (n *NucleiAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil, nil
	}

	var findings []*adapter.NormalizedFinding
	now := time.Now()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item nucleiResultItem
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			adapter.LogWarn("nuclei jsonl parse skipped: %v", err)
			continue
		}

		severity := item.Info.Severity
		if severity == "" {
			severity = item.Severity
		}

		cveID := ""
		if len(item.Info.Classification.CVEID) > 0 {
			cveID = item.Info.Classification.CVEID[0]
		}

		refs := ""
		if len(item.Info.Reference) > 0 {
			refs = strings.Join(item.Info.Reference, "; ")
		}

		target := item.Host
		if item.IP != "" {
			target = item.Host + " (" + item.IP + ")"
		}

		f := &adapter.NormalizedFinding{
			ID:          item.TemplateID,
			Source:      "nuclei",
			ToolName:    "Nuclei",
			Timestamp:   now,
			FindingType: adapter.FindingVulnerability,
			Severity:    adapter.ParseSeverity(severity),
			Title:       item.Info.Name,
			Description: item.Info.Description,
			Resource:    target,
			Reference:   refs,
			Passed:      false,
			Detail:      fmt.Sprintf("Template %s matched on %s", item.TemplateID, item.MatchedAt),
			CVSEScore:   item.Info.Classification.CVEScore,
			CVE:         cveID,
			Metadata: map[string]string{
				"template_url": item.TemplateURL,
				"type":         item.Type,
				"matched_at":   item.MatchedAt,
			},
			Domain: model.DomainAttackSurface,
		}

		adapter.ApplyDelegation(f, "nuclei")
		findings = append(findings, f)
	}

	return findings, nil
}

func (n *NucleiAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	for _, f := range findings {
		if f.Title == "" {
			f.Title = f.ID
		}
		f.Passed = false
	}
	return findings
}

func (n *NucleiAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
