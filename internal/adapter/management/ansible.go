package management

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/argus-security/argus/internal/adapter"
	"github.com/argus-security/argus/internal/model"
)

type AnsibleAdapter struct {
	adapter.BaseAdapter
}

func NewAnsibleAdapter() *AnsibleAdapter {
	return &AnsibleAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"ansible",
			"Ansible",
			"management",
			"P0",
			"1.0",
		),
	}
}

func (a *AnsibleAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	inventoryPath := config["ansible.inventory_path"]
	if inventoryPath == "" {
		inventoryPath = "/etc/ansible/hosts"
	}

	data, err := os.ReadFile(inventoryPath)
	if err != nil {
		ansiblePath := config["adapter_paths.ansible"]
		if ansiblePath == "" {
			ansiblePath = "ansible"
		}
		cmd := exec.CommandContext(ctx, ansiblePath, "-m", "setup", "--tree", "/tmp/ansible_facts")
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("ansible facts fetch failed: %w", err)
		}
		return out, nil
	}
	return data, nil
}

func (a *AnsibleAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	lines := strings.Split(string(raw), "\n")
	var findings []*adapter.NormalizedFinding
	now := time.Now()

	currentGroup := ""
	hostCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentGroup = strings.Trim(line, "[]")
			continue
		}

		if currentGroup == "" {
			currentGroup = "ungrouped"
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			hostName := strings.TrimSpace(parts[0])

			f := &adapter.NormalizedFinding{
				ID:          fmt.Sprintf("ANSIBLE-HOST-%s", hostName),
				Source:      "ansible",
				ToolName:    "Ansible",
				Timestamp:   now,
				FindingType: adapter.FindingConfigState,
				Severity:    adapter.SeverityInfo,
				Title:       fmt.Sprintf("Host %s in group %s", hostName, currentGroup),
				Resource:    hostName,
				Passed:      true,
				Detail:      fmt.Sprintf("Managed host %s (group: %s) present in inventory", hostName, currentGroup),
				Domain:      model.DomainOperationTrust,
				Metadata: map[string]string{
					"ansible_group": currentGroup,
					"host":          hostName,
				},
			}
			adapter.ApplyDelegation(f, "ansible")
			findings = append(findings, f)
			hostCount++
		} else {
			f := &adapter.NormalizedFinding{
				ID:          fmt.Sprintf("ANSIBLE-HOST-%s", line),
				Source:      "ansible",
				ToolName:    "Ansible",
				Timestamp:   now,
				FindingType: adapter.FindingConfigState,
				Severity:    adapter.SeverityInfo,
				Title:       fmt.Sprintf("Host %s in group %s", line, currentGroup),
				Resource:    line,
				Passed:      true,
				Detail:      fmt.Sprintf("Managed host %s (group: %s) present in inventory", line, currentGroup),
				Domain:      model.DomainOperationTrust,
				Metadata: map[string]string{
					"ansible_group": currentGroup,
					"host":          line,
				},
			}
			adapter.ApplyDelegation(f, "ansible")
			findings = append(findings, f)
			hostCount++
		}
	}

	if hostCount == 0 {
		return []*adapter.NormalizedFinding{{
			ID:          "ANSIBLE-NO-HOSTS",
			Source:      "ansible",
			ToolName:    "Ansible",
			Timestamp:   now,
			FindingType: adapter.FindingConfigState,
			Severity:    adapter.SeverityMedium,
			Title:       "No hosts defined in Ansible inventory",
			Passed:      false,
			Detail:      "Ansible inventory is empty - no managed hosts configured",
			Domain:      model.DomainOperationTrust,
			DelegatedTo: "ansible",
		}}, nil
	}

	return findings, nil
}

func (a *AnsibleAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (a *AnsibleAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}
