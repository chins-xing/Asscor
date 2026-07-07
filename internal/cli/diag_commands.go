package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ──────────────────────────── diag ────────────────────────────

var diagCmdInfo = CommandInfo{
	Name:         "diag",
	Short:        "Runtime diagnostics",
	Description:  "Display kernel runtime diagnostics: event bus metrics and worker pool stats",
	Usage:        "diag",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Examples: []string{
		"diag",
		"diag --json",
	},
}

func diagCmdHandler(ctx *CommandContext) *CommandResult {
	if ctx.Kernel == nil {
		return &CommandResult{ExitCode: ExitError, Output: "kernel not available\n"}
	}

	diag := ctx.Kernel.Diagnostics()

	if ctx.JSON {
		data, _ := json.MarshalIndent(diag, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: diag}
	}

	var b strings.Builder
	b.WriteString("\n  Kernel Runtime Diagnostics\n")
	b.WriteString("  ────────────────────────────\n")

	if bus, ok := diag["bus"].(map[string]interface{}); ok {
		b.WriteString("  Event Bus:\n")
		b.WriteString(fmt.Sprintf("    Messages : %v\n", bus["messages"]))
		b.WriteString(fmt.Sprintf("    Errors   : %v\n", bus["errors"]))
		b.WriteString(fmt.Sprintf("    Panics   : %v\n", bus["panics"]))
	}

	if wp, ok := diag["worker_pool"].(map[string]interface{}); ok {
		b.WriteString("  Worker Pool:\n")
		b.WriteString(fmt.Sprintf("    Active   : %v\n", wp["active"]))
		b.WriteString(fmt.Sprintf("    Available: %v\n", wp["available"]))
		b.WriteString(fmt.Sprintf("    Max      : %v\n", wp["max"]))
	}

	if len(diag) == 0 {
		b.WriteString("  (no diagnostics available)\n")
	}
	b.WriteString("\n")

	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: diag}
}

// ──────────────────────────── policy ────────────────────────────

var policyCmdInfo = CommandInfo{
	Name:         "policy",
	Short:        "Policy and host status",
	Description:  "View policy-driven host status tier for a given host",
	Usage:        "policy status <host-id>",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "status", Required: true, EnumValues: []string{"status"}},
		{Name: "host", Description: "host identifier", Required: false},
	},
	Examples: []string{
		"policy status web-server-01",
	},
}

func policyCmdHandler(ctx *CommandContext) *CommandResult {
	if ctx.Kernel == nil {
		return &CommandResult{ExitCode: ExitError, Output: "kernel not available\n"}
	}

	action := ""
	if len(ctx.Args) > 0 {
		action = ctx.Args[0]
	}

	switch action {
	case "status", "":
		hostID := ""
		if len(ctx.Args) > 1 {
			hostID = ctx.Args[1]
		}
		if hostID == "" {
			// Aggregate view across all known agents.
			agents := ctx.Kernel.Agents().ListAgents()
			if len(agents) == 0 {
				return &CommandResult{ExitCode: ExitOK, Output: "no agents registered\n"}
			}
			type row struct {
				HostID string `json:"host_id"`
				Status string `json:"status"`
			}
			rows := make([]row, 0, len(agents))
			for _, a := range agents {
				st, ok := ctx.Kernel.PolicyStatus(a.HostID)
				if !ok {
					st = "unknown"
				}
				rows = append(rows, row{HostID: a.HostID, Status: st})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].HostID < rows[j].HostID })
			if ctx.JSON {
				data, _ := json.MarshalIndent(rows, "", "  ")
				return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: rows}
			}
			var b strings.Builder
			b.WriteString("\n  Host Policy Status\n  ──────────────────\n")
			for _, r := range rows {
				b.WriteString(fmt.Sprintf("  %-24s %s\n", r.HostID, r.Status))
			}
			b.WriteString("\n")
			return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: rows}
		}
		status, ok := ctx.Kernel.PolicyStatus(hostID)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "policy module not available\n"}
		}
		if ctx.JSON {
			data, _ := json.MarshalIndent(map[string]string{"host_id": hostID, "status": status}, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
		}
		return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("host %s policy status: %s\n", hostID, status)}
	default:
		return &CommandResult{ExitCode: ExitUsage, Output: "usage: policy status [host-id]\n"}
	}
}
