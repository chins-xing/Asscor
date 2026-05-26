package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

var sourceCmdInfo = CommandInfo{
	Name:        "source",
	Short:       "Manage external sources",
	Description: "Deploy, configure, enable/disable, update, and uninstall external integration sources",
	Usage:       "source <list|info|deploy|enable|disable|update|uninstall|run|config|audit> [args]",
	Category:    CategorySource,
	Params: []CommandParam{
		{Name: "action", Description: "Action to perform", Required: true, EnumValues: []string{"list", "info", "deploy", "enable", "disable", "update", "uninstall", "run", "config", "audit"}},
	},
	Options: []CommandOption{
		{Name: "category", Short: "c", Description: "Filter by category (scanner/management)", Default: ""},
		{Name: "version", Short: "v", Description: "Version (for deploy/update)", Default: ""},
		{Name: "force", Short: "f", Description: "Force operation", IsBool: true},
		{Name: "limit", Short: "l", Description: "Limit results", Default: "50"},
	},
	Examples: []string{
		"source list",
		"source list --category scanner",
		"source info trivy",
		"source enable trivy",
		"source disable trivy",
		"source update trivy --version 0.50.0",
		"source uninstall trivy --force",
		"source run trivy",
		"source config trivy",
		"source audit trivy --limit 20",
	},
}

func sourceCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("source: action required"),
			Output:   formatHelp(sourceCmdInfo),
		}
	}

	action := ctx.Args[0]
	srcAccess := ctx.Kernel.Sources()

	switch action {
	case "list":
		return sourceListHandler(ctx, srcAccess)
	case "info":
		return sourceInfoHandler(ctx, srcAccess)
	case "enable":
		return sourceEnableHandler(ctx, srcAccess)
	case "disable":
		return sourceDisableHandler(ctx, srcAccess)
	case "update":
		return sourceUpdateHandler(ctx, srcAccess)
	case "uninstall":
		return sourceUninstallHandler(ctx, srcAccess)
	case "run":
		return sourceRunHandler(ctx, srcAccess)
	case "config":
		return sourceConfigHandler(ctx, srcAccess)
	case "audit":
		return sourceAuditHandler(ctx, srcAccess)
	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("source: unknown action '%s'", action),
			Output:   formatHelp(sourceCmdInfo),
		}
	}
}

func sourceListHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	category := ctx.Options["category"]

	var sources []kernel.SourceStatus
	if category != "" {
		sources = src.ListSources(kernel.SourceCategory(category))
	} else {
		sources = src.ListAllSources()
	}

	sort.Slice(sources, func(i, j int) bool {
		return sources[i].ID < sources[j].ID
	})

	if ctx.JSON {
		data, _ := json.MarshalIndent(sources, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: sources}
	}

	var b strings.Builder
	b.WriteString("\n  External Sources\n")
	b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  %-14s %-20s %-10s %-5s %-8s %-10s %s\n",
		"ID", "NAME", "CATEGORY", "PRI", "STATE", "VERSION", "ENABLED"))
	b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")

	for _, s := range sources {
		b.WriteString(fmt.Sprintf("  %-14s %-20s %-10s %-5s %-8s %-10s %v\n",
			s.ID, truncate(s.ID, 20), s.ID, "", s.State, s.Version, s.Enabled))
	}

	if len(sources) == 0 {
		b.WriteString("  (no sources)\n")
	}

	enabled := 0
	for _, s := range sources {
		if s.Enabled {
			enabled++
		}
	}
	b.WriteString(fmt.Sprintf("\n  Total: %d  Enabled: %d  Disabled: %d\n\n", len(sources), enabled, len(sources)-enabled))

	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: sources}
}

func sourceInfoHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source info: id required"), Output: "Usage: source info <id>\n"}
	}
	id := ctx.Args[1]

	status, ok := src.GetSourceStatus(id)
	if !ok {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("source %s not found", id), Output: fmt.Sprintf("Source '%s' not found\n", id)}
	}

	spec, _ := src.GetSourceSpec(id)

	if ctx.JSON {
		data := map[string]interface{}{
			"status": status,
			"spec":   spec,
		}
		raw, _ := json.MarshalIndent(data, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(raw) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  Source Detail\n")
	b.WriteString("  ─────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  ID:          %s\n", status.ID))
	if spec != nil {
		b.WriteString(fmt.Sprintf("  Name:        %s\n", spec.Name))
		b.WriteString(fmt.Sprintf("  Category:    %s\n", spec.Category))
		b.WriteString(fmt.Sprintf("  Priority:    %s\n", spec.Priority))
		b.WriteString(fmt.Sprintf("  Description: %s\n", spec.Description))
		if spec.Interface != "" {
			b.WriteString(fmt.Sprintf("  Interface:   %s\n", spec.Interface))
		}
		if spec.OutputFormat != "" {
			b.WriteString(fmt.Sprintf("  Output:      %s\n", spec.OutputFormat))
		}
		if len(spec.DependsOn) > 0 {
			b.WriteString(fmt.Sprintf("  Depends On:  %s\n", strings.Join(spec.DependsOn, ", ")))
		}
	}
	b.WriteString(fmt.Sprintf("  Version:     %s\n", status.Version))
	b.WriteString(fmt.Sprintf("  State:       %s\n", status.State))
	b.WriteString(fmt.Sprintf("  Enabled:     %v\n", status.Enabled))
	if !status.LastSync.IsZero() {
		b.WriteString(fmt.Sprintf("  Last Sync:   %s\n", status.LastSync.Format(time.RFC3339)))
	}
	if status.LastError != "" {
		b.WriteString(fmt.Sprintf("  Last Error:  %s\n", status.LastError))
	}
	b.WriteString(fmt.Sprintf("  Findings:    %d\n", status.Findings))
	b.WriteString(fmt.Sprintf("  Sync Count:  %d\n", status.SyncCount))
	b.WriteString(fmt.Sprintf("  Error Count: %d\n", status.ErrorCount))
	if !status.InstalledAt.IsZero() {
		b.WriteString(fmt.Sprintf("  Installed:   %s\n", status.InstalledAt.Format(time.RFC3339)))
	}
	b.WriteString("\n")

	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func sourceEnableHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source enable: id required"), Output: "Usage: source enable <id>\n"}
	}
	id := ctx.Args[1]

	if err := src.EnableSource(ctx.Ctx, id); err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Error: %s\n", err)}
	}

	return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Source '%s' enabled.\n", id)}
}

func sourceDisableHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source disable: id required"), Output: "Usage: source disable <id>\n"}
	}
	id := ctx.Args[1]

	if err := src.DisableSource(ctx.Ctx, id); err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Error: %s\n", err)}
	}

	return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Source '%s' disabled.\n", id)}
}

func sourceUpdateHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source update: id required"), Output: "Usage: source update <id> --version <version>\n"}
	}
	id := ctx.Args[1]
	version := ctx.Options["version"]
	if version == "" {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("--version is required"), Output: "Usage: source update <id> --version <version>\n"}
	}

	if err := src.UpdateSource(ctx.Ctx, id, version); err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Error: %s\n", err)}
	}

	return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Source '%s' updated to v%s.\n", id, version)}
}

func sourceUninstallHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source uninstall: id required"), Output: "Usage: source uninstall <id> [--force]\n"}
	}
	id := ctx.Args[1]
	force := ctx.Flags["force"]

	if err := src.UninstallSource(ctx.Ctx, id, force); err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Error: %s\n", err)}
	}

	return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Source '%s' uninstalled.\n", id)}
}

func sourceRunHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source run: id required"), Output: "Usage: source run <id>\n"}
	}
	id := ctx.Args[1]

	if err := src.RunSourceNow(ctx.Ctx, id); err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Error: %s\n", err)}
	}

	status, _ := src.GetSourceStatus(id)
	findings := 0
	if status != nil {
		findings = status.Findings
	}

	return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Source '%s' executed. Findings: %d\n", id, findings)}
}

func sourceConfigHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	if len(ctx.Args) < 2 {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("source config: id required"), Output: "Usage: source config <id>\n"}
	}
	id := ctx.Args[1]

	cfg, ok := src.GetSourceConfig(id)
	if !ok {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("source %s not found", id), Output: fmt.Sprintf("Source '%s' not found\n", id)}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(cfg, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Source Config: %s\n", id))
	b.WriteString("  ─────────────────────────────────────────\n")
	if len(cfg.Settings) == 0 {
		b.WriteString("  (no custom configuration)\n")
	} else {
		for k, v := range cfg.Settings {
			b.WriteString(fmt.Sprintf("  %-30s %s\n", k, v))
		}
	}
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func sourceAuditHandler(ctx *CommandContext, src SourceAccess) *CommandResult {
	sourceID := ""
	if len(ctx.Args) >= 2 {
		sourceID = ctx.Args[1]
	}

	limit := 50
	if v := ctx.Options["limit"]; v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}

	entries := src.GetAuditLog(sourceID, limit)

	if ctx.JSON {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  Source Audit Log\n")
	b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  %-20s %-12s %-14s %-8s %s\n", "TIME", "ACTION", "SOURCE", "OK", "DETAIL"))
	b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")

	for _, e := range entries {
		okMark := "✓"
		if !e.Success {
			okMark = "✗"
		}
		b.WriteString(fmt.Sprintf("  %-20s %-12s %-14s %-8s %s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Action,
			e.SourceID,
			okMark,
			e.Detail,
		))
	}

	if len(entries) == 0 {
		b.WriteString("  (no audit entries)\n")
	}
	b.WriteString("\n")

	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func sourceCompletions(ctx *CommandContext, partial string) []string {
	actions := []string{"list", "info", "deploy", "enable", "disable", "update", "uninstall", "run", "config", "audit"}
	var matches []string
	for _, a := range actions {
		if strings.HasPrefix(a, partial) {
			matches = append(matches, a)
		}
	}
	return matches
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
