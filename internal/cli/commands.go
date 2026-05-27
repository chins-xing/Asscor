package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/version"
)

var helpCmdInfo = CommandInfo{
	Name:        "help",
	Short:       "Show help information",
	Description: "Display help for a specific command or list all available commands",
	Usage:       "help [command]",
	Category:    CategoryCore,
	Params: []CommandParam{
		{Name: "command", Description: "Command name to get help for", Required: false},
	},
	Examples: []string{
		"help",
		"help spc",
		"help assess",
	},
}

func helpCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) > 0 {
		cmdName := ctx.Args[0]
		resolved, ok := ctx.Kernel.Registry().Resolve(cmdName)
		if !ok {
			return &CommandResult{
				ExitCode: ExitUsage,
				Err:      fmt.Errorf("unknown command: %s", cmdName),
				Output:   fmt.Sprintf("No help available for '%s'\n", cmdName),
			}
		}
		entry, _ := ctx.Kernel.Registry().Get(resolved)
		if entry != nil {
			return &CommandResult{ExitCode: ExitOK, Output: formatHelp(entry.info)}
		}
	}

	var b strings.Builder
	b.WriteString("\n  ASSCOR \u00b5Kernel CLI\n")
	b.WriteString(fmt.Sprintf("  Framework: %s   SSAM: %s\n\n", version.ASSCORVersion, version.SSAMVersion))

	categories := []CommandCategory{CategoryCore, CategoryAgent, CategoryAssess, CategorySPC, CategoryPlugin, CategorySource, CategorySystem, CategoryDebug}
	categoryLabels := map[CommandCategory]string{
		CategoryCore:   "Core Commands",
		CategoryAgent:  "Agent Management",
		CategoryAssess: "Assessment",
		CategorySPC:    "Security Posture",
		CategoryPlugin: "Plugin Management",
		CategorySource: "Source Management",
		CategorySystem: "System",
		CategoryDebug:  "Debug",
	}

	allCmds := ctx.Kernel.Registry().List()
	sort.Slice(allCmds, func(i, j int) bool {
		return allCmds[i].Name < allCmds[j].Name
	})

	for _, cat := range categories {
		var cmds []CommandInfo
		for _, c := range allCmds {
			if c.Category == cat && !c.Hidden {
				cmds = append(cmds, c)
			}
		}
		if len(cmds) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("  %s:\n", categoryLabels[cat]))
		for _, c := range cmds {
			deprecated := ""
			if c.Deprecated {
				deprecated = " [DEPRECATED]"
			}
			b.WriteString(fmt.Sprintf("    %-16s %s%s\n", c.Name, c.Short, deprecated))
		}
		b.WriteString("\n")
	}

	b.WriteString("  Options:\n")
	b.WriteString("    --verbose, -v     Show detailed output\n")
	b.WriteString("    --json, -j        Output in JSON format\n")
	b.WriteString("    --quiet, -q       Suppress non-essential output\n")
	b.WriteString("    --help, -h        Show help for a command\n")
	b.WriteString("\n  Type 'help <command>' for detailed usage.\n\n")

	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func helpCompletions(ctx *CommandContext, partial string) []string {
	return ctx.Kernel.Registry().Completions("")
}

var versionCmdInfo = CommandInfo{
	Name:        "version",
	Short:       "Show version information",
	Description: "Display ASSCOR framework and SSAM model version",
	Usage:       "version",
	Category:    CategoryCore,
	Examples: []string{
		"version",
		"version --json",
	},
}

func versionCmdHandler(ctx *CommandContext) *CommandResult {
	info := map[string]string{
		"framework":     version.ASSCORVersion,
		"ssam":          version.SSAMVersion,
		"go":            "",
		"build_time":    "",
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(info, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  ASSCOR Security Assessment Framework\n")
	b.WriteString(fmt.Sprintf("  Framework Version:  %s\n", info["framework"]))
	b.WriteString(fmt.Sprintf("  SSAM Model:         %s\n", info["ssam"]))
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

var statusCmdInfo = CommandInfo{
	Name:        "status",
	Short:       "Show kernel status",
	Description: "Display current kernel status including plugin states, uptime, and resource usage",
	Usage:       "status",
	Category:    CategoryCore,
	Options: []CommandOption{
		{Name: "format", Short: "f", Description: "Output format", Default: "text", EnumValues: []string{"text", "json"}},
	},
	Examples: []string{
		"status",
		"status --json",
	},
}

func statusCmdHandler(ctx *CommandContext) *CommandResult {
	plugins := ctx.Kernel.ListPlugins()
	healthResults := ctx.Kernel.HealthCheck(ctx.Ctx)

	type statusOutput struct {
		Plugins  int              `json:"plugins"`
		Healthy  int              `json:"healthy"`
		Unhealthy int             `json:"unhealthy"`
		Details  []PluginInfo     `json:"details,omitempty"`
		Health   []HealthStatus   `json:"health,omitempty"`
	}

	healthy, unhealthy := 0, 0
	for _, h := range healthResults {
		if h.Healthy {
			healthy++
		} else {
			unhealthy++
		}
	}

	out := statusOutput{
		Plugins:   len(plugins),
		Healthy:   healthy,
		Unhealthy: unhealthy,
		Details:   plugins,
		Health:    healthResults,
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(out, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: out}
	}

	var b strings.Builder
	b.WriteString("\n  Kernel Status\n")
	b.WriteString("  ─────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Plugins:  %d loaded  (%d healthy, %d unhealthy)\n\n", out.Plugins, out.Healthy, out.Unhealthy))

	if len(plugins) > 0 {
		b.WriteString("  Plugin Details:\n")
		for _, p := range plugins {
			stateMark := "●"
			if p.State != "started" {
				stateMark = "○"
			}
			b.WriteString(fmt.Sprintf("    %s %-16s v%-8s %s\n", stateMark, p.Name, p.Version, p.Description))
		}
	}

	if unhealthy > 0 {
		b.WriteString("\n  Unhealthy Plugins:\n")
		for _, h := range healthResults {
			if !h.Healthy {
				b.WriteString(fmt.Sprintf("    ✗ %s: %s\n", h.Name, h.Error))
			}
		}
	}
	b.WriteString("\n")

	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: out}
}

var pluginCmdInfo = CommandInfo{
	Name:        "plugin",
	Short:       "Manage plugins",
	Description: "List, inspect, and manage kernel plugins",
	Usage:       "plugin <list|info|health> [name]",
	Category:    CategoryPlugin,
	Params: []CommandParam{
		{Name: "action", Description: "Action: list, info, health", Required: true, EnumValues: []string{"list", "info", "health"}},
		{Name: "name", Description: "Plugin name (for info action)", Required: false},
	},
	Examples: []string{
		"plugin list",
		"plugin info spc",
		"plugin health",
	},
}

func pluginCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("plugin: action required"),
			Output:   formatHelp(pluginCmdInfo),
		}
	}

	action := ctx.Args[0]

	switch action {
	case "list":
		plugins := ctx.Kernel.ListPlugins()
		if ctx.JSON {
			data, _ := json.MarshalIndent(plugins, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  Registered Plugins\n")
		b.WriteString("  ──────────────────────────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  %-16s %-10s %-12s %s\n", "NAME", "VERSION", "STATE", "DESCRIPTION"))
		b.WriteString("  ──────────────────────────────────────────────────────────────\n")
		for _, p := range plugins {
			b.WriteString(fmt.Sprintf("  %-16s %-10s %-12s %s\n", p.Name, p.Version, p.State, p.Description))
		}
		b.WriteString(fmt.Sprintf("\n  Total: %d plugins\n\n", len(plugins)))
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "info":
		if len(ctx.Args) < 2 {
			return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("plugin name required"), Output: "Usage: plugin info <name>\n"}
		}
		name := ctx.Args[1]
		p, ok := ctx.Kernel.GetPlugin(name)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("plugin %q not found", name), Output: fmt.Sprintf("Plugin %q not found\n", name)}
		}

		pi, _ := p.(*PluginInfo)
		if pi == nil {
			pi = &PluginInfo{Name: name}
		}

		if ctx.JSON {
			data, _ := json.MarshalIndent(pi, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
		}

		var b strings.Builder
		b.WriteString(fmt.Sprintf("\n  Plugin: %s\n", pi.Name))
		b.WriteString("  ─────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  Version:     %s\n", pi.Version))
		b.WriteString(fmt.Sprintf("  State:       %s\n", pi.State))
		b.WriteString(fmt.Sprintf("  Description: %s\n", pi.Description))
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "health":
		results := ctx.Kernel.HealthCheck(ctx.Ctx)
		if ctx.JSON {
			data, _ := json.MarshalIndent(results, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  Plugin Health Check\n")
		b.WriteString("  ─────────────────────────────────────────\n")
		for _, h := range results {
			mark := "✓"
			if !h.Healthy {
				mark = "✗"
			}
			line := fmt.Sprintf("  %s %s", mark, h.Name)
			if !h.Healthy {
				line += fmt.Sprintf(": %s", h.Error)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown plugin action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: list, info, health\n", action),
		}
	}
}

func pluginCompletions(ctx *CommandContext, partial string) []string {
	return []string{"list", "info", "health"}
}

var configCmdInfo = CommandInfo{
	Name:        "config",
	Short:       "View configuration",
	Description: "Display or query current kernel configuration",
	Usage:       "config [key]",
	Category:    CategorySystem,
	Params: []CommandParam{
		{Name: "key", Description: "Configuration key to query (dot-separated path)", Required: false},
	},
	Options: []CommandOption{
		{Name: "format", Short: "f", Description: "Output format", Default: "text", EnumValues: []string{"text", "json"}},
	},
	Examples: []string{
		"config",
		"config threshold",
		"config --json",
	},
}

func configCmdHandler(ctx *CommandContext) *CommandResult {
	cfg := ctx.Kernel.Config()

	if ctx.JSON {
		data, _ := json.MarshalIndent(cfg, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: cfg}
	}

	if len(ctx.Args) > 0 {
		key := ctx.Args[0]
		if val, ok := cfg[key]; ok {
			return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("%s = %s\n", key, val)}
		}
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("config key %q not found", key), Output: fmt.Sprintf("Key %q not found\n", key)}
	}

	var b strings.Builder
	b.WriteString("\n  Configuration\n")
	b.WriteString("  ─────────────────────────────────────────\n")
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("  %-32s %s\n", k, cfg[k]))
	}
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func configCompletions(ctx *CommandContext, partial string) []string {
	cfg := ctx.Kernel.Config()
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	return keys
}

var spcCmdInfo = CommandInfo{
	Name:        "spc",
	Short:       "Security Posture Calculator",
	Description: "Query SPC module: CVE cache, P-score, KEV count, and correction data",
	Usage:       "spc <summary|cve|kev|score|fetch>",
	Category:    CategorySPC,
	Params: []CommandParam{
		{Name: "action", Description: "Action: summary, cve, kev, score, fetch", Required: true, EnumValues: []string{"summary", "cve", "kev", "score", "fetch"}},
	},
	Options: []CommandOption{
		{Name: "limit", Short: "n", Description: "Limit number of results", Default: "20"},
		{Name: "cvss-min", Description: "Minimum CVSS score filter"},
		{Name: "kev-only", Description: "Show only KEV entries", IsBool: true},
	},
	Examples: []string{
		"spc summary",
		"spc cve --cvss-min=9.0",
		"spc kev",
		"spc score --host=web01",
		"spc fetch",
	},
}

func spcCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("spc: action required"),
			Output:   formatHelp(spcCmdInfo),
		}
	}

	action := ctx.Args[0]
	spcPlugin, ok := ctx.Kernel.GetPlugin("spc")
	if !ok {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("SPC module not available"), Output: "SPC module not available\n"}
	}

	switch action {
	case "summary":
		summary, ok := spcPlugin.(interface{ Summary() map[string]interface{} })
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "SPC module does not support summary\n"}
		}
		data := summary.Summary()
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  SPC Summary\n")
		b.WriteString("  ─────────────────────────────────────────\n")
		for k, v := range data {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", k, v))
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "cve", "kev", "score", "fetch":
		return &CommandResult{
			ExitCode: ExitOK,
			Output:   fmt.Sprintf("SPC '%s' action executed\n", action),
		}

	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown spc action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: summary, cve, kev, score, fetch\n", action),
		}
	}
}

func spcCompletions(ctx *CommandContext, partial string) []string {
	return []string{"summary", "cve", "kev", "score", "fetch"}
}

var assessCmdInfo = CommandInfo{
	Name:        "assess",
	Short:       "Run assessment",
	Description: "Trigger a security assessment on the local host or a specified target",
	Usage:       "assess [host]",
	Category:    CategoryAssess,
	Params: []CommandParam{
		{Name: "host", Description: "Target host ID (default: local)", Required: false},
	},
	Options: []CommandOption{
		{Name: "format", Short: "f", Description: "Output format", Default: "text", EnumValues: []string{"text", "json"}},
		{Name: "domain", Short: "d", Description: "Assess specific domain only"},
	},
	Examples: []string{
		"assess",
		"assess web-server-01",
		"assess --domain=attack_surface",
		"assess --json",
	},
}

func assessCmdHandler(ctx *CommandContext) *CommandResult {
	hostID := "local"
	if len(ctx.Args) > 0 {
		hostID = ctx.Args[0]
	}

	result, err := ctx.Kernel.Evaluate(hostID)
	if err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err, Output: fmt.Sprintf("Assessment failed: %v\n", err)}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: result}
	}

	var b strings.Builder
	b.WriteString("\n  Assessment Result\n")
	b.WriteString("  ─────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Host:    %s\n", hostID))
	b.WriteString(fmt.Sprintf("  Result:  %v\n", result))
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: result}
}

var healthCmdInfo = CommandInfo{
	Name:        "health",
	Short:       "Health check",
	Description: "Run health checks on all kernel plugins",
	Usage:       "health",
	Category:    CategorySystem,
	Examples: []string{
		"health",
		"health --json",
	},
}

func healthCmdHandler(ctx *CommandContext) *CommandResult {
	results := ctx.Kernel.HealthCheck(ctx.Ctx)

	if ctx.JSON {
		data, _ := json.MarshalIndent(results, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  Health Check Results\n")
	b.WriteString("  ─────────────────────────────────────────\n")

	allHealthy := true
	for _, h := range results {
		mark := "✓"
		if !h.Healthy {
			mark = "✗"
			allHealthy = false
		}
		line := fmt.Sprintf("  %s %-20s", mark, h.Name)
		if !h.Healthy {
			line += fmt.Sprintf("  %s", h.Error)
		} else {
			line += "  OK"
		}
		b.WriteString(line + "\n")
	}

	exitCode := ExitOK
	if !allHealthy {
		exitCode = ExitError
	}
	b.WriteString("\n")
	return &CommandResult{ExitCode: exitCode, Output: b.String()}
}

var historyCmdInfo = CommandInfo{
	Name:        "history",
	Short:       "Command history",
	Description: "Show command execution history",
	Usage:       "history [count]",
	Category:    CategoryDebug,
	Params: []CommandParam{
		{Name: "count", Description: "Number of recent entries to show", Required: false, Default: "20"},
	},
	Options: []CommandOption{
		{Name: "failed", Short: "f", Description: "Show only failed commands", IsBool: true},
		{Name: "clear", Description: "Clear command history", IsBool: true},
	},
	Examples: []string{
		"history",
		"history 50",
		"history --failed",
		"history --clear",
	},
}

func historyCmdHandler(ctx *CommandContext) *CommandResult {
	hist := ctx.Kernel.History()

	if _, ok := ctx.Flags["clear"]; ok {
		hist.Clear()
		return &CommandResult{ExitCode: ExitOK, Output: "History cleared.\n"}
	}

	count := 20
	if len(ctx.Args) > 0 {
		if n, err := parsePositiveInt(ctx.Args[0]); err == nil && n > 0 {
			count = n
		}
	}

	onlyFailed := ctx.Flags["failed"]
	entries := hist.Recent(count)

	if ctx.JSON {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  Command History\n")
	b.WriteString("  ──────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  %-5s %-6s %-12s %s\n", "#", "EXIT", "DURATION", "COMMAND"))
	b.WriteString("  ──────────────────────────────────────────────────────────────────────\n")

	shown := 0
	for _, e := range entries {
		if onlyFailed && e.ExitCode == 0 {
			continue
		}
		mark := "OK"
		if e.ExitCode != 0 {
			mark = fmt.Sprintf("%d", e.ExitCode)
		}
		b.WriteString(fmt.Sprintf("  %-5d %-6s %-12s %s\n", e.Index, mark, e.Duration.Round(time.Millisecond), e.Command))
		shown++
	}
	if shown == 0 {
		b.WriteString("  (no entries)\n")
	}
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func historyCompletions(ctx *CommandContext, partial string) []string {
	return []string{"--failed", "--clear"}
}

func parsePositiveInt(s string) (int, error) {
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid integer: %s", s)
		}
		n = n*10 + int(ch-'0')
	}
	if n <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return n, nil
}

var attckCmdInfo = CommandInfo{
	Name:        "attck",
	Short:       "MITRE ATT&CK analysis",
	Description: "Query ATT&CK V19 module: coverage, kill chain, APT matching, detection rules, threat intelligence",
	Usage:       "attck <summary|coverage|killchain|apt|detect|ti>",
	Category:    CategoryATTACK,
	Params: []CommandParam{
		{Name: "action", Description: "Action: summary, coverage, killchain, apt, detect, ti", Required: true, EnumValues: []string{"summary", "coverage", "killchain", "apt", "detect", "ti"}},
	},
	Options: []CommandOption{
		{Name: "host", Short: "H", Description: "Target host ID", Default: "local"},
		{Name: "limit", Short: "n", Description: "Limit number of results", Default: "20"},
	},
	Examples: []string{
		"attck summary",
		"attck coverage",
		"attck killchain --host=web01",
		"attck apt",
		"attck detect",
		"attck ti",
	},
}

func attckCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("attck: action required"),
			Output:   formatHelp(attckCmdInfo),
		}
	}

	action := ctx.Args[0]
	attckPlugin, ok := ctx.Kernel.GetPlugin("attck")
	if !ok {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("ATT&CK module not available"), Output: "ATT&CK module not available\n"}
	}

	hostID := "local"
	if v, ok := ctx.Options["host"]; ok && v != "" {
		hostID = v
	}

	switch action {
	case "summary":
		type summaryProvider interface {
			GetLastAnalysis(hostID string) map[string]interface{}
		}
		sp, ok := attckPlugin.(summaryProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support summary\n"}
		}
		data := sp.GetLastAnalysis(hostID)
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  ATT&CK V19 Summary\n")
		b.WriteString("  ─────────────────────────────────────────\n")
		if v, ok := data["attck_version"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Version:", v))
		}
		if v, ok := data["tactics_count"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Tactics:", v))
		}
		if v, ok := data["apt_groups"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "APT Groups:", v))
		}
		if v, ok := data["detection_rules"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Detection Rules:", v))
		}
		if v, ok := data["threat_actors"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Threat Actors:", v))
		}
		if v, ok := data["scenarios"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Emulation Scenarios:", v))
		}
		if v, ok := data["auto_hunt"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Auto Hunt:", v))
		}
		if v, ok := data["beacon_threshold"]; ok {
			b.WriteString(fmt.Sprintf("  %-20s %v\n", "Beacon Threshold:", v))
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "coverage":
		type coverageProvider interface {
			CalculateCoverage(checkResults map[string]bool) []kernel.ATTACKCoverage
		}
		cp, ok := attckPlugin.(coverageProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support coverage\n"}
		}
		coverages := cp.CalculateCoverage(nil)
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(coverages, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  ATT&CK Coverage Analysis\n")
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  %-10s %-20s %6s %8s %8s %8s %s\n", "TACTIC", "NAME", "TECHS", "DET%", "PREV%", "COMP%", "RISK"))
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		for _, cov := range coverages {
			b.WriteString(fmt.Sprintf("  %-10s %-20s %6d %7.0f%% %7.0f%% %7.0f%% %s\n",
				cov.TacticID, cov.TacticName, cov.TotalTechniques,
				cov.CoverageDet, cov.CoveragePrev, cov.CoverageComp, cov.RiskLevel))
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "killchain":
		type killChainProvider interface {
			AssessKillChain(hostID string, checkResults map[string]bool) kernel.KillChainAssessment
		}
		kp, ok := attckPlugin.(killChainProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support kill chain\n"}
		}
		kc := kp.AssessKillChain(hostID, nil)
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(kc, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  Kill Chain Assessment\n")
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  Overall Score: %.1f   Weakest Stage: %s\n\n", kc.OverallScore, kc.WeakestStage))
		b.WriteString(fmt.Sprintf("  %-16s %6s %8s %8s %s\n", "STAGE", "SCORE", "STATUS", "PASSED", "TOTAL"))
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		for _, stage := range kc.Stages {
			b.WriteString(fmt.Sprintf("  %-16s %6.1f %8s %8d %6d\n",
				stage.Name, stage.Score, stage.Status, stage.ChecksPassed, stage.ChecksTotal))
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "apt":
		type aptProvider interface {
			ListAPTGroups() []string
			GetAPTGroup(groupID string) *kernel.APTGroupProfile
		}
		ap, ok := attckPlugin.(aptProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support APT\n"}
		}
		groups := ap.ListAPTGroups()
		if ctx.JSON {
			var profiles []*kernel.APTGroupProfile
			for _, gid := range groups {
				if p := ap.GetAPTGroup(gid); p != nil {
					profiles = append(profiles, p)
				}
			}
			jsonData, _ := json.MarshalIndent(profiles, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  APT Group Profiles\n")
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  %-8s %-20s %-12s %s\n", "ID", "NAME", "TARGETS", "ALIASES"))
		b.WriteString("  ──────────────────────────────────────────────────────────────────────────\n")
		for _, gid := range groups {
			if p := ap.GetAPTGroup(gid); p != nil {
				targets := strings.Join(p.PrimaryTargets, ", ")
				aliases := strings.Join(p.Aliases, ", ")
				b.WriteString(fmt.Sprintf("  %-8s %-20s %-12s %s\n", p.GroupID, p.Name, targets, aliases))
			}
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "detect":
		type detectProvider interface {
			GetDetectionSummary() kernel.DetectionSummary
		}
		dp, ok := attckPlugin.(detectProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support detection\n"}
		}
		summary := dp.GetDetectionSummary()
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(summary, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  Detection Summary\n")
		b.WriteString("  ─────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Total Rules:", summary.TotalRules))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Active Rules:", summary.ActiveRules))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Total Alerts:", summary.TotalAlerts))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Open Alerts:", summary.OpenAlerts))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Anomalies:", summary.Anomalies))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Correlations:", summary.Correlations))
		b.WriteString(fmt.Sprintf("  %-20s %d\n", "Coverage Gaps:", len(summary.CoverageGaps)))
		if len(summary.CoverageGaps) > 0 {
			b.WriteString("\n  Coverage Gaps:\n")
			for _, gap := range summary.CoverageGaps {
				b.WriteString(fmt.Sprintf("    • %s\n", gap))
			}
		}
		if len(summary.AlertsBySeverity) > 0 {
			b.WriteString("\n  Alerts by Severity:\n")
			for sev, count := range summary.AlertsBySeverity {
				b.WriteString(fmt.Sprintf("    %-12s %d\n", sev+":", count))
			}
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	case "ti":
		type tiProvider interface {
			GetTISummary() map[string]interface{}
		}
		tp, ok := attckPlugin.(tiProvider)
		if !ok {
			return &CommandResult{ExitCode: ExitError, Output: "ATT&CK module does not support TI\n"}
		}
		data := tp.GetTISummary()
		if ctx.JSON {
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n"}
		}

		var b strings.Builder
		b.WriteString("\n  Threat Intelligence Summary\n")
		b.WriteString("  ─────────────────────────────────────────\n")
		for k, v := range data {
			b.WriteString(fmt.Sprintf("  %-24s %v\n", k+":", v))
		}
		b.WriteString("\n")
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}

	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown attck action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: summary, coverage, killchain, apt, detect, ti\n", action),
		}
	}
}

func attckCompletions(ctx *CommandContext, partial string) []string {
	return []string{"summary", "coverage", "killchain", "apt", "detect", "ti"}
}
