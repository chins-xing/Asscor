package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

var agentCmdInfo = CommandInfo{
	Name:         "agent",
	Short:        "Manage agents",
	Description:  "Agent lifecycle management: list, inspect, control, and configure registered agents",
	Usage:        "agent <list|status|start|stop|restart|config|command> [options]",
	Category:     CategoryAgent,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: list, status, start, stop, restart, config, command", Required: true, EnumValues: []string{"list", "status", "start", "stop", "restart", "config", "command"}},
	},
	Options: []CommandOption{
		{Name: "host", Short: "H", Description: "Target agent host ID"},
		{Name: "all", Short: "a", Description: "Apply to all agents", IsBool: true},
		{Name: "filter", Short: "f", Description: "Filter agents by field (key=value)"},
		{Name: "limit", Short: "n", Description: "Limit number of results", Default: "50"},
		{Name: "watch", Short: "w", Description: "Watch mode (continuous refresh)", IsBool: true},
	},
	Examples: []string{
		"agent list",
		"agent list --filter=active=true",
		"agent status --host=web-server-01",
		"agent stop --host=db-master-01",
		"agent restart --all",
		"agent config --host=web-01 --set threshold=80",
		"agent command --host=web-01 --action=scan",
	},
}

func agentCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent: action required"),
			Output:   formatHelp(agentCmdInfo),
		}
	}

	action := ctx.Args[0]
	agents := ctx.Kernel.Agents()

	switch action {
	case "list":
		return agentListHandler(ctx, agents)
	case "status":
		return agentStatusHandler(ctx, agents)
	case "start":
		if !ctx.Kernel.CheckPermission(PermWrite) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: agent start requires write level access"), Output: "Permission denied: agent start requires write level access\n"}
		}
		return agentStartHandler(ctx, agents)
	case "stop":
		if !ctx.Kernel.CheckPermission(PermWrite) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: agent stop requires write level access"), Output: "Permission denied: agent stop requires write level access\n"}
		}
		return agentStopHandler(ctx, agents)
	case "restart":
		if !ctx.Kernel.CheckPermission(PermWrite) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: agent restart requires write level access"), Output: "Permission denied: agent restart requires write level access\n"}
		}
		return agentRestartHandler(ctx, agents)
	case "config":
		if !ctx.Kernel.CheckPermission(PermWrite) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: agent config requires write level access"), Output: "Permission denied: agent config requires write level access\n"}
		}
		return agentConfigHandler(ctx, agents)
	case "command":
		if !ctx.Kernel.CheckPermission(PermAdmin) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: agent command requires admin level access"), Output: "Permission denied: agent command requires admin level access\n"}
		}
		return agentCommandHandler(ctx, agents)
	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown agent action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: list, status, start, stop, restart, config, command\n", action),
		}
	}
}

func agentCompletions(ctx *CommandContext, partial string) []string {
	return []string{"list", "status", "start", "stop", "restart", "config", "command"}
}

func agentListHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	agentList := agents.ListAgents()

	filterStr, _ := ctx.Options["filter"]
	if filterStr != "" {
		agentList = filterAgents(agentList, filterStr)
	}

	limit := 50
	if v, ok := ctx.Options["limit"]; ok {
		if n, err := parsePositiveInt(v); err == nil {
			limit = n
		}
	}

	if limit > 0 && len(agentList) > limit {
		agentList = agentList[:limit]
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(agentList, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: agentList}
	}

	active, inactive := 0, 0
	for _, a := range agentList {
		if a.Active {
			active++
		} else {
			inactive++
		}
	}

	var b strings.Builder
	b.WriteString("\n  Registered Agents\n")
	b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  %-20s %-16s %-10s %-8s %-20s %s\n", "HOST_ID", "HOSTNAME", "VERSION", "STATUS", "LAST_SEEN", "CONNS"))
	b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")

	sort.Slice(agentList, func(i, j int) bool {
		if agentList[i].Active != agentList[j].Active {
			return agentList[i].Active
		}
		return agentList[i].HostID < agentList[j].HostID
	})

	for _, a := range agentList {
		status := "●"
		if !a.Active {
			status = "○"
		}
		lastSeen := formatDuration(time.Since(a.LastSeen))
		b.WriteString(fmt.Sprintf("  %-20s %-16s %-10s %-8s %-20s %d\n",
			a.HostID, a.Hostname, a.Version, status, lastSeen, a.Connections))
	}

	b.WriteString(fmt.Sprintf("\n  Total: %d agents (%d active, %d inactive)\n\n", len(agentList), active, inactive))
	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: agentList}
}

func agentStatusHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	hostID, _ := ctx.Options["host"]
	if hostID == "" && len(ctx.Args) > 1 {
		hostID = ctx.Args[1]
	}

	if hostID == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent status: --host required"),
			Output:   "Usage: agent status --host <host_id>\n",
		}
	}

	agent, found := agents.GetAgent(hostID)
	if !found {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      fmt.Errorf("agent %q not found", hostID),
			Output:   fmt.Sprintf("Agent %q not found. Use 'agent list' to see registered agents.\n", hostID),
		}
	}

	alive := agents.IsAgentAlive(hostID)

	if ctx.JSON {
		data := map[string]interface{}{
			"host_id":     agent.HostID,
			"hostname":    agent.Hostname,
			"version":     agent.Version,
			"active":      agent.Active,
			"alive":       alive,
			"last_seen":   agent.LastSeen.Format(time.RFC3339),
			"registered":  agent.Registered.Format(time.RFC3339),
			"uptime":      time.Since(agent.Registered).Round(time.Second).String(),
			"connections": agent.Connections,
		}
		jsonData, _ := json.MarshalIndent(data, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(jsonData) + "\n", Data: data}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Agent Status: %s\n", hostID))
	b.WriteString("  ─────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Host ID:     %s\n", agent.HostID))
	b.WriteString(fmt.Sprintf("  Hostname:    %s\n", agent.Hostname))
	b.WriteString(fmt.Sprintf("  Version:     %s\n", agent.Version))
	b.WriteString(fmt.Sprintf("  Active:      %t\n", agent.Active))
	b.WriteString(fmt.Sprintf("  Alive:       %t\n", alive))
	b.WriteString(fmt.Sprintf("  Last Seen:   %s (%s)\n", agent.LastSeen.Format(time.RFC3339), formatDuration(time.Since(agent.LastSeen))))
	b.WriteString(fmt.Sprintf("  Registered:  %s\n", agent.Registered.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("  Uptime:      %s\n", time.Since(agent.Registered).Round(time.Second)))
	b.WriteString(fmt.Sprintf("  Connections: %d\n", agent.Connections))
	b.WriteString("\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func agentStartHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	return agentLifecycleAction(ctx, agents, "start")
}

func agentStopHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	return agentLifecycleAction(ctx, agents, "stop")
}

func agentRestartHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	return agentLifecycleAction(ctx, agents, "restart")
}

func agentLifecycleAction(ctx *CommandContext, agents AgentAccess, action string) *CommandResult {
	hostID, _ := ctx.Options["host"]
	applyAll, _ := ctx.Flags["all"]

	if hostID == "" && !applyAll {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent %s: --host or --all required", action),
			Output:   fmt.Sprintf("Usage: agent %s --host <host_id>  or  agent %s --all\n", action, action),
		}
	}

	if applyAll {
		agentList := agents.ListAgents()
		if len(agentList) == 0 {
			return &CommandResult{ExitCode: ExitOK, Output: "No agents registered.\n"}
		}

		var results []map[string]string
		for _, a := range agentList {
			cmdID, err := agents.SendCommand(a.HostID, action, nil)
			status := "sent"
			if err != nil {
				status = fmt.Sprintf("error: %v", err)
			}
			results = append(results, map[string]string{
				"host_id":    a.HostID,
				"command_id": cmdID,
				"status":     status,
			})
		}

		if ctx.JSON {
			data, _ := json.MarshalIndent(results, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: results}
		}

		var b strings.Builder
		b.WriteString(fmt.Sprintf("\n  Agent %s — Broadcast\n", strings.Title(action)))
		b.WriteString("  ─────────────────────────────────────────\n")
		for _, r := range results {
			b.WriteString(fmt.Sprintf("  %-20s  cmd=%s  status=%s\n", r["host_id"], r["command_id"], r["status"]))
		}
		b.WriteString(fmt.Sprintf("\n  %d agent(s) notified.\n\n", len(results)))
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}
	}

	cmdID, err := agents.SendCommand(hostID, action, nil)
	if err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Failed to send %s command to agent %q: %v\n", action, hostID, err),
		}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(map[string]string{
			"host_id":    hostID,
			"action":     action,
			"command_id": cmdID,
			"status":     "sent",
		}, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	return &CommandResult{
		ExitCode: ExitOK,
		Output:   fmt.Sprintf("Command '%s' sent to agent %q (command_id=%s)\n", action, hostID, cmdID),
	}
}

func agentConfigHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	hostID, _ := ctx.Options["host"]
	if hostID == "" && len(ctx.Args) > 1 {
		hostID = ctx.Args[1]
	}

	if hostID == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent config: --host required"),
			Output:   "Usage: agent config --host <host_id> [--set key=value ...]\n",
		}
	}

	agent, found := agents.GetAgent(hostID)
	if !found {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      fmt.Errorf("agent %q not found", hostID),
			Output:   fmt.Sprintf("Agent %q not found.\n", hostID),
		}
	}

	setValues, hasSet := ctx.Repeat["set"]
	if hasSet && len(setValues) > 0 {
		params := make(map[string]string)
		for _, sv := range setValues {
			parts := strings.SplitN(sv, "=", 2)
			if len(parts) != 2 {
				return &CommandResult{
					ExitCode: ExitUsage,
					Err:      fmt.Errorf("invalid --set format: %s (expected key=value)", sv),
					Output:   fmt.Sprintf("Invalid --set format: %s (expected key=value)\n", sv),
				}
			}
			params[parts[0]] = parts[1]
		}

		cmdID, err := agents.SendCommand(hostID, "config_update", params)
		if err != nil {
			return &CommandResult{
				ExitCode: ExitError,
				Err:      err,
				Output:   fmt.Sprintf("Failed to send config update to agent %q: %v\n", hostID, err),
			}
		}

		if ctx.JSON {
			data, _ := json.MarshalIndent(map[string]interface{}{
				"host_id":    hostID,
				"action":     "config_update",
				"command_id": cmdID,
				"params":     params,
			}, "", "  ")
			return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
		}

		var b strings.Builder
		b.WriteString(fmt.Sprintf("Config update sent to agent %q (command_id=%s)\n", hostID, cmdID))
		for k, v := range params {
			b.WriteString(fmt.Sprintf("  %s = %s\n", k, v))
		}
		return &CommandResult{ExitCode: ExitOK, Output: b.String()}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"host_id":  agent.HostID,
			"hostname": agent.Hostname,
			"version":  agent.Version,
			"active":   agent.Active,
		}, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Agent Config: %s\n", hostID))
	b.WriteString("  ─────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Host ID:   %s\n", agent.HostID))
	b.WriteString(fmt.Sprintf("  Hostname:  %s\n", agent.Hostname))
	b.WriteString(fmt.Sprintf("  Version:   %s\n", agent.Version))
	b.WriteString(fmt.Sprintf("  Status:    %s\n", agentStatusStr(agent.Active)))
	b.WriteString("\n  Use --set key=value to update agent configuration.\n\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func agentCommandHandler(ctx *CommandContext, agents AgentAccess) *CommandResult {
	hostID, _ := ctx.Options["host"]
	actionName, _ := ctx.Options["action"]

	if hostID == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent command: --host required"),
			Output:   "Usage: agent command --host <host_id> --action <action> [--param key=value ...]\n",
		}
	}

	if actionName == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("agent command: --action required"),
			Output:   "Usage: agent command --host <host_id> --action <action>\n",
		}
	}

	params := make(map[string]string)
	paramValues, hasParams := ctx.Repeat["param"]
	if hasParams {
		for _, pv := range paramValues {
			parts := strings.SplitN(pv, "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			}
		}
	}

	cmdID, err := agents.SendCommand(hostID, actionName, params)
	if err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Failed to send command to agent %q: %v\n", hostID, err),
		}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"host_id":    hostID,
			"action":     actionName,
			"command_id": cmdID,
			"params":     params,
			"status":     "enqueued",
		}, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	return &CommandResult{
		ExitCode: ExitOK,
		Output:   fmt.Sprintf("Command '%s' enqueued for agent %q (command_id=%s)\n", actionName, hostID, cmdID),
	}
}

var logCmdInfo = CommandInfo{
	Name:         "log",
	Short:        "View agent logs",
	Description:  "View, filter, and export agent runtime logs",
	Usage:        "log <show|export> [options]",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: show, export", Required: true, EnumValues: []string{"show", "export"}},
	},
	Options: []CommandOption{
		{Name: "host", Short: "H", Description: "Filter by agent host ID"},
		{Name: "level", Short: "l", Description: "Filter by log level (debug, info, warn, error)", EnumValues: []string{"debug", "info", "warn", "error"}},
		{Name: "limit", Short: "n", Description: "Number of entries to show", Default: "50"},
		{Name: "format", Short: "f", Description: "Export format (json, csv)", Default: "json", EnumValues: []string{"json", "csv"}},
		{Name: "output", Short: "o", Description: "Output file path for export"},
	},
	Examples: []string{
		"log show",
		"log show --host=web-01 --level=error",
		"log show --limit=100",
		"log export --host=db-01 --format=csv --output=logs.csv",
		"log export --format=json --output=logs.json",
	},
}

func logCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("log: action required"),
			Output:   formatHelp(logCmdInfo),
		}
	}

	action := ctx.Args[0]
	logs := ctx.Kernel.Logs()

	switch action {
	case "show":
		return logShowHandler(ctx, logs)
	case "export":
		return logExportHandler(ctx, logs)
	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown log action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: show, export\n", action),
		}
	}
}

func logCompletions(ctx *CommandContext, partial string) []string {
	return []string{"show", "export"}
}

func logShowHandler(ctx *CommandContext, logs LogAccess) *CommandResult {
	hostID, _ := ctx.Options["host"]
	level, _ := ctx.Options["level"]
	limit := 50
	if v, ok := ctx.Options["limit"]; ok {
		if n, err := parsePositiveInt(v); err == nil {
			limit = n
		}
	}

	entries, err := logs.ReadLogs(hostID, limit, level)
	if err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Failed to read logs: %v\n", err),
		}
	}

	if len(entries) == 0 {
		return &CommandResult{ExitCode: ExitOK, Output: "No log entries found.\n"}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: entries}
	}

	var b strings.Builder
	b.WriteString("\n  Agent Logs\n")
	b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  %-24s %-8s %-16s %s\n", "TIMESTAMP", "LEVEL", "HOST_ID", "MESSAGE"))
	b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")

	for _, e := range entries {
		levelMark := e.Level
		switch strings.ToUpper(e.Level) {
		case "ERROR":
			levelMark = "ERROR"
		case "WARN", "WARNING":
			levelMark = "WARN "
		case "INFO":
			levelMark = "INFO "
		case "DEBUG":
			levelMark = "DEBUG"
		}

		msg := e.Message
		if len(msg) > 80 {
			msg = msg[:77] + "..."
		}
		b.WriteString(fmt.Sprintf("  %-24s %-8s %-16s %s\n",
			e.Timestamp.Format(time.RFC3339),
			levelMark,
			e.HostID,
			msg,
		))
	}
	b.WriteString(fmt.Sprintf("\n  Showing %d entries\n\n", len(entries)))
	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: entries}
}

func logExportHandler(ctx *CommandContext, logs LogAccess) *CommandResult {
	hostID, _ := ctx.Options["host"]
	format, _ := ctx.Options["format"]
	if format == "" {
		format = "json"
	}
	outputPath, _ := ctx.Options["output"]

	content, err := logs.ExportLogs(hostID, format)
	if err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Failed to export logs: %v\n", err),
		}
	}

	if outputPath != "" {
		if err := writeFile(outputPath, content); err != nil {
			return &CommandResult{
				ExitCode: ExitError,
				Err:      err,
				Output:   fmt.Sprintf("Failed to write to %s: %v\n", outputPath, err),
			}
		}
		return &CommandResult{ExitCode: ExitOK, Output: fmt.Sprintf("Logs exported to %s (%s format)\n", outputPath, format)}
	}

	return &CommandResult{ExitCode: ExitOK, Output: content}
}

func filterAgents(agents []AgentInfo, filter string) []AgentInfo {
	parts := strings.SplitN(filter, "=", 2)
	if len(parts) != 2 {
		return agents
	}
	key, val := parts[0], parts[1]

	var filtered []AgentInfo
	for _, a := range agents {
		switch key {
		case "active":
			if fmt.Sprintf("%t", a.Active) == val {
				filtered = append(filtered, a)
			}
		case "hostname":
			if strings.Contains(a.Hostname, val) {
				filtered = append(filtered, a)
			}
		case "version":
			if a.Version == val {
				filtered = append(filtered, a)
			}
		case "host_id":
			if strings.Contains(a.HostID, val) {
				filtered = append(filtered, a)
			}
		}
	}
	return filtered
}

func agentStatusStr(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

func writeFile(path, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
