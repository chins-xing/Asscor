package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/federation"
)

// FederationProvider is the narrow CLI contract for the T4 federation demo
// module. It is implemented by internal/federation.Plugin and injected by
// cmd/kernel after Bootstrap (cli.SetFederationProvider), so the CLI package
// needs no build tag and stays usable in builds without the federation plugin.
type FederationProvider interface {
	FederationStatus() federation.Status
}

var federationProvider FederationProvider

// SetFederationProvider injects the federation status provider (kernel main
// calls it after Bootstrap, mirroring cli.SetReachChecker). Passing nil is
// allowed and is what tests use to assert the "plugin not loaded" path.
func SetFederationProvider(p FederationProvider) {
	federationProvider = p
}

var federationCmdInfo = CommandInfo{
	Name:         "federation",
	Short:        "Show federation master/node status (T4 demo)",
	Description:  "Master: list node kernels that reported aggregate summaries (config hash, hosts, avg SSAM). Node: show this kernel's federation config and last report state.",
	Usage:        "federation status [--json]",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: status", Required: false, EnumValues: []string{"status"}},
	},
	Examples: []string{
		"federation status",
		"federation status --json",
	},
}

func federationCmdHandler(ctx *CommandContext) *CommandResult {
	fail := func(code ExitCode, msg string) *CommandResult {
		return &CommandResult{ExitCode: code, Err: fmt.Errorf("%s", msg), Output: "error: " + msg + "\n"}
	}

	// `federation status` / `federation --json`: the socket session passes
	// positional tokens through Args, so accept both Params and Args.
	action := strings.TrimSpace(ctx.Params["action"])
	if action == "" && len(ctx.Args) > 0 {
		action = strings.TrimSpace(ctx.Args[0])
	}
	if action == "" {
		action = "status"
	}
	if action != "status" {
		return fail(ExitUsage, "unsupported action: "+action+" (usage: federation status [--json])")
	}
	if len(ctx.Args) > 1 {
		return fail(ExitUsage, "unexpected argument: "+ctx.Args[1]+" (usage: federation status [--json])")
	}
	if federationProvider == nil {
		// Socket sessions render Output only — the error MUST be in Output,
		// not just Err (same discipline as the SRD command).
		return fail(ExitError, "federation 插件未加载（构建需 -tags federation）")
	}

	st := federationProvider.FederationStatus()

	if ctx.JSON {
		data, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return fail(ExitError, "marshal federation status: "+err.Error())
		}
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	return &CommandResult{ExitCode: ExitOK, Output: renderFederationStatus(st)}
}

func renderFederationStatus(st federation.Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  Federation (%s)\n", st.Role)
	b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")

	if st.ConfigError != "" {
		fmt.Fprintf(&b, "  Config error:   %s\n", st.ConfigError)
	}
	if st.ListenError != "" {
		fmt.Fprintf(&b, "  Listen error:   %s\n", st.ListenError)
	}
	fmt.Fprintf(&b, "  Running:        %v\n", st.Running)
	if st.NodeID != "" {
		fmt.Fprintf(&b, "  Node ID:        %s\n", st.NodeID)
	}

	switch st.Role {
	case federation.RoleMaster:
		addr := st.ListenAddr
		if addr == "" {
			addr = federation.DefaultListenAddr
		}
		fmt.Fprintf(&b, "  Listen:         %s\n", addr)
		fmt.Fprintf(&b, "  Report path:    %s (POST, node→master)\n", federation.ReportPath)
		fmt.Fprintf(&b, "  Nodes path:     %s (GET)\n", federation.NodesPath)
		fmt.Fprintf(&b, "  Nodes:          %d\n", len(st.Nodes))

		if len(st.Nodes) == 0 {
			b.WriteString("\n  (no node reports yet)\n\n")
			return b.String()
		}

		b.WriteString("\n")
		fmt.Fprintf(&b, "  %-14s %-18s %6s %10s  %s\n",
			"NODE_ID", "CONFIG_HASH", "HOSTS", "AVG_SSAM", "LAST_REPORT")
		b.WriteString("  ─────────────────────────────────────────────────────────────────────\n")
		for _, n := range st.Nodes {
			at := ""
			if !n.ReceivedAt.IsZero() {
				at = formatFederationTime(n.ReceivedAt)
			} else if !n.ReportedAt.IsZero() {
				at = formatFederationTime(n.ReportedAt)
			}
			fmt.Fprintf(&b, "  %-14s %-18s %6d %10.1f  %s\n",
				n.NodeID, federation.ShortHash(n.ConfigHash), n.Hosts, n.AvgSSAM, at)
		}
		b.WriteString("\n")

		// Zone breakdown (the aggregate that explains the average).
		for _, n := range st.Nodes {
			if len(n.Zones) == 0 {
				continue
			}
			fmt.Fprintf(&b, "  Zones (%s): %s\n", n.NodeID, renderFederationZones(n.Zones))
		}
		b.WriteString("\n")

	case federation.RoleNode:
		fmt.Fprintf(&b, "  Master URL:     %s\n", st.MasterURL)
		fmt.Fprintf(&b, "  Report every:   %ds\n", st.ReportIntervalSec)
		fmt.Fprintf(&b, "  Config hash:    %s\n", st.ConfigHash)
		if p := federation.FormatParams(st.Params); p != "" {
			fmt.Fprintf(&b, "  Params:         %s\n", p)
		}
		fmt.Fprintf(&b, "  Hosts:          %d\n", st.Hosts)
		fmt.Fprintf(&b, "  Avg SSAM:       %.1f\n", st.AvgSSAM)
		if len(st.Zones) > 0 {
			fmt.Fprintf(&b, "  Zones:          %s\n", renderFederationZones(st.Zones))
		}
		if st.LastReportAt != nil {
			fmt.Fprintf(&b, "  Last report:    %s (attempts: %d)\n",
				formatFederationTime(*st.LastReportAt), st.LastReportAttempts)
		} else {
			b.WriteString("  Last report:    (none yet)\n")
		}
		if st.LastReportError != "" {
			fmt.Fprintf(&b, "  Last error:     %s\n", st.LastReportError)
		}
		b.WriteString("\n")

	default:
		b.WriteString("\n  federation 未启用（[federation] role = off）\n")
		b.WriteString("  Set role=master (with listen_addr) or role=node (with node_id/master_url)\n\n")
	}
	return b.String()
}

func renderFederationZones(zones map[string]federation.ZoneSummary) string {
	names := make([]string, 0, len(zones))
	for z := range zones {
		names = append(names, z)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, z := range names {
		zs := zones[z]
		parts = append(parts, fmt.Sprintf("%s: %d hosts/%d scored, avg %.1f",
			z, zs.Hosts, zs.Scored, zs.AvgSSAM))
	}
	return strings.Join(parts, "; ")
}

func formatFederationTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04:05")
}
