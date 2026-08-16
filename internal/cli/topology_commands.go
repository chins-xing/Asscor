package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/asscor/asscor/internal/topology"
)

// topologyCmdInfo exposes the topology awareness state (M1, L7 观测):
// registered nodes with subnets/zone/status.
var topologyCmdInfo = CommandInfo{
	Name:         "topology",
	Short:        "Show network topology awareness state",
	Description:  "List hosts registered in the topology registry (subnets, zone, status) — M1 拓扑视图",
	Usage:        "topology <list>",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: list", Required: false, EnumValues: []string{"list"}},
	},
	Examples: []string{
		"topology",
		"topology list",
		"topology --json",
	},
}

func topologyCmdHandler(ctx *CommandContext) *CommandResult {
	nodes := topology.ListNodes()
	if nodes == nil {
		nodes = []*topology.TopoNode{}
	}

	if ctx.JSON {
		type nodeOut struct {
			HostID  string   `json:"host_id"`
			Subnets []string `json:"subnets"`
			Zone    string   `json:"zone"`
			Status  string   `json:"status"`
		}
		out := make([]nodeOut, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, nodeOut{HostID: n.HostID, Subnets: n.Subnets, Zone: n.Zone, Status: n.Status})
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString("\n  Topology Nodes\n")
	b.WriteString("  ─────────────────────────────────────────────────────────────\n")
	if len(nodes) == 0 {
		b.WriteString("  (no nodes registered)\n")
	} else {
		b.WriteString(fmt.Sprintf("  %-20s %-14s %-10s %s\n", "HOST_ID", "ZONE", "STATUS", "SUBNETS"))
		b.WriteString("  ─────────────────────────────────────────────────────────────\n")
		for _, n := range nodes {
			b.WriteString(fmt.Sprintf("  %-20s %-14s %-10s %s\n",
				n.HostID, n.Zone, n.Status, strings.Join(n.Subnets, ", ")))
		}
	}
	b.WriteString(fmt.Sprintf("\n  Total: %d nodes\n\n", len(nodes)))
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}
