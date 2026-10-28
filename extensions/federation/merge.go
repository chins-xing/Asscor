package federation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chins-xing/asscor/internal/topology"
)

// MergedStep 是合并图上的一跳。
type MergedStep struct {
	Host    string `json:"host"`
	Subnet  string `json:"subnet"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// MergedPath 是合并图的路径判定。
type MergedPath struct {
	Path      []string     `json:"path"`
	Verdict   string       `json:"verdict"`
	BlockedAt string       `json:"blocked_at,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	Unknowns  []string     `json:"unknowns,omitempty"`
	Steps     []MergedStep `json:"steps,omitempty"`
}

// MergedCheck 是 `federation check <src> <dst>` 的输出（v0.2）。
type MergedCheck struct {
	Src      string         `json:"src"`
	Dst      string         `json:"dst"`
	Verdict  string         `json:"verdict"`
	Paths    int            `json:"paths"`
	Nodes    int            `json:"nodes"` // 参与合并的上报节点数
	Hosts    int            `json:"hosts"`
	Best     *MergedPath    `json:"best,omitempty"`
	Unknowns []string       `json:"unknowns,omitempty"`
	Stats    map[string]int `json:"stats,omitempty"`
}

// BuildMergedGraph 把多个节点上报的事实合并成一张分层图（v0.2）。
//
// 合并规则：
//   - 同一 host id：子网/IP 取并集；Zone/SSAM/Forwards/StatefulInput 以后上报者为准；
//   - 转发策略：按 (from,to,allow) 去重后取并集；
//   - 主 kernel 自己的拓扑（老实验域）也会并入，作为 "master" 视角的本地事实。
//
// 该函数不返回 nil：没有事实时返回空图，调用方据此给出错误。
func BuildMergedGraph(reports []NodeReport) *topology.LayeredGraph {
	lh, lp, lk := localFactsFromTopology()
	return BuildMergedGraphWithLocal(reports, lh, lp, lk)
}

// BuildMergedGraphWithLocal 用调用方提供的本地事实建图（进程隔离模式）。
func BuildMergedGraphWithLocal(reports []NodeReport, localHosts []HostFact, localPolicies []PolicyFact, localKnown bool) *topology.LayeredGraph {
	hosts, policies, policyKnown := mergedFactsFrom(reports, localHosts, localPolicies, localKnown)

	ids := make([]string, 0, len(hosts))
	for id := range hosts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	facts := make([]topology.HostFacts, 0, len(ids))
	for _, id := range ids {
		h := hosts[id]
		facts = append(facts, topology.HostFacts{
			HostID:        h.ID,
			IPs:           h.IPs,
			Subnets:       h.Subnets,
			Zone:          h.Zone,
			Forwards:      h.Forwards,
			StatefulInput: h.StatefulInput,
			Inbound:       toPolicyRules(h.Inbound),
			Outbound:      toPolicyRules(h.Outbound),
			Links:         h.Links,
		})
	}
	keys := make([]string, 0, len(policies))
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ps := make([]topology.PolicyRule, 0, len(keys))
	for _, k := range keys {
		p := policies[k]
		ps = append(ps, topology.PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
	}
	return topology.BuildLayeredGraph(facts, ps, policyKnown, true)
}

// CheckMerged 在合并图上回答 src→dst 的可达性（深度上限由调用方给）。
func CheckMerged(g *topology.LayeredGraph, src, dst string, maxDepth int) *MergedCheck {
	if maxDepth <= 0 {
		maxDepth = 5
	}
	out := &MergedCheck{Src: src, Dst: dst, Stats: g.Stats()}
	out.Hosts = out.Stats["hosts"]
	verdicts := g.HostReachable(src, dst, maxDepth)
	out.Paths = len(verdicts)
	out.Verdict = string(topology.Summary(verdicts))

	var best *topology.PathVerdict
	rank := func(v topology.Verdict) int {
		switch v {
		case topology.VerdictReachable:
			return 3
		case topology.VerdictBlocked:
			return 2
		default:
			return 1
		}
	}
	for i := range verdicts {
		if best == nil || rank(verdicts[i].Verdict) > rank(best.Verdict) {
			best = &verdicts[i]
		}
	}
	if best != nil {
		mp := &MergedPath{
			Path:      append([]string(nil), best.Path...),
			Verdict:   string(best.Verdict),
			BlockedAt: best.BlockedAt,
			Reason:    best.Reason,
			Unknowns:  append([]string(nil), best.Unknowns...),
		}
		for _, s := range best.Steps {
			mp.Steps = append(mp.Steps, MergedStep{Host: s.Host, Subnet: s.Subnet, Verdict: string(s.Verdict), Reason: s.Reason})
		}
		out.Best = mp
		out.Unknowns = mp.Unknowns
	}
	return out
}

// String 渲染 CLI 文本输出。
func (c *MergedCheck) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  federation check  %s -> %s\n", c.Src, c.Dst)
	fmt.Fprintf(&b, "  verdict : %s   (paths=%d, merged hosts=%d)\n", c.Verdict, c.Paths, c.Hosts)
	if c.Best != nil {
		fmt.Fprintf(&b, "  path    : %s\n", strings.Join(c.Best.Path, " -> "))
		if c.Best.BlockedAt != "" {
			fmt.Fprintf(&b, "  blocked : %s\n", c.Best.BlockedAt)
		}
		if c.Best.Reason != "" {
			fmt.Fprintf(&b, "  reason  : %s\n", c.Best.Reason)
		}
		for _, s := range c.Best.Steps {
			fmt.Fprintf(&b, "    - %-16s %-18s %-10s %s\n", s.Host, s.Subnet, s.Verdict, s.Reason)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func toPolicyRules(in []PolicyFact) []topology.PolicyRule {
	out := make([]topology.PolicyRule, 0, len(in))
	for _, p := range in {
		out = append(out, topology.PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
	}
	return out
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// hostFactFromTopo 把主 kernel 本地 TopoNode 转成上报事实（含入/出向拆分）。
func hostFactFromTopo(n *topology.TopoNode) HostFact {
	h := HostFact{
		ID:            n.HostID,
		IPs:           append([]string(nil), n.IPs...),
		Subnets:       append([]string(nil), n.Subnets...),
		Zone:          n.Zone,
		Forwards:      n.Forwards,
		StatefulInput: n.StatefulInput,
		Links:         map[string]bool{},
	}
	for _, l := range n.Links {
		for _, s := range l.Subnets {
			h.Links[s] = h.Links[s] || l.Up
		}
	}
	for _, p := range n.Policies {
		pf := PolicyFact{From: p.From, To: p.To, Allow: p.Allow}
		switch p.Direction {
		case "inbound":
			h.Inbound = append(h.Inbound, pf)
		case "outbound":
			h.Outbound = append(h.Outbound, pf)
		}
	}
	return h
}
