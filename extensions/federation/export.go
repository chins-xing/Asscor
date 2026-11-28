package federation

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/topology"
)

// ExportedHost 是导出为主端合并拓扑的主机条目（与 srdroc 的 topology JSON 兼容）。
type ExportedHost struct {
	ID            string          `json:"id"`
	IPs           []string        `json:"ips,omitempty"`
	Subnets       []string        `json:"subnets,omitempty"`
	Zone          string          `json:"zone,omitempty"`
	Forwards      bool            `json:"forwards,omitempty"`
	StatefulInput bool            `json:"stateful_input,omitempty"`
	Inbound       []PolicyFact    `json:"inbound,omitempty"`
	Outbound      []PolicyFact    `json:"outbound,omitempty"`
	Links         map[string]bool `json:"links,omitempty"`
	SourceNodes   []string        `json:"source_nodes,omitempty"`
	ObservedAt    time.Time       `json:"observed_at,omitempty"`
	ValidUntil    time.Time       `json:"valid_until,omitempty"`
	Confidence    float64         `json:"confidence,omitempty"`
}

// TopologyExport 是主端合并图的"可评分"导出（v0.2）。
type TopologyExport struct {
	PolicyKnown bool           `json:"policy_known"`
	Policies    []PolicyFact   `json:"policies"`
	Hosts       []ExportedHost `json:"hosts"`
}

// mergedFacts 把节点上报 + 主端本地拓扑合并成事实集合（供建图与导出共用）。
func mergedFacts(reports []NodeReport) (map[string]*HostFact, map[string]PolicyFact, bool) {
	lh, lp, lk := localFactsFromTopology()
	return mergedFactsFrom(reports, lh, lp, lk)
}

// localFactsFromTopology 把主 kernel 本地拓扑转成事实（进程内模式）。
func localFactsFromTopology() ([]HostFact, []PolicyFact, bool) {
	hosts := make([]HostFact, 0)
	policies := make([]PolicyFact, 0)
	known := false
	for _, n := range topology.ListNodes() {
		hosts = append(hosts, hostFactFromTopo(n))
		if n.PolicyKnown {
			known = true
		}
		for _, p := range n.Policies {
			if p.Direction == "" || p.Direction == "forward" {
				policies = append(policies, PolicyFact{From: p.From, To: p.To, Allow: p.Allow, Protocol: p.Protocol, SrcPort: p.SrcPort, DstPort: p.DstPort, ObservedAt: p.ObservedAt, ValidUntil: p.ValidUntil, Confidence: p.Confidence})
			}
		}
	}
	return hosts, policies, known
}

// mergedFactsFrom 是 merge 的核心：节点上报 + 调用方提供的本地事实。
// mergedFactsFrom 保留原有三返回值签名，供导出/兼容路径使用。
func mergedFactsFrom(reports []NodeReport, localHosts []HostFact, localPolicies []PolicyFact, localKnown bool) (map[string]*HostFact, map[string]PolicyFact, bool) {
	hosts, policies, known, _ := mergedFactsWithConflicts(reports, localHosts, localPolicies, localKnown)
	return hosts, policies, known
}

// mergedFactsWithConflicts 是 merge 的核心：节点上报 + 调用方提供的本地事实。
// 审计 LayeredGraph P0：同一 (from,to) 的 allow/deny 都保留，并记录来源冲突，
// 不再让“先匹配到哪条”静默决定结果。
func mergedFactsWithConflicts(reports []NodeReport, localHosts []HostFact, localPolicies []PolicyFact, localKnown bool) (map[string]*HostFact, map[string]PolicyFact, bool, []topology.PolicyConflict) {
	hosts := map[string]*HostFact{}
	policies := map[string]PolicyFact{}
	votes := map[string]map[bool]map[string]bool{}
	hostVotes := map[string]map[bool]map[string]bool{}
	policyKnown := false

	addHostRule := func(host, direction string, r PolicyFact, source string) {
		from := normalizeFactSubnet(r.From)
		to := normalizeFactSubnet(r.To)
		key := host + "|" + direction + "|" + from + "|" + to + "|" + l4Key(r)
		if hostVotes[key] == nil {
			hostVotes[key] = map[bool]map[string]bool{true: {}, false: {}}
		}
		hostVotes[key][r.Allow][source] = true
	}

	mergeHost := func(h HostFact, source string) {
		h.SourceNodes = unionStrings(h.SourceNodes, []string{source})
		for _, r := range h.Inbound {
			addHostRule(h.ID, "inbound", r, source)
		}
		for _, r := range h.Outbound {
			addHostRule(h.ID, "outbound", r, source)
		}
		h.Subnets = normalizeFactSubnets(h.Subnets)
		cur, ok := hosts[h.ID]
		if !ok {
			cp := h
			cp.IPs = unionStrings(nil, h.IPs)
			cp.Subnets = unionStrings(nil, h.Subnets)
			cp.Inbound = append([]PolicyFact(nil), h.Inbound...)
			cp.Outbound = append([]PolicyFact(nil), h.Outbound...)
			if h.Links != nil {
				cp.Links = map[string]bool{}
				for k, v := range h.Links {
					cp.Links[k] = v
				}
			}
			hosts[h.ID] = &cp
			return
		}
		cur.Subnets = unionStrings(cur.Subnets, h.Subnets)
		cur.IPs = unionStrings(cur.IPs, h.IPs)
		cur.SourceNodes = unionStrings(cur.SourceNodes, h.SourceNodes)
		cur.ObservedAt = laterTime(cur.ObservedAt, h.ObservedAt)
		cur.ValidUntil = earlierNonZero(cur.ValidUntil, h.ValidUntil)
		cur.Confidence = minPositive(cur.Confidence, h.Confidence)
		if h.Zone != "" {
			cur.Zone = h.Zone
		}
		cur.Forwards = cur.Forwards || h.Forwards
		cur.StatefulInput = cur.StatefulInput || h.StatefulInput
		cur.Inbound = append(cur.Inbound, h.Inbound...)
		cur.Outbound = append(cur.Outbound, h.Outbound...)
		if len(h.Links) > 0 {
			if cur.Links == nil {
				cur.Links = map[string]bool{}
			}
			for k, v := range h.Links {
				cur.Links[k] = v
			}
		}
	}

	addPolicy := func(p PolicyFact, source string) {
		p.From = normalizeFactSubnet(p.From)
		p.To = normalizeFactSubnet(p.To)
		p.SourceNodes = unionStrings(p.SourceNodes, []string{source})
		pair := p.From + "|" + p.To
		voteKey := pair + "|" + l4Key(p)
		if votes[voteKey] == nil {
			votes[voteKey] = map[bool]map[string]bool{true: {}, false: {}}
		}
		votes[voteKey][p.Allow][source] = true
		key := voteKey + "|" + boolKey(p.Allow)
		if existing, ok := policies[key]; ok {
			p.SourceNodes = unionStrings(existing.SourceNodes, p.SourceNodes)
			p.ObservedAt = laterTime(existing.ObservedAt, p.ObservedAt)
			p.ValidUntil = earlierNonZero(existing.ValidUntil, p.ValidUntil)
			p.Confidence = minPositive(existing.Confidence, p.Confidence)
		}
		policies[key] = p
	}

	for _, r := range reports {
		policyKnown = policyKnown || r.PolicyKnown
		source := r.NodeID
		if source == "" {
			source = "unknown-node"
		}
		for _, h := range r.HostFacts {
			mergeHost(h, source)
		}
		for _, p := range r.PolicyFacts {
			addPolicy(p, source)
		}
	}
	for _, h := range localHosts {
		mergeHost(h, "master")
	}
	for _, p := range localPolicies {
		addPolicy(p, "master")
	}
	if localKnown {
		policyKnown = true
	}

	keys := make([]string, 0, len(votes))
	for pair := range votes {
		keys = append(keys, pair)
	}
	sort.Strings(keys)
	conflicts := make([]topology.PolicyConflict, 0)
	for _, pair := range keys {
		byAllow := votes[pair]
		if len(byAllow[true]) == 0 || len(byAllow[false]) == 0 {
			continue
		}
		parts := strings.SplitN(pair, "|", 5)
		if len(parts) != 5 {
			continue
		}
		sport, _ := strconv.Atoi(parts[3])
		dport, _ := strconv.Atoi(parts[4])
		conflicts = append(conflicts, topology.PolicyConflict{
			From:         parts[0],
			To:           parts[1],
			Protocol:     parts[2],
			SrcPort:      sport,
			DstPort:      dport,
			AllowSources: sortedKeys(byAllow[true]),
			DenySources:  sortedKeys(byAllow[false]),
		})
	}
	// Host 级 inbound/outbound 冲突（审计 LayeredGraph P0 尾项）。
	hostKeys := make([]string, 0, len(hostVotes))
	for k := range hostVotes {
		hostKeys = append(hostKeys, k)
	}
	sort.Strings(hostKeys)
	for _, key := range hostKeys {
		byAllow := hostVotes[key]
		if len(byAllow[true]) == 0 || len(byAllow[false]) == 0 {
			continue
		}
		parts := strings.SplitN(key, "|", 7)
		if len(parts) != 7 {
			continue
		}
		sport, _ := strconv.Atoi(parts[5])
		dport, _ := strconv.Atoi(parts[6])
		conflicts = append(conflicts, topology.PolicyConflict{
			Host:         parts[0],
			Direction:    parts[1],
			From:         parts[2],
			To:           parts[3],
			Protocol:     parts[4],
			SrcPort:      sport,
			DstPort:      dport,
			AllowSources: sortedKeys(byAllow[true]),
			DenySources:  sortedKeys(byAllow[false]),
		})
	}
	return hosts, policies, policyKnown, conflicts
}

func l4Key(p PolicyFact) string {
	return strings.ToLower(p.Protocol) + "|" + strconv.Itoa(p.SrcPort) + "|" + strconv.Itoa(p.DstPort)
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func earlierNonZero(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.Before(a) {
		return b
	}
	return a
}

func minPositive(a, b float64) float64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if b < a {
		return b
	}
	return a
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func MergedTopology(reports []NodeReport) TopologyExport {
	hosts, policies, known := mergedFacts(reports)
	return exportFromFacts(hosts, policies, known)
}

func exportFromFacts(hosts map[string]*HostFact, policies map[string]PolicyFact, known bool) TopologyExport {
	ids := make([]string, 0, len(hosts))
	for id := range hosts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := TopologyExport{PolicyKnown: known, Policies: make([]PolicyFact, 0, len(policies))}
	for _, id := range ids {
		h := hosts[id]
		eh := ExportedHost{
			ID: h.ID, IPs: h.IPs, Subnets: h.Subnets, Zone: h.Zone,
			Forwards: h.Forwards, StatefulInput: h.StatefulInput,
			Inbound: h.Inbound, Outbound: h.Outbound, Links: h.Links,
			SourceNodes: append([]string(nil), h.SourceNodes...),
			ObservedAt:  h.ObservedAt, ValidUntil: h.ValidUntil, Confidence: h.Confidence,
		}
		if len(eh.IPs) == 0 {
			eh.IPs = nil
		}
		out.Hosts = append(out.Hosts, eh)
	}
	// 策略排序，导出稳定
	keys := make([]string, 0, len(policies))
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Policies = append(out.Policies, policies[k])
	}
	return out
}

// normalizeFactSubnet 归一单个子网/策略地址（带主机位时取网络地址）。
func normalizeFactSubnet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String()
	}
	return s
}

// normalizeFactSubnets 把子网归一到网络地址（与 topology.normalizeSubnets 同规则）。
func normalizeFactSubnets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			s = n.String()
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// MergedTopologyWithLocal 导出"节点上报 + 指定本地事实"的合并拓扑。
// 进程隔离模式下，主 kernel 把本地事实通过 RPC 推给联邦子进程，由子进程调用它。
func MergedTopologyWithLocal(reports []NodeReport, localHosts []HostFact, localPolicies []PolicyFact, localKnown bool) TopologyExport {
	hosts, policies, known := mergedFactsFrom(reports, localHosts, localPolicies, localKnown)
	return exportFromFacts(hosts, policies, known)
}
