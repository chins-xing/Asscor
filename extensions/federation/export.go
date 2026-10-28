package federation

import (
	"net"
	"sort"
	"strings"

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
				policies = append(policies, PolicyFact{From: p.From, To: p.To, Allow: p.Allow})
			}
		}
	}
	return hosts, policies, known
}

// mergedFactsFrom 是 merge 的核心：节点上报 + 调用方提供的本地事实。
func mergedFactsFrom(reports []NodeReport, localHosts []HostFact, localPolicies []PolicyFact, localKnown bool) (map[string]*HostFact, map[string]PolicyFact, bool) {
	hosts := map[string]*HostFact{}
	policies := map[string]PolicyFact{}
	policyKnown := false

	mergeHost := func(h HostFact) {
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

	for _, r := range reports {
		policyKnown = policyKnown || r.PolicyKnown
		for _, h := range r.HostFacts {
			mergeHost(h)
		}
		for _, p := range r.PolicyFacts {
			p.From = normalizeFactSubnet(p.From)
			p.To = normalizeFactSubnet(p.To)
			key := p.From + "|" + p.To + "|" + boolKey(p.Allow)
			policies[key] = p
		}
	}
	for _, h := range localHosts {
		mergeHost(h)
	}
	for _, p := range localPolicies {
		p.From = normalizeFactSubnet(p.From)
		p.To = normalizeFactSubnet(p.To)
		key := p.From + "|" + p.To + "|" + boolKey(p.Allow)
		policies[key] = p
	}
	if localKnown {
		policyKnown = true
	}
	return hosts, policies, policyKnown
}

// MergedTopology 导出合并事实（主端 /federation/export 与离线 AUC 实验共用）。
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
