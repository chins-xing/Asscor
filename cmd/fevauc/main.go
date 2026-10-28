//go:build engine

// fevauc 是 T4 联邦 AUC 实验的评分器（ARC 专属）。
//
// 输入：topology JSON（srdroc 兼容）、真值 CSV（src,target_ip,reachable,rtt_ms）、
// srcmap（vmid=host）、hostmap（ip→host，含模型不认识的主机）、decay、depth、aggregation。
// 输出：逐对分数 CSV + AUC（与 topology.HostReachable 同一 API，避免工具口径不一致）。
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/chins-xing/asscor/internal/topology"
)

type rule struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Allow bool   `json:"allow"`
}

type hostSpec struct {
	ID            string          `json:"id"`
	IPs           []string        `json:"ips"`
	Subnets       []string        `json:"subnets"`
	Forwards      bool            `json:"forwards"`
	StatefulInput bool            `json:"stateful_input"`
	Inbound       []rule          `json:"inbound"`
	Outbound      []rule          `json:"outbound"`
	Links         map[string]bool `json:"links"`
}

type topoFile struct {
	Policies    []rule     `json:"policies"`
	PolicyKnown bool       `json:"policy_known"`
	Hosts       []hostSpec `json:"hosts"`
}

func main() {
	if len(os.Args) < 8 {
		fmt.Fprintln(os.Stderr, "usage: fevauc <topo.json> <truth.csv> <srcmap.txt|vmid=host,...> <hostmap.json> <dump.csv> <decay> <depth> [aggregation]")
		os.Exit(2)
	}
	topoPath, truthPath, srcmapArg, hostmapPath, dumpPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	decay, _ := strconv.ParseFloat(os.Args[6], 64)
	depth, _ := strconv.Atoi(os.Args[7])
	aggMode := "linear"
	if len(os.Args) > 8 {
		aggMode = os.Args[8]
	}

	b, err := os.ReadFile(topoPath)
	if err != nil {
		panic(err)
	}
	var tf topoFile
	if err := json.Unmarshal(b, &tf); err != nil {
		panic(err)
	}
	hosts := make([]topology.HostFacts, 0, len(tf.Hosts))
	for _, h := range tf.Hosts {
		hf := topology.HostFacts{
			HostID: h.ID, IPs: h.IPs, Subnets: h.Subnets,
			Forwards: h.Forwards, StatefulInput: h.StatefulInput, Links: h.Links,
		}
		for _, r := range h.Inbound {
			hf.Inbound = append(hf.Inbound, topology.PolicyRule{From: r.From, To: r.To, Allow: r.Allow})
		}
		for _, r := range h.Outbound {
			hf.Outbound = append(hf.Outbound, topology.PolicyRule{To: r.To, Allow: r.Allow})
		}
		hosts = append(hosts, hf)
	}
	policies := make([]topology.PolicyRule, 0, len(tf.Policies))
	for _, p := range tf.Policies {
		policies = append(policies, topology.PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
	}
	lg := topology.BuildLayeredGraph(hosts, policies, tf.PolicyKnown, true)

	// srcmap：支持 "vmid=host,..." 内联或文件路径
	src := map[string]string{}
	raw := srcmapArg
	if data, err := os.ReadFile(srcmapArg); err == nil {
		raw = strings.TrimSpace(string(data))
	}
	for _, kv := range strings.Split(raw, ",") {
		p := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(p) == 2 && p[0] != "" {
			src[p[0]] = p[1]
		}
	}

	ip2host := map[string]string{}
	if rb, err := os.ReadFile(hostmapPath); err == nil {
		_ = json.Unmarshal(rb, &ip2host)
	}
	for _, h := range tf.Hosts {
		for _, ip := range h.IPs {
			if _, ok := ip2host[ip]; !ok {
				ip2host[ip] = h.ID
			}
		}
	}

	f, err := os.Open(truthPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		panic(err)
	}
	agg := map[[2]string]bool{}
	for i, r := range rows {
		if i == 0 || len(r) < 3 {
			continue
		}
		s := src[r[0]]
		d := ip2host[r[1]]
		if s == "" || d == "" || d == s {
			continue
		}
		k := [2]string{s, d}
		agg[k] = agg[k] || r[2] == "1"
	}

	out, err := os.Create(dumpPath)
	if err != nil {
		panic(err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	_ = w.Write([]string{"src", "dst", "truth", "layered"})

	type sample struct {
		truth bool
		score float64
	}
	samples := make([]sample, 0, len(agg))
	pos, neg := 0, 0
	for k, tr := range agg {
		pvs := lg.HostReachable(k[0], k[1], depth)
		var maxB, sumSq, sum float64
		for _, v := range pvs {
			if v.Verdict == topology.VerdictBlocked {
				continue
			}
			hops := len(v.Path) - 1
			if hops < 1 {
				continue
			}
			base := math.Pow(decay, float64(hops-1))
			if v.Verdict == topology.VerdictProbable {
				base *= 0.4
			}
			if base > maxB {
				maxB = base
			}
			sumSq += base * base
			sum += base
		}
		var aggScore float64
		switch aggMode {
		case "max":
			aggScore = maxB
		case "rss":
			aggScore = math.Sqrt(sumSq)
		default:
			aggScore = sum
		}
		score := 1 - math.Exp(-aggScore)
		truthStr := "0"
		if tr {
			truthStr = "1"
			pos++
		} else {
			neg++
		}
		_ = w.Write([]string{k[0], k[1], truthStr, fmt.Sprintf("%.6f", score)})
		samples = append(samples, sample{truth: tr, score: score})
	}
	w.Flush()

	var wins float64
	for _, a := range samples {
		if !a.truth {
			continue
		}
		for _, b := range samples {
			if b.truth {
				continue
			}
			switch {
			case a.score > b.score:
				wins++
			case a.score == b.score:
				wins += 0.5
			}
		}
	}
	auc := 0.0
	if pos > 0 && neg > 0 {
		auc = wins / float64(pos*neg)
	}
	fmt.Printf("pairs=%d pos=%d neg=%d AUC=%.3f\n", len(samples), pos, neg, auc)
}
