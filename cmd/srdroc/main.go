//go:build engine

// srdroc 用**实测可达性真值**评估 SRD 两种模型的判别能力并输出 ROC/AUC。
//
// 输入：
//   - -topology：与 srdbench 相同的拓扑 JSON（hosts[].ips 必填，用于 IP→主机映射）；
//   - -truth：实测 CSV（src_vmid,target_ip,reachable,rtt_ms），来自真实 ping 矩阵；
//   - -srcmap：vmid=hostID 的映射（如 921=domA-web,...）。
//
// 输出：两种模型（flat / layered）在相同真值上的 ROC 点、AUC，以及可选 SVG 曲线。
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	prismlib "github.com/chins-xing/prism"

	"github.com/chins-xing/asscor/internal/engine/srd"
	"github.com/chins-xing/asscor/internal/topology"
)

type hostSpec struct {
	ID       string   `json:"id"`
	Subnets  []string `json:"subnets"`
	IPs      []string `json:"ips"`
	Score    float64  `json:"score"`
	Visible  bool     `json:"visible"`
	Forwards bool     `json:"forwards"`
	// v2.2 语义输入：主机入向策略（域内/主机级 ACL）与链路状态。
	Inbound []struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Allow bool   `json:"allow"`
	} `json:"inbound,omitempty"`
	Outbound []struct {
		To    string `json:"to"`
		Allow bool   `json:"allow"`
	} `json:"outbound,omitempty"`
	StatefulInput bool `json:"stateful_input,omitempty"`
	Links map[string]bool `json:"links,omitempty"` // 子网 -> 链路是否 up
}
type policySpec struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Allow bool   `json:"allow"`
}
type topoFile struct {
	Policies    []policySpec `json:"policies"`
	PolicyKnown bool         `json:"policy_known"`
	Hosts       []hostSpec   `json:"hosts"`
}

type scored struct {
	p             pair
	flat, layered float64
}

type pair struct {
	Src, Dst string
	Truth    bool
}

type rocPoint struct {
	Threshold float64
	TPR, FPR  float64
}

func main() {
	topoPath := flag.String("topology", "", "拓扑 JSON（hosts[].ips 用于 IP→主机映射）")
	truthPath := flag.String("truth", "", "实测连通矩阵 CSV")
	srcmap := flag.String("srcmap", "", "vmid=hostID，逗号分隔")
	svgPath := flag.String("svg", "", "输出 ROC SVG 路径（可选）")
	flag.Parse()

	tf := topoFile{}
	if b, err := os.ReadFile(*topoPath); err == nil {
		_ = json.Unmarshal(b, &tf)
	} else {
		fmt.Fprintln(os.Stderr, "读取拓扑失败:", err)
		os.Exit(1)
	}
	ipToHost := map[string]string{}
	for _, h := range tf.Hosts {
		for _, ip := range h.IPs {
			ipToHost[ip] = h.ID
		}
	}

	vmidToHost := map[string]string{}
	for _, kv := range strings.Split(*srcmap, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) == 2 {
			vmidToHost[parts[0]] = parts[1]
		}
	}

	// 真值：按 (srcHost, dstHost) 折叠（同一主机多 IP 任一可达即算可达）
	type key struct{ s, d string }
	truth := map[key]bool{}
	f, err := os.Open(*truthPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取真值失败:", err)
		os.Exit(1)
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rows, _ := rd.ReadAll()
	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}
		src := vmidToHost[row[0]]
		dst, ok := ipToHost[row[1]]
		if src == "" || !ok {
			continue
		}
		reach := row[2] == "1"
		k := key{src, dst}
		truth[k] = truth[k] || reach
	}

	pairs := make([]pair, 0, len(truth))
	for k, v := range truth {
		if k.s == k.d {
			continue // 自己到自己的对不参与
		}
		pairs = append(pairs, pair{Src: k.s, Dst: k.d, Truth: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Src != pairs[j].Src {
			return pairs[i].Src < pairs[j].Src
		}
		return pairs[i].Dst < pairs[j].Dst
	})

	// ---------- 模型分数 ----------
	hostFacts := make([]topology.HostFacts, 0, len(tf.Hosts))
	var policies []topology.PolicyRule
	for _, h := range tf.Hosts {
		if !h.Visible {
			continue
		}
			inb := make([]topology.PolicyRule, 0, len(h.Inbound))
		for _, r := range h.Inbound {
			inb = append(inb, topology.PolicyRule{From: r.From, To: r.To, Allow: r.Allow})
		}
		outb := make([]topology.PolicyRule, 0, len(h.Outbound))
		for _, r := range h.Outbound {
			outb = append(outb, topology.PolicyRule{To: r.To, Allow: r.Allow})
		}
		hostFacts = append(hostFacts, topology.HostFacts{
			HostID: h.ID, Subnets: h.Subnets, Forwards: h.Forwards,
			Inbound: inb,
		Outbound: outb,
		IPs:      h.IPs,
		StatefulInput: h.StatefulInput,
		Links:   h.Links,
	})
	}
	for _, p := range tf.Policies {
		policies = append(policies, topology.PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
	}
	lg := topology.BuildLayeredGraph(hostFacts, policies, tf.PolicyKnown, true)

	nodes := map[string]*prismlib.NodeState{}
	topoInfo := map[string]*srd.TopologyInfo{}
	for _, h := range tf.Hosts {
		topoInfo[h.ID] = &srd.TopologyInfo{Subnets: h.Subnets}
		if h.Visible {
			nodes[h.ID] = &prismlib.NodeState{HostID: h.ID, SSAMScore: h.Score, Criticality: 0.5}
		}
	}
	flatEdges := srd.BuildEdgesWithTopology(topoInfo, nodes, 0.1)
	prismCfg := prismlib.DefaultConfig()

	items := make([]scored, 0, len(pairs))
	for _, p := range pairs {
		// flat：prism 找得到路径=1，否则 0
		flatScore := 0.0
		if _, ok := nodes[p.Src]; ok {
			if _, ok2 := nodes[p.Dst]; ok2 {
				if paths := prismlib.FindPropagationPaths(p.Src, p.Dst, nodes, flatEdges, prismCfg, 0, 5, 50); len(paths) > 0 {
					flatScore = 1
				}
			}
		}
		// layered：reachable=1、probable=0.5、blocked=0（连续化：按最短跳数衰减）
		// 连续分数：对所有非 blocked 路径求和"跳数衰减 × 允许性"，
		// 再映射到 (0,1)：score = 1 - exp(-sum)。路径越多/越短 ⇒ 分数越高；
		// probable（未知层）按 0.4 降权；blocked 恒为 0。
		pvs := lg.HostReachable(p.Src, p.Dst, 5)
		sum := 0.0
		for _, v := range pvs {
			if v.Verdict == topology.VerdictBlocked {
				continue
			}
			hops := len(v.Path) - 1
			if hops < 1 {
				continue
			}
			base := math.Pow(0.9, float64(hops-1))
			if v.Verdict == topology.VerdictProbable {
				base *= 0.4
			}
			sum += base
		}
		layScore := 1 - math.Exp(-sum)
		items = append(items, scored{p: p, flat: flatScore, layered: layScore})
	}

	report("flat", items, func(s scored) float64 { return s.flat })
	report("layered", items, func(s scored) float64 { return s.layered })
	if *svgPath != "" {
		writeSVG(*svgPath, items)
	}
}

func report(name string, items []scored, score func(scored) float64) {
	pts := rocPoints(items, score)
	auc := 0.0
	for i := 1; i < len(pts); i++ {
		auc += (pts[i].FPR - pts[i-1].FPR) * (pts[i].TPR + pts[i-1].TPR) / 2
	}
	fmt.Printf("== %s ==\n", name)
	fmt.Println("threshold\tTPR\tFPR")
	for _, p := range pts {
		fmt.Printf("%.2f\t%.3f\t%.3f\n", p.Threshold, p.TPR, p.FPR)
	}
	fmt.Printf("AUC=%.3f\n\n", auc)
}

func rocPoints(items []scored, score func(scored) float64) []rocPoint {
	pos, neg := 0, 0
	for _, s := range items {
		if s.p.Truth {
			pos++
		} else {
			neg++
		}
	}
	thresholds := []float64{}
	seen := map[float64]bool{}
	for _, s := range items {
		v := score(s)
		if !seen[v] {
			seen[v] = true
			thresholds = append(thresholds, v)
		}
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(thresholds)))
	out := []rocPoint{{Threshold: 1e9, TPR: 0, FPR: 0}}
	for _, thr := range thresholds {
		tp, fp := 0, 0
		for _, s := range items {
			if score(s) >= thr {
				if s.p.Truth {
					tp++
				} else {
					fp++
				}
			}
		}
		out = append(out, rocPoint{Threshold: thr,
			TPR: safeDiv(tp, pos), FPR: safeDiv(fp, neg)})
	}
	// 终点点 (1,1)
	out = append(out, rocPoint{Threshold: -1, TPR: 1, FPR: 1})
	return out
}

func safeDiv(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// writeSVG 输出两种模型的 ROC 曲线（宽度 480，高度 480，留边 40）。
func writeSVG(path string, items []scored) {
	const w, h, pad = 520, 520, 50
	toXY := func(tpr, fpr float64) (float64, float64) {
		x := pad + fpr*float64(w-2*pad)
		y := float64(h-pad) - tpr*float64(h-2*pad)
		return x, y
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, w, h, w, h)
	b.WriteString(`<rect width="100%" height="100%" fill="white"/>`)
	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#888"/>`, pad, pad, w-2*pad, h-2*pad)
	b.WriteString(`<line x1="50" y1="470" x2="470" y2="50" stroke="#bbb" stroke-dasharray="6,4"/>`)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="12" fill="#333">TPR</text>`, pad-30, pad+10)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="12" fill="#333">FPR</text>`, w-pad-10, h-pad+22)
	b.WriteString(`<text x="260" y="26" font-size="14" text-anchor="middle" fill="#111">SRD ROC (measured ground truth)</text>`)
	for _, m := range []struct {
		name  string
		color string
		f     func(scored) float64
	}{
		{"flat", "#d62728", func(s scored) float64 { return s.flat }},
		{"layered", "#1f77b4", func(s scored) float64 { return s.layered }},
	} {
		pts := rocPoints(items, m.f)
		b.WriteString(`<polyline fill="none" stroke="` + m.color + `" stroke-width="2" points="`)
		for _, p := range pts {
			x, y := toXY(p.TPR, p.FPR)
			fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
		}
		b.WriteString(`"/>`)
		x, y := toXY(0.97, 0.03)
		b.WriteString(`<text x="` + strconv.Itoa(int(x)) + `" y="` + strconv.Itoa(int(y)) + `" font-size="12" fill="` + m.color + `">` + m.name + `</text>`)
	}
	b.WriteString(`</svg>`)
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
	fmt.Println("SVG →", path)
}
