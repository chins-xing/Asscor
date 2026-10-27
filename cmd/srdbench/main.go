//go:build engine

// srdbench 是 SRD 路径识别能力的**离线基准**：给定真实拓扑（含哪些主机对 SRD
// 可见）与一组已知攻击链（ground truth），复算 SRD 的边集与传播路径，输出
//
//	路径识别的 precision / recall、可达集合的 precision / recall，
//	以及参数扫描（transmission / path_decay / prop_cap / max_depth / aggregation）
//	对上述指标的影响。
//
// 它复用 `srd.BuildEdgesWithTopology`（与 kernel 内 SRD 完全同一份构边规则），
// 因此"基准算出来的"和"线上跑的"不会分叉。
//
// 用法：
//
//	go run -tags engine ./cmd/srdbench -topology lab/three-domain.json
//	go run -tags engine ./cmd/srdbench -topology lab/three-domain.json \
//	    -sweep max_depth=1,2,3 -sweep transmission=0.05,0.1,0.2
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	prismlib "github.com/chins-xing/prism"

	"github.com/chins-xing/asscor/internal/engine/srd"
)

// ---------------------------------------------------------------- 输入模型

type hostSpec struct {
	ID          string   `json:"id"`
	Subnets     []string `json:"subnets"`
	Score       float64  `json:"score"`       // SSAM 分数 [0,100]
	Visible     bool     `json:"visible"`     // false = 真实存在但 SRD 看不到（无 agent）
	Criticality float64  `json:"criticality"` // 0..1，缺省 0.5
}

type chainSpec struct {
	ID      string `json:"id"`
	Src     string `json:"src"`
	DstNode string `json:"dst"`
	// TruthPaths 是**真实**可被利用的攻击链（按节点序列）；空数组表示"不存在路径"。
	TruthPaths [][]string `json:"truth_paths"`
	// TruthRank 可选：按"真实风险从高到低"排列的路径（用于评估排序一致性）。
	TruthRank [][]string `json:"truth_rank,omitempty"`
	// TruthReachable 是从 src 出发在 maxHops 内**真实可达**的主机集合。
	TruthReachable []string `json:"truth_reachable,omitempty"`
}

type topologyFile struct {
	Transmission float64     `json:"transmission"`
	Hosts        []hostSpec  `json:"hosts"`
	Chains       []chainSpec `json:"chains"`
}

// ---------------------------------------------------------------- 参数

type params struct {
	Transmission float64
	PathDecay    float64
	PropCap      float64
	MaxDepth     int
	Limit        int
	Aggregation  string
}

func defaultParams() params {
	c := prismlib.DefaultConfig()
	return params{
		Transmission: 0.1,
		PathDecay:    c.PathDecay,
		PropCap:      c.PropCap,
		MaxDepth:     c.MaxPathDepth,
		Limit:        50,
		Aggregation:  c.AggregationMode,
	}
}

func (p params) prismConfig() prismlib.PrismConfig {
	c := prismlib.DefaultConfig()
	c.PathDecay = p.PathDecay
	c.PropCap = p.PropCap
	c.MaxPathDepth = p.MaxDepth
	if p.Aggregation != "" {
		c.AggregationMode = p.Aggregation
	}
	return c
}

// ---------------------------------------------------------------- 评估

type chainResult struct {
	ChainID   string
	Found     [][]string
	Truth     [][]string
	PathPrec  float64
	PathRec   float64
	ReachPrec float64
	ReachRec  float64
	// RankConcordance: 0..1，1 = Found 中路径的 CumulativeRisk 排序与 TruthRank 完全一致。
	RankConcordance float64
	HasRank         bool
}

func evaluate(tf *topologyFile, p params) []chainResult {
	nodes := map[string]*prismlib.NodeState{}
	topo := map[string]*srd.TopologyInfo{}
	for _, h := range tf.Hosts {
		topo[h.ID] = &srd.TopologyInfo{Subnets: h.Subnets}
		if !h.Visible {
			continue // 不可见主机不进 SRD 的视野
		}
		crit := h.Criticality
		if crit == 0 {
			crit = 0.5
		}
		nodes[h.ID] = &prismlib.NodeState{HostID: h.ID, SSAMScore: h.Score, Criticality: crit}
	}
	edges := srd.BuildEdgesWithTopology(topo, nodes, p.Transmission)
	cfg := p.prismConfig()

	results := make([]chainResult, 0, len(tf.Chains))
	for _, ch := range tf.Chains {
		src, dst := ch.Src, ch.DstNode
		var found []PathResult
		if _, ok := nodes[src]; ok {
			if _, ok2 := nodes[dst]; ok2 {
				found = prismlib.FindPropagationPaths(src, dst, nodes, edges, cfg, 0, p.MaxDepth, p.Limit)
			}
		}
		foundPaths := make([][]string, 0, len(found))
		for _, fr := range found {
			foundPaths = append(foundPaths, fr.Path)
		}

		cr := chainResult{ChainID: ch.ID, Found: foundPaths, Truth: ch.TruthPaths}
		cr.PathPrec, cr.PathRec = setMetrics(foundPaths, ch.TruthPaths)

		if len(ch.TruthReachable) > 0 {
			reach := reachableWithin(src, edges, p.MaxDepth)
			truthReach := make([][]string, 0, len(ch.TruthReachable))
			for _, id := range ch.TruthReachable {
				truthReach = append(truthReach, []string{id})
			}
			cr.ReachPrec, cr.ReachRec = setMetrics(reach, truthReach)
		}

		if len(ch.TruthRank) > 1 {
			cr.HasRank = true
			cr.RankConcordance = rankConcordance(found, ch.TruthRank)
		}
		results = append(results, cr)
	}
	return results
}

type PathResult = prismlib.PathResult

// setMetrics 计算集合式 precision / recall（元素为路径序列或主机 ID）。
func setMetrics(found [][]string, truth [][]string) (prec, rec float64) {
	if len(truth) == 0 {
		if len(found) == 0 {
			return 1, 1
		}
		return 0, 1
	}
	tset := map[string]bool{}
	for _, p := range truth {
		tset[keyOf(p)] = true
	}
	hit := 0
	for _, p := range found {
		if tset[keyOf(p)] {
			hit++
		}
	}
	prec = 1
	if len(found) > 0 {
		prec = float64(hit) / float64(len(found))
	}
	rec = float64(hit) / float64(len(tset))
	return prec, rec
}

func keyOf(path []string) string { return strings.Join(path, ">") }

// reachableWithin 从 src 出发、沿有向边做不超过 hops 跳的可达集合。
func reachableWithin(src string, edges []prismlib.EdgeState, hops int) [][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
	}
	seen := map[string]bool{src: true}
	frontier := []string{src}
	for h := 0; h < hops; h++ {
		var next []string
		for _, cur := range frontier {
			for _, nx := range adj[cur] {
				if !seen[nx] {
					seen[nx] = true
					next = append(next, nx)
				}
			}
		}
		frontier = next
	}
	out := make([][]string, 0, len(seen)-1)
	ids := make([]string, 0, len(seen))
	for id := range seen {
		if id != src {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, []string{id})
	}
	return out
}

// rankConcordance 用"成对一致率"（类似 Kendall tau 的正规化版本）衡量
// Found 的 CumulativeRisk 排序与 TruthRank 的一致性。
func rankConcordance(found []prismlib.PathResult, truth [][]string) float64 {
	truthRank := map[string]int{}
	for i, p := range truth {
		truthRank[keyOf(p)] = i
	}
	type item struct {
		key  string
		risk float64
		rank int
	}
	items := make([]item, 0, len(found))
	for _, f := range found {
		k := keyOf(f.Path)
		if r, ok := truthRank[k]; ok {
			items = append(items, item{key: k, risk: f.CumulativeRisk, rank: r})
		}
	}
	if len(items) < 2 {
		return 0
	}
	concordant, discordant := 0, 0
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			a, b := items[i], items[j]
			if a.risk == b.risk {
				continue
			}
			riskOrder := a.risk < b.risk // 风险高者应 rank 小
			rankOrder := a.rank < b.rank
			if riskOrder == rankOrder {
				concordant++
			} else {
				discordant++
			}
		}
	}
	if concordant+discordant == 0 {
		return 0
	}
	return float64(concordant) / float64(concordant+discordant)
}

// ---------------------------------------------------------------- main

type sweepSpec struct {
	key    string
	values []string
}

func main() {
	topoPath := flag.String("topology", "", "拓扑与 ground truth 的 JSON 文件")
	jsonOut := flag.Bool("json", false, "以 JSON 输出结果")
	sweepFlags := multiFlag{}
	flag.Var(&sweepFlags, "sweep", "参数扫描，形如 max_depth=1,2,3；可重复")
	flag.Parse()

	if *topoPath == "" {
		fmt.Fprintln(os.Stderr, "需要 -topology <file.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(*topoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取拓扑: %v\n", err)
		os.Exit(1)
	}
	var tf topologyFile
	if err := json.Unmarshal(data, &tf); err != nil {
		fmt.Fprintf(os.Stderr, "解析拓扑 JSON: %v\n", err)
		os.Exit(1)
	}

	base := defaultParams()
	if tf.Transmission > 0 {
		base.Transmission = tf.Transmission
	}

	combos := expandSweep(base, sweepFlags)
	if *jsonOut {
		out := make([]map[string]interface{}, 0, len(combos))
		for _, p := range combos {
			out = append(out, map[string]interface{}{
				"params":  p,
				"results": evaluate(&tf, p),
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Printf("# SRD 路径识别基准（%s）\n\n", *topoPath)
	fmt.Printf("可见主机 %d / 总主机 %d，攻击链 %d；ground truth 见文件。\n\n",
		countVisible(&tf), len(tf.Hosts), len(tf.Chains))
	fmt.Println("| params | chain | path P | path R | reach P | reach R | rank |")
	fmt.Println("|---|---|---|---|---|---|---|")
	for _, p := range combos {
		res := evaluate(&tf, p)
		for _, r := range res {
			rank := "-"
			if r.HasRank {
				rank = fmt.Sprintf("%.2f", r.RankConcordance)
			}
			fmt.Printf("| %s | %s | %.2f | %.2f | %.2f | %.2f | %s |\n",
				p.String(), r.ChainID, r.PathPrec, r.PathRec, r.ReachPrec, r.ReachRec, rank)
		}
	}
}

func countVisible(tf *topologyFile) int {
	n := 0
	for _, h := range tf.Hosts {
		if h.Visible {
			n++
		}
	}
	return n
}

func (p params) String() string {
	return fmt.Sprintf("t=%.2f decay=%.2f cap=%.2f depth=%d %s",
		p.Transmission, p.PathDecay, p.PropCap, p.MaxDepth, p.Aggregation)
}

func expandSweep(base params, flags multiFlag) []params {
	specs := make([]sweepSpec, 0, len(flags))
	for _, raw := range flags {
		kv := strings.SplitN(raw, "=", 2)
		if len(kv) != 2 {
			continue
		}
		specs = append(specs, sweepSpec{key: strings.TrimSpace(kv[0]), values: strings.Split(kv[1], ",")})
	}
	combos := []params{base}
	for _, s := range specs {
		var next []params
		for _, c := range combos {
			for _, v := range s.values {
				n := c
				switch s.key {
				case "transmission":
					n.Transmission = parseFloat(v, c.Transmission)
				case "path_decay":
					n.PathDecay = parseFloat(v, c.PathDecay)
				case "prop_cap":
					n.PropCap = parseFloat(v, c.PropCap)
				case "max_depth":
					n.MaxDepth = parseInt(v, c.MaxDepth)
				case "aggregation":
					n.Aggregation = strings.TrimSpace(v)
				default:
					continue
				}
				next = append(next, n)
			}
		}
		if len(next) > 0 {
			combos = next
		}
	}
	return combos
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ";") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parseFloat(s string, def float64) float64 {
	var f float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%f", &f); err != nil {
		return def
	}
	return f
}

func parseInt(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
		return def
	}
	return n
}
