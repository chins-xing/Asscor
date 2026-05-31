package prism

import "sort"

func FindPropagationPaths(
	source, target string,
	nodes map[string]*NodeState,
	edges []EdgeState,
	cfg PrismConfig,
	_ int64,
	maxDepth int,
	limit int,
) []PathResult {
	if maxDepth <= 0 {
		maxDepth = cfg.MaxPathDepth
	}
	if limit <= 0 {
		limit = 10
	}

	adj := make(map[string][]EdgeState)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e)
	}

	var allPaths []struct {
		path  []string
		risk  float64
		depth int
	}
	visited := map[string]bool{source: true}

	var dfs func(cur string, path []string, accumRisk float64, decay float64, hop int)
	dfs = func(cur string, path []string, accumRisk float64, decay float64, hop int) {
		if hop > maxDepth {
			return
		}

		if cur == target && hop > 0 {
			pathCopy := make([]string, len(path))
			copy(pathCopy, path)
			allPaths = append(allPaths, struct {
				path  []string
				risk  float64
				depth int
			}{pathCopy, accumRisk, hop})
			return
		}

		for _, e := range adj[cur] {
			if visited[e.Target] {
				continue
			}
			upstream, ok := nodes[cur]
			if !ok {
				continue
			}

			erisk := externalRisk(upstream.SSAMScore)
			spill := computeSpillover(erisk, e.RiskTransmission)
			decayedSpill := spill * decay

			visited[e.Target] = true
			newPath := make([]string, len(path)+1)
			copy(newPath, path)
			newPath[len(path)] = e.Target

			dfs(e.Target, newPath, accumRisk+decayedSpill, decay*cfg.PathDecay, hop+1)

			delete(visited, e.Target)
		}
	}

	dfs(source, []string{source}, 0.0, 1.0, 0)

	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].risk > allPaths[j].risk
	})

	if limit > len(allPaths) {
		limit = len(allPaths)
	}

	results := make([]PathResult, 0, limit)
	for i := 0; i < limit; i++ {
		p := allPaths[i]
		results = append(results, PathResult{
			Path:           p.path,
			CumulativeRisk: p.risk,
		})
	}

	return results
}
