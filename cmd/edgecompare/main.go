//go:build edgeexp

// Command edgecompare 是方向② 的离线重算工具（spec §5.2）。
//
// 当前（Task 8）交付的是**读取层 + 三层指标**：把实验 JSONL（spec §5.1）读进来、按在线
// 同一口径重算、算决策层/排序层/数值层指标。报告渲染与参数段导出（Task 9）、logistic 拟合
// 与离线↔在线一致性门禁（Task 10）会在此入口上继续接线；本入口目前只做数据集自检，
// 不构造任何候选参数 —— 参数只能来自配置/实验模板，凭空造一套参数会让报告"看起来能用"。
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	recordsPath := flag.String("records", "", "实验 JSONL 路径（spec §5.1 schema）")
	verbose := flag.Bool("v", false, "逐条打印场景摘要")
	flag.Parse()

	if strings.TrimSpace(*recordsPath) == "" {
		fmt.Fprintln(os.Stderr, "edgecompare: -records 是必填项（实验 JSONL 路径）")
		flag.Usage()
		os.Exit(2)
	}

	records, err := LoadRecords(*recordsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	compromised, factored, chained := 0, 0, 0
	envs := map[string]int{}
	factors := map[string]int{}
	for _, rec := range records {
		if rec.GroundTruth.Compromised {
			compromised++
		}
		if len(rec.Factors) > 0 {
			factored++
		}
		if len(rec.Observed.EdgeFactorChain) > 0 {
			chained++
		}
		envs[rec.Meta.Env]++
		for _, c := range rec.Observed.EdgeFactorChain {
			factors[normalizeFactorID(c.Factor)]++
		}
	}

	fmt.Printf("记录数: %d\n", len(records))
	fmt.Printf("客观被攻陷: %d/%d\n", compromised, len(records))
	fmt.Printf("含因子场景: %d｜含因子链观测: %d\n", factored, chained)
	fmt.Printf("环境: %s\n", formatCounts(envs))
	fmt.Printf("因子出现次数: %s\n", formatCounts(factors))
	if *verbose {
		fmt.Println("\n场景明细:")
		for _, rec := range records {
			fmt.Printf("  %-28s 阈值=%.4g 观测总分=%.4g 判=%v 攻陷=%v 链=%d 因子=%s\n",
				rec.ScenarioID, rec.Observed.Threshold, rec.Observed.FinalScore,
				rec.Observed.Acceptable, rec.GroundTruth.Compromised,
				len(rec.Observed.EdgeFactorChain), strings.Join(rec.Factors, ","))
		}
	}
}

// formatCounts 以稳定的字典序输出计数表（报告/日志必须可复现，不能依赖 map 迭代序）。
func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "(无)"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			k = "(未填写)"
		}
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}
