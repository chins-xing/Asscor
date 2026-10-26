package config

import (
	"math"
	"testing"
)

// `Resolve` 必须返回**生效值**：规则命中后立即按 floor 抬升、按 1 封顶。
//
// 为什么钉这个：`NormalizeConfidence` 在评分时也会夹取，但报告的 `confidence`
// 字段取自 `Resolve` 的返回值 —— 不在解析处夹，报告会写出低于 floor 的值，
// 而评分按 floor 计算（实测：floor=0.05 + 规则 0.01 ⇒ 报告 0.01、分数按 0.05）。
func TestConfidenceResolveAppliesFloorAndCap(t *testing.T) {
	cfg, err := Parse(`
[confidence]
enabled = true
default = 1.0
floor = 0.05

[confidence.check]
LOW-001 = 0.01
HIGH-001 = 1.0
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.Confidence.Resolve("LOW-001", "builtin", "attack_surface"); math.Abs(got-0.05) > 1e-9 {
		t.Errorf("低于 floor 的规则值必须被抬到 floor：want 0.05, got %v", got)
	}
	if got := cfg.Confidence.Resolve("HIGH-001", "builtin", "attack_surface"); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("want 1.0, got %v", got)
	}
	// 未命中任何规则 ⇒ default，且同样按 floor/1 夹取。
	if got := cfg.Confidence.Resolve("NOPE-999", "nuclei", "other_domain"); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("want default 1.0, got %v", got)
	}
}

// 关闭时 Resolve 必须恒为 1.0（历史行为，不因 floor 改动而变）。
func TestConfidenceResolveDisabledIsOne(t *testing.T) {
	cfg, err := Parse("[confidence]\nenabled = false\nfloor = 0.30\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.Confidence.Resolve("ANY", "builtin", "attack_surface"); got != 1.0 {
		t.Errorf("disabled ⇒ want 1.0, got %v", got)
	}
}
