package edgefactor

import (
	"math"
	"strings"
	"testing"
)

func baseParams() Params {
	return Params{
		Model:   ModelVector,
		PFloor:  0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8},
	}
}

func TestValidateAcceptsWellFormedParams(t *testing.T) {
	if err := baseParams().Validate([]string{"attack_surface", "operation_trust"}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Params){
		"factor out of range": func(p *Params) { p.Factors["EF-SELINUX"] = 1.5 },
		"zero factor":         func(p *Params) { p.Factors["EF-SELINUX"] = 0 },
		"negative coupling": func(p *Params) {
			p.Coupling = map[string]map[string]float64{"A": {"B": -0.1}}
		},
		"non-positive lambda": func(p *Params) { p.Lambda["attack_surface"] = 0 },
		"pfloor out of range": func(p *Params) { p.PFloor = 1.0 },
		"unknown domain in vector": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"nope": 0.5}
		},
		"vector sum above one": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": 0.7, "operation_trust": 0.7}
		},
		"negative vector component": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": -0.1}
		},
	}
	for name, mutate := range cases {
		p := baseParams()
		mutate(&p)
		if err := p.Validate([]string{"attack_surface", "operation_trust"}); err == nil {
			t.Errorf("%s: Validate must fail", name)
		}
	}
}

func TestValidateRejectsUnknownModel(t *testing.T) {
	p := baseParams()
	p.Model = "oracle"
	if err := p.Validate([]string{"attack_surface"}); err == nil {
		t.Fatal("unknown model must be rejected")
	}
}

func TestHashIsStableAndSensitive(t *testing.T) {
	a := baseParams()
	h1, h2 := a.Hash(), a.Hash()
	if h1 != h2 || len(h1) != 16 || strings.ContainsAny(h1, "ABCDEF") {
		t.Errorf("Hash must be a stable 16-char lowercase hex, got %q/%q", h1, h2)
	}
	b := baseParams()
	b.Factors["EF-SELINUX"] = 0.79
	if a.Hash() == b.Hash() {
		t.Error("Hash must change when parameters change")
	}
}

// 非有限值必须被 Validate 拒绝：NaN 与任何比较均为 false，会绕过所有范围检查。
func TestValidateRejectsNonFiniteValues(t *testing.T) {
	domains := []string{"attack_surface", "operation_trust"}
	// field 必须带上 "edgefactor: " 前缀：错误文本本身就含有 "factor"
	// （包名 edgefactor），只用裸字段名会变成恒真的空断言。
	cases := []struct {
		name   string
		mutate func(*Params)
		field  string // 错误信息必须指明的「前缀 + 字段」
	}{
		{"NaN p_floor", func(p *Params) { p.PFloor = math.NaN() }, "edgefactor: p_floor"},
		{"+Inf p_floor", func(p *Params) { p.PFloor = math.Inf(1) }, "edgefactor: p_floor"},
		{"NaN lambda", func(p *Params) { p.Lambda["attack_surface"] = math.NaN() }, "edgefactor: lambda"},
		{"+Inf lambda", func(p *Params) { p.Lambda["operation_trust"] = math.Inf(1) }, "edgefactor: lambda"},
		{"NaN factor", func(p *Params) { p.Factors["EF-SELINUX"] = math.NaN() }, "edgefactor: factor"},
		{"-Inf factor", func(p *Params) { p.Factors["EF-SELINUX"] = math.Inf(-1) }, "edgefactor: factor"},
		{"NaN vector component", func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": math.NaN()}
		}, "edgefactor: vector"},
		{"+Inf vector component", func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"operation_trust": math.Inf(1)}
		}, "edgefactor: vector"},
		{"NaN coupling", func(p *Params) {
			p.Coupling = map[string]map[string]float64{"EF-A": {"EF-B": math.NaN()}}
		}, "edgefactor: coupling"},
		{"+Inf coupling", func(p *Params) {
			p.Coupling = map[string]map[string]float64{"EF-A": {"EF-B": math.Inf(1)}}
		}, "edgefactor: coupling"},
	}
	for _, tc := range cases {
		p := baseParams()
		tc.mutate(&p)
		err := p.Validate(domains)
		if err == nil {
			t.Errorf("%s: Validate must fail", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: error must name field %q, got %q", tc.name, tc.field, err)
		}
	}
}

// Hash 对非有限参数（绕过 Validate 直接构造）必须返回 16 位哨兵，绝不返回空串。
func TestHashReturnsSentinelForNonFiniteParams(t *testing.T) {
	const sentinel = "0000000000000000"
	p := baseParams()
	p.Factors["EF-SELINUX"] = math.NaN()
	if got := p.Hash(); got != sentinel {
		t.Errorf("Hash with NaN factor must return sentinel %q, got %q (len %d)", sentinel, got, len(got))
	}
	q := baseParams()
	q.PFloor = math.Inf(1)
	if got := q.Hash(); got != sentinel {
		t.Errorf("Hash with +Inf p_floor must return sentinel %q, got %q (len %d)", sentinel, got, len(got))
	}
}

// DefaultDomains 的**顺序**是契约（与 config.ini / WeightConfig 逐位一致），
// 故用字面量期望值锁定；这里刻意不 import internal/model，避免测试跟随实现漂移。
func TestDefaultDomainsOrder(t *testing.T) {
	want := []string{"attack_surface", "business_continuity", "operation_trust", "resilience", "kernel_security"}
	got := DefaultDomains()
	if len(got) != len(want) {
		t.Fatalf("DefaultDomains() has %d domains, want %d: %v", len(got), len(want), got)
	}
	for i, d := range want {
		if got[i] != d {
			t.Errorf("DefaultDomains()[%d] = %q, want %q (full: %v)", i, got[i], d, got)
		}
	}
}

// Hash 必须与 map 插入顺序无关：ParamsHash 是跨进程/跨运行的溯源字段，
// 若指纹随 Go map 迭代序漂移，同一份配置在不同运行中会得到不同指纹。
func TestHashIgnoresMapInsertionOrder(t *testing.T) {
	domains := []string{"attack_surface", "resilience"}
	ids := []string{"EF-A", "EF-B", "EF-C"}

	// build 按给定顺序插入全部 map。
	build := func(orderedIDs, orderedDomains []string) Params {
		p := Params{
			Model:    ModelGraph,
			PFloor:   0.4,
			Lambda:   map[string]float64{},
			Vectors:  map[string]map[string]float64{},
			Coupling: map[string]map[string]float64{},
			Factors:  map[string]float64{},
		}
		for _, d := range orderedDomains {
			p.Lambda[d] = 1.5
		}
		for _, id := range orderedIDs {
			p.Factors[id] = 0.8
			p.Vectors[id] = map[string]float64{}
			for _, d := range orderedDomains {
				p.Vectors[id][d] = 0.25
			}
		}
		for _, from := range orderedIDs {
			for _, to := range orderedIDs {
				if from == to {
					continue
				}
				if p.Coupling[from] == nil {
					p.Coupling[from] = map[string]float64{}
				}
				p.Coupling[from][to] = 0.3
			}
		}
		return p
	}

	reverse := func(in []string) []string {
		out := make([]string, 0, len(in))
		for i := len(in) - 1; i >= 0; i-- {
			out = append(out, in[i])
		}
		return out
	}

	forward := build(ids, domains)
	backward := build(reverse(ids), reverse(domains))

	for _, p := range []Params{forward, backward} {
		if err := p.Validate(domains); err != nil {
			t.Fatalf("fixture must be valid: %v", err)
		}
	}
	if forward.Hash() != backward.Hash() {
		t.Errorf("Hash must not depend on map insertion order: %q vs %q", forward.Hash(), backward.Hash())
	}
}

// chain 必须有严格正的时序窗口：窗口 ≤ 0 会让全部耦合项被静默跳过（配置静默失效）。
func TestValidateRejectsChainWithoutWindow(t *testing.T) {
	domains := []string{"attack_surface", "operation_trust"}
	for name, window := range map[string]int{"zero window": 0, "negative window": -1} {
		p := baseParams()
		p.Model = ModelChain
		p.ChainWindowSeconds = window
		err := p.Validate(domains)
		if err == nil {
			t.Errorf("%s: Validate must fail", name)
			continue
		}
		if !strings.Contains(err.Error(), "edgefactor: chain") {
			t.Errorf("%s: error must name the chain window, got %q", name, err)
		}
	}
}

// legacy / graph 的接受路径：两者都不读 chain_window_seconds，窗口缺省不得误伤。
func TestValidateAcceptsLegacyAndGraph(t *testing.T) {
	domains := []string{"attack_surface", "operation_trust"}
	for _, m := range []ModelID{ModelLegacy, ModelGraph} {
		p := baseParams()
		p.Model = m
		if err := p.Validate(domains); err != nil {
			t.Errorf("model %q must be accepted: %v", m, err)
		}
	}

	// legacy 即便带非正窗口也必须被接受：窗口语义只属于 chain。
	legacy := baseParams()
	legacy.Model = ModelLegacy
	legacy.ChainWindowSeconds = -1
	if err := legacy.Validate(domains); err != nil {
		t.Errorf("legacy must ignore chain_window_seconds, got %v", err)
	}

	// chain 在窗口 > 0 时必须被接受。
	chain := baseParams()
	chain.Model = ModelChain
	chain.ChainWindowSeconds = 300
	if err := chain.Validate(domains); err != nil {
		t.Errorf("chain with a positive window must be accepted: %v", err)
	}
}
