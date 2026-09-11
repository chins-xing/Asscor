package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// vectorDistinct is a five-value vector with pairwise distinct components in
// canonical domain order (attack_surface, business_continuity, operation_trust,
// resilience, kernel_security). Distinct values are what make a reordering of
// the domain mapping detectable — a vector with repeated components would hide
// e.g. a swap of the first and last domain.
const vectorDistinct = "0.05,0.10,0.15,0.20,0.25"

// vectorDistinctValues are the literal components encoded in vectorDistinct,
// in canonical domain order. Literals (not i*0.05) so the comparison stays
// exact and free of float artifacts.
var vectorDistinctValues = [5]float64{0.05, 0.10, 0.15, 0.20, 0.25}

func vectorKeys(vec map[string]float64) []string {
	keys := make([]string, 0, len(vec))
	for k := range vec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func assertCanonicalVector(t *testing.T, vec map[string]float64) {
	t.Helper()
	if len(vec) != 5 {
		t.Errorf("vector must cover exactly 5 domains, got %d: %v", len(vec), vec)
	}
	for i, domain := range edgeFactorDomainOrder {
		want := vectorDistinctValues[i]
		if got := vec[domain]; got != want {
			t.Errorf("vector[%d] (%s) = %v, want %v — domain order is broken", i, domain, got, want)
		}
	}
}

func TestParseEdgeFactorModelAbsentMeansLegacy(t *testing.T) {
	cfg, present, err := ParseEdgeFactorModel(map[string]map[string]string{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if present {
		t.Error("present must be false when the section is absent")
	}
	if cfg.Model != "" {
		t.Errorf("model = %q, want empty", cfg.Model)
	}
}

// TestParseEdgeFactorModelRequiresPFloorWhenSectionPresent 钉住主控 I3 的最小裁定：
// `[edge_factors.model]` 段**存在**却缺 `p_floor` 时，装载层必须直接报错。
//
// 为什么这不是"多一条校验"而是必须的：`p_floor` 的零值 0 不在 `(0,1)` 内，`edgefactor.Validate`
// 会以同样的理由拒绝它 —— 但那一步发生在**装配期**，而装配失败的后果是"打印一条 Warn 后回落
// legacy"。于是配置里明明写着 `model = graph`，内核却按历史乘性评分：**假溯源**，
// 且操作者只会在日志里看到一行 Warn。装载层是唯一能把这个错误变成"启动即失败"的地方
// （内核是否把装配失败升级为启动失败是另一件事，见 spec §10 的独立决策）。
//
// 反向对照：段缺席仍是合法的（`present=false` ⇒ 调用方走 legacy），不得误报。
func TestParseEdgeFactorModelRequiresPFloorWhenSectionPresent(t *testing.T) {
	cases := []map[string]string{
		{"model": "graph"},
		{"model": "graph", "lambda.attack_surface": "1.5"},
		{"model": "vector", "lambda.attack_surface": "1.5", "vector.EF-A": vectorDistinct},
		{"model": "legacy"},
	}
	for i, kv := range cases {
		_, present, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv})
		if err == nil {
			t.Errorf("case %d：段存在但缺 p_floor 必须报错：%v（present=%v）", i, kv, present)
			continue
		}
		if !strings.Contains(err.Error(), "p_floor") {
			t.Errorf("case %d：错误必须点名 p_floor：%v", i, err)
		}
	}

	// 有 p_floor 的正常配置不受影响。
	if _, present, err := ParseEdgeFactorModel(map[string]map[string]string{
		"edge_factors.model": {"model": "legacy", "p_floor": "0.2"},
	}); err != nil || !present {
		t.Errorf("带 p_floor 的合法段不应报错：present=%v err=%v", present, err)
	}
	// 段缺席仍然合法（调用方据此走 legacy）。
	cfg, present, err := ParseEdgeFactorModel(map[string]map[string]string{})
	if err != nil || present || cfg.Model != "" {
		t.Errorf("段缺席必须保持 (zero,false,nil)：present=%v err=%v cfg=%+v", present, err, cfg)
	}
	// 整条配置装载路径（config.Parse）同样必须报错（装载层才是操作者能看见的地方）。
	if _, err := Parse("[edge_factors.model]\nmodel = graph\nlambda.attack_surface = 1.5\n"); err == nil {
		t.Error("config.Parse 必须把『段存在但缺 p_floor』当成本错")
	}
}

func TestParseEdgeFactorModelReadsAllFields(t *testing.T) {
	sections := map[string]map[string]string{
		"edge_factors.model": {
			"model":                           "graph",
			"p_floor":                         "0.4",
			"lambda.attack_surface":           "1.5",
			"vector.EF-SELINUX":               vectorDistinct,
			"coupling.EF-SELINUX.EF-APPARMOR": "0.35",
			"chain.window_seconds":            "300",
			"trigger.EF-SELINUX":              "OT-005",
		},
	}
	cfg, present, err := ParseEdgeFactorModel(sections)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !present || cfg.Model != "graph" || cfg.PFloor != 0.4 {
		t.Fatalf("unexpected: present=%v cfg=%+v", present, cfg)
	}
	if cfg.Lambda["attack_surface"] != 1.5 {
		t.Errorf("lambda = %v", cfg.Lambda)
	}
	// Domain order (design §4 rule 4): attack_surface, business_continuity,
	// operation_trust, resilience, kernel_security. All five positions are
	// pinned with distinct values, so swapping any two domains (including the
	// outermost attack_surface/kernel_security pair) fails.
	assertCanonicalVector(t, cfg.Vectors["EF-SELINUX"])
	if cfg.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
		t.Errorf("coupling = %v", cfg.Coupling)
	}
	if cfg.ChainWindowSeconds != 300 || cfg.TriggerMap["EF-SELINUX"] != "OT-005" {
		t.Errorf("window/trigger wrong: %+v", cfg)
	}
}

func TestParseEdgeFactorModelRejectsBadValues(t *testing.T) {
	cases := []map[string]string{
		{"model": "oracle"},
		{"model": "graph", "p_floor": "1.5"},
		{"model": "graph", "p_floor": "0.5", "lambda.attack_surface": "0"},
		{"model": "graph", "p_floor": "0.5", "vector.EF-A": "0.1,abc"},                 // 个数不足
		{"model": "graph", "p_floor": "0.5", "vector.EF-A": "0.1,abc,0.1,0.1,0.1"},     // 个数正确但含非数字
		{"model": "graph", "p_floor": "0.5", "vector.EF-A": "0.1,-0.2,0.1,0.1,0.1"},    // 负分量
		{"model": "graph", "p_floor": "0.5", "vector.EF-A": "0.1,0.1,0.1,0.1,0.1,0.1"}, // 个数过多
		{"model": "graph", "p_floor": "0.5", "coupling.A.B": "-1"},
		{"model": "chain", "p_floor": "0.5"}, // chain 缺窗口
		{"model": "graph", "p_floor": "0.5", "p_floor_extra": "x"},
	}
	for i, kv := range cases {
		if _, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv}); err == nil {
			t.Errorf("case %d must fail: %v", i, kv)
		}
	}
}

// TestParseEdgeFactorModelRejectsNonFiniteValues pins the fail-fast rule for
// non-finite numbers: strconv.ParseFloat accepts "NaN"/"Inf"/"-Inf", and a
// non-finite value would silently poison the penalty formula (a NaN penalty is
// neither bounded nor monotone, defeating P1/P2 of the design). Every numeric
// key — p_floor, lambda.*, each of the five vector components, coupling.* —
// must reject it, and the error must name the key and echo the raw value.
func TestParseEdgeFactorModelRejectsNonFiniteValues(t *testing.T) {
	nonFinite := []string{"NaN", "nan", "Inf", "+Inf", "-Inf"}

	vectorOf := func(parts ...string) string { return strings.Join(parts, ",") }

	for _, bad := range nonFinite {
		cases := []struct {
			name string
			key  string // key whose name must appear in the error
			kv   map[string]string
		}{
			{
				name: "p_floor",
				key:  "p_floor",
				kv:   map[string]string{"model": "graph", "p_floor": bad},
			},
			{
				name: "lambda",
				key:  "lambda.attack_surface",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "lambda.attack_surface": bad},
			},
			{
				name: "vector_component_0",
				key:  "vector.EF-A[0]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf(bad, "0.1", "0.1", "0.1", "0.1")},
			},
			{
				name: "vector_component_1",
				key:  "vector.EF-A[1]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", bad, "0.1", "0.1", "0.1")},
			},
			{
				name: "vector_component_2",
				key:  "vector.EF-A[2]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", bad, "0.1", "0.1")},
			},
			{
				name: "vector_component_3",
				key:  "vector.EF-A[3]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", "0.1", bad, "0.1")},
			},
			{
				name: "vector_component_4",
				key:  "vector.EF-A[4]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", "0.1", "0.1", bad)},
			},
			{
				name: "coupling",
				key:  "coupling.A.B",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "coupling.A.B": bad},
			},
		}
		for _, tc := range cases {
			_, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": tc.kv})
			if err == nil {
				t.Errorf("%s=%q must be rejected (%s)", tc.name, bad, tc.name)
				continue
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("%s=%q: error %q must name the key %q", tc.name, bad, err.Error(), tc.key)
			}
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("%s=%q: error %q must echo the raw value", tc.name, bad, err.Error())
			}
		}
	}
}

// TestParseEdgeFactorModelNormalizesIdentityToUpper pins Important#1: config
// sections are lower-cased by parseSections, while the synthesis layer looks
// vectors/couplings/triggers up by the engine's canonical UPPERCASE FactorID.
// Without normalization a configured vector silently degrades to the
// all-domains fallback (and Validate cannot catch it, since it only checks
// vectors that were declared). Factor ids — and the trigger check id — are
// therefore stored upper-cased; domain names stay lower-case.
func TestParseEdgeFactorModelNormalizesIdentityToUpper(t *testing.T) {
	for _, spelling := range []string{"EF-SELINUX", "ef-selinux", "Ef-Selinux"} {
		kv := map[string]string{
			"model":                                 "graph",
			"p_floor":                               "0.5",
			"vector." + spelling:                    vectorDistinct,
			"coupling." + spelling + ".ef-apparmor": "0.35",
			"trigger." + spelling:                   "ot-005",
		}
		cfg, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv})
		if err != nil {
			t.Fatalf("spelling %q: %v", spelling, err)
		}
		if len(cfg.Vectors) != 1 {
			t.Errorf("spelling %q: factor ids must collapse to one canonical key, got %v",
				spelling, vectorKeys2(cfg.Vectors))
		}
		vec, ok := cfg.Vectors["EF-SELINUX"]
		if !ok {
			t.Fatalf("spelling %q: Vectors keys = %v, want canonical \"EF-SELINUX\"",
				spelling, vectorKeys2(cfg.Vectors))
		}
		assertCanonicalVector(t, vec)
		if _, ok := vec["attack_surface"]; !ok {
			t.Errorf("spelling %q: domain keys must stay lower-case, got %v", spelling, vectorKeys(vec))
		}
		if cfg.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
			t.Errorf("spelling %q: coupling keys must be canonical, got %v", spelling, cfg.Coupling)
		}
		if len(cfg.Coupling) != 1 || len(cfg.Coupling["EF-SELINUX"]) != 1 {
			t.Errorf("spelling %q: coupling must collapse to one canonical pair, got %v", spelling, cfg.Coupling)
		}
		if cfg.TriggerMap["EF-SELINUX"] != "OT-005" {
			t.Errorf("spelling %q: trigger key/value must be canonical, got %v", spelling, cfg.TriggerMap)
		}
		if len(cfg.TriggerMap) != 1 {
			t.Errorf("spelling %q: trigger map must hold one canonical key, got %v", spelling, cfg.TriggerMap)
		}
	}

	// 错误串回显用户原始写法，方便定位配置行。
	_, _, err := ParseEdgeFactorModel(map[string]map[string]string{
		"edge_factors.model": {
			"model":       "graph",
			"p_floor":     "0.5",
			"vector.ef-a": "0.1,x,0.1,0.1,0.1",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "vector.ef-a") {
		t.Errorf("error must echo the user's spelling, got %v", err)
	}
}

// TestParseEdgeFactorModelKeysMatchEngineFactorIDs pins the end-to-end key
// contract through the real config text: whatever case the operator types,
// Vectors/Coupling/TriggerMap are keyed by the canonical factor id spelling
// used by the engine (ssam-lib defaults.go / adapter.go, all upper-case).
func TestParseEdgeFactorModelKeysMatchEngineFactorIDs(t *testing.T) {
	engineIDs := []string{
		"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR",
		"EF-NO-SIEM", "EF-NO-IDS", "EF-3FA",
	}
	var b strings.Builder
	b.WriteString("[edge_factors.model]\nmodel = graph\np_floor = 0.5\n")
	for _, id := range engineIDs {
		fmt.Fprintf(&b, "vector.%s = %s\n", strings.ToLower(id), vectorDistinct)
		fmt.Fprintf(&b, "coupling.%s.ef-apparmor = 0.1\n", strings.ToLower(id))
		fmt.Fprintf(&b, "trigger.%s = ot-005\n", strings.ToLower(id))
	}
	cfg, err := Parse(b.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, id := range engineIDs {
		if _, ok := cfg.EdgeFactorModel.Vectors[id]; !ok {
			t.Errorf("Vectors must be keyed by engine factor id %q, got %v",
				id, vectorKeys2(cfg.EdgeFactorModel.Vectors))
		}
		if _, ok := cfg.EdgeFactorModel.TriggerMap[id]; !ok {
			t.Errorf("TriggerMap must be keyed by engine factor id %q, got %v",
				id, cfg.EdgeFactorModel.TriggerMap)
		}
	}
	if len(cfg.EdgeFactorModel.Vectors) != len(engineIDs) {
		t.Errorf("Vectors has %d keys, want %d: %v",
			len(cfg.EdgeFactorModel.Vectors), len(engineIDs), vectorKeys2(cfg.EdgeFactorModel.Vectors))
	}
}

// TestParseEdgeFactorModelRejectsEmptyNames pins the Minor fix: an empty
// trailing name ("vector.", "lambda.", "trigger.") would create an empty key —
// an empty factor can slip past edgefactor.Validate (empty name + full 5-domain
// coverage) and an empty trigger can never fire. An empty trigger *value* is
// the same class of silent-degradation bug (no check id can ever match), so it
// is rejected too.
func TestParseEdgeFactorModelRejectsEmptyNames(t *testing.T) {
	cases := []struct {
		name string
		kv   map[string]string
	}{
		{"empty vector name", map[string]string{"model": "graph", "p_floor": "0.5", "vector.": vectorDistinct}},
		{"empty lambda name", map[string]string{"model": "graph", "p_floor": "0.5", "lambda.": "1.5"}},
		{"empty trigger name", map[string]string{"model": "graph", "p_floor": "0.5", "trigger.": "OT-005"}},
		{"empty trigger value", map[string]string{"model": "graph", "p_floor": "0.5", "trigger.EF-A": ""}},
		{"whitespace trigger value", map[string]string{"model": "graph", "p_floor": "0.5", "trigger.EF-A": "   "}},
		{"coupling empty from", map[string]string{"model": "graph", "p_floor": "0.5", "coupling..B": "0.1"}},
		{"coupling empty to", map[string]string{"model": "graph", "p_floor": "0.5", "coupling.A.": "0.1"}},
		{"coupling no separator", map[string]string{"model": "graph", "p_floor": "0.5", "coupling.AB": "0.1"}},
	}
	for _, tc := range cases {
		if _, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": tc.kv}); err == nil {
			t.Errorf("%s must fail: %v", tc.name, tc.kv)
		}
	}
}

// TestParseEdgeFactorModelChainWindowBoundaries covers the missing boundary
// cases: a valid chain configuration is accepted, and a broken window value
// (zero, negative, non-integer, non-finite, empty) is rejected regardless of
// the selected model.
func TestParseEdgeFactorModelChainWindowBoundaries(t *testing.T) {
	cfg, present, err := ParseEdgeFactorModel(map[string]map[string]string{
		"edge_factors.model": {"model": "chain", "p_floor": "0.5", "chain.window_seconds": "300"},
	})
	if err != nil || !present {
		t.Fatalf("valid chain config must parse: present=%v err=%v", present, err)
	}
	if cfg.ChainWindowSeconds != 300 {
		t.Errorf("window = %d, want 300", cfg.ChainWindowSeconds)
	}

	for _, bad := range []string{"0", "-5", "-1", "3.5", "abc", "NaN", "Inf", "300s", ""} {
		for _, model := range []string{"chain", "graph"} {
			kv := map[string]string{"model": model, "p_floor": "0.5", "chain.window_seconds": bad}
			if _, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv}); err == nil {
				t.Errorf("chain.window_seconds=%q with model=%s must fail", bad, model)
			}
		}
	}
}

// TestParsePopulatesEdgeFactorModelSection pins the wiring into Config and the
// canonical (upper-case) key face after a real config.ini parse: the section
// lands in Config.EdgeFactorModel, factor ids are canonical, and an absent
// section leaves the zero value (Model == "" ⇒ the caller keeps legacy).
func TestParsePopulatesEdgeFactorModelSection(t *testing.T) {
	content := `
[edge_factors.model]
model = graph
p_floor = 0.4
lambda.attack_surface = 1.5
vector.ef-selinux = 0.05,0.10,0.15,0.20,0.25
coupling.ef-selinux.ef-apparmor = 0.35
trigger.ef-selinux = ot-005
`
	cfg, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.EdgeFactorModel.Model != "graph" {
		t.Fatalf("model = %q, want graph", cfg.EdgeFactorModel.Model)
	}
	if cfg.EdgeFactorModel.PFloor != 0.4 {
		t.Errorf("p_floor = %v, want 0.4", cfg.EdgeFactorModel.PFloor)
	}
	assertCanonicalVector(t, cfg.EdgeFactorModel.Vectors["EF-SELINUX"])
	if len(cfg.EdgeFactorModel.Vectors) != 1 {
		t.Errorf("Vectors keys must be canonical, got %v", vectorKeys2(cfg.EdgeFactorModel.Vectors))
	}
	if cfg.EdgeFactorModel.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
		t.Errorf("coupling keys must be canonical, got %v", cfg.EdgeFactorModel.Coupling)
	}
	if cfg.EdgeFactorModel.TriggerMap["EF-SELINUX"] != "OT-005" {
		t.Errorf("trigger map keys/value must be canonical, got %v", cfg.EdgeFactorModel.TriggerMap)
	}

	absent, err := Parse("[weights]\nattack_surface = 35\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if absent.EdgeFactorModel.Model != "" {
		t.Errorf("absent section must leave the zero value, got %+v", absent.EdgeFactorModel)
	}
}

// TestParseRejectsBadEdgeFactorModelSection pins that Parse propagates the
// parse error instead of silently ignoring a misconfigured section.
func TestParseRejectsBadEdgeFactorModelSection(t *testing.T) {
	if _, err := Parse("[edge_factors.model]\nmodel = oracle\n"); err == nil {
		t.Error("Parse must fail on an unknown edge factor model")
	}
}

// TestParseRejectsEdgeFactorModelKeysInLegacySection pins Important#2: those
// keys are only meaningful inside [edge_factors.model]. Written into the legacy
// [edge_factors] section they used to be dropped silently (the loop only acts
// on keys that parse as floats), so the operator believed graph/chain was
// active while the kernel still scored M0.
func TestParseRejectsEdgeFactorModelKeysInLegacySection(t *testing.T) {
	keys := []string{
		"model", "p_floor",
		"lambda.attack_surface", "vector.EF-A", "coupling.A.B",
		"chain.window_seconds", "trigger.EF-A",
	}
	for _, k := range keys {
		_, err := Parse("[edge_factors]\n" + k + " = 1\n")
		if err == nil {
			t.Errorf("[edge_factors] %s must be rejected (it is silently ignored otherwise)", k)
			continue
		}
		if !strings.Contains(err.Error(), "[edge_factors.model]") {
			t.Errorf("[edge_factors] %s: error %q must point the operator at the [edge_factors.model] section", k, err.Error())
		}
	}

	// 合法的 [edge_factors] 段不受影响（无假阳性）。
	ok, err := Parse("[edge_factors]\ntwo_factor_failure = 0.70\nsync_cookie_disabled = 0.75\nno_ids = 0.88\n")
	if err != nil {
		t.Fatalf("legacy [edge_factors] section must still parse: %v", err)
	}
	if ok.EdgeFactors.TwoFactorFailure != 0.70 || ok.EdgeFactors.NoIDS != 0.88 {
		t.Errorf("legacy edge factors not applied: %+v", ok.EdgeFactors)
	}
	if ok.EdgeFactorModel.Model != "" {
		t.Errorf("[edge_factors] alone must not populate the model config, got %+v", ok.EdgeFactorModel)
	}
}

// vectorKeys2 lists the factor ids of a Vectors map (test helper).
func vectorKeys2(m map[string]map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
