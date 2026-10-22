package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/model"
)

const confidenceIni = `
[confidence]
enabled = true
algorithm = weighted_evidence
accept_by_lower_bound = true
default = 0.85
floor = 0.1

[confidence.check]
as-001 = 0.99
ot-005 = 0.7

[confidence.checkrx]
^rs- = 0.92

[confidence.source]
user = 0.9
cti = 0.5

[confidence.domain]
attack_surface = 0.95
`

func TestParseConfidenceSection(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	cc := cfg.Confidence
	if !cc.Enabled {
		t.Error("enabled must be true")
	}
	if cc.Algorithm != "weighted_evidence" {
		t.Errorf("algorithm = %q", cc.Algorithm)
	}
	if !cc.AcceptByLowerBound {
		t.Error("accept_by_lower_bound must be true")
	}
	if cc.Default != 0.85 || cc.Floor != 0.1 {
		t.Errorf("default/floor = %v/%v", cc.Default, cc.Floor)
	}
	if cc.ByCheckID["as-001"] != 0.99 || cc.ByCheckID["ot-005"] != 0.7 {
		t.Errorf("ByCheckID = %v", cc.ByCheckID)
	}
	if cc.BySource["user"] != 0.9 || cc.BySource["cti"] != 0.5 {
		t.Errorf("BySource = %v", cc.BySource)
	}
	if cc.ByDomain["attack_surface"] != 0.95 {
		t.Errorf("ByDomain = %v", cc.ByDomain)
	}
	if len(cc.CheckPatterns) != 1 {
		t.Fatalf("CheckPatterns = %d, want 1", len(cc.CheckPatterns))
	}
}

// TestConfidenceResolveRulePriority exercises the exact precedence:
// check-id > checkrx > source > domain > default.
func TestConfidenceResolveRulePriority(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	cc := cfg.Confidence

	cases := []struct {
		name                       string
		checkID, sourceKey, domain string
		want                       float64
	}{
		{"exact check wins", "AS-001", "builtin", "attack_surface", 0.99},
		{"regex after exact miss", "RS-777", "builtin", "resilience", 0.92},
		{"source after regex miss", "XY-1", "cti", "operation_trust", 0.5},
		{"domain after source miss", "XY-1", "unknown-key", "attack_surface", 0.95},
		{"default fallback", "XY-1", "unknown-key", "unknown-domain", 0.85},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cc.Resolve(tc.checkID, tc.sourceKey, tc.domain)
			if got != tc.want {
				t.Errorf("Resolve(%q,%q,%q) = %v, want %v", tc.checkID, tc.sourceKey, tc.domain, got, tc.want)
			}
		})
	}
}

// TestConfidenceDisabledReturnsOne: when [confidence] is absent, every
// resolution is 1.0 — the backward-compatible default.
func TestConfidenceDisabledReturnsOne(t *testing.T) {
	cfg, err := Parse("[weights]\nattack_surface = 35\n")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Confidence.Enabled {
		t.Error("confidence must default to disabled")
	}
	if got := cfg.Confidence.Resolve("AS-001", "cti", "attack_surface"); got != 1.0 {
		t.Errorf("disabled resolve = %v, want 1.0", got)
	}
}

// TestConfidenceBadRegexFailsParse: an invalid checkrx pattern must fail the
// whole config load (fail-fast, never silently ignore a typo'd rule).
func TestConfidenceBadRegexFailsParse(t *testing.T) {
	ini := "[confidence]\nenabled = true\n\n[confidence.checkrx]\n[unclosed = 0.5\n"
	if _, err := Parse(ini); err == nil {
		t.Error("invalid regex must fail Parse")
	} else if !strings.Contains(err.Error(), "checkrx") {
		t.Errorf("error should mention checkrx, got %v", err)
	}
}

// TestConfidenceValueClamping was retired by the I-9 fail-fast contract: the
// old case asserted that "cti = 2.0" was clamped to 1.0 and "extension = -1"
// was silently dropped. Both outcomes were the audited defect. The same two
// inputs are now covered (with stricter assertions) by
// TestConfidenceBadValuesFailFast's "source value above one" and "domain value
// negative" cases — no coverage was dropped.

// TestDefaultConfidenceSourcePriors locks the factory prior table (audit I-2):
// enabling [confidence] out of the box must not be a no-op. The factory values
// are the design §3.1 examples adapted to §3.4's "source defaults + config
// override" strategy; they are PRIORS (not experimentally calibrated — see
// design §7.3/I-3). The default stays Enabled=false, so the disabled path is
// untouched (1.0 everywhere).
func TestDefaultConfidenceSourcePriors(t *testing.T) {
	cc := DefaultConfidenceConfig()
	if cc.Enabled {
		t.Fatal("factory default must stay disabled (backward compatibility)")
	}
	// Disabled: every resolution is 1.0 regardless of the prior table.
	for _, tc := range []struct{ checkID, source, domain string }{
		{"AS-001", "builtin", "attack_surface"},
		{"CU-1", "user", "operation_trust"},
		{"NV-1", "adapter", "attack_surface"},
	} {
		if got := cc.Resolve(tc.checkID, tc.source, tc.domain); got != 1.0 {
			t.Errorf("disabled Resolve(%q,%q) = %v, want 1.0", tc.checkID, tc.source, got)
		}
	}

	// Enabled: the shipped prior table takes effect.
	cc.Enabled = true
	cases := []struct {
		checkID, source, domain string
		want                    float64
	}{
		{"AS-001", "builtin", "attack_surface", 1.0},
		{"CU-1", "user", "operation_trust", 0.90},
		{"NV-1", "adapter", "attack_surface", 0.80},
	}
	for _, tc := range cases {
		if got := cc.Resolve(tc.checkID, tc.source, tc.domain); got != tc.want {
			t.Errorf("enabled Resolve(%q,%q) = %v, want %v (factory prior table)", tc.checkID, tc.source, got, tc.want)
		}
	}
}

// TestConfidenceCheckPatternsDeterministic locks the tie-break for overlapping
// [confidence.checkrx] patterns (audit I-5). The parser stores sections in a
// map, so declaration order is not available; we document BYTE-LEXICOGRAPHIC
// KEY ORDER instead ("^as-" sorts before "^as-0"), which is deterministic
// across processes/platforms and needs no parser rewrite. Same INI parsed 300
// times must yield the same rule order and the same first-match resolution.
func TestConfidenceCheckPatternsDeterministic(t *testing.T) {
	const ini = `
[confidence]
enabled = true

[confidence.checkrx]
^as- = 0.9
^as-0 = 0.1
`
	const rounds = 300
	var first []float64
	for i := 0; i < rounds; i++ {
		cfg, err := Parse(ini)
		if err != nil {
			t.Fatalf("round %d: Parse failed: %v", i, err)
		}
		got := make([]float64, len(cfg.Confidence.CheckPatterns))
		for j, pr := range cfg.Confidence.CheckPatterns {
			got[j] = pr.Confidence
		}
		if i == 0 {
			first = got
		} else if !reflect.DeepEqual(first, got) {
			t.Fatalf("round %d: CheckPatterns order = %v, first round = %v — parse is nondeterministic", i, got, first)
		}
		// Both patterns match AS-001; the documented tie-break must pick ^as-.
		if r := cfg.Confidence.Resolve("AS-001", "builtin", "attack_surface"); r != 0.9 {
			t.Fatalf("round %d: Resolve = %v, want 0.9 (^as- first by byte-lexicographic key order)", i, r)
		}
	}
	want := []float64{0.9, 0.1}
	if !reflect.DeepEqual(first, want) {
		t.Errorf("CheckPatterns = %v, want %v (byte-lexicographic key order)", first, want)
	}
}

// TestConfidenceBadValuesFailFast is the I-9 contract: every explicit
// [confidence*] value is validated at load time. A typo must not be silently
// dropped and fall back to the (usually 1.0) default — the error names
// section, key and the offending value so an operator can fix the rule.
func TestConfidenceBadValuesFailFast(t *testing.T) {
	cases := []struct {
		name, ini, section, key, value string
	}{
		{
			"check value non-numeric",
			"[confidence]\nenabled = true\n\n[confidence.check]\nas-001 = abc\n",
			"confidence.check", "as-001", "abc",
		},
		{
			"default non-numeric",
			"[confidence]\ndefault = abc\n",
			"confidence", "default", "abc",
		},
		{
			"floor negative",
			"[confidence]\nfloor = -1\n",
			"confidence", "floor", "-1",
		},
		{
			"floor one is not a clamp minimum",
			"[confidence]\nfloor = 1.0\n",
			"confidence", "floor", "1.0",
		},
		{
			"enabled non-boolean",
			"[confidence]\nenabled = maybe\n",
			"confidence", "enabled", "maybe",
		},
		{
			"accept_by_lower_bound non-boolean",
			"[confidence]\naccept_by_lower_bound = maybe\n",
			"confidence", "accept_by_lower_bound", "maybe",
		},
		{
			"source value above one",
			"[confidence]\nenabled = true\n\n[confidence.source]\ncti = 2.0\n",
			"confidence.source", "cti", "2.0",
		},
		{
			"domain value negative",
			"[confidence.domain]\nattack_surface = -0.5\n",
			"confidence.domain", "attack_surface", "-0.5",
		},
		{
			"checkrx value non-numeric",
			"[confidence.checkrx]\n^rs- = nope\n",
			"confidence.checkrx", "^rs-", "nope",
		},
		{
			"prior_strength non-numeric",
			"[confidence]\nprior_strength = abc\n",
			"confidence", "prior_strength", "abc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.ini)
			if err == nil {
				t.Fatalf("Parse succeeded; want fail-fast error naming [%s] %s = %q", tc.section, tc.key, tc.value)
			}
			for _, want := range []string{tc.section, tc.key, tc.value} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must contain %q (section/key/value)", err, want)
				}
			}
		})
	}
}

// TestConfidenceZeroSentinelClears: 0 is the ONLY allowed sentinel and means
// "unset/clear". For rule tables it removes the entry (including a factory
// prior); scalars accept it as "unset" (Resolve then normalizes default 0 to
// 1.0, exactly like an absent key).
func TestConfidenceZeroSentinelClears(t *testing.T) {
	ini := `
[confidence]
enabled = true
default = 0
floor = 0

[confidence.check]
as-001 = 0

[confidence.checkrx]
^rs- = 0

[confidence.source]
user = 0
adapter = 0.75

[confidence.domain]
attack_surface = 0
`
	cfg, err := Parse(ini)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	cc := cfg.Confidence
	if _, ok := cc.ByCheckID["as-001"]; ok {
		t.Error("check rule with value 0 must be cleared, not installed")
	}
	if len(cc.CheckPatterns) != 0 {
		t.Errorf("checkrx rule with value 0 must be cleared, got %d patterns", len(cc.CheckPatterns))
	}
	if _, ok := cc.BySource["user"]; ok {
		t.Error("source value 0 must clear the factory user prior")
	}
	if got, ok := cc.BySource["adapter"]; !ok || got != 0.75 {
		t.Errorf("adapter override = %v/%v, want 0.75 (non-zero values still override)", got, ok)
	}
	if _, ok := cc.ByDomain["attack_surface"]; ok {
		t.Error("domain value 0 must be cleared, not installed")
	}
	// default=0 / floor=0 are "unset": the factory values (1.0 / 0.05) stay.
	if got := cc.Resolve("XY-1", "unknown-src", "unknown-domain"); got != 1.0 {
		t.Errorf("default=0 resolve = %v, want 1.0 (unset sentinel)", got)
	}
	if cc.Default != 1.0 {
		t.Errorf("default = %v, want factory 1.0 (0 = unset)", cc.Default)
	}
	if cc.Floor != 0.05 {
		t.Errorf("floor = %v, want factory 0.05 (0 = unset)", cc.Floor)
	}
}

// TestConfigResolveChecks: the shared per-result resolver (used by both the
// ssam plugin engine and the legacy DynamicScoringEngine) fills confidences
// from the rule table and preserves upstream-set ones.
func TestConfigResolveChecks(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Source: model.CheckSourceBuiltin}, // exact rule 0.99
		{CheckID: "CU-1", Domain: "operation_trust", Source: model.CheckSourceUser},     // source user 0.9
		{CheckID: "XY-9", Domain: "resilience", Source: model.CheckSourceUser},          // source user 0.9 (no exact/regex hit)
		{CheckID: "NOPE-1", Domain: "resilience", Source: model.CheckSource("unknown-src")}, // no rule → domain miss → default 0.85
		{CheckID: "Y-9", Domain: "attack_surface", Confidence: 0.77},                    // upstream preserved
	}
	cfg.ResolveChecks(checks)

	want := []float64{0.99, 0.9, 0.9, 0.85, 0.77}
	for i := range checks {
		if checks[i].Confidence != want[i] {
			t.Errorf("check %s confidence = %v, want %v", checks[i].CheckID, checks[i].Confidence, want[i])
		}
	}

	// Disabled config is a no-op.
	disabled, _ := Parse("[weights]\nattack_surface = 35\n")
	checks2 := []model.CheckResult{{CheckID: "AS-001", Domain: "attack_surface"}}
	disabled.ResolveChecks(checks2)
	if checks2[0].Confidence != 0 {
		t.Error("disabled config must not touch confidences")
	}
}
