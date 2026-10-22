//go:build assessor

package assessor

import (
	"context"
	"math"
	"sort"
	"testing"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/model"
	prismlib "github.com/chins-xing/prism"
)

// fakeKernelContext is the minimal KernelContext needed by applyCTIOnly: an
// empty DI container (no CTI plugin), so the coefficient falls back to cfg.
type fakeKernelContext struct{}

func (fakeKernelContext) Container() *kernel.Container           { return kernel.NewContainer() }
func (fakeKernelContext) Bus() *kernel.Bus                       { return kernel.NewBus(8) }
func (fakeKernelContext) Extensions() kernel.ModuleExtensions    { return nil }
func (fakeKernelContext) Context() context.Context               { return context.Background() }
func (fakeKernelContext) Config() map[string]string              { return nil }
func (fakeKernelContext) SetConfig(string, string)               {}
func (fakeKernelContext) GetConfigObj() *config.Config           { return nil }
func (fakeKernelContext) SetConfigObj(*config.Config)            {}
func (fakeKernelContext) GetPlugin(string) (kernel.Plugin, bool) { return nil, false }
func (fakeKernelContext) ListPlugins() []kernel.PluginInfo       { return nil }
func (fakeKernelContext) HealthCheck(context.Context) []kernel.PluginHealthStatus {
	return nil
}

// TestApplyCTIOnlyAcceptsByLowerBound covers the kernel post-correction
// acceptance point (audit B-2, internal/assessor/assessor.go): applying a new
// threat coefficient must re-decide acceptability with the shared rule, and
// the sigma/interval must be rescaled alongside the point estimate so the
// lower bound is not stale.
func TestApplyCTIOnlyAcceptsByLowerBound(t *testing.T) {
	newResult := func() *model.AssessmentResult {
		return &model.AssessmentResult{
			FinalScore:   90,
			FinalSigma:   20,
			ScoreLower95: 50.8,
			ScoreUpper95: 129.2,
			Threshold:    60,
			ThreatCoeff:  1.0,
		}
	}

	// cti coefficient 0.8: 90 → 72, lower 50.8 → 40.64 (< threshold 60).
	cfg := config.Default()
	cfg.Threshold = 60
	cfg.ThreatCoeff = 0.8
	cfg.Confidence.AcceptByLowerBound = false
	m := &Module{cfg: cfg, kc: fakeKernelContext{}}

	off := newResult()
	m.applyCTIOnly(off)
	if math.Abs(off.FinalScore-72) > 1e-9 {
		t.Fatalf("FinalScore = %v, want 72 (rescaled by 0.8)", off.FinalScore)
	}
	if math.Abs(off.ScoreLower95-40.64) > 1e-9 {
		t.Errorf("lower95 = %v, want 40.64 (interval must be rescaled with the point estimate)", off.ScoreLower95)
	}
	if math.Abs(off.FinalSigma-16) > 1e-9 {
		t.Errorf("FinalSigma = %v, want 16", off.FinalSigma)
	}
	if !off.Acceptable {
		t.Errorf("accept_by_lower_bound=false must accept on the point estimate (72 ≥ 60)")
	}

	cfgOn := config.Default()
	cfgOn.Threshold = 60
	cfgOn.ThreatCoeff = 0.8
	cfgOn.Confidence.AcceptByLowerBound = true
	mOn := &Module{cfg: cfgOn, kc: fakeKernelContext{}}

	on := newResult()
	mOn.applyCTIOnly(on)
	if on.ScoreLower95 >= on.Threshold {
		t.Fatalf("fixture precondition: lower95 %v must be below threshold %v", on.ScoreLower95, on.Threshold)
	}
	if on.Acceptable {
		t.Errorf("accept_by_lower_bound=true must reject: lower95 %v < threshold %v (point estimate %v)",
			on.ScoreLower95, on.Threshold, on.FinalScore)
	}
}

func TestParseFloatConfig(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"0.5", 0.5},
		{"1.25", 1.25},
		{"not-a-number", 0},
		{"12x", 0},
	}
	for _, tc := range cases {
		if got := parseFloatConfig(tc.in); got != tc.want {
			t.Errorf("parseFloatConfig(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// +Inf parses successfully (ParseFloat allows it) and is > 0 — callers
	// must not blindly apply it; pin the parse behavior here.
	if got := parseFloatConfig("+Inf"); !math.IsInf(got, 1) {
		t.Errorf("parseFloatConfig(+Inf) = %v, want +Inf", got)
	}
}

func TestParseIntConfig(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"7", 7},
		{"-3", -3},
		{"12x", 0},
		{"abc", 0},
	}
	for _, tc := range cases {
		if got := parseIntConfig(tc.in); got != tc.want {
			t.Errorf("parseIntConfig(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFilterAssessmentResult(t *testing.T) {
	// nil → nil
	if got := filterAssessmentResult(nil); got != nil {
		t.Fatalf("filterAssessmentResult(nil) = %v, want nil", got)
	}

	r := &model.AssessmentResult{
		HostID:     "h1",
		Hostname:   "web-01",
		FinalScore: 85.5,
		Acceptable: true,
		Threshold:  80,
		Checks:     []model.CheckResult{{CheckID: "AS-001"}, {CheckID: "OT-001"}, {CheckID: "OT-002"}},
		DomainScores: model.DomainScores{
			AttackSurface:      90,
			BusinessContinuity: 85,
			OperationTrust:     80,
			Resilience:         75,
		},
	}
	out := filterAssessmentResult(r)
	if out["host_id"] != "h1" || out["hostname"] != "web-01" {
		t.Errorf("identity fields wrong: %v", out)
	}
	if out["final_score"] != 85.5 || out["acceptable"] != true || out["threshold"] != 80.0 {
		t.Errorf("score fields wrong: %v", out)
	}
	if out["check_count"] != 3 {
		t.Errorf("check_count = %v, want 3", out["check_count"])
	}
	domains, ok := out["domains"].(map[string]interface{})
	if !ok {
		t.Fatalf("domains not a map: %T", out["domains"])
	}
	if domains["attack_surface"] != 90.0 || domains["operation_trust"] != 80.0 {
		t.Errorf("domain scores wrong: %v", domains)
	}
}

func TestModelCoverage(t *testing.T) {
	// Register a controlled check universe, then restore.
	checks.Register(
		model.CheckItem{ID: "MC-A", Domain: "attack_surface"},
		model.CheckItem{ID: "MC-B", Domain: "operation_trust"},
		model.CheckItem{ID: "MC-C", Domain: "resilience"},
	)
	defer checks.Unregister("MC-A", "MC-B", "MC-C")

	cases := []struct {
		name    string
		results []model.CheckResult
		want    float64
	}{
		{"empty results", nil, 0},
		{"all scored", []model.CheckResult{
			{CheckID: "MC-A", Delta: -5}, {CheckID: "MC-B", Delta: -3}, {CheckID: "MC-C", Delta: -8},
		}, 1.0},
		{"partial coverage", []model.CheckResult{
			{CheckID: "MC-A", Delta: -5},
		}, 1.0 / 3.0},
		{"delta zero not counted", []model.CheckResult{
			{CheckID: "MC-A", Delta: -5}, {CheckID: "MC-B", Delta: 0},
		}, 1.0 / 3.0},
	}
	for _, tc := range cases {
		if got := modelCoverage(tc.results); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: modelCoverage = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestExtractPackagesFromChecks(t *testing.T) {
	results := []model.CheckResult{
		{CheckID: "AS-001", Detail: "OpenSSH server version 9.6 detected on port 22", Name: "SSH config"},
		{CheckID: "OT-005", Detail: "nginx default page exposed", Name: "Web server"},
		{CheckID: "BC-001", Detail: "MySQL 8.0 running", Name: "Database"},
		{CheckID: "RS-001", Detail: "Docker daemon socket exposure", Name: "Container"},
	}
	pkgs := (&Module{}).extractPackagesFromChecks(results)
	sort.Strings(pkgs) // function returns map-iteration order; normalize before compare

	want := []string{"docker", "mysql", "mariadb", "nginx", "openssh", "ssh"}
	sort.Strings(want)

	if len(pkgs) != len(want) {
		t.Fatalf("extractPackagesFromChecks returned %v, want %v", pkgs, want)
	}
	for i := range want {
		if pkgs[i] != want[i] {
			t.Errorf("packages = %v, want %v", pkgs, want)
			break
		}
	}

	// Empty input → empty output, no panic.
	if got := (&Module{}).extractPackagesFromChecks(nil); len(got) != 0 {
		t.Errorf("empty input must yield empty packages, got %v", got)
	}
}

func TestFilterIncoming(t *testing.T) {
	edges := []prismlib.EdgeState{
		{Source: "a", Target: "self"},
		{Source: "self", Target: "b"},
		{Source: "c", Target: "self"},
		{Source: "self", Target: "d"},
	}
	in := filterIncoming("self", edges)
	if len(in) != 2 {
		t.Fatalf("filterIncoming len = %d, want 2", len(in))
	}
	for _, e := range in {
		if e.Target != "self" {
			t.Errorf("incoming edge target = %q, want self", e.Target)
		}
	}
}
