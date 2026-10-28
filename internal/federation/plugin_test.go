package federation

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/model"
	"github.com/chins-xing/asscor/internal/topology"
)

// --- test doubles -----------------------------------------------------------

type fakeKC struct {
	cfg       *config.Config
	container *kernel.Container
	ctx       context.Context
	bus       *kernel.Bus
	ext       kernel.ModuleExtensions
}

func newFakeKC(cfg *config.Config) *fakeKC {
	return &fakeKC{
		cfg:       cfg,
		container: kernel.NewContainer(),
		ctx:       context.Background(),
		bus:       kernel.NewBus(16),
		ext:       kernel.NewExtensionRegistry(),
	}
}

func (f *fakeKC) Container() *kernel.Container                { return f.container }
func (f *fakeKC) Bus() *kernel.Bus                            { return f.bus }
func (f *fakeKC) Extensions() kernel.ModuleExtensions         { return f.ext }
func (f *fakeKC) Context() context.Context                    { return f.ctx }
func (f *fakeKC) Config() map[string]string                   { return map[string]string{} }
func (f *fakeKC) SetConfig(key, value string)                 {}
func (f *fakeKC) GetConfigObj() *config.Config                { return f.cfg }
func (f *fakeKC) SetConfigObj(c *config.Config)               { f.cfg = c }
func (f *fakeKC) GetPlugin(name string) (kernel.Plugin, bool) { return nil, false }
func (f *fakeKC) ListPlugins() []kernel.PluginInfo            { return nil }
func (f *fakeKC) HealthCheck(ctx context.Context) []kernel.PluginHealthStatus {
	return nil
}

type fakeAssessor struct {
	scores map[string]float64
}

func (f *fakeAssessor) Evaluate(hostID string) *model.AssessmentResult {
	return f.GetResult(hostID)
}

func (f *fakeAssessor) EvaluateFromResults(hostID, hostname string, checks []model.CheckResult) *model.AssessmentResult {
	return f.GetResult(hostID)
}

func (f *fakeAssessor) GetResult(hostID string) *model.AssessmentResult {
	score, ok := f.scores[hostID]
	if !ok {
		return nil
	}
	return &model.AssessmentResult{HostID: hostID, FinalScore: score}
}

func (f *fakeAssessor) ReloadConfig(cfg *config.Config) {}

// configAdapter mimics the srdwrapper adapter chain: kc.GetConfigObj() may be
// an adapter whose GetConfigObj() returns the real *config.Config.
type configAdapter struct{ cfg *config.Config }

func (a *configAdapter) GetConfigObj() interface{} { return a.cfg }
func (a *configAdapter) Get(key string) string     { return a.cfg.Get(key) }

func testConfig(adapterConfig map[string]string) *config.Config {
	c := config.Default()
	c.AdapterConfig = adapterConfig
	return c
}

// --- role / config parsing --------------------------------------------------

func TestParseRole(t *testing.T) {
	cases := map[string]Role{
		"":         RoleOff,
		"off":      RoleOff,
		" OFF ":    RoleOff,
		"none":     RoleOff,
		"disabled": RoleOff,
		"master":   RoleMaster,
		"Master":   RoleMaster,
		"node":     RoleNode,
		" NODE ":   RoleNode,
	}
	for raw, want := range cases {
		got, err := ParseRole(raw)
		if err != nil {
			t.Fatalf("ParseRole(%q) unexpected error: %v", raw, err)
		}
		if got != want {
			t.Errorf("ParseRole(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseRoleInvalid(t *testing.T) {
	for _, raw := range []string{"master node", "server", "true", "1", "noda"} {
		if _, err := ParseRole(raw); err == nil {
			t.Errorf("ParseRole(%q) expected error for invalid role", raw)
		}
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("ParseConfig(nil): %v", err)
	}
	if cfg.Role != RoleOff {
		t.Errorf("default role = %q, want off", cfg.Role)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("default listen_addr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.ReportIntervalSec() != DefaultReportIntervalSec {
		t.Errorf("default interval = %d, want %d", cfg.ReportIntervalSec(), DefaultReportIntervalSec)
	}
}

func TestParseConfigNode(t *testing.T) {
	values := map[string]string{
		"federation.role":                "node",
		"federation.node_id":             "nk1",
		"federation.master_url":          "http://192.168.30.50:5099",
		"federation.report_interval_sec": "15",
		"federation.token":               "demo-token",
	}
	cfg, err := ParseConfig(func(k string) string { return values[k] })
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Role != RoleNode || cfg.NodeID != "nk1" || cfg.MasterURL != values["federation.master_url"] {
		t.Errorf("unexpected node config: %+v", cfg)
	}
	if cfg.ReportInterval != 15*time.Second {
		t.Errorf("interval = %s, want 15s", cfg.ReportInterval)
	}
	if cfg.Token != "demo-token" {
		t.Errorf("token = %q", cfg.Token)
	}
}

func TestParseConfigInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"bad role":       {"federation.role": "chief"},
		"bad interval":   {"federation.role": "node", "federation.master_url": "http://m:5099", "federation.report_interval_sec": "0"},
		"nan interval":   {"federation.role": "node", "federation.master_url": "http://m:5099", "federation.report_interval_sec": "abc"},
		"node no master": {"federation.role": "node", "federation.node_id": "nk1"},
	}
	for name, values := range cases {
		if _, err := ParseConfig(func(k string) string { return values[k] }); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestConfigSectionExposed verifies the [federation] section survives
// config.Parse into AdapterConfig (the adapterSections whitelist) — otherwise
// the plugin would silently read an empty section.
func TestConfigSectionExposed(t *testing.T) {
	c, err := config.Parse(`[federation]
role = node
node_id = nk1
master_url = http://192.168.30.50:5099
report_interval_sec = 30
token = demo
`)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	if got := c.Get("federation.role"); got != "node" {
		t.Fatalf("Get(federation.role) = %q, want node", got)
	}
	cfg, err := ParseConfig(c.Get)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Role != RoleNode || cfg.NodeID != "nk1" {
		t.Errorf("parsed config = %+v", cfg)
	}
}

func TestUnwrapConfigAdapterChain(t *testing.T) {
	base := testConfig(map[string]string{"srd.layered_graph": "true"})
	adapter := &configAdapter{cfg: base}

	got := unwrapConfig(adapter)
	c, ok := got.(*config.Config)
	if !ok || c != base {
		t.Fatalf("unwrapConfig returned %T (%v), want the base *config.Config", got, got)
	}
	// A plain config object is returned as-is.
	if got := unwrapConfig(base); got != interface{}(base) {
		t.Errorf("unwrapConfig(*config.Config) changed the object")
	}
}

// --- plugin lifecycle -------------------------------------------------------

func TestPluginInitInvalidRoleDisablesWithoutError(t *testing.T) {
	kc := newFakeKC(testConfig(map[string]string{"federation.role": "chief"}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init must not fail on a bad demo config (bootstrap must not block): %v", err)
	}
	st := p.FederationStatus()
	if st.Role != RoleOff {
		t.Errorf("role = %q, want off", st.Role)
	}
	if st.ConfigError == "" || !strings.Contains(st.ConfigError, "chief") {
		t.Errorf("ConfigError = %q, want the invalid role echoed", st.ConfigError)
	}
	if got := p.State(); got != kernel.PluginInitialized {
		t.Errorf("state = %v, want initialized", got)
	}
}

func TestPluginStartStopOff(t *testing.T) {
	kc := newFakeKC(testConfig(nil))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := p.State(); got != kernel.PluginStarted {
		t.Errorf("state = %v, want started", got)
	}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := p.State(); got != kernel.PluginStopped {
		t.Errorf("state = %v, want stopped", got)
	}
}

func TestPluginMasterStartBindsAndStatus(t *testing.T) {
	kc := newFakeKC(testConfig(map[string]string{
		"federation.role":        "master",
		"federation.listen_addr": "127.0.0.1:0",
	}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = p.Stop(context.Background()) }()

	st := p.FederationStatus()
	if st.Role != RoleMaster {
		t.Fatalf("role = %q, want master", st.Role)
	}
	if st.ListenAddr == "" || strings.HasSuffix(st.ListenAddr, ":0") {
		t.Errorf("ListenAddr = %q, want the bound address", st.ListenAddr)
	}
	if !st.Running {
		t.Error("Running = false, want true after Start")
	}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}

// TestPluginMasterListenFailureDegrades pins the "a busy :5099 must not take
// the kernel down" contract: Start returns nil, the plugin stays Started, the
// failure is visible via Status.ListenError and HealthCheck, and Stop is safe
// with a nil server.
func TestPluginMasterListenFailureDegrades(t *testing.T) {
	// Occupy a port first, then ask the plugin to listen on the same address.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	kc := newFakeKC(testConfig(map[string]string{
		"federation.role":        "master",
		"federation.listen_addr": addr,
	}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start must degrade instead of failing the kernel: %v", err)
	}
	if got := p.State(); got != kernel.PluginStarted {
		t.Errorf("state = %v, want started (degraded)", got)
	}

	st := p.FederationStatus()
	if !st.Running {
		t.Error("Running = false, want true (degraded master is still started)")
	}
	if st.ListenError == "" {
		t.Fatalf("ListenError is empty, want the bind failure surfaced (status: %+v)", st)
	}
	if !strings.Contains(st.ListenError, addr) {
		t.Errorf("ListenError = %q, want it to mention the occupied address %s", st.ListenError, addr)
	}

	health := p.HealthCheck(context.Background())
	if health == nil || !strings.Contains(health.Error(), "degraded") {
		t.Errorf("HealthCheck = %v, want a degraded-master error", health)
	}

	if err := p.Stop(context.Background()); err != nil {
		t.Errorf("Stop with a nil server: %v", err)
	}
	if got := p.State(); got != kernel.PluginStopped {
		t.Errorf("state = %v, want stopped", got)
	}
}

func TestPluginPriorityAndInfo(t *testing.T) {
	p := New()
	info := p.Info()
	if info.Name != "federation" {
		t.Errorf("plugin name = %q", info.Name)
	}
	if info.Version != PluginVersion || PluginVersion != "0.1.0" {
		t.Errorf("plugin version = %q, want 0.1.0", info.Version)
	}
	if p.Priority() <= 0 {
		t.Errorf("priority = %d, want > 0", p.Priority())
	}
	if len(p.Dependencies()) != 0 {
		t.Errorf("unexpected dependencies: %v", p.Dependencies())
	}
}

// --- snapshot ---------------------------------------------------------------

func TestSnapshotAggregatesZones(t *testing.T) {
	topology.ResetForTesting()
	t.Cleanup(topology.ResetForTesting)
	topology.RecordTopologyDetailed("dma-1", []string{"10.1.0.0/24"}, "dma")
	topology.RecordTopologyDetailed("dma-2", []string{"10.1.0.0/24"}, "dma")
	topology.RecordTopologyDetailed("web-1", []string{"10.2.0.0/24"}, "web")

	kc := newFakeKC(testConfig(map[string]string{
		"federation.role":       "node",
		"federation.node_id":    "nk1",
		"federation.master_url": "http://192.168.30.50:5099",
		"prism.debt_alpha":      "1.2",
		"srd.layered_graph":     "true",
	}))
	kc.container.Bind((*kernel.AssessorInterface)(nil), &fakeAssessor{scores: map[string]float64{
		"dma-1": 80,
		"dma-2": 90,
		"web-1": 70,
	}})

	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rep := p.Snapshot()

	if rep.NodeID != "nk1" {
		t.Errorf("node_id = %q", rep.NodeID)
	}
	if rep.Hosts != 3 {
		t.Errorf("hosts = %d, want 3", rep.Hosts)
	}
	dma, ok := rep.Zones["dma"]
	if !ok {
		t.Fatalf("missing dma zone: %v", rep.Zones)
	}
	if dma.Hosts != 2 || dma.Scored != 2 {
		t.Errorf("dma = %+v, want 2 hosts / 2 scored", dma)
	}
	if dma.AvgSSAM != 85 {
		t.Errorf("dma avg = %v, want 85", dma.AvgSSAM)
	}
	want := (85.0*2 + 70.0) / 3.0
	if rep.AvgSSAM != want {
		t.Errorf("overall avg = %v, want %v", rep.AvgSSAM, want)
	}
	if rep.ConfigHash == "" {
		t.Error("config_hash is empty")
	}
	if rep.Params["prism.debt_alpha"] != "1.2" {
		t.Errorf("params = %v", rep.Params)
	}
	if rep.ReportedAt.IsZero() {
		t.Error("reported_at is zero")
	}
}

func TestSnapshotConfigHashTracksParams(t *testing.T) {
	topology.ResetForTesting()
	t.Cleanup(topology.ResetForTesting)

	mk := func(params map[string]string) string {
		kc := newFakeKC(testConfig(params))
		p := New()
		if err := p.Init(context.Background(), kc); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return p.Snapshot().ConfigHash
	}

	a := mk(map[string]string{"prism.debt_alpha": "1.2", "srd.aggregation": "rss"})
	b := mk(map[string]string{"prism.debt_alpha": "1.2", "srd.aggregation": "rss"})
	c := mk(map[string]string{"prism.debt_alpha": "1.8", "srd.aggregation": "rss"})

	if a != b {
		t.Errorf("identical params produced different hashes: %s != %s", a, b)
	}
	if a == c {
		t.Errorf("different params produced the same hash: %s", a)
	}
}

func TestSnapshotWithoutAssessorScoresNothing(t *testing.T) {
	topology.ResetForTesting()
	t.Cleanup(topology.ResetForTesting)
	topology.RecordTopologyDetailed("h1", []string{"10.0.0.0/24"}, "dma")

	kc := newFakeKC(testConfig(map[string]string{"federation.role": "node", "federation.master_url": "http://m:5099"}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rep := p.Snapshot()
	if rep.Zones["dma"].Hosts != 1 || rep.Zones["dma"].Scored != 0 {
		t.Errorf("dma = %+v, want 1 host / 0 scored", rep.Zones["dma"])
	}
	if rep.AvgSSAM != 0 {
		t.Errorf("avg = %v, want 0 when nothing is scored", rep.AvgSSAM)
	}
}

func TestStatusNodeBeforeFirstReport(t *testing.T) {
	kc := newFakeKC(testConfig(map[string]string{
		"federation.role":                "node",
		"federation.node_id":             "nk2",
		"federation.master_url":          "http://m:5099",
		"federation.report_interval_sec": "7",
	}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	st := p.FederationStatus()
	if st.Role != RoleNode || st.NodeID != "nk2" {
		t.Errorf("status = %+v", st)
	}
	if st.ListenAddr != "" {
		t.Errorf("ListenAddr = %q for a node role, want empty (master-only field)", st.ListenAddr)
	}
	if st.ReportIntervalSec != 7 {
		t.Errorf("interval = %d, want 7", st.ReportIntervalSec)
	}
	if st.LastReportAt != nil {
		t.Errorf("last_report_at = %v before any report, want nil", st.LastReportAt)
	}
}

func TestHealthCheckReportsConfigError(t *testing.T) {
	kc := newFakeKC(testConfig(map[string]string{"federation.role": "nope"}))
	p := New()
	if err := p.Init(context.Background(), kc); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err := p.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("HealthCheck = %v, want the role config error", err)
	}
	_ = p.Stop(context.Background())
}
