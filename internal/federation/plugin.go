package federation

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/logger"
	"github.com/chins-xing/asscor/internal/topology"
)

// Status is the CLI-facing snapshot of the federation module. It is produced
// by Plugin.FederationStatus and rendered by `federation status [--json]`.
type Status struct {
	Role               Role                   `json:"role"`
	NodeID             string                 `json:"node_id,omitempty"`
	MasterURL          string                 `json:"master_url,omitempty"`
	ListenAddr         string                 `json:"listen_addr,omitempty"`
	ReportIntervalSec  int                    `json:"report_interval_sec"`
	ConfigHash         string                 `json:"config_hash,omitempty"`
	Params             map[string]string      `json:"params,omitempty"`
	Hosts              int                    `json:"hosts"`
	Zones              map[string]ZoneSummary `json:"zones,omitempty"`
	AvgSSAM            float64                `json:"avg_ssam"`
	Nodes              []NodeReport           `json:"nodes,omitempty"`
	LastReportAt       *time.Time             `json:"last_report_at,omitempty"`
	LastReportError    string                 `json:"last_report_error,omitempty"`
	LastReportAttempts int                    `json:"last_report_attempts,omitempty"`
	ConfigError        string                 `json:"config_error,omitempty"`
	// ListenError is the master-only collection endpoint failure (e.g. the
	// listen_addr is already in use). It is a degradation, not a fatal error:
	// the kernel keeps running and the operator sees it here/HealthCheck.
	ListenError string     `json:"listen_error,omitempty"`
	Running     bool       `json:"running"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
}

// Plugin is the kernel.Plugin that implements the federation demo module.
// Lifecycle:
//
//	Init  — unwrap the kernel config object, parse [federation]; a bad section
//	        is logged and disables the module (never blocks bootstrap).
//	Start — master: bind the collection endpoint (non-blocking serve loop); a
//	        bind failure is logged and degraded, NOT fatal to the kernel;
//	        node: launch the background reporter; off: no-op.
//	Stop  — cancel the reporter, shut the HTTP server down, wait for goroutines.
type Plugin struct {
	mu        sync.Mutex
	state     kernel.PluginState
	kc        kernel.KernelContext
	cfg       Config
	cfgErr    error
	cfgObj    interface{} // unwrapped *config.Config (or adapter), for params/zones
	started   time.Time
	listenErr error

	collector *Collector
	server    *MasterServer
	reporter  *Reporter
	cancel    context.CancelFunc
}

// New builds a fresh federation plugin (registered by cmd/kernel when the
// `federation` build tag is enabled).
func New() *Plugin {
	return &Plugin{state: kernel.PluginUnregistered, cfg: Defaults()}
}

// Info implements kernel.Plugin.
func (p *Plugin) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "federation",
		Version:     PluginVersion,
		Description: "T4 federation demo — node kernels report aggregate Prism/SRD summaries to a master kernel (one network, many configuration profiles)",
		Author:      "ASSCOR Core Team",
	}
}

// Dependencies implements kernel.Plugin.
func (p *Plugin) Dependencies() []kernel.PluginDependency { return nil }

// Priority runs the module after topology-producing plugins (heartbeat P=?) and
// before the CLI (P=90) so `federation status` sees a started plugin.
func (p *Plugin) Priority() int { return 95 }

// Init implements kernel.Plugin.
func (p *Plugin) Init(ctx context.Context, kc kernel.KernelContext) error {
	p.mu.Lock()
	p.kc = kc
	p.state = kernel.PluginInitialized
	p.mu.Unlock()

	// The kernel exposes the parsed config through GetConfigObj. Depending on
	// the composition root this is either *config.Config directly or an
	// adapter wrapping it (the srdwrapper path); unwrapConfig walks the chain
	// so the [federation] keys are always read from the real object
	// (srd manager.go A-1 after the same bug silently dropped [srd]).
	var cfgObj interface{}
	if kc != nil {
		if c := kc.GetConfigObj(); c != nil {
			cfgObj = unwrapConfig(c)
		}
	}

	cfg, err := ParseConfig(configGetter(cfgObj))

	p.mu.Lock()
	p.cfgObj = cfgObj
	p.cfg = cfg
	p.cfgErr = err
	if err != nil {
		// Demo module: a typo must not abort kernel bootstrap. Stay off and
		// surface the error through `federation status` + logs + HealthCheck.
		p.cfg.Role = RoleOff
	}
	p.mu.Unlock()

	log := logger.WithComponent("federation")
	if err != nil {
		log.Warn("federation config invalid; module disabled", "error", err)
		return nil
	}
	attrs := []any{
		"role", string(cfg.Role),
		"node_id", cfg.NodeID,
		"master_url", cfg.MasterURL,
		"report_interval_sec", cfg.ReportIntervalSec(),
		"token_set", cfg.Token != "",
	}
	if cfg.Role == RoleMaster {
		attrs = append(attrs, "listen_addr", cfg.ListenAddr)
	}
	log.Info("federation config", attrs...)
	return nil
}

// Start implements kernel.Plugin. It never blocks on the network: the master
// only binds a listener, the node only launches a goroutine.
func (p *Plugin) Start(ctx context.Context) error {
	p.mu.Lock()
	cfg := p.cfg
	p.mu.Unlock()

	log := logger.WithComponent("federation")
	switch cfg.Role {
	case RoleMaster:
		collector := NewCollector()
		server := NewMasterServer(collector, cfg.ListenAddr, cfg.Token)
		if err := server.Start(); err != nil {
			// Degraded, not fatal: a busy :5099 must never take the whole
			// kernel down (the demo master also hosts unrelated plugins). The
			// operator sees the failure in `federation status`, HealthCheck and
			// the log.
			log.Warn("federation master listen failed; module degraded (no collection endpoint)",
				"addr", cfg.ListenAddr, "error", err)
			p.mu.Lock()
			p.listenErr = err
			p.started = time.Now()
			p.mu.Unlock()
			break
		}
		p.mu.Lock()
		p.collector = collector
		p.server = server
		p.listenErr = nil
		p.started = time.Now()
		p.mu.Unlock()
		log.Info("federation master listening",
			"addr", server.Addr(), "report_path", ReportPath, "nodes_path", NodesPath,
			"token_required", cfg.Token != "")

	case RoleNode:
		reporter, err := NewReporter(ReporterConfig{
			MasterURL: cfg.MasterURL,
			NodeID:    cfg.NodeID,
			Token:     cfg.Token,
			Interval:  cfg.ReportInterval,
			Timeout:   cfg.RequestTimeout,
			OnReport:  p.onReport,
		})
		if err != nil {
			p.setState(kernel.PluginFailed)
			return err
		}
		runCtx, cancel := context.WithCancel(ctx)
		p.mu.Lock()
		p.reporter = reporter
		p.cancel = cancel
		p.started = time.Now()
		p.mu.Unlock()
		reporter.Run(runCtx, p.Snapshot)
		log.Info("federation node reporter started",
			"node_id", cfg.NodeID,
			"master_url", cfg.MasterURL,
			"interval_sec", cfg.ReportIntervalSec())

	default:
		log.Info("federation disabled ([federation] role=off)")
	}

	p.setState(kernel.PluginStarted)
	return nil
}

// Stop implements kernel.Plugin: cancel the reporter, wait for it, then shut
// the master HTTP endpoint down gracefully (bounded).
func (p *Plugin) Stop(ctx context.Context) error {
	p.setState(kernel.PluginStopping)

	p.mu.Lock()
	cancel := p.cancel
	reporter := p.reporter
	server := p.server
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if reporter != nil {
		reporter.Stop()
	}
	if server != nil {
		sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := server.Stop(sctx); err != nil {
			logger.WithComponent("federation").Warn("federation master shutdown", "error", err)
		}
		scancel()
	}

	p.mu.Lock()
	p.cancel = nil
	p.reporter = nil
	p.server = nil
	p.state = kernel.PluginStopped
	p.mu.Unlock()

	logger.WithComponent("federation").Info("federation stopped")
	return nil
}

// State implements kernel.Plugin.
func (p *Plugin) State() kernel.PluginState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *Plugin) setState(s kernel.PluginState) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
}

// HealthCheck implements kernel.HealthCheckable.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	p.mu.Lock()
	state := p.state
	cfg := p.cfg
	cfgErr := p.cfgErr
	listenErr := p.listenErr
	reporter := p.reporter
	started := p.started
	p.mu.Unlock()

	if state != kernel.PluginStarted {
		return fmt.Errorf("federation not started (state=%s)", state)
	}
	if cfgErr != nil {
		return cfgErr
	}
	if cfg.Role == RoleMaster && listenErr != nil {
		return fmt.Errorf("federation master degraded (collection endpoint not listening): %w", listenErr)
	}
	if cfg.Role == RoleNode {
		if reporter == nil {
			return fmt.Errorf("federation node reporter is not running")
		}
		last, err, _ := reporter.LastReport()
		if err != nil {
			return fmt.Errorf("last federation report failed: %w", err)
		}
		if last.IsZero() && !started.IsZero() && time.Since(started) > 2*cfg.ReportInterval {
			return fmt.Errorf("no successful federation report since start (%s)", time.Since(started).Round(time.Second))
		}
	}
	return nil
}

// onReport logs reporter outcomes (the loop itself stays silent so the plugin
// owns component-scoped logging).
func (p *Plugin) onReport(err error, attempts int) {
	if err == nil {
		logger.WithComponent("federation").Debug("federation report sent", "attempts", attempts)
		return
	}
	logger.WithComponent("federation").Warn("federation report failed",
		"attempts", attempts, "error", err)
}

// FederationStatus implements the CLI provider contract
// (cli.FederationProvider). It is a snapshot: safe while the reporter loop
// and HTTP handlers run concurrently.
func (p *Plugin) FederationStatus() Status {
	p.mu.Lock()
	cfg := p.cfg
	cfgErr := p.cfgErr
	listenErr := p.listenErr
	state := p.state
	started := p.started
	collector := p.collector
	server := p.server
	reporter := p.reporter
	p.mu.Unlock()

	st := Status{
		Role:              cfg.Role,
		NodeID:            cfg.NodeID,
		MasterURL:         cfg.MasterURL,
		ReportIntervalSec: cfg.ReportIntervalSec(),
		Running:           state == kernel.PluginStarted,
		ConfigError:       errString(cfgErr),
	}
	if !started.IsZero() {
		t := started
		st.StartedAt = &t
	}
	// listen_addr only means something for the master; showing the node-side
	// default (:5099) in `federation status` would be misleading.
	if cfg.Role == RoleMaster {
		st.ListenAddr = cfg.ListenAddr
		if server != nil {
			st.ListenAddr = server.Addr()
		}
		st.ListenError = errString(listenErr)
	}

	switch cfg.Role {
	case RoleMaster:
		if collector != nil {
			st.Nodes = collector.Nodes()
		}
	case RoleNode:
		if reporter != nil {
			last, err, attempts := reporter.LastReport()
			if !last.IsZero() {
				t := last
				st.LastReportAt = &t
			}
			st.LastReportError = errString(err)
			st.LastReportAttempts = attempts
		}
		// Live view of this kernel's own summary (works before the first
		// successful report, when the node cannot reach the master).
		snap := p.Snapshot()
		st.ConfigHash = snap.ConfigHash
		st.Params = snap.Params
		st.Hosts = snap.Hosts
		st.Zones = snap.Zones
		st.AvgSSAM = snap.AvgSSAM
	}
	return st
}

// Snapshot builds the aggregate summary this node reports to the master:
// effective Prism/SRD parameters (+ their hash), host count, and per-zone
// average SSAM. It reads only exported topology/assessor APIs, so it can be
// exposed as a provider for tests or future CLIs.
func (p *Plugin) Snapshot() NodeReport {
	p.mu.Lock()
	kc := p.kc
	cfg := p.cfg
	cfgObj := p.cfgObj
	p.mu.Unlock()

	params := effectiveParams(cfgObj)
	report := NodeReport{
		NodeID:     cfg.NodeID,
		ConfigHash: ConfigHash(params),
		Params:     params,
		ReportedAt: time.Now().UTC(),
	}

	nodes := topology.ListNodes()
	report.Hosts = len(nodes)
	if len(nodes) == 0 {
		return report
	}

	assessor := resolveAssessor(kc)
	zoneCfg := configZones(cfgObj)

	type acc struct {
		hosts  int
		scored int
		sum    float64
	}
	perZone := make(map[string]*acc)
	for _, n := range nodes {
		zone := n.Zone
		if zone == "" && zoneCfg != nil {
			zone = zoneCfg[n.HostID]
		}
		if zone == "" {
			zone = "unknown"
		}
		a := perZone[zone]
		if a == nil {
			a = &acc{}
			perZone[zone] = a
		}
		a.hosts++
		if assessor != nil {
			if res := assessor.GetResult(n.HostID); res != nil {
				a.scored++
				a.sum += res.FinalScore
			}
		}
	}

	report.Zones = make(map[string]ZoneSummary, len(perZone))
	for zone, a := range perZone {
		zs := ZoneSummary{Hosts: a.hosts, Scored: a.scored}
		if a.scored > 0 {
			zs.AvgSSAM = a.sum / float64(a.scored)
		}
		report.Zones[zone] = zs
	}
	report.AvgSSAM = report.OverallAvgSSAM()
	return report
}

// resolveAssessor returns the kernel assessor when the build includes one.
func resolveAssessor(kc kernel.KernelContext) kernel.AssessorInterface {
	if kc == nil || kc.Container() == nil {
		return nil
	}
	impl, ok := kc.Container().Resolve((*kernel.AssessorInterface)(nil))
	if !ok {
		return nil
	}
	assessor, ok := impl.(kernel.AssessorInterface)
	if !ok {
		return nil
	}
	return assessor
}

// configZones returns the [zones] hostID→zone map when the config object is
// available (zone is normally reported by the agent, this is a fallback).
func configZones(cfgObj interface{}) map[string]string {
	if c, ok := cfgObj.(*kernelconfig.Config); ok && c != nil {
		return c.Zones
	}
	return nil
}

// effectiveParams collects the effective [prism]/[srd] parameter map — the
// "key parameters" the config hash fingerprints. Values are the parsed
// configuration strings as read through cfg.Get; this is exactly the surface
// the SRD manager consumes, so two nodes differing in model tuning always
// produce different hashes.
func effectiveParams(cfgObj interface{}) map[string]string {
	out := make(map[string]string)
	if c, ok := cfgObj.(*kernelconfig.Config); ok && c != nil {
		for k, v := range c.AdapterConfig {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "prism.") || strings.HasPrefix(lk, "srd.") {
				out[k] = v
			}
		}
		return out
	}
	if g, ok := cfgObj.(interface{ Get(string) string }); ok && !isNilInterface(cfgObj) {
		for _, k := range effectiveParamKeys {
			if v := g.Get(k); v != "" {
				out[k] = v
			}
		}
	}
	return out
}

// effectiveParamKeys is the fallback read surface used when the config object
// is an adapter rather than *config.Config (map iteration is impossible then).
var effectiveParamKeys = []string{
	"prism.default_transmission", "prism.debt_alpha", "prism.debt_cap",
	"prism.debt_norm_days", "prism.score_floor", "prism.collapse_beta",
	"prism.stable_threshold", "prism.degraded_threshold", "prism.untrusted_threshold",
	"prism.horizon_days", "prism.path_decay", "prism.prop_cap",
	"prism.max_path_depth", "prism.aggregation",
	"srd.layered_graph", "srd.roles", "srd.transmission", "srd.max_path_depth",
	"srd.path_decay", "srd.prop_cap", "srd.aggregation", "srd.horizon_days",
	"srd.sync_interval_sec", "srd.debt_alpha", "srd.debt_cap", "srd.debt_norm_days",
	"srd.score_floor", "srd.collapse_beta", "srd.stable_threshold",
	"srd.degraded_threshold", "srd.untrusted_threshold",
}

// unwrapConfig walks an adapter chain (GetConfigObj() interface{}) until the
// real config object is reached; max 4 hops guards against cycles. Mirrors the
// srd manager fix A-1 so [federation] keys read through cfg.Get are not
// silently dropped when the composition root passes an adapter.
func unwrapConfig(v interface{}) interface{} {
	for i := 0; i < 4 && v != nil; i++ {
		g, ok := v.(interface{ GetConfigObj() interface{} })
		if !ok {
			return v
		}
		next := g.GetConfigObj()
		if next == nil || next == v {
			return v
		}
		v = next
	}
	return v
}

// configGetter adapts the unwrapped config object to the getter ParseConfig
// expects; nil means "section absent → defaults".
func configGetter(v interface{}) func(string) string {
	g, ok := v.(interface{ Get(string) string })
	if !ok || isNilInterface(v) {
		return nil
	}
	return g.Get
}

func isNilInterface(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
