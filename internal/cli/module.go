package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
)

type kernelBridge struct {
	kernel kernel.KernelContext
	engine *Engine
}

func newKernelBridge(k kernel.KernelContext, e *Engine) *kernelBridge {
	return &kernelBridge{kernel: k, engine: e}
}

func (b *kernelBridge) GetPlugin(name string) (interface{}, bool) {
	p, ok := b.kernel.GetPlugin(name)
	if !ok {
		return nil, false
	}
	info := p.Info()
	state := p.State().String()
	pi := &PluginInfo{
		Name:        info.Name,
		Version:     info.Version,
		Description: info.Description,
		State:       state,
	}
	return pi, true
}

func (b *kernelBridge) ListPlugins() []PluginInfo {
	infos := b.kernel.ListPlugins()
	result := make([]PluginInfo, len(infos))
	for i, info := range infos {
		p, _ := b.kernel.GetPlugin(info.Name)
		state := "unknown"
		if p != nil {
			state = p.State().String()
		}
		result[i] = PluginInfo{
			Name:        info.Name,
			Version:     info.Version,
			Description: info.Description,
			State:       state,
		}
	}
	return result
}

func (b *kernelBridge) Config() map[string]string {
	return b.kernel.Config()
}

func (b *kernelBridge) SetConfig(key, value string) {
	b.kernel.SetConfig(key, value)
}

func (b *kernelBridge) Evaluate(hostID string) (interface{}, error) {
	impl, ok := b.kernel.Container().Resolve((*kernel.AssessorInterface)(nil))
	if !ok {
		return nil, fmt.Errorf("assessor not available")
	}
	assessor, ok := impl.(kernel.AssessorInterface)
	if !ok {
		return nil, fmt.Errorf("assessor type mismatch")
	}
	return assessor.Evaluate(hostID), nil
}

func (b *kernelBridge) HealthCheck(ctx context.Context) []HealthStatus {
	kernelResults := b.kernel.HealthCheck(ctx)
	results := make([]HealthStatus, len(kernelResults))
	for i, kr := range kernelResults {
		results[i] = HealthStatus{
			Name:    kr.Name,
			Healthy: kr.Healthy,
			Error:   kr.Error,
		}
	}
	return results
}

func (b *kernelBridge) Bus() BusAccess {
	return newBusBridge(b.kernel.Bus(), b.kernel.Context())
}

func (b *kernelBridge) Agents() AgentAccess {
	return &agentBridge{kernel: b.kernel}
}

func (b *kernelBridge) Logs() LogAccess {
	return &logBridge{kernel: b.kernel}
}

func (b *kernelBridge) Sources() SourceAccess {
	return &sourceBridge{kernel: b.kernel}
}

func (b *kernelBridge) Revocations() RevocationAccess {
	return &revocationBridge{kernel: b.kernel}
}

func (b *kernelBridge) CheckPermission(level PermissionLevel) bool {
	// Local CLI (Unix socket / stdin on the kernel host) runs with operator
	// privileges. Read/Write/Admin are permitted; Super (destructive kernel
	// ops) is gated off by default and requires explicit elevation.
	return level <= PermAdmin
}

func (b *kernelBridge) Registry() *Registry {
	return b.engine.Registry()
}

func (b *kernelBridge) History() *History {
	return b.engine.History()
}

func (b *kernelBridge) Diagnostics() map[string]interface{} {
	diag := make(map[string]interface{})

	bm := b.kernel.Bus().GetMetrics()
	diag["bus"] = map[string]interface{}{
		"messages": bm.MessageCount,
		"errors":   bm.ErrorCount,
		"panics":   bm.PanicCount,
	}

	if impl, ok := b.kernel.Container().Resolve((*kernel.WorkerPoolInterface)(nil)); ok {
		if wp, ok := impl.(kernel.WorkerPoolInterface); ok {
			diag["worker_pool"] = map[string]interface{}{
				"active":    wp.ActiveWorkers(),
				"available": wp.AvailableSlots(),
				"max":       wp.MaxConcurrency(),
			}
		}
	}

	return diag
}

func (b *kernelBridge) PolicyStatus(hostID string) (string, bool) {
	p, ok := b.kernel.GetPlugin("policy")
	if !ok {
		return "", false
	}
	pol, ok := p.(kernel.PolicyInterface)
	if !ok {
		return "", false
	}
	return pol.GetHostStatus(hostID).String(), true
}

type agentBridge struct {
	kernel kernel.KernelContext
}

func (a *agentBridge) ListAgents() []AgentInfo {
	p, ok := a.kernel.GetPlugin("heartbeat")
	if !ok {
		return nil
	}
	hb, ok := p.(kernel.HeartbeatInterface)
	if !ok {
		return nil
	}
	agents := hb.ListAgents()
	result := make([]AgentInfo, len(agents))
	for i, ag := range agents {
		result[i] = AgentInfo{
			HostID:      ag.HostID,
			Hostname:    ag.Hostname,
			Version:     ag.Version,
			LastSeen:    ag.LastSeen,
			Registered:  ag.Registered,
			Connections: ag.Connections,
			Active:      ag.Active,
		}
	}
	return result
}

func (a *agentBridge) GetAgent(hostID string) (*AgentInfo, bool) {
	p, ok := a.kernel.GetPlugin("heartbeat")
	if !ok {
		return nil, false
	}
	hb, ok := p.(kernel.HeartbeatInterface)
	if !ok {
		return nil, false
	}
	ag := hb.GetAgent(hostID)
	if ag == nil {
		return nil, false
	}
	info := &AgentInfo{
		HostID:      ag.HostID,
		Hostname:    ag.Hostname,
		Version:     ag.Version,
		LastSeen:    ag.LastSeen,
		Registered:  ag.Registered,
		Connections: ag.Connections,
		Active:      ag.Active,
	}
	return info, true
}

func (a *agentBridge) IsAgentAlive(hostID string) bool {
	p, ok := a.kernel.GetPlugin("heartbeat")
	if !ok {
		return false
	}
	hb, ok := p.(kernel.HeartbeatInterface)
	if !ok {
		return false
	}
	return hb.IsAlive(hostID)
}

func (a *agentBridge) SendCommand(hostID, action string, params map[string]string) (string, error) {
	p, ok := a.kernel.GetPlugin("commander")
	if !ok {
		return "", fmt.Errorf("commander plugin not available")
	}
	cmd, ok := p.(kernel.CommanderInterface)
	if !ok {
		return "", fmt.Errorf("commander plugin type mismatch")
	}
	cmdID := cmd.EnqueueCommand(hostID, action, params)
	return cmdID, nil
}

// revocationBridge exposes certificate revocation management through the
// heartbeat module (audit I-03).
type revocationBridge struct {
	kernel kernel.KernelContext
}

func (r *revocationBridge) heartbeat() (kernel.HeartbeatInterface, bool) {
	p, ok := r.kernel.GetPlugin("heartbeat")
	if !ok {
		return nil, false
	}
	hb, ok := p.(kernel.HeartbeatInterface)
	return hb, ok
}

func (r *revocationBridge) Revoke(fingerprint, reason string) error {
	hb, ok := r.heartbeat()
	if !ok {
		return fmt.Errorf("heartbeat module not available")
	}
	return hb.RevokeCert(fingerprint, reason)
}

func (r *revocationBridge) Unrevoke(fingerprint string) error {
	hb, ok := r.heartbeat()
	if !ok {
		return fmt.Errorf("heartbeat module not available")
	}
	return hb.UnrevokeCert(fingerprint)
}

func (r *revocationBridge) ListRevoked() []kernel.RevokedCertInfo {
	hb, ok := r.heartbeat()
	if !ok {
		return nil
	}
	return hb.ListRevokedCerts()
}

type logBridge struct {
	kernel kernel.KernelContext
}

func (l *logBridge) ReadLogs(hostID string, limit int, level string) ([]LogEntry, error) {
	logPath := "ASSCOR-kernel.log"
	f, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file: %w", err)
	}
	defer f.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record map[string]interface{}
		if err := json.Unmarshal(line, &record); err != nil {
			continue
		}

		hostIDVal, _ := record["host_id"].(string)
		if hostID != "" && hostIDVal != hostID {
			continue
		}

		levelVal, _ := record["level"].(string)
		if level != "" && !strings.EqualFold(levelVal, level) {
			continue
		}

		ts, _ := record["timestamp"].(string)
		tsTime, _ := time.Parse(time.RFC3339Nano, ts)
		msg, _ := record["message"].(string)
		src, _ := record["source"].(string)

		entries = append(entries, LogEntry{
			Timestamp: tsTime,
			Level:     levelVal,
			HostID:    hostIDVal,
			Message:   msg,
			Source:    src,
		})

		if limit > 0 && len(entries) >= limit {
			break
		}
	}

	return entries, nil
}

func (l *logBridge) ExportLogs(hostID string, format string) (string, error) {
	entries, err := l.ReadLogs(hostID, 0, "")
	if err != nil {
		return "", err
	}

	if len(entries) == 0 {
		return "", fmt.Errorf("no log entries found")
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal logs: %w", err)
		}
		return string(data), nil

	case "csv":
		var b strings.Builder
		b.WriteString("timestamp,level,host_id,source,message\n")
		for _, e := range entries {
			msg := strings.ReplaceAll(e.Message, "\"", "\"\"")
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,\"%s\"\n",
				e.Timestamp.Format(time.RFC3339),
				e.Level,
				e.HostID,
				e.Source,
				msg,
			))
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported export format: %s (use json or csv)", format)
	}
}

var _ kernel.BusAccess = (*busBridge)(nil)

type sourceBridge struct {
	kernel kernel.KernelContext
}

func (s *sourceBridge) resolveManager() (kernel.SourceManagerInterface, error) {
	impl, ok := s.kernel.Container().Resolve((*kernel.SourceManagerInterface)(nil))
	if !ok {
		return nil, fmt.Errorf("source manager not available")
	}
	sm, ok := impl.(kernel.SourceManagerInterface)
	if !ok {
		return nil, fmt.Errorf("source manager type mismatch")
	}
	return sm, nil
}

func (s *sourceBridge) DeploySource(ctx context.Context, spec kernel.SourceSpec, cfg kernel.SourceConfig) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.DeploySource(ctx, spec, cfg)
}

func (s *sourceBridge) UninstallSource(ctx context.Context, id string, force bool) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.UninstallSource(ctx, id, force)
}

func (s *sourceBridge) EnableSource(ctx context.Context, id string) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.EnableSource(ctx, id)
}

func (s *sourceBridge) DisableSource(ctx context.Context, id string) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.DisableSource(ctx, id)
}

func (s *sourceBridge) UpdateSource(ctx context.Context, id string, version string) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.UpdateSource(ctx, id, version)
}

func (s *sourceBridge) GetSourceStatus(id string) (*kernel.SourceStatus, bool) {
	sm, err := s.resolveManager()
	if err != nil {
		return nil, false
	}
	return sm.GetSourceStatus(id)
}

func (s *sourceBridge) ListSources(category kernel.SourceCategory) []kernel.SourceStatus {
	sm, err := s.resolveManager()
	if err != nil {
		return nil
	}
	return sm.ListSources(category)
}

func (s *sourceBridge) ListAllSources() []kernel.SourceStatus {
	sm, err := s.resolveManager()
	if err != nil {
		return nil
	}
	return sm.ListAllSources()
}

func (s *sourceBridge) ConfigureSource(ctx context.Context, id string, cfg kernel.SourceConfig) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.ConfigureSource(ctx, id, cfg)
}

func (s *sourceBridge) GetSourceConfig(id string) (*kernel.SourceConfig, bool) {
	sm, err := s.resolveManager()
	if err != nil {
		return nil, false
	}
	return sm.GetSourceConfig(id)
}

func (s *sourceBridge) GetSourceSpec(id string) (*kernel.SourceSpec, bool) {
	sm, err := s.resolveManager()
	if err != nil {
		return nil, false
	}
	return sm.GetSourceSpec(id)
}

func (s *sourceBridge) RunSourceNow(ctx context.Context, id string) error {
	sm, err := s.resolveManager()
	if err != nil {
		return err
	}
	return sm.RunSourceNow(ctx, id)
}

func (s *sourceBridge) GetAuditLog(sourceID string, limit int) []kernel.AuditLogEntry {
	sm, err := s.resolveManager()
	if err != nil {
		return nil
	}
	return sm.GetAuditLog(sourceID, limit)
}

type busBridge struct {
	bus *kernel.Bus
	ctx context.Context
}

func newBusBridge(bus *kernel.Bus, ctx context.Context) *busBridge {
	return &busBridge{bus: bus, ctx: ctx}
}

func (bb *busBridge) Publish(ctx context.Context, topic string, payload interface{}) {
	bb.bus.Publish(ctx, kernel.Message{
		Topic:   topic,
		Payload: payload,
		Source:  "cli",
	})
}

func (bb *busBridge) Subscribe(topic, subscriberID string) <-chan interface{} {
	ch := make(chan interface{}, 64)
	bb.bus.Subscribe(topic, subscriberID, func(ctx context.Context, msg kernel.Message) error {
		select {
		case ch <- msg.Payload:
		default:
		}
		return nil
	})
	return ch
}

type CLIModule struct {
	kernel        kernel.KernelContext
	engine        *Engine
	bridge        *kernelBridge
	enabled       bool
	done          chan struct{}
	socketPath    string
	logRedirected bool

	mu    sync.RWMutex
	state kernel.PluginState
}

func NewCLIModule() *CLIModule {
	return &CLIModule{
		done:       make(chan struct{}),
		socketPath: defaultSocketPath,
	}
}

func (m *CLIModule) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "cli",
		Version:     "1.0.0",
		Description: "Command-line interface — interactive CLI with command registration, completion, history, and plugin extensibility",
		Author:      "ASSCOR Core Team",
	}
}

func (m *CLIModule) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *CLIModule) Priority() int {
	return 90
}

func (m *CLIModule) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kernel = kc
	m.state = kernel.PluginInitialized

	cfgMap := kc.Config()
	if v := cfgMap["cli.enabled"]; v == "off" || v == "false" || v == "0" {
		m.enabled = false
		logger.WithComponent("cli").Info("CLI disabled by configuration")
		return nil
	}
	m.enabled = true

	m.engine = NewEngine(nil)
	m.bridge = newKernelBridge(kc, m.engine)
	m.engine.kernel = m.bridge

	m.engine.RegisterBuiltinCommands()

	kc.Container().Bind((*CLIInterface)(nil), m)

	logger.WithComponent("cli").Info("CLI module initialized")
	return nil
}

func (m *CLIModule) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted

	if !m.enabled {
		logger.WithComponent("cli").Info("CLI module disabled, not starting interactive terminal")
		return nil
	}

	if logger.CurrentOutput() == "stderr" || logger.CurrentOutput() == "stdout" {
		logPath := "ASSCOR-kernel.log"
		if err := logger.RedirectToFile(logPath); err != nil {
			logger.WithComponent("cli").Warn("failed to redirect logs to file, CLI output may be interleaved", "path", logPath, "error", err)
		} else {
			m.logRedirected = true
			fmt.Fprintf(os.Stderr, "CLI active: logs redirected to %s\n", logPath)
		}
	}

	if errs := m.kernel.Extensions().Execute(m.kernel.Context(), "cli.command.register", m); len(errs) > 0 {
		logger.WithComponent("cli").Warn("cli.command.register extension errors", "count", len(errs))
	}

	go func() {
		defer close(m.done)
		term := NewTerminal(m.engine)
		if err := term.Run(); err != nil {
			logger.WithComponent("cli").Error("terminal error", "error", err)
		}
	}()

	go m.serveCLI(ctx)

	logger.WithComponent("cli").Info("CLI module started", "log_output", logger.CurrentOutput())
	return nil
}

func (m *CLIModule) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	if m.engine != nil {
		m.engine.Stop()
	}
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		logger.WithComponent("cli").Warn("terminal goroutine did not exit in time")
		close(m.done)
	}
	if m.logRedirected {
		logger.RedirectToStderr()
	}
	m.state = kernel.PluginStopped
	logger.WithComponent("cli").Info("CLI module stopped")
	return nil
}

func (m *CLIModule) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *CLIModule) HealthCheck(ctx context.Context) error {
	if m.state != kernel.PluginStarted {
		return fmt.Errorf("CLI module not started (state=%s)", m.state)
	}
	return nil
}

func (m *CLIModule) Engine() *Engine {
	return m.engine
}

func (m *CLIModule) RegisterCommand(cmd Command) error {
	if m.engine == nil {
		return fmt.Errorf("CLI engine not initialized")
	}
	return m.engine.Registry().Register(cmd)
}

func (m *CLIModule) Execute(input string) *CommandResult {
	if m.engine == nil {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("CLI engine not initialized")}
	}
	return m.engine.Execute(input)
}

func (m *CLIModule) Done() <-chan struct{} {
	return m.done
}

type CLIInterface interface {
	RegisterCommand(cmd Command) error
	Execute(input string) *CommandResult
	Engine() *Engine
	Done() <-chan struct{}
}

type BaseCommand struct {
	info        CommandInfo
	handler     CommandHandler
	completions func(ctx *CommandContext, partial string) []string
}

func NewBaseCommand(info CommandInfo, handler CommandHandler) *BaseCommand {
	return &BaseCommand{info: info, handler: handler}
}

func (c *BaseCommand) Info() CommandInfo {
	return c.info
}

func (c *BaseCommand) Execute(ctx *CommandContext) *CommandResult {
	return c.handler(ctx)
}

func (c *BaseCommand) Completions(ctx *CommandContext, partial string) []string {
	if c.completions != nil {
		return c.completions(ctx, partial)
	}
	return nil
}

func (c *BaseCommand) WithCompletions(fn func(ctx *CommandContext, partial string) []string) *BaseCommand {
	c.completions = fn
	return c
}
