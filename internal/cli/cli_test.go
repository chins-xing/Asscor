package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

type mockKernel struct {
	plugins   map[string]interface{}
	config    map[string]string
	agents    []AgentInfo
	logs      []LogEntry
	permLevel PermissionLevel
	registry  *Registry
	history   *History
}

func newMockKernel() *mockKernel {
	return &mockKernel{
		plugins: make(map[string]interface{}),
		config: map[string]string{
			"threshold":   "80",
			"listen_addr": ":9090",
		},
		agents: []AgentInfo{
			{HostID: "web-01", Hostname: "web-server-01", Version: "v0.1.1", Active: true, LastSeen: time.Now(), Registered: time.Now().Add(-24 * time.Hour), Connections: 42},
			{HostID: "db-01", Hostname: "db-master-01", Version: "v0.1.1", Active: true, LastSeen: time.Now().Add(-5 * time.Second), Registered: time.Now().Add(-48 * time.Hour), Connections: 18},
			{HostID: "cache-01", Hostname: "redis-cache", Version: "v0.1.0", Active: false, LastSeen: time.Now().Add(-10 * time.Minute), Registered: time.Now().Add(-72 * time.Hour), Connections: 3},
		},
		logs: []LogEntry{
			{Timestamp: time.Now(), Level: "info", HostID: "web-01", Message: "heartbeat received", Source: "agent"},
			{Timestamp: time.Now(), Level: "error", HostID: "db-01", Message: "connection timeout", Source: "agent"},
			{Timestamp: time.Now(), Level: "warn", HostID: "cache-01", Message: "memory usage high", Source: "agent"},
		},
		permLevel: PermSuper,
	}
}

func (m *mockKernel) GetPlugin(name string) (interface{}, bool) {
	p, ok := m.plugins[name]
	return p, ok
}

func (m *mockKernel) ListPlugins() []PluginInfo {
	return []PluginInfo{
		{Name: "heartbeat", Version: "1.2.0", Description: "Heartbeat monitor", State: "started"},
		{Name: "assessor", Version: "1.2.0", Description: "Assessment engine", State: "started"},
	}
}

func (m *mockKernel) Config() map[string]string {
	cp := make(map[string]string, len(m.config))
	for k, v := range m.config {
		cp[k] = v
	}
	return cp
}

func (m *mockKernel) SetConfig(key, value string) {
	m.config[key] = value
}

func (m *mockKernel) Evaluate(hostID string) (interface{}, error) {
	return map[string]interface{}{"host_id": hostID, "score": 85.5}, nil
}

func (m *mockKernel) HealthCheck(ctx context.Context) []HealthStatus {
	return []HealthStatus{
		{Name: "heartbeat", Healthy: true},
		{Name: "assessor", Healthy: true},
	}
}

func (m *mockKernel) Bus() BusAccess {
	return &mockBus{}
}

func (m *mockKernel) Agents() AgentAccess {
	return &mockAgentAccess{agents: m.agents}
}

func (m *mockKernel) Logs() LogAccess {
	return &mockLogAccess{logs: m.logs}
}

func (m *mockKernel) CheckPermission(level PermissionLevel) bool {
	return m.permLevel >= level
}

func (m *mockKernel) Diagnostics() map[string]interface{} {
	return map[string]interface{}{}
}

func (m *mockKernel) PolicyStatus(hostID string) (string, bool) {
	return "OK", true
}

func (m *mockKernel) Registry() *Registry {
	if m.registry != nil {
		return m.registry
	}
	return NewRegistry()
}

func (m *mockKernel) History() *History {
	if m.history != nil {
		return m.history
	}
	return NewHistory(100)
}

func (m *mockKernel) Sources() SourceAccess {
	return &mockSourceAccess{}
}

type mockSourceAccess struct{}

func (s *mockSourceAccess) DeploySource(ctx context.Context, spec kernel.SourceSpec, cfg kernel.SourceConfig) error {
	return nil
}
func (s *mockSourceAccess) UninstallSource(ctx context.Context, id string, force bool) error {
	return nil
}
func (s *mockSourceAccess) EnableSource(ctx context.Context, id string) error    { return nil }
func (s *mockSourceAccess) DisableSource(ctx context.Context, id string) error   { return nil }
func (s *mockSourceAccess) UpdateSource(ctx context.Context, id string, version string) error {
	return nil
}
func (s *mockSourceAccess) GetSourceStatus(id string) (*kernel.SourceStatus, bool) {
	return nil, false
}
func (s *mockSourceAccess) ListSources(category kernel.SourceCategory) []kernel.SourceStatus {
	return nil
}
func (s *mockSourceAccess) ListAllSources() []kernel.SourceStatus { return nil }
func (s *mockSourceAccess) ConfigureSource(ctx context.Context, id string, cfg kernel.SourceConfig) error {
	return nil
}
func (s *mockSourceAccess) GetSourceConfig(id string) (*kernel.SourceConfig, bool) {
	return nil, false
}
func (s *mockSourceAccess) GetSourceSpec(id string) (*kernel.SourceSpec, bool) {
	return nil, false
}
func (s *mockSourceAccess) RunSourceNow(ctx context.Context, id string) error {
	return nil
}
func (s *mockSourceAccess) GetAuditLog(sourceID string, limit int) []kernel.AuditLogEntry {
	return nil
}

type mockBus struct{}

func (b *mockBus) Publish(ctx context.Context, topic string, payload interface{}) {}
func (b *mockBus) Subscribe(topic, subscriberID string) <-chan interface{} {
	return make(chan interface{}, 1)
}

type mockAgentAccess struct {
	agents []AgentInfo
}

func (a *mockAgentAccess) ListAgents() []AgentInfo {
	return a.agents
}

func (a *mockAgentAccess) GetAgent(hostID string) (*AgentInfo, bool) {
	for _, ag := range a.agents {
		if ag.HostID == hostID {
			return &ag, true
		}
	}
	return nil, false
}

func (a *mockAgentAccess) IsAgentAlive(hostID string) bool {
	for _, ag := range a.agents {
		if ag.HostID == hostID {
			return ag.Active
		}
	}
	return false
}

func (a *mockAgentAccess) SendCommand(hostID, action string, params map[string]string) (string, error) {
	return fmt.Sprintf("cmd-%s-%s", hostID, action), nil
}

type mockLogAccess struct {
	logs []LogEntry
}

func (l *mockLogAccess) ReadLogs(hostID string, limit int, level string) ([]LogEntry, error) {
	var filtered []LogEntry
	for _, e := range l.logs {
		if hostID != "" && e.HostID != hostID {
			continue
		}
		if level != "" && !strings.EqualFold(e.Level, level) {
			continue
		}
		filtered = append(filtered, e)
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

func (l *mockLogAccess) ExportLogs(hostID string, format string) (string, error) {
	entries, err := l.ReadLogs(hostID, 0, "")
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no log entries found")
	}
	if format == "json" {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return string(data), nil
	}
	return "", fmt.Errorf("unsupported format: %s", format)
}

func newTestEngine(kernel KernelAccess) *Engine {
	e := NewEngine(kernel)
	e.output = NewOutput(bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	e.output.SetColor(false)
	e.RegisterBuiltinCommands()
	if mk, ok := kernel.(*mockKernel); ok {
		mk.registry = e.Registry()
		mk.history = e.History()
	}
	return e
}

func TestParseInput_Basic(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		command  string
		args     []string
		json     bool
		verbose  bool
		help     bool
	}{
		{"empty", []string{}, "", nil, false, false, false},
		{"simple", []string{"help"}, "help", nil, false, false, false},
		{"with_args", []string{"agent", "list"}, "agent", []string{"list"}, false, false, false},
		{"json_flag", []string{"status", "--json"}, "status", nil, true, false, false},
		{"verbose_flag", []string{"status", "-v"}, "status", nil, false, true, false},
		{"help_flag", []string{"agent", "--help"}, "agent", nil, false, false, true},
		{"option_eq", []string{"spc", "cve", "--cvss-min=9.0"}, "spc", []string{"cve"}, false, false, false},
		{"option_space", []string{"config", "--format", "json"}, "config", nil, false, false, false},
		{"bool_flag", []string{"history", "--failed"}, "history", nil, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ParseInput(tt.input)
			if p.Command != tt.command {
				t.Errorf("Command = %q, want %q", p.Command, tt.command)
			}
			if tt.args != nil && len(p.Args) != len(tt.args) {
				t.Errorf("Args = %v, want %v", p.Args, tt.args)
			}
			if p.JSON != tt.json {
				t.Errorf("JSON = %v, want %v", p.JSON, tt.json)
			}
			if p.Verbose != tt.verbose {
				t.Errorf("Verbose = %v, want %v", p.Verbose, tt.verbose)
			}
			if p.Help != tt.help {
				t.Errorf("Help = %v, want %v", p.Help, tt.help)
			}
		})
	}
}

func TestParseInput_QuotedStrings(t *testing.T) {
	tokens := tokenize(`agent command --host "web server 01" --action scan`)
	if tokens[0] != "agent" {
		t.Errorf("token[0] = %q", tokens[0])
	}
	if tokens[1] != "command" {
		t.Errorf("token[1] = %q", tokens[1])
	}
	if tokens[2] != "--host" {
		t.Errorf("token[2] = %q", tokens[2])
	}
	if tokens[3] != "web server 01" {
		t.Errorf("token[3] = %q, want %q", tokens[3], "web server 01")
	}
}

func TestRegistry_RegisterAndResolve(t *testing.T) {
	r := NewRegistry()

	info := CommandInfo{Name: "test", Short: "Test", Description: "Test command", Category: CategoryCore}
	err := r.RegisterFrom(info, func(ctx *CommandContext) *CommandResult {
		return &CommandResult{ExitCode: ExitOK}
	}, nil, "test")
	if err != nil {
		t.Fatalf("RegisterFrom failed: %v", err)
	}

	resolved, ok := r.Resolve("test")
	if !ok {
		t.Fatal("Resolve failed")
	}
	if resolved != "test" {
		t.Errorf("Resolve = %q, want %q", resolved, "test")
	}

	err = r.RegisterFrom(info, nil, nil, "test2")
	if err == nil {
		t.Error("duplicate registration should fail")
	}
}

func TestRegistry_Alias(t *testing.T) {
	r := NewRegistry()
	info := CommandInfo{Name: "help", Short: "Help", Category: CategoryCore}
	r.RegisterFrom(info, func(ctx *CommandContext) *CommandResult { return &CommandResult{ExitCode: ExitOK} }, nil, "builtin")

	err := r.RegisterAlias("?", "help")
	if err != nil {
		t.Fatalf("RegisterAlias failed: %v", err)
	}

	resolved, ok := r.Resolve("?")
	if !ok {
		t.Fatal("Alias resolve failed")
	}
	if resolved != "help" {
		t.Errorf("Alias resolved to %q, want %q", resolved, "help")
	}
}

func TestRegistry_Completions(t *testing.T) {
	r := NewRegistry()
	for _, name := range []string{"help", "health", "history", "agent"} {
		r.RegisterFrom(CommandInfo{Name: name, Category: CategoryCore}, func(ctx *CommandContext) *CommandResult { return &CommandResult{ExitCode: ExitOK} }, nil, "builtin")
	}

	completions := r.Completions("he")
	if len(completions) != 2 {
		t.Errorf("Completions for 'he' = %v, want 2 results", completions)
	}

	completions = r.Completions("hi")
	if len(completions) != 1 || completions[0] != "history" {
		t.Errorf("Completions for 'hi' = %v, want [history]", completions)
	}
}

func TestEngine_ExecuteHelp(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("help")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "ASSCOR") {
		t.Error("Help output should contain 'ASSCOR'")
	}
}

func TestEngine_ExecuteVersion(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("version")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "SSAM") {
		t.Error("Version output should contain 'SSAM'")
	}
}

func TestEngine_ExecuteVersionJSON(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("version --json")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(result.Output), &data); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if data["framework"] == "" {
		t.Error("JSON output missing 'framework' key")
	}
}

func TestEngine_ExecuteStatus(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("status")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "Plugins") {
		t.Error("Status output should contain 'Plugins'")
	}
}

func TestEngine_ExecuteUnknownCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("foobar")
	if result.ExitCode != ExitUsage {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitUsage)
	}
	if result.Err == nil {
		t.Error("Should have error for unknown command")
	}
}

func TestEngine_ExecuteHelpForCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("help agent")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "agent") {
		t.Error("Help for 'agent' should contain 'agent'")
	}
}

func TestAgentListCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent list")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "web-01") {
		t.Error("Agent list should contain 'web-01'")
	}
	if !strings.Contains(result.Output, "db-01") {
		t.Error("Agent list should contain 'db-01'")
	}
	if !strings.Contains(result.Output, "3 agents") {
		t.Error("Agent list should show total count")
	}
}

func TestAgentListJSON(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent list --json")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	var agents []AgentInfo
	if err := json.Unmarshal([]byte(result.Output), &agents); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if len(agents) != 3 {
		t.Errorf("Agent count = %d, want 3", len(agents))
	}
}

func TestAgentStatusCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent status --host=web-01")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "web-01") {
		t.Error("Agent status should contain host ID")
	}
	if !strings.Contains(result.Output, "Alive") {
		t.Error("Agent status should show alive status")
	}
}

func TestAgentStatusNotFound(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent status --host=nonexistent")
	if result.ExitCode != ExitError {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitError)
	}
}

func TestAgentStatusNoHost(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent status")
	if result.ExitCode != ExitUsage {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitUsage)
	}
}

func TestAgentStopCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent stop --host=web-01")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "stop") {
		t.Error("Stop command output should mention 'stop'")
	}
	if !strings.Contains(result.Output, "web-01") {
		t.Error("Stop command output should contain host ID")
	}
}

func TestAgentRestartAll(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent restart --all")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "Broadcast") {
		t.Error("Restart --all should mention 'Broadcast'")
	}
}

func TestAgentCommandAction(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent command --host=web-01 --action=scan")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "scan") {
		t.Error("Command output should mention action 'scan'")
	}
}

func TestAgentCommandNoAction(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent command --host=web-01")
	if result.ExitCode != ExitUsage {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitUsage)
	}
}

func TestAgentConfigSet(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent config --host=web-01 --set threshold=90")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "config_update") {
		t.Error("Config set should mention 'config_update'")
	}
}

func TestAgentFilterActive(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("agent list --filter=active=true")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if strings.Contains(result.Output, "cache-01") {
		t.Error("Filtered list should not contain inactive agent 'cache-01'")
	}
}

func TestLogShowCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("log show")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "web-01") {
		t.Error("Log show should contain 'web-01'")
	}
}

func TestLogShowWithLevel(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("log show --level=error")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if strings.Contains(result.Output, "web-01") {
		t.Error("Error-level filter should not show info logs from web-01")
	}
	if !strings.Contains(result.Output, "db-01") {
		t.Error("Error-level filter should show db-01 error log")
	}
}

func TestLogShowJSON(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("log show --json")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	var entries []LogEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Log entries count = %d, want 3", len(entries))
	}
}

func TestPermissionDenied(t *testing.T) {
	mk := newMockKernel()
	mk.permLevel = PermRead
	e := newTestEngine(mk)

	result := e.Execute("agent stop --host=web-01")
	if result.ExitCode != ExitError {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitError)
	}
	if !strings.Contains(result.Output, "Permission denied") {
		t.Errorf("Should show permission denied error, got: %s", result.Output)
	}
}

func TestPermissionReadAllowed(t *testing.T) {
	mk := newMockKernel()
	mk.permLevel = PermRead
	e := newTestEngine(mk)

	result := e.Execute("agent list")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d (read-level should allow list)", result.ExitCode, ExitOK)
	}
}

func TestHistoryCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	e.Execute("version")
	e.Execute("status")
	e.Execute("help")

	result := e.Execute("history")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "version") {
		t.Error("History should contain 'version'")
	}
}

func TestHistoryClear(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	e.Execute("version")
	e.Execute("history --clear")

	if e.History().Count() > 1 {
		t.Errorf("History count after clear = %d, want <=1 (clear command itself)", e.History().Count())
	}
}

func TestHistoryFailed(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	e.Execute("version")
	e.Execute("foobar")

	result := e.Execute("history --failed")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if strings.Contains(result.Output, "version") {
		t.Error("Failed filter should not show successful 'version' command")
	}
}

func TestConfigCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("config")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "threshold") {
		t.Error("Config output should contain 'threshold'")
	}
}

func TestConfigQueryKey(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("config threshold")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "80") {
		t.Error("Config threshold should be '80'")
	}
}

func TestConfigNotFound(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("config nonexistent_key")
	if result.ExitCode != ExitError {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitError)
	}
}

func TestPluginListCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("plugin list")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "heartbeat") {
		t.Error("Plugin list should contain 'heartbeat'")
	}
}

func TestHealthCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("health")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "heartbeat") {
		t.Error("Health output should contain 'heartbeat'")
	}
}

func TestAssessCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("assess web-01")
	if result.ExitCode != ExitOK {
		t.Errorf("ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
	if !strings.Contains(result.Output, "web-01") {
		t.Error("Assess output should contain host ID")
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		input  string
		expect []string
	}{
		{"hello world", []string{"hello", "world"}},
		{`say "hello world"`, []string{"say", "hello world"}},
		{`echo 'single quotes'`, []string{"echo", "single quotes"}},
		{`path C:\Users\test`, []string{"path", `C:\Users\test`}},
		{"  spaces   between  ", []string{"spaces", "between"}},
	}

	for _, tt := range tests {
		tokens := tokenize(tt.input)
		if len(tokens) != len(tt.expect) {
			t.Errorf("tokenize(%q) = %v, want %v", tt.input, tokens, tt.expect)
			continue
		}
		for i, tok := range tokens {
			if tok != tt.expect[i] {
				t.Errorf("tokenize(%q)[%d] = %q, want %q", tt.input, i, tok, tt.expect[i])
			}
		}
	}
}

func TestHistoryAddAndRecent(t *testing.T) {
	h := NewHistory(5)

	h.Add("cmd1", ExitOK, time.Millisecond)
	h.Add("cmd2", ExitError, time.Second)
	h.Add("cmd3", ExitOK, time.Millisecond*100)

	if h.Count() != 3 {
		t.Errorf("Count = %d, want 3", h.Count())
	}

	recent := h.Recent(2)
	if len(recent) != 2 {
		t.Errorf("Recent(2) = %d entries, want 2", len(recent))
	}
	if recent[0].Command != "cmd2" {
		t.Errorf("Recent(2)[0].Command = %q, want %q", recent[0].Command, "cmd2")
	}
}

func TestHistoryOverflow(t *testing.T) {
	h := NewHistory(3)
	for i := 0; i < 10; i++ {
		h.Add(fmt.Sprintf("cmd%d", i), ExitOK, 0)
	}
	if h.Count() != 3 {
		t.Errorf("Count after overflow = %d, want 3", h.Count())
	}
}

func TestHistorySearch(t *testing.T) {
	h := NewHistory(100)
	h.Add("agent list", ExitOK, 0)
	h.Add("agent status --host=web-01", ExitOK, 0)
	h.Add("version", ExitOK, 0)

	results := h.Search("agent")
	if len(results) != 2 {
		t.Errorf("Search('agent') = %d results, want 2", len(results))
	}
}

func TestHistoryClearMethod(t *testing.T) {
	h := NewHistory(100)
	h.Add("cmd1", ExitOK, 0)
	h.Add("cmd2", ExitOK, 0)
	h.Clear()
	if h.Count() != 0 {
		t.Errorf("Count after clear = %d, want 0", h.Count())
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d   time.Duration
		exp string
	}{
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{2 * time.Hour, "2h0m"},
		{26 * time.Hour, "1d2h"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.exp {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.exp)
		}
	}
}

func TestFilterAgents(t *testing.T) {
	agents := []AgentInfo{
		{HostID: "web-01", Hostname: "web", Active: true, Version: "v1"},
		{HostID: "db-01", Hostname: "db", Active: false, Version: "v2"},
	}

	filtered := filterAgents(agents, "active=true")
	if len(filtered) != 1 || filtered[0].HostID != "web-01" {
		t.Errorf("filterAgents(active=true) = %v, want only web-01", filtered)
	}

	filtered = filterAgents(agents, "hostname=db")
	if len(filtered) != 1 || filtered[0].HostID != "db-01" {
		t.Errorf("filterAgents(hostname=db) = %v, want only db-01", filtered)
	}

	filtered = filterAgents(agents, "invalid")
	if len(filtered) != 2 {
		t.Errorf("filterAgents(invalid) = %d, want 2", len(filtered))
	}
}

func TestPermLabel(t *testing.T) {
	tests := []struct {
		level PermissionLevel
		label string
	}{
		{PermRead, "read"},
		{PermWrite, "write"},
		{PermAdmin, "admin"},
		{PermSuper, "super"},
		{PermissionLevel(99), "unknown"},
	}
	for _, tt := range tests {
		got := permLabel(tt.level)
		if got != tt.label {
			t.Errorf("permLabel(%d) = %q, want %q", tt.level, got, tt.label)
		}
	}
}

func TestEngine_ExecuteNoArgs(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("")
	if result.ExitCode != ExitOK {
		t.Errorf("Empty input ExitCode = %d, want %d", result.ExitCode, ExitOK)
	}
}

func TestEngine_ExecuteExitCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	result := e.Execute("exit")
	if result.ExitCode != ExitUsage {
		t.Errorf("Exit ExitCode = %d, want %d (exit is not a registered command)", result.ExitCode, ExitUsage)
	}
}

func TestLogExportCommand(t *testing.T) {
	mk := newMockKernel()
	e := newTestEngine(mk)

	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/export.json"
	result := e.Execute(fmt.Sprintf("log export --format=json --output=%s", tmpFile))
	if result.ExitCode != ExitOK {
		t.Fatalf("ExitCode = %d, want %d, output: %s", result.ExitCode, ExitOK, result.Output)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}
	var entries []LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Exported entries = %d, want 3", len(entries))
	}
}

func TestOutput_ColorToggle(t *testing.T) {
	o := NewOutput(bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	o.SetColor(true)
	if !o.color {
		t.Error("SetColor(true) should enable color")
	}
	if o.colors.Reset == "" {
		t.Error("Colors should be set when color enabled")
	}

	o.SetColor(false)
	if o.color {
		t.Error("SetColor(false) should disable color")
	}
	if o.colors.Reset != "" {
		t.Error("Colors should be empty when disabled")
	}
}
