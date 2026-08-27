package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
)

type ExitCode int

const (
	ExitOK     ExitCode = 0
	ExitError  ExitCode = 1
	ExitUsage  ExitCode = 2
	ExitCancel ExitCode = 130
)

type CommandCategory string

const (
	CategoryCore   CommandCategory = "core"
	CategoryAssess CommandCategory = "assess"
	CategorySPC    CommandCategory = "spc"
	CategoryATTACK CommandCategory = "attck"
	CategoryPlugin CommandCategory = "plugin"
	CategorySystem CommandCategory = "system"
	CategoryDebug  CommandCategory = "debug"
	CategoryAgent  CommandCategory = "agent"
	CategorySource CommandCategory = "source"
)

type CommandParam struct {
	Name        string
	Short       string
	Description string
	Required    bool
	Default     string
	IsBool      bool
	IsRepeat    bool
	EnumValues  []string
}

type CommandOption struct {
	Name        string
	Short       string
	Description string
	Default     string
	Required    bool
	IsBool      bool
	EnumValues  []string
}

type CommandInfo struct {
	Name         string
	Short        string
	Description  string
	Usage        string
	Category     CommandCategory
	Hidden       bool
	Deprecated   bool
	Replacement  string
	RequiredPerm PermissionLevel
	Params       []CommandParam
	Options      []CommandOption
	Examples     []string
}

type CommandContext struct {
	Ctx     context.Context
	Args    []string
	Params  map[string]string
	Options map[string]string
	Flags   map[string]bool
	Repeat  map[string][]string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Kernel  KernelAccess
	Verbose bool
	JSON    bool
	Quiet   bool
}

type CommandResult struct {
	ExitCode ExitCode
	Output   string
	Err      error
	Data     interface{}
	Duration time.Duration
}

type CommandHandler func(ctx *CommandContext) *CommandResult

type Command interface {
	Info() CommandInfo
	Execute(ctx *CommandContext) *CommandResult
	Completions(ctx *CommandContext, partial string) []string
}

type PluginInfo struct {
	Name        string
	Version     string
	Description string
	State       string
}

type HealthStatus struct {
	Name    string
	Healthy bool
	Error   string
}

type AgentInfo struct {
	HostID      string    `json:"host_id"`
	Hostname    string    `json:"hostname"`
	Version     string    `json:"version"`
	LastSeen    time.Time `json:"last_seen"`
	Registered  time.Time `json:"registered"`
	Connections int64     `json:"connections"`
	Active      bool      `json:"active"`
}

type AgentAccess interface {
	ListAgents() []AgentInfo
	GetAgent(hostID string) (*AgentInfo, bool)
	IsAgentAlive(hostID string) bool
	SendCommand(hostID, action string, params map[string]string) (string, error)
}

type LogAccess interface {
	ReadLogs(hostID string, limit int, level string) ([]LogEntry, error)
	ExportLogs(hostID string, format string) (string, error)
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	HostID    string    `json:"host_id"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
}

type PermissionLevel int

const (
	PermRead  PermissionLevel = 0
	PermWrite PermissionLevel = 1
	PermAdmin PermissionLevel = 2
	PermSuper PermissionLevel = 3
)

type KernelAccess interface {
	GetPlugin(name string) (interface{}, bool)
	ListPlugins() []PluginInfo
	Config() map[string]string
	SetConfig(key, value string)
	Evaluate(hostID string) (interface{}, error)
	HealthCheck(ctx context.Context) []HealthStatus
	Bus() BusAccess
	Agents() AgentAccess
	Logs() LogAccess
	Sources() SourceAccess
	Revocations() RevocationAccess
	CheckPermission(level PermissionLevel) bool
	Registry() *Registry
	History() *History
	Diagnostics() map[string]interface{}
	PolicyStatus(hostID string) (string, bool)
}

type SourceAccess interface {
	DeploySource(ctx context.Context, spec kernel.SourceSpec, cfg kernel.SourceConfig) error
	UninstallSource(ctx context.Context, id string, force bool) error
	EnableSource(ctx context.Context, id string) error
	DisableSource(ctx context.Context, id string) error
	UpdateSource(ctx context.Context, id string, version string) error
	GetSourceStatus(id string) (*kernel.SourceStatus, bool)
	ListSources(category kernel.SourceCategory) []kernel.SourceStatus
	ListAllSources() []kernel.SourceStatus
	ConfigureSource(ctx context.Context, id string, cfg kernel.SourceConfig) error
	GetSourceConfig(id string) (*kernel.SourceConfig, bool)
	GetSourceSpec(id string) (*kernel.SourceSpec, bool)
	RunSourceNow(ctx context.Context, id string) error
	GetAuditLog(sourceID string, limit int) []kernel.AuditLogEntry
}

// RevocationAccess exposes certificate revocation management (audit I-03):
// revoke a compromised certificate fingerprint, list revocations, and restore
// a mistakenly revoked one.
type RevocationAccess interface {
	Revoke(fingerprint, reason string) error
	Unrevoke(fingerprint string) error
	ListRevoked() []kernel.RevokedCertInfo
}

type BusAccess = kernel.BusAccess

type commandEntry struct {
	info        CommandInfo
	handler     CommandHandler
	completions func(ctx *CommandContext, partial string) []string
	source      string
}

type Registry struct {
	mu         sync.RWMutex
	commands   map[string]*commandEntry
	aliases    map[string]string
	categories map[string]CommandCategory
}

func NewRegistry() *Registry {
	return &Registry{
		commands:   make(map[string]*commandEntry),
		aliases:    make(map[string]string),
		categories: make(map[string]CommandCategory),
	}
}

func (r *Registry) Register(cmd Command) error {
	return r.RegisterFrom(cmd.Info(), cmd.Execute, cmd.Completions, "plugin")
}

func (r *Registry) RegisterFrom(info CommandInfo, handler CommandHandler, completions func(ctx *CommandContext, partial string) []string, source string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := info.Name
	if name == "" {
		return fmt.Errorf("command name cannot be empty")
	}
	if strings.Contains(name, " ") {
		return fmt.Errorf("command name %q must not contain spaces", name)
	}
	if _, exists := r.commands[name]; exists {
		return fmt.Errorf("command %q already registered", name)
	}

	r.commands[name] = &commandEntry{
		info:        info,
		handler:     handler,
		completions: completions,
		source:      source,
	}
	r.categories[name] = info.Category

	logger.WithComponent("cli").Debug("command registered", "name", name, "category", string(info.Category), "source", source)
	return nil
}

func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.commands[name]; !exists {
		return fmt.Errorf("command %q not found", name)
	}
	delete(r.commands, name)
	delete(r.aliases, name)
	delete(r.categories, name)
	return nil
}

func (r *Registry) RegisterAlias(alias, target string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.commands[target]; !exists {
		return fmt.Errorf("target command %q not found", target)
	}
	if _, exists := r.aliases[alias]; exists {
		return fmt.Errorf("alias %q already exists", alias)
	}
	r.aliases[alias] = target
	return nil
}

func (r *Registry) Get(name string) (*commandEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if entry, ok := r.commands[name]; ok {
		return entry, true
	}
	if target, ok := r.aliases[name]; ok {
		if entry, ok := r.commands[target]; ok {
			return entry, true
		}
	}
	return nil, false
}

func (r *Registry) List() []CommandInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]CommandInfo, 0, len(r.commands))
	for _, entry := range r.commands {
		list = append(list, entry.info)
	}
	return list
}

func (r *Registry) ListByCategory(cat CommandCategory) []CommandInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []CommandInfo
	for name, entry := range r.commands {
		if r.categories[name] == cat {
			list = append(list, entry.info)
		}
	}
	return list
}

func (r *Registry) Resolve(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.commands[name]; ok {
		return name, true
	}
	if target, ok := r.aliases[name]; ok {
		return target, true
	}
	return "", false
}

func (r *Registry) Completions(partial string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []string
	for name := range r.commands {
		if strings.HasPrefix(name, partial) {
			entry := r.commands[name]
			if entry.info.Hidden {
				continue
			}
			matches = append(matches, name)
		}
	}
	for alias := range r.aliases {
		if strings.HasPrefix(alias, partial) {
			matches = append(matches, alias)
		}
	}
	return matches
}

type ParsedInput struct {
	Command string
	Args    []string
	Params  map[string]string
	Options map[string]string
	Flags   map[string]bool
	Repeat  map[string][]string
	Verbose bool
	JSON    bool
	Quiet   bool
	Help    bool
}

func ParseInput(tokens []string) *ParsedInput {
	p := &ParsedInput{
		Params:  make(map[string]string),
		Options: make(map[string]string),
		Flags:   make(map[string]bool),
		Repeat:  make(map[string][]string),
	}

	if len(tokens) == 0 {
		return p
	}

	p.Command = tokens[0]
	remaining := tokens[1:]

	i := 0
	for i < len(remaining) {
		tok := remaining[i]

		switch {
		case tok == "--help" || tok == "-h":
			p.Help = true
			i++

		case tok == "--verbose" || tok == "-v":
			p.Verbose = true
			i++

		case tok == "--json" || tok == "-j":
			p.JSON = true
			i++

		case tok == "--quiet" || tok == "-q":
			p.Quiet = true
			i++

		case strings.HasPrefix(tok, "--") && strings.Contains(tok, "="):
			parts := strings.SplitN(tok[2:], "=", 2)
			key := parts[0]
			val := parts[1]
			p.Options[key] = val
			p.Repeat[key] = append(p.Repeat[key], val)
			i++

		case strings.HasPrefix(tok, "--"):
			key := tok[2:]
			if i+1 < len(remaining) && !strings.HasPrefix(remaining[i+1], "-") {
				p.Options[key] = remaining[i+1]
				p.Repeat[key] = append(p.Repeat[key], remaining[i+1])
				i += 2
			} else {
				p.Flags[key] = true
				i++
			}

		case strings.HasPrefix(tok, "-") && len(tok) == 2:
			key := string(tok[1])
			if i+1 < len(remaining) && !strings.HasPrefix(remaining[i+1], "-") {
				p.Options[key] = remaining[i+1]
				p.Repeat[key] = append(p.Repeat[key], remaining[i+1])
				i += 2
			} else {
				p.Flags[key] = true
				i++
			}

		default:
			p.Args = append(p.Args, tok)
			i++
		}
	}

	return p
}

type Engine struct {
	registry *Registry
	kernel   KernelAccess
	history  *History
	output   *Output

	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewEngine(kernel KernelAccess) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		registry: NewRegistry(),
		kernel:   kernel,
		history:  NewHistory(1000),
		output:   NewOutput(os.Stdout, os.Stderr),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (e *Engine) Registry() *Registry {
	return e.registry
}

func (e *Engine) History() *History {
	return e.history
}

func (e *Engine) Output() *Output {
	return e.output
}

func (e *Engine) RegisterBuiltinCommands() {
	builtins := []struct {
		info        CommandInfo
		handler     CommandHandler
		completions func(ctx *CommandContext, partial string) []string
	}{
		{helpCmdInfo, helpCmdHandler, helpCompletions},
		{versionCmdInfo, versionCmdHandler, nil},
		{statusCmdInfo, statusCmdHandler, nil},
		{pluginCmdInfo, pluginCmdHandler, pluginCompletions},
		{configCmdInfo, configCmdHandler, configCompletions},
		{spcCmdInfo, spcCmdHandler, spcCompletions},
		{attckCmdInfo, attckCmdHandler, attckCompletions},
		{assessCmdInfo, assessCmdHandler, nil},
		{healthCmdInfo, healthCmdHandler, nil},
		{historyCmdInfo, historyCmdHandler, historyCompletions},
		{agentCmdInfo, agentCmdHandler, agentCompletions},
		{topologyCmdInfo, topologyCmdHandler, nil},
		{logCmdInfo, logCmdHandler, logCompletions},
		{sourceCmdInfo, sourceCmdHandler, sourceCompletions},
		{diagCmdInfo, diagCmdHandler, nil},
		{policyCmdInfo, policyCmdHandler, nil},
		{certCmdInfo, certCmdHandler, certCompletions},
	}

	for _, b := range builtins {
		if err := e.registry.RegisterFrom(b.info, b.handler, b.completions, "builtin"); err != nil {
			logger.WithComponent("cli").Error("failed to register builtin command", "name", b.info.Name, "error", err)
		}
	}

	aliases := map[string]string{
		"?":  "help",
		"v":  "version",
		"st": "status",
		"h":  "history",
		"ag": "agent",
		"ak": "attck",
		"dg": "diag",
	}
	for alias, target := range aliases {
		if err := e.registry.RegisterAlias(alias, target); err != nil {
			logger.WithComponent("cli").Debug("alias registration skipped", "alias", alias, "target", target, "error", err)
		}
	}
}

func (e *Engine) Execute(input string) *CommandResult {
	tokens := tokenize(input)
	if len(tokens) == 0 {
		return &CommandResult{ExitCode: ExitOK}
	}

	parsed := ParseInput(tokens)

	if parsed.Command == "" {
		return &CommandResult{ExitCode: ExitOK}
	}

	resolved, ok := e.registry.Resolve(parsed.Command)
	if !ok {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown command: %s", parsed.Command),
			Output:   fmt.Sprintf("Unknown command: %s\nType 'help' for available commands.\n", parsed.Command),
		}
	}

	entry, _ := e.registry.Get(resolved)

	if entry.info.Deprecated {
		msg := fmt.Sprintf("WARNING: command '%s' is deprecated", entry.info.Name)
		if entry.info.Replacement != "" {
			msg += fmt.Sprintf("; use '%s' instead", entry.info.Replacement)
		}
		e.output.Warn(msg)
	}

	if parsed.Help {
		return &CommandResult{
			ExitCode: ExitOK,
			Output:   formatHelp(entry.info),
		}
	}

	if entry.info.RequiredPerm > PermRead && e.kernel != nil {
		if !e.kernel.CheckPermission(entry.info.RequiredPerm) {
			return &CommandResult{
				ExitCode: ExitError,
				Err:      fmt.Errorf("permission denied: command '%s' requires %s level access", entry.info.Name, permLabel(entry.info.RequiredPerm)),
				Output:   fmt.Sprintf("Permission denied: command '%s' requires %s level access\n", entry.info.Name, permLabel(entry.info.RequiredPerm)),
			}
		}
	}

	cmdCtx := &CommandContext{
		Ctx:     e.ctx,
		Args:    parsed.Args,
		Params:  parsed.Params,
		Options: parsed.Options,
		Flags:   parsed.Flags,
		Repeat:  parsed.Repeat,
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Kernel:  e.kernel,
		Verbose: parsed.Verbose,
		JSON:    parsed.JSON,
		Quiet:   parsed.Quiet,
	}

	start := time.Now()
	result := entry.handler(cmdCtx)
	result.Duration = time.Since(start)

	e.history.Add(redactSecrets(input), result.ExitCode, result.Duration)

	return result
}

// secretEqRe / secretSpaceRe match password-bearing options in both CLI forms
// (`--flag=value` and `--flag value`; quoted values redacted as one unit).
// redactSecrets is applied to the raw input line before History.Add so secret
// material never survives in the CLI history (deferred minor #9): it covers
// every Execute channel (local terminal AND unix-socket sessions) regardless
// of whether the operator used the interactive password prompt — a socket
// client that cannot prompt must not leak via `history` either. Redaction is
// deliberately conservative (a token that merely LOOKS like a value is masked)
// — over-redaction is safe, under-redaction leaks.
var (
	secretEqRe    = regexp.MustCompile(`(--(?:password|old|new))=("[^"]*"|'[^']*'|\S+)`)
	secretSpaceRe = regexp.MustCompile(`(--(?:password|old|new))\s+("[^"]*"|'[^']*'|\S+)`)
)

// redactSecrets replaces password-bearing option values with a fixed marker.
func redactSecrets(input string) string {
	input = secretEqRe.ReplaceAllString(input, `$1=***`)
	input = secretSpaceRe.ReplaceAllString(input, `$1 ***`)
	return input
}

func (e *Engine) Completions(partial string) []string {
	tokens := tokenize(partial)
	if len(tokens) <= 1 {
		prefix := ""
		if len(tokens) == 1 {
			prefix = tokens[0]
		}
		return e.registry.Completions(prefix)
	}

	cmdName, ok := e.registry.Resolve(tokens[0])
	if !ok {
		return nil
	}
	entry, ok := e.registry.Get(cmdName)
	if !ok || entry.completions == nil {
		return nil
	}

	cmdCtx := &CommandContext{
		Ctx:    e.ctx,
		Kernel: e.kernel,
	}
	return entry.completions(cmdCtx, partial)
}

func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = true
	logger.WithComponent("cli").Info("CLI engine started", "commands", len(e.registry.List()))
	return nil
}

func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = false
	e.cancel()
	logger.WithComponent("cli").Info("CLI engine stopped")
	return nil
}

func (e *Engine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func tokenize(input string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		ch := input[i]

		if inQuote {
			if ch == quoteChar {
				inQuote = false
				quoteChar = 0
			} else if ch == '\\' && i+1 < len(input) && (input[i+1] == quoteChar || input[i+1] == '\\') {
				i++
				current.WriteByte(input[i])
			} else {
				current.WriteByte(ch)
			}
			continue
		}

		switch ch {
		case '"', '\'':
			inQuote = true
			quoteChar = ch
		case ' ', '\t':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

func formatHelp(info CommandInfo) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  %s — %s\n", info.Name, info.Description))
	if info.Usage != "" {
		b.WriteString(fmt.Sprintf("\n  Usage: %s\n", info.Usage))
	}

	if len(info.Params) > 0 {
		b.WriteString("\n  Parameters:\n")
		for _, p := range info.Params {
			req := ""
			if p.Required {
				req = " (required)"
			}
			b.WriteString(fmt.Sprintf("    %-20s %s%s\n", p.Name, p.Description, req))
		}
	}

	if len(info.Options) > 0 {
		b.WriteString("\n  Options:\n")
		for _, o := range info.Options {
			flag := fmt.Sprintf("--%s", o.Name)
			if o.Short != "" {
				flag = fmt.Sprintf("-%s, --%s", o.Short, o.Name)
			}
			def := ""
			if o.Default != "" {
				def = fmt.Sprintf(" (default: %s)", o.Default)
			}
			b.WriteString(fmt.Sprintf("    %-24s %s%s\n", flag, o.Description, def))
		}
	}

	if len(info.Examples) > 0 {
		b.WriteString("\n  Examples:\n")
		for _, ex := range info.Examples {
			b.WriteString(fmt.Sprintf("    %s\n", ex))
		}
	}

	if info.Deprecated {
		msg := "  DEPRECATED"
		if info.Replacement != "" {
			msg += fmt.Sprintf(" — use '%s' instead", info.Replacement)
		}
		b.WriteString(fmt.Sprintf("\n  %s\n", msg))
	}

	return b.String()
}

func permLabel(level PermissionLevel) string {
	switch level {
	case PermRead:
		return "read"
	case PermWrite:
		return "write"
	case PermAdmin:
		return "admin"
	case PermSuper:
		return "super"
	default:
		return "unknown"
	}
}
