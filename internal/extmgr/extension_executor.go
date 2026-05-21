package extmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
)

type ExecutionPolicy string

const (
	ExecPolicyAllowed    ExecutionPolicy = "allowed"
	ExecPolicyWhitelist  ExecutionPolicy = "whitelist"
	ExecPolicySandboxed  ExecutionPolicy = "sandboxed"
	ExecPolicyDisabled   ExecutionPolicy = "disabled"
)

type ExecutionConfig struct {
	Policy      ExecutionPolicy
	Timeout     time.Duration
	WorkingDir  string
	Environment map[string]string
	BinaryPaths map[string]string
}

type ExecutionResult struct {
	Success  bool
	Output   string
	Duration time.Duration
	Error    string
	Findings []model.CheckResult
}

type ExtensionExecutor struct {
	mu     sync.RWMutex
	config ExecutionConfig
	whitelist map[string]bool
}

func NewExtensionExecutor(cfg ExecutionConfig) *ExtensionExecutor {
	return &ExtensionExecutor{
		config:    cfg,
		whitelist: make(map[string]bool),
	}
}

func (e *ExtensionExecutor) SetWhitelist(commands []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.whitelist = make(map[string]bool, len(commands))
	for _, cmd := range commands {
		e.whitelist[cmd] = true
	}
}

func (e *ExtensionExecutor) AddToWhitelist(command string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.whitelist[command] = true
}

func (e *ExtensionExecutor) isCommandAllowed(cmdPath string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.config.Policy == ExecPolicyAllowed {
		return true
	}
	if e.config.Policy == ExecPolicyDisabled {
		return false
	}

	base := filepath.Base(cmdPath)
	if allowed, exists := e.whitelist[base]; exists && allowed {
		return true
	}

	if allowed, exists := e.whitelist[cmdPath]; exists && allowed {
		return true
	}

	resolvedPath, err := filepath.EvalSymlinks(cmdPath)
	if err != nil {
		return false
	}

	resolvedBase := filepath.Base(resolvedPath)
	if allowed, exists := e.whitelist[resolvedBase]; exists && allowed {
		return true
	}

	absPath, err := filepath.Abs(resolvedPath)
	if err == nil {
		for allowedPath := range e.whitelist {
			if absPath == allowedPath {
				return true
			}
		}
	}

	return false
}

func (e *ExtensionExecutor) Execute(ctx context.Context, spec ExtensionSpec, args []string) (*ExecutionResult, error) {
	if spec.State != ExtStateEnabled {
		return nil, fmt.Errorf("extension %s is not enabled (state: %s)", spec.ID, spec.State)
	}

	start := time.Now()
	result := &ExecutionResult{}

	config := e.resolveConfig(spec)

	binary, ok := e.resolveBinary(spec, config)
	if !ok {
		return nil, fmt.Errorf("no executable found for extension %s", spec.ID)
	}

	if !e.isCommandAllowed(binary) {
		return nil, fmt.Errorf("command %s is not in the execution whitelist", binary)
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, binary, args...)
	cmd.Dir = config.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = spec.InstallPath
	}

	cmd.Env = os.Environ()
	for k, v := range spec.CustomConfig {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	for k, v := range config.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		if execCtx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Sprintf("execution timed out after %v", timeout)
		}
		return result, fmt.Errorf("execute %s: %w", spec.ID, err)
	}

	result.Success = true
	logger.With("component", "extmgr").Info("executed extension", "extension_id", spec.ID, "duration", result.Duration)
	return result, nil
}

func (e *ExtensionExecutor) ExecuteCheck(ctx context.Context, spec ExtensionSpec, checkID string) (*ExecutionResult, error) {
	return e.Execute(ctx, spec, []string{"--check", checkID})
}

func (e *ExtensionExecutor) ExecuteAllChecks(ctx context.Context, spec ExtensionSpec) (*ExecutionResult, error) {
	return e.Execute(ctx, spec, []string{"--all"})
}

func (e *ExtensionExecutor) ExecuteCustom(ctx context.Context, spec ExtensionSpec, script string, args []string) (*ExecutionResult, error) {
	if spec.State != ExtStateEnabled {
		return nil, fmt.Errorf("extension %s is not enabled", spec.ID)
	}

	start := time.Now()
	result := &ExecutionResult{}

	config := e.resolveConfig(spec)

	cleanInstallPath := filepath.Clean(spec.InstallPath)
	scriptPath := filepath.Join(cleanInstallPath, script)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		scriptPath = filepath.Join(cleanInstallPath, "scripts", script)
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("script %s not found in extension %s", script, spec.ID)
		}
	}

	if !strings.HasPrefix(filepath.Clean(scriptPath), cleanInstallPath+string(os.PathSeparator)) &&
		filepath.Clean(scriptPath) != cleanInstallPath {
		return nil, fmt.Errorf("script path traversal detected: %s", script)
	}

	if !e.isCommandAllowed(scriptPath) {
		return nil, fmt.Errorf("script %s is not in the execution whitelist", filepath.Base(scriptPath))
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, scriptPath, args...)
	cmd.Dir = cleanInstallPath

	cmd.Env = os.Environ()
	for k, v := range spec.CustomConfig {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Success = true
	return result, nil
}

func (e *ExtensionExecutor) resolveConfig(spec ExtensionSpec) ExecutionConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cfg := e.config

	if path, ok := e.config.BinaryPaths[spec.ID]; ok {
		if cfg.BinaryPaths == nil {
			cfg.BinaryPaths = make(map[string]string)
		}
		cfg.BinaryPaths[spec.ID] = path
	}

	return cfg
}

func (e *ExtensionExecutor) resolveBinary(spec ExtensionSpec, config ExecutionConfig) (string, bool) {
	if path, ok := config.BinaryPaths[spec.ID]; ok {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}

	candidates := []string{
		spec.ID,
		spec.ID + ".exe",
		spec.ID + ".sh",
		spec.ID + ".py",
		"bin/" + spec.ID,
		"bin/" + spec.ID + ".exe",
	}

	for _, name := range candidates {
		path := filepath.Join(spec.InstallPath, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}

	return "", false
}

func (e *ExtensionExecutor) ValidateScript(ctx context.Context, spec ExtensionSpec, script string) error {
	scriptPath := filepath.Join(spec.InstallPath, script)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		scriptPath = filepath.Join(spec.InstallPath, "scripts", script)
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			return fmt.Errorf("script %s not found", script)
		}
	}

	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return fmt.Errorf("script %s is empty", script)
	}

	return nil
}

func DefaultExecutionConfig() ExecutionConfig {
	return ExecutionConfig{
		Policy:      ExecPolicyWhitelist,
		Timeout:     30 * time.Second,
		BinaryPaths: make(map[string]string),
		Environment: make(map[string]string),
	}
}
