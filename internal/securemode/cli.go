package securemode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AgentCommander is the kernel-side interface for enqueueing instructions to
// agents. It is satisfied by kernel.CommanderInterface and wired by
// cmd/kernel; defined here so ModeCLI stays free of internal/cli and
// internal/kernel imports (no dependency cycle, review I-1).
type AgentCommander interface {
	EnqueueCommand(hostID, action string, params map[string]string) string
}

// ModeCLI is the kernel-side CLI adapter for mode/config commands. It stays
// free of any internal/cli import to avoid a dependency cycle; internal/cli
// wires it via handler functions (Task 10).
type ModeCLI struct {
	Ctrl      *Controller
	Commander AgentCommander
	// OnConfigChanged, when set, is invoked after the run-mode in-memory
	// config is updated (unlock or config-set) so the kernel wiring can feed
	// it back into the kernel runtime — config.Parse -> SetConfigObj +
	// assessor.ReloadConfig, mirroring the agent-side reloadProtectedConfig
	// (review I-1). immediate=true for unlock and config-set --temp (spec §9:
	// applies immediately); false for config-set --persist (applies only on
	// 'config reload'). The hook runs BEFORE the guard mutation on config-set,
	// so a failure leaves both the guard and the kernel runtime unchanged.
	OnConfigChanged func(plain string, immediate bool) error
}

// NewModeCLI creates the kernel-side CLI adapter for a controller. A nil
// controller yields a nil adapter, which the kernel wiring treats as a no-op
// (the securemode build tag is off).
func NewModeCLI(ctrl *Controller) *ModeCLI {
	if ctrl == nil {
		return nil
	}
	return &ModeCLI{Ctrl: ctrl}
}

// SetCommander wires the commander channel used by `mode agent <id>
// enter|exit|rotate-password` to enqueue real instructions (review I-1).
// Without it those actions fail loudly instead of pretending to dispatch.
func (m *ModeCLI) SetCommander(c AgentCommander) {
	m.Commander = c
}

// HandleMode implements the `mode` command family:
//
//	mode status
//	mode enter
//	mode exit --password <pw>
//	mode set-password --old <pw> --new <pw>
//	mode unlock --password <pw>
//	mode agent <id> status|enter|exit|rotate-password
func (m *ModeCLI) HandleMode(sub string, args []string, params map[string]string) (string, error) {
	switch sub {
	case "status":
		return m.status()
	case "enter":
		return m.enter(params)
	case "exit":
		return m.exit(params)
	case "unlock":
		return m.unlock(params)
	case "set-password":
		return m.setPassword(params)
	case "agent":
		return m.agent(args, params)
	default:
		return "", fmt.Errorf("mode: unknown subcommand %q", sub)
	}
}

func (m *ModeCLI) status() (string, error) {
	m.Ctrl.Mu.RLock()
	defer m.Ctrl.Mu.RUnlock()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Mode: %s\n", m.Ctrl.Mode))
	for _, v := range m.Ctrl.Vaults {
		st := v.State()
		b.WriteString(fmt.Sprintf("  %s: plaintext=%v enc=%v\n", v.ConfigPath, st.hasPlain, st.hasEnc))
	}
	if m.Ctrl.Secrets.Size() > 0 {
		b.WriteString("Registered agents (cert-fingerprint keyed):\n")
		b.WriteString("  fingerprint                           agent_id                 updated\n")
		for _, e := range m.Ctrl.Secrets.ListEntries() {
			b.WriteString(fmt.Sprintf("  %-38s %-24s %s\n", truncateFP(e.Fingerprint), e.AgentID, e.UpdatedAt.Format("15:04:05")))
		}
	}
	return b.String(), nil
}

func (m *ModeCLI) enter(params map[string]string) (string, error) {
	password := params["password"]
	if password == "" {
		return "", fmt.Errorf("mode enter: --password is required to establish the run-mode secret")
	}
	if err := m.Ctrl.EnterRun(password); err != nil {
		return "", err
	}
	return "Entered run mode — configuration files encrypted.\n", nil
}

func (m *ModeCLI) exit(params map[string]string) (string, error) {
	password := params["password"]
	if err := m.Ctrl.ExitRun(password); err != nil {
		return "", err
	}
	return "Exited to default mode — configuration restored to plaintext.\n", nil
}

func (m *ModeCLI) unlock(params map[string]string) (string, error) {
	// Kernel restart in run mode (Ruling 3): the marker says run but the
	// config is not in memory yet. `mode unlock --password <pw>` loads the
	// protected config into the memory guard before serving continues.
	password := params["password"]
	if password == "" {
		return "", fmt.Errorf("mode unlock: --password is required")
	}
	if err := m.Ctrl.Unlock(password); err != nil {
		return "", err
	}
	// I-1: the protected config is now in memory — feed it into the kernel
	// runtime immediately. The kernel started on config.Default() in run mode
	// (the plaintext was encrypted at shutdown), so this is the moment its
	// real protected settings (weights, threshold, interceptor keys, ...)
	// become active again.
	if m.OnConfigChanged != nil {
		m.Ctrl.Mu.RLock()
		guard := m.Ctrl.Guard
		m.Ctrl.Mu.RUnlock()
		if guard == nil {
			return "", fmt.Errorf("mode unlock: guard not populated after unlock")
		}
		if err := m.OnConfigChanged(string(guard.Snapshot()), true); err != nil {
			return "", fmt.Errorf("mode unlock: apply config to kernel runtime: %w", err)
		}
	}
	return "Unlocked — run-mode config loaded into memory.\n", nil
}

func (m *ModeCLI) setPassword(params map[string]string) (string, error) {
	oldPw := params["old"]
	newPw := params["new"]
	if oldPw == "" || newPw == "" {
		return "", fmt.Errorf("mode set-password: --old and --new are required")
	}
	if err := m.Ctrl.SetPassword(oldPw, newPw); err != nil {
		return "", err
	}
	return "Password rotated; configuration re-encrypted.\n", nil
}

func (m *ModeCLI) agent(args []string, params map[string]string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("mode agent: agent id required")
	}
	agentID := args[0]
	action := "status"
	if len(args) > 1 {
		action = args[1]
	}
	switch action {
	case "status":
		m.Ctrl.Mu.RLock()
		defer m.Ctrl.Mu.RUnlock()
		if s, ok := m.Ctrl.Secrets.LookupByAgent(agentID); ok {
			return fmt.Sprintf("agent %s: registered (updated %s)\n", agentID, s.UpdatedAt.Format("15:04:05")), nil
		}
		return fmt.Sprintf("agent %s: not registered\n", agentID), nil
	case "enter", "exit", "rotate-password":
		// Real instruction dispatch (review I-1): enqueue the agent action via
		// the commander channel. exit/rotate need the registered password (the
		// agent decrypts/re-encrypts with it); enter is self-driven (the agent
		// generates its own ephemeral password) so no params are attached.
		if m.Commander == nil {
			return "", fmt.Errorf("mode agent: commander not available (commander build tag off?)")
		}
		// CLI action vocabulary (enter/exit/rotate-password) maps to the
		// agent-side command names (securemode_enter/exit/rotate).
		cmdName := map[string]string{
			"enter":           "securemode_enter",
			"exit":            "securemode_exit",
			"rotate-password": "securemode_rotate",
		}[action]
		if action == "enter" {
			cmdID := m.Commander.EnqueueCommand(agentID, cmdName, nil)
			return fmt.Sprintf("agent %s: %s enqueued (command_id=%s)\n", agentID, cmdName, cmdID), nil
		}
		sec, ok := m.Ctrl.Secrets.LookupByAgent(agentID)
		if !ok || sec.Password == "" {
			return "", fmt.Errorf("mode agent: agent %q has no registered unlock secret", agentID)
		}
		cmdID := m.Commander.EnqueueCommand(agentID, cmdName, map[string]string{"password": sec.Password})
		return fmt.Sprintf("agent %s: %s enqueued (command_id=%s)\n", agentID, cmdName, cmdID), nil
	default:
		return "", fmt.Errorf("mode agent: unknown action %q", action)
	}
}

// HandleConfigSet implements `config set <key> <value> [--temp|--persist]`
// with the spec §9 two-phase persistence:
//
//	--temp    (default): update the in-memory config, take effect immediately,
//	          never touch disk — a restart falls back to the disk values.
//	--persist: update the in-memory config AND write it to disk in the current
//	          mode's format (plaintext in default mode, encrypted in run
//	          mode); it does NOT take effect until `config reload`.
//
// In run mode a correct --password is required and the in-memory config must
// pass the integrity check before any mutation.
func (m *ModeCLI) HandleConfigSet(args []string, flags map[string]string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("config set: key and value required")
	}
	key, value := args[0], args[1]
	password := flags["password"]
	persist := flags["persist"] == "true" || flags["persist"] == "1"

	// Hold the controller read lock for the WHOLE operation (review I-1). A
	// concurrent mode transition (EnterRun/ExitRun/SetPassword/Startup/Unlock,
	// all write-locked) can no longer interleave with the password check,
	// guard snapshot and persist decision — previously that window could end
	// in a plaintext+.enc residue (ErrResidue) or silently drop updates.
	// None of the work below re-enters c.Mu: Password.Verify only reads a
	// file, the guard methods take the guard's own mutex, and writePersisted
	// (reencryptVault / osWriteFileAll) touches only files — so holding RLock
	// here is deadlock-free, and the lock order stays c.Mu -> guard.mu,
	// consistent with ExitRun's IntegrityOK call.
	m.Ctrl.Mu.RLock()
	defer m.Ctrl.Mu.RUnlock()

	runMode := m.Ctrl.Mode == ModeRun
	guard := m.Ctrl.Guard

	if runMode {
		if password == "" {
			return "", fmt.Errorf("config set: run mode requires --password")
		}
		if !m.Ctrl.Password.Verify(password) {
			return "", fmt.Errorf("config set: incorrect password")
		}
		if guard == nil {
			// Run marker but not yet unlocked: the config is not in memory,
			// so there is nothing safe to edit — fail closed.
			return "", fmt.Errorf("config set: run mode config not loaded (unlock required)")
		}
		if !guard.IntegrityOK() {
			return "", fmt.Errorf("config set: in-memory config integrity check failed")
		}
	}

	// Base the edit on the current config view: the in-memory guard snapshot
	// in run mode, the on-disk plaintext in default mode (so --persist can
	// rewrite the plaintext config per spec §9).
	var snap []byte
	if guard != nil {
		snap = guard.Snapshot()
	} else {
		if len(m.Ctrl.Vaults) == 0 {
			return "", fmt.Errorf("config set: no vault configured")
		}
		plain, err := m.Ctrl.Vaults[0].LoadPlaintext()
		if err != nil {
			return "", fmt.Errorf("config set: read plaintext config: %w", err)
		}
		snap = []byte(plain)
	}
	updated, err := applyKeyValue(string(snap), key, value)
	if err != nil {
		return "", err
	}
	// I-1: feed the updated in-memory config into the kernel runtime — --temp
	// applies immediately (spec §9), --persist only on 'config reload'. Runs
	// BEFORE the guard mutation so a failing hook leaves both the guard and
	// the kernel runtime unchanged (no split state).
	if guard != nil && m.OnConfigChanged != nil {
		if err := m.OnConfigChanged(updated, !persist); err != nil {
			return "", fmt.Errorf("config set: apply to runtime: %w", err)
		}
	}
	if guard != nil {
		guard.Replace([]byte(updated))
	}

	if persist {
		if runMode {
			// Write the UPDATED in-memory snapshot back as encrypted content
			// (review ruling T9): the disk plaintext no longer exists in run
			// mode, and the memory snapshot may have accumulated --temp
			// changes, so re-encrypting stale disk state would lose them.
			if err := m.writePersisted(runMode, []byte(updated), password); err != nil {
				return "", err
			}
			return fmt.Sprintf("config set: %s=%s persisted (encrypted); run 'config reload' to apply\n", key, value), nil
		}
		if err := m.writePersisted(false, []byte(updated), ""); err != nil {
			return "", err
		}
		return fmt.Sprintf("config set: %s=%s persisted (plaintext); run 'config reload' to apply\n", key, value), nil
	}
	if !runMode {
		// Default mode has no in-memory config owned by securemode; applying
		// "temp" to a throwaway copy would silently do nothing.
		return "", fmt.Errorf("config set: default mode has no in-memory config; use --persist to edit the plaintext file")
	}
	return fmt.Sprintf("config set: %s=%s applied in memory (temp, not persisted)\n", key, value), nil
}

// writePersisted writes the updated config to disk in the current mode format.
// In run mode the content is encrypted purely in memory and the .enc replaced
// atomically — reusing Controller.reencryptVault, the Task 8 pattern for
// "encrypt an in-memory snapshot and commit it atomically" (it never reads
// disk state, so temp changes are preserved). In default mode the plaintext
// config is rewritten atomically.
func (m *ModeCLI) writePersisted(runMode bool, content []byte, password string) error {
	if len(m.Ctrl.Vaults) == 0 {
		return fmt.Errorf("config set: no vault configured")
	}
	v := m.Ctrl.Vaults[0]
	if runMode {
		return m.Ctrl.reencryptVault(v, string(content), password)
	}
	return osWriteFileAll(v.ConfigPath, content, 0o600)
}

// osWriteFileAll writes path atomically (tmp + fsync + rename + dir sync),
// creating parent directories as needed — a crash can never leave a torn
// plaintext config.
func osWriteFileAll(path string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, perm); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// applyKeyValue replaces `key = <old>` in an INI-like text with the new value.
// Only existing keys are rewritten; an unknown key is an error (never silently
// appended into an arbitrary section).
func applyKeyValue(content, key, value string) (string, error) {
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(trimmed[:eq]) == key {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + key + " = " + value
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("config set: key %q not found", key)
	}
	return strings.Join(lines, "\n"), nil
}

func truncateFP(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}
