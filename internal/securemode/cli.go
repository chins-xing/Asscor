package securemode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ModeCLI is the kernel-side CLI adapter for mode/config commands. It stays
// free of any internal/cli import to avoid a dependency cycle; internal/cli
// wires it via handler functions (Task 10).
type ModeCLI struct {
	Ctrl *Controller
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

// HandleMode implements the `mode` command family:
//
//	mode status
//	mode enter
//	mode exit --password <pw>
//	mode set-password --old <pw> --new <pw>
//	mode agent <id> status|enter|exit|rotate-password
func (m *ModeCLI) HandleMode(sub string, args []string, params map[string]string) (string, error) {
	switch sub {
	case "status":
		return m.status()
	case "enter":
		return m.enter(params)
	case "exit":
		return m.exit(params)
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
		for _, s := range m.Ctrl.Secrets.List() {
			b.WriteString(fmt.Sprintf("  %s (agent %s, updated %s)\n", truncateFP(s.AgentID), s.AgentID, s.UpdatedAt.Format("15:04:05")))
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
		// Actual agent instruction dispatch happens via CommanderInterface
		// (Task 11). This CLI surface returns the intended action for the
		// wiring layer to enqueue.
		return fmt.Sprintf("agent %s: %s instruction prepared (dispatch via commander)\n", agentID, action), nil
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
