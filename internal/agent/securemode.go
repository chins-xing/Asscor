package agent

import (
	"fmt"
	"strings"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/securemode"
)

// secureState is the agent's secure-mode runtime state. It is nil when the
// securemode build tag is off (cmd/agent agentSecureVault returns nil), so
// default builds behave exactly as before.
type secureState struct {
	vault    *securemode.Vault
	password string // ephemeral unlock secret; memory only, never persisted (spec §3.1/P1-1)
	reported bool   // password already accepted by the kernel
	locked   bool   // run-mode restart: awaiting the kernel-issued password
}

// InitSecureMode records the agent's secure-mode vault and classifies the
// startup state. It is a no-op for a nil vault (securemode tag off). No files
// are modified here: first-start encryption is deferred to the first heartbeat
// (secureMaybeBootstrap) so an unreachable kernel never leaves the config
// locked with a password that was not registered anywhere.
func (a *Agent) InitSecureMode(vault *securemode.Vault) error {
	if vault == nil {
		return nil
	}
	switch {
	case vault.HasPlaintext() && vault.IsEncrypted():
		// Crash residue: plaintext + .enc both present. Manual recovery
		// required (matches Controller.Startup's fail-closed semantics).
		return fmt.Errorf("secure mode: crash residue on %s (plaintext and .enc both present) — manual recovery required", vault.ConfigPath)
	case vault.HasPlaintext():
		a.secure = &secureState{vault: vault}
		if !a.cfg.TLSEnabled {
			logger.WithComponent("agent").Warn("secure mode active but mTLS is disabled — the kernel cannot key the password registration on a certificate fingerprint")
		}
		logger.WithComponent("agent").Info("secure mode: agent config plaintext — will encrypt and report on first heartbeat")
	case vault.IsEncrypted():
		a.secure = &secureState{vault: vault, locked: true}
		if err := a.applyBootstrapFromVault(); err != nil {
			logger.WithComponent("agent").Warn("secure mode: cannot recover bootstrap connectivity essentials", "error", err)
		}
		logger.WithComponent("agent").Info("secure mode: agent config encrypted — awaiting kernel-issued password (locked)")
	default:
		logger.WithComponent("agent").Warn("secure mode: no agent config file found (plaintext or .enc) — nothing to protect")
		a.secure = &secureState{vault: vault}
	}
	return nil
}

// applyBootstrapFromVault recovers connectivity essentials (kernel address,
// cert paths) from the .enc bootstrap section on a run-mode restart, when the
// plaintext agent.ini no longer exists. Values are applied only when the flag
// defaults are still in place (an explicit --kernel/--cert-dir flag wins).
func (a *Agent) applyBootstrapFromVault() error {
	boot, err := a.secure.vault.ReadBootstrap()
	if err != nil {
		return fmt.Errorf("read bootstrap from .enc: %w", err)
	}
	vals := map[string]string{}
	for _, line := range strings.Split(boot, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 {
			vals[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
		}
	}
	if v := vals["kernel_addr"]; v != "" && a.cfg.KernelAddr == "127.0.0.1:50051" {
		a.cfg.KernelAddr = v
	}
	if v := vals["cert_dir"]; v != "" && a.cfg.CertDir == "" {
		a.cfg.CertDir = v
	}
	if v := vals["tls_enabled"]; v != "" && !a.cfg.TLSEnabled {
		a.cfg.TLSEnabled = v == "true" || v == "yes" || v == "1"
	}
	if v := vals["tls_skip_verify"]; v != "" && !a.cfg.TLSSkipVerify {
		a.cfg.TLSSkipVerify = v == "true" || v == "yes" || v == "1"
	}
	logger.WithComponent("agent").Info("secure mode: bootstrap connectivity restored from .enc", "kernel_addr", a.cfg.KernelAddr)
	return nil
}

// secureMaybeBootstrap performs the first-start secure-mode bootstrap exactly
// once: self-generate the ephemeral password and encrypt agent.ini so the
// first heartbeat can report the password to the kernel (spec §8.2). Deferred
// from startup so an unreachable kernel never locks the config with an
// unregistered password. No-op unless the secure state is active and the
// config is still plaintext.
func (a *Agent) secureMaybeBootstrap() error {
	if a.secure == nil || a.secure.vault == nil || a.secure.locked || a.secure.password != "" {
		return nil
	}
	if !a.secure.vault.HasPlaintext() {
		return nil // already encrypted or missing; nothing to bootstrap
	}
	if a.secure.vault.IsEncrypted() {
		// Residue appeared between startup and the first heartbeat — do not
		// overwrite the .enc blindly.
		return fmt.Errorf("secure mode: crash residue on %s (plaintext and .enc both present)", a.secure.vault.ConfigPath)
	}
	pw, err := securemode.NewEphemeralPassword()
	if err != nil {
		return fmt.Errorf("secure mode: generate ephemeral password: %w", err)
	}
	if err := a.secure.vault.EncryptFile(pw); err != nil {
		return fmt.Errorf("secure mode: encrypt agent config: %w", err)
	}
	a.secure.password = pw
	a.secure.reported = false
	logger.WithComponent("agent").Info("secure mode: agent config encrypted — ephemeral password ready to report")
	return nil
}

// attachSecureModeReport fills the heartbeat's SecureMode field with the
// ephemeral password until the kernel has accepted it. Locked agents (run-mode
// restart) and agents without mTLS (no certificate fingerprint to key the
// registration on) never report.
func (a *Agent) attachSecureModeReport(req *apiv1.HeartbeatRequest) {
	if a.secure == nil || a.secure.locked || a.secure.password == "" || a.secure.reported {
		return
	}
	if !a.cfg.TLSEnabled {
		return
	}
	req.SecureMode = &apiv1.SecureModeReport{Password: a.secure.password}
}

// executeSecureModeCommand handles kernel-issued secure-mode instructions. The
// kernel supplies the agent's current (or registered) ephemeral password in
// Params["password"]; the command itself is HMAC-authenticated by
// executePendingCommands before it reaches this dispatch.
func (a *Agent) executeSecureModeCommand(cmd *apiv1.Command) {
	if a.secure == nil || a.secure.vault == nil {
		logger.WithComponent("agent").Warn("securemode command ignored: secure mode not active", "command_id", cmd.CommandId)
		return
	}
	pw := cmd.Params["password"]
	if pw == "" {
		logger.WithComponent("agent").Warn("securemode command missing password", "command_id", cmd.CommandId)
		return
	}
	switch cmd.Command {
	case "securemode_exit":
		// Decrypt .enc back to plaintext (kernel-requested mode exit) and
		// clear the ephemeral secret — the agent is back in default mode.
		if err := a.secure.vault.DecryptFile(pw); err != nil {
			logger.WithComponent("agent").Error("securemode exit failed", "command_id", cmd.CommandId, "error", err)
			return
		}
		a.secure.password = ""
		a.secure.reported = false
		a.secure.locked = false
		logger.WithComponent("agent").Info("secure mode exited — agent config restored to plaintext", "command_id", cmd.CommandId)
	case "securemode_rotate":
		// Re-encrypt with a fresh self-generated password and report it on the
		// next heartbeat (spec §8.2 password rotation).
		newPW, err := securemode.NewEphemeralPassword()
		if err != nil {
			logger.WithComponent("agent").Error("securemode rotate: generate new password failed", "command_id", cmd.CommandId, "error", err)
			return
		}
		if err := a.secure.vault.RotatePassword(pw, newPW); err != nil {
			logger.WithComponent("agent").Error("securemode rotate failed", "command_id", cmd.CommandId, "error", err)
			return
		}
		a.secure.password = newPW
		a.secure.reported = false
		logger.WithComponent("agent").Info("secure mode password rotated — new ephemeral password will be reported on the next heartbeat", "command_id", cmd.CommandId)
	case "securemode_unlock":
		// Run-mode restart: the kernel issues the registered password; the
		// agent decrypts in memory and RELOADS the protected config so
		// subsequent heartbeats carry the correct check set (Ruling 2).
		plain, err := a.secure.vault.LoadCiphertext(pw)
		if err != nil {
			logger.WithComponent("agent").Error("securemode unlock failed", "command_id", cmd.CommandId, "error", err)
			return
		}
		a.secure.password = pw
		a.secure.locked = false
		a.secure.reported = false
		a.reloadProtectedConfig(plain)
		logger.WithComponent("agent").Info("secure mode unlocked — protected config reloaded", "command_id", cmd.CommandId)
	default:
		logger.WithComponent("agent").Warn("unknown securemode command", "command_id", cmd.CommandId, "command", cmd.Command)
	}
}

// reloadProtectedConfig re-derives check-affecting configuration (user checks
// + delta overrides) from agent.ini content after an unlock, so subsequent
// heartbeats carry the correct check set. Timing/address fields are NOT
// re-applied mid-run — they take effect on the next restart.
func (a *Agent) reloadProtectedConfig(plain string) {
	if plain == "" {
		return
	}
	full, err := config.Parse(plain)
	if err != nil {
		logger.WithComponent("agent").Warn("securemode config reload: parse failed", "error", err)
		return
	}
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	a.cfg.UserCheckItems = config.ParseUserChecks(full.AdapterConfig)
	a.cfg.CheckDeltas = full.CheckDeltas
	a.checkers = buildAgentCheckers(a.cfg, a.syncedChecks)
	logger.WithComponent("agent").Info("securemode config reloaded",
		"user_checks", len(a.cfg.UserCheckItems), "delta_overrides", len(a.cfg.CheckDeltas))
}
