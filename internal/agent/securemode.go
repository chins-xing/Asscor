package agent

import (
	"fmt"
	"strings"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/securemode"
)

// secureModeMaxNoUnlock is the number of consecutive heartbeats without a
// successful unlock that a locked agent tolerates before triggering the
// spec §8.2 self-recovery (self-generate a new password, re-encrypt its .enc,
// re-report). The kernel's SecureModeNoSecret signal short-circuits this wait
// (review I-2) — the counter is the fallback for kernels that never signal
// (e.g. the securemode build tag off).
const secureModeMaxNoUnlock = 3

// secureState is the agent's secure-mode runtime state. It is nil when the
// securemode build tag is off (cmd/agent agentSecureVault returns nil), so
// default builds behave exactly as before.
type secureState struct {
	vault    *securemode.Vault
	password string // ephemeral unlock secret; memory only, never persisted (spec §3.1/P1-1)
	reported bool   // password already accepted by the kernel
	locked   bool   // run-mode restart: awaiting the kernel-issued password
	// noUnlockCount counts consecutive heartbeats without a successful unlock
	// while locked (review I-2). Reaching secureModeMaxNoUnlock triggers
	// secureSelfRecover.
	noUnlockCount int
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
// plaintext agent.ini no longer exists. Values are applied only for keys
// whose flag was NOT explicitly set on the command line (review I-3): the old
// default-value sentinels (CertDir == "" / !TLSEnabled) were dead code
// because main.go applies the flag defaults unconditionally, and a magic
// default string for kernel_addr was fragile — explicit-flag tracking is the
// only reliable "operator did not override this" signal.
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
	if v := vals["kernel_addr"]; v != "" && !a.flagExplicit("kernel") {
		a.cfg.KernelAddr = v
	}
	if v := vals["cert_dir"]; v != "" && !a.flagExplicit("cert-dir") {
		a.cfg.CertDir = v
	}
	if v := vals["tls_enabled"]; v != "" && !a.flagExplicit("tls") {
		a.cfg.TLSEnabled = v == "true" || v == "yes" || v == "1"
	}
	if v := vals["tls_skip_verify"]; v != "" && !a.flagExplicit("tls-skip-verify") {
		a.cfg.TLSSkipVerify = v == "true" || v == "yes" || v == "1"
	}
	logger.WithComponent("agent").Info("secure mode: bootstrap connectivity restored from .enc", "kernel_addr", a.cfg.KernelAddr)
	return nil
}

// flagExplicit reports whether the operator passed the flag explicitly
// (recorded by cmd/agent/main.go via flag.Visit). A nil map (library/test
// use) means nothing was explicit, so bootstrap values apply.
func (a *Agent) flagExplicit(name string) bool {
	return a.cfg.ExplicitFlags != nil && a.cfg.ExplicitFlags[name]
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

// attachSecureModeReport fills the heartbeat's SecureMode field: locked
// agents (run-mode restart) declare Locked so the kernel can issue the
// registered password back in the response (review I-1); first-run agents
// report the ephemeral password until the kernel has accepted it. Agents
// without mTLS (no certificate fingerprint to key the registration on) never
// report.
func (a *Agent) attachSecureModeReport(req *apiv1.HeartbeatRequest) {
	if a.secure == nil {
		return
	}
	if !a.cfg.TLSEnabled {
		return
	}
	if a.secure.locked {
		// Run-mode restart: no password to report; ask the kernel for the
		// registered one (delivered as SecureModeUnlock in the response).
		req.SecureMode = &apiv1.SecureModeReport{Locked: true}
		return
	}
	if a.secure.password == "" || a.secure.reported {
		return
	}
	req.SecureMode = &apiv1.SecureModeReport{Password: a.secure.password}
}

// executeSecureModeCommand handles kernel-issued secure-mode instructions. The
// kernel supplies the agent's current (or registered) ephemeral password in
// Params["password"] for exit/rotate/unlock; the command itself is
// HMAC-authenticated by executePendingCommands before it reaches this
// dispatch. Unlock normally arrives via the heartbeat response instead
// (unlockWithPassword) because a locked agent cannot verify a command yet.
func (a *Agent) executeSecureModeCommand(cmd *apiv1.Command) {
	if a.secure == nil || a.secure.vault == nil {
		logger.WithComponent("agent").Warn("securemode command ignored: secure mode not active", "command_id", cmd.CommandId)
		return
	}
	switch cmd.Command {
	case "securemode_enter":
		// Kernel-requested entry into run mode (spec §8.2): force the
		// first-start bootstrap (self-generate password + encrypt + report on
		// the next heartbeat). Normally the agent self-enters on its first
		// heartbeat; this lets the operator trigger it immediately and is a
		// no-op once entered. No password is involved — the agent generates
		// its own ephemeral secret.
		if err := a.secureMaybeBootstrap(); err != nil {
			logger.WithComponent("agent").Error("securemode enter failed", "command_id", cmd.CommandId, "error", err)
			return
		}
		logger.WithComponent("agent").Info("secure mode entered (kernel-requested)", "command_id", cmd.CommandId)
	case "securemode_exit", "securemode_rotate", "securemode_unlock":
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
			// Re-encrypt with a fresh self-generated password and report it on
			// the next heartbeat (spec §8.2 password rotation).
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
			// Legacy/pending-command path; the primary unlock channel is the
			// heartbeat response (unlockWithPassword), which works even when
			// the agent has no hmac_key yet.
			if err := a.unlockWithPassword(pw); err != nil {
				logger.WithComponent("agent").Error("securemode unlock failed", "command_id", cmd.CommandId, "error", err)
				return
			}
			logger.WithComponent("agent").Info("secure mode unlocked — protected config reloaded", "command_id", cmd.CommandId)
		}
	default:
		logger.WithComponent("agent").Warn("unknown securemode command", "command_id", cmd.CommandId, "command", cmd.Command)
	}
}

// unlockWithPassword unlocks the agent with the kernel-issued registered
// password (received over the authenticated mTLS heartbeat channel, review
// I-1) and reloads the protected config — including hmac_key — so subsequent
// pending commands (exit/rotate) pass HMAC verification (review I-2). A
// no-op when the agent is not locked.
func (a *Agent) unlockWithPassword(pw string) error {
	if a.secure == nil || !a.secure.locked {
		return nil
	}
	plain, err := a.secure.vault.LoadCiphertext(pw)
	if err != nil {
		return fmt.Errorf("secure mode unlock: %w", err)
	}
	a.secure.password = pw
	a.secure.locked = false
	a.secure.reported = false
	a.reloadProtectedConfig(plain)
	logger.WithComponent("agent").Info("secure mode unlocked — protected config reloaded")
	return nil
}

// handleSecureModeResponse processes the kernel's secure-mode response after
// a heartbeat (review I-2). While locked (run-mode restart):
//
//   - an issued unlock password is applied; a success resets the miss counter,
//     a failure counts as a miss and keeps the agent locked (stale/wrong
//     registration self-heals via the counter → self-recovery);
//   - otherwise the miss counter grows — the kernel's SecureModeNoSecret
//     signal (no registration for this fingerprint) jumps straight to the
//     spec §8.2 self-recovery threshold, and N consecutive misses do the same
//     (covers kernels that never signal, e.g. the securemode tag off).
//
// It is a no-op for unlocked agents.
func (a *Agent) handleSecureModeResponse(resp *apiv1.HeartbeatResponse) error {
	if a.secure == nil || !a.secure.locked {
		return nil
	}
	if resp.SecureModeUnlock != nil && resp.SecureModeUnlock.Password != "" {
		if err := a.unlockWithPassword(resp.SecureModeUnlock.Password); err != nil {
			a.secure.noUnlockCount++
			return fmt.Errorf("secure mode unlock failed: %w", err)
		}
		a.secure.noUnlockCount = 0
		return nil
	}
	// No unlock issued this cycle.
	if resp.SecureModeNoSecret {
		a.secure.noUnlockCount = secureModeMaxNoUnlock
	} else {
		a.secure.noUnlockCount++
	}
	if a.secure.noUnlockCount >= secureModeMaxNoUnlock {
		if err := a.secureSelfRecover(); err != nil {
			// Keep the counter at the threshold: the next heartbeat retries
			// the recovery immediately instead of re-waiting N cycles.
			return fmt.Errorf("secure mode self-recovery failed: %w", err)
		}
	}
	return nil
}

// secureSelfRecover implements spec §8.2's last-resort path: when the kernel
// can no longer provide this agent's registered unlock secret (registry lost
// or unrecoverable), the agent self-generates a fresh ephemeral password and
// re-encrypts its OWN .enc with it (overwriting the old encryption — the old
// protected content is unrecoverable without the old password, so it is lost
// by design in this recovery; only the still-readable bootstrap section
// survives). The report is re-armed so the next heartbeat registers the new
// password as a fresh registration (reported=false). This is a LOCAL agent
// action: the kernel only signals (SecureModeNoSecret) and never supplies the
// new password — a malicious kernel cannot force a specific password on the
// agent (review I-2 security note).
func (a *Agent) secureSelfRecover() error {
	if a.secure == nil || !a.secure.locked || a.secure.vault == nil {
		return nil
	}
	newPW, err := securemode.NewEphemeralPassword()
	if err != nil {
		return fmt.Errorf("self-recover: generate new password: %w", err)
	}
	// Rebuild a minimal config: the still-readable bootstrap section plus an
	// empty protected section (old settings lost — the documented cost of
	// this recovery).
	boot, err := a.secure.vault.ReadBootstrap()
	if err != nil {
		return fmt.Errorf("self-recover: read bootstrap: %w", err)
	}
	fresh := strings.TrimRight(boot, "\n") + "\n\n[agent]\n"
	if err := a.secure.vault.ReencryptOverwrite(newPW, []byte(fresh)); err != nil {
		return fmt.Errorf("self-recover: re-encrypt: %w", err)
	}
	a.secure.password = newPW
	a.secure.locked = false
	a.secure.reported = false
	a.secure.noUnlockCount = 0
	logger.WithComponent("agent").Warn("secure mode: kernel did not provide the unlock password — self-recovered with a fresh ephemeral password; previous protected settings were lost (spec §8.2)")
	return nil
}

// secureReArmReport re-arms the password report when the kernel signals it has
// no registration for this agent (review I-2 derived case): an UNLOCKED agent
// whose registration was lost (kernel restarted with an unrecoverable
// registry) must re-report its password on the next heartbeat so the kernel
// re-registers it — otherwise its next restart would lock with no way back.
func (a *Agent) secureReArmReport(resp *apiv1.HeartbeatResponse) {
	if a.secure == nil || a.secure.locked || a.secure.password == "" {
		return
	}
	if resp.SecureModeNoSecret {
		a.secure.reported = false
		logger.WithComponent("agent").Warn("secure mode: kernel has no registration for this agent — re-reporting the ephemeral password on the next heartbeat")
	}
}

// reloadProtectedConfig re-derives check-affecting configuration (user checks
// + delta overrides) from agent.ini content after an unlock, so subsequent
// heartbeats carry the correct check set. It also restores hmac_key from the
// protected [agent] section (review I-2): a locked restart has no plaintext,
// so without this every pending command — including exit/rotate — would be
// rejected by verifyCommandSignature and the agent would stay locked.
// Timing/address fields are NOT re-applied mid-run — they take effect on the
// next restart.
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
	// The [agent] section is not part of AdapterConfig; parse it directly for
	// hmac_key (mirrors cmd/agent main.go loadConfigFile). Restoring it makes
	// the post-unlock agent behave exactly like a plaintext startup, where
	// the config value wins over the ASSCOR_HMAC_KEY env fallback.
	if hk := parseAgentSectionValue(plain, "hmac_key"); hk != "" {
		a.cfg.HMACKey = hk
		a.hmacKeyConfigured = true
	}
	a.checkers = buildAgentCheckers(a.cfg, a.syncedChecks)
	logger.WithComponent("agent").Info("securemode config reloaded",
		"user_checks", len(a.cfg.UserCheckItems), "delta_overrides", len(a.cfg.CheckDeltas))
}

// parseAgentSectionValue extracts a key's value from the [agent] section of
// an agent.ini-style text (mirrors cmd/agent main.go loadConfigFile's section
// parser). Returns "" when the key is absent.
func parseAgentSectionValue(plain, key string) string {
	section := ""
	for _, line := range strings.Split(plain, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "agent" {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 && strings.TrimSpace(line[:eq]) == key {
			return strings.TrimSpace(line[eq+1:])
		}
	}
	return ""
}
