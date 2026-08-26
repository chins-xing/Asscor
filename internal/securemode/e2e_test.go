package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EKernelAgentFlow simulates the full kernel+agent lifecycle:
// kernel enter run -> agent registers secret -> kernel restart recovery
// (registry persisted, spec §10.1 P0-1) -> agent restart unlock ->
// agent exit via kernel instruction.
//
// Deviation from the plan's reference code (recorded in task-12-report.md):
// the reference assumed the registry survives the kernel restart in memory;
// with the P0-1 persistence design the registration is persisted explicitly
// (the comms hook does this after every heartbeat registration) and recovered
// automatically by Unlock on restart.
func TestE2EKernelAgentFlow(t *testing.T) {
	dir := t.TempDir()

	// --- kernel side ---
	kernelCfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(kernelCfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kernelVault := &Vault{DataDir: dir, ConfigPath: kernelCfg, BootstrapHeader: "[bootstrap]"}
	ctrl := NewController(dir, []*Vault{kernelVault})
	if err := ctrl.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}

	// --- agent reports ephemeral password (fingerprint-keyed) ---
	if err := ctrl.Secrets.Register("fp-agent1", "host-1", "agent-ephemeral-pw"); err != nil {
		t.Fatal(err)
	}
	// The kernel persists the registry (the comms heartbeat hook does this
	// after every successful registration while in run mode).
	if err := ctrl.PersistSecrets(); err != nil {
		t.Fatal(err)
	}

	// --- kernel restart: marker says run -> unlock; registry recovered ---
	ctrl2 := NewController(dir, []*Vault{kernelVault})
	if err := ctrl2.Startup(); err != nil {
		t.Fatal(err)
	}
	if ctrl2.Mode != ModeRun {
		t.Fatalf("kernel restart mode = %q, want run", ctrl2.Mode)
	}
	if err := ctrl2.Unlock("kernel-pw"); err != nil {
		t.Fatal(err)
	}

	// --- agent restart: kernel issues the registered password ---
	agentDir := filepath.Join(dir, "agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	agentCfg := filepath.Join(agentDir, "agent.ini")
	if err := os.WriteFile(agentCfg, []byte("[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentVault := &Vault{DataDir: agentDir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}

	// simulate prior run-mode disk state: agent.ini already encrypted
	if err := agentVault.EncryptFile("agent-ephemeral-pw"); err != nil {
		t.Fatal(err)
	}
	// restart: kernel issues password, agent decrypts
	issued, ok := ctrl2.Secrets.Lookup("fp-agent1")
	if !ok {
		t.Fatal("kernel must have the agent password (recovered from the persisted registry after restart)")
	}
	plain, err := agentVault.LoadCiphertext(issued.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Error("agent config not decrypted with kernel-issued password")
	}

	// --- kernel instructs agent exit (decrypt to plaintext) ---
	if err := agentVault.DecryptFile(issued.Password); err != nil {
		t.Fatal(err)
	}
	st := agentVault.State()
	if !st.hasPlain || st.hasEnc {
		t.Errorf("agent exit state = %+v, want plaintext only", st)
	}
}

// TestE2ECrashResidueRecovery: crash between encrypt stages must not lose
// config — a valid .enc decrypts despite the stale plaintext residue, and the
// manual recovery branch (validate .enc, drop the stale plaintext) restores
// the run-mode disk state.
func TestE2ECrashResidueRecovery(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(cfg, []byte("[weights]\na=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: ""}
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate crash residue: plaintext still present alongside .enc.
	if err := os.WriteFile(cfg, []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := v.State()
	if !st.hasPlain || !st.hasEnc {
		t.Fatalf("residue state not detected: %+v", st)
	}
	// Recovery: validate .enc (with password), then remove stale plaintext.
	plain, err := v.LoadCiphertext("pw")
	if err != nil {
		t.Fatal("valid .enc must decrypt despite residue")
	}
	if !strings.Contains(plain, "a=1") {
		t.Error("recovered content mismatch")
	}
	// The .enc is authoritative; removing the stale plaintext completes the
	// manual recovery and restores the enc-only run-mode disk state.
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	st = v.State()
	if st.hasPlain || !st.hasEnc {
		t.Errorf("after manual recovery state = %+v, want enc-only", st)
	}
}

// TestE2EKernelCrashRegistryRecovery (P2-2 combo #1): kernel crashes after
// entering run mode with a persisted registry; on restart the registry is
// recovered and a restarted (locked) agent unlocks with the recovered
// password.
func TestE2EKernelCrashRegistryRecovery(t *testing.T) {
	dir := t.TempDir()
	kernelCfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(kernelCfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kernelVault := &Vault{DataDir: dir, ConfigPath: kernelCfg, BootstrapHeader: "[bootstrap]"}

	// --- pre-crash: run mode + agent registered + registry persisted ---
	ctrl := NewController(dir, []*Vault{kernelVault})
	if err := ctrl.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Secrets.Register("fp-agent1", "host-1", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.PersistSecrets(); err != nil {
		t.Fatal(err)
	}

	// --- the agent's .enc was already on disk when the kernel crashed ---
	agentDir := filepath.Join(dir, "agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	agentCfg := filepath.Join(agentDir, "agent.ini")
	if err := os.WriteFile(agentCfg, []byte("[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentVault := &Vault{DataDir: agentDir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}
	if err := agentVault.EncryptFile("agent-pw"); err != nil {
		t.Fatal(err)
	}

	// --- kernel crash + restart: Startup sees the run marker, Unlock
	// recovers the registry before serving (fail-closed on registry loss) ---
	ctrl2 := NewController(dir, []*Vault{kernelVault})
	if err := ctrl2.Startup(); err != nil {
		t.Fatal(err)
	}
	if ctrl2.Mode != ModeRun {
		t.Fatalf("kernel restart mode = %q, want run", ctrl2.Mode)
	}
	if err := ctrl2.Unlock("kernel-pw"); err != nil {
		t.Fatal(err)
	}

	// --- agent restart (locked): kernel issues the recovered password ---
	issued, ok := ctrl2.Secrets.Lookup("fp-agent1")
	if !ok {
		t.Fatal("registry must be recovered after kernel crash")
	}
	plain, err := agentVault.LoadCiphertext(issued.Password)
	if err != nil {
		t.Fatalf("restarted agent must unlock with the recovered password: %v", err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Error("protected agent config lost after recovery")
	}
}

// TestE2ERegistryCorruptFailClosed (P2-2 combo #2): the persisted registry is
// corrupted (tampered/disk corruption); the kernel refuses to serve run mode
// (Unlock fails closed), the file is preserved for manual recovery, and
// removing it is the operator's fresh-start escape hatch (agents re-register).
func TestE2ERegistryCorruptFailClosed(t *testing.T) {
	dir := t.TempDir()
	kernelCfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(kernelCfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kernelVault := &Vault{DataDir: dir, ConfigPath: kernelCfg, BootstrapHeader: "[bootstrap]"}

	ctrl := NewController(dir, []*Vault{kernelVault})
	if err := ctrl.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Secrets.Register("fp-agent1", "host-1", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.PersistSecrets(); err != nil {
		t.Fatal(err)
	}

	// Corrupt the persisted registry (bit flip inside the ciphertext).
	sp := SecretsFilePath(dir)
	data, err := os.ReadFile(sp)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(sp, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Restart: Startup still succeeds (marker = run), Unlock fails closed.
	ctrl2 := NewController(dir, []*Vault{kernelVault})
	if err := ctrl2.Startup(); err != nil {
		t.Fatal(err)
	}
	if ctrl2.Mode != ModeRun {
		t.Fatalf("kernel restart mode = %q, want run", ctrl2.Mode)
	}
	if err := ctrl2.Unlock("kernel-pw"); err == nil {
		t.Fatal("corrupt registry must fail unlock (fail-closed: refuse to serve run mode)")
	}
	// The kernel did NOT enter the serving state.
	if ctrl2.Guard != nil {
		t.Error("guard must not be populated when unlock fails")
	}
	// Fail-closed: the corrupt file is preserved (manual recovery evidence),
	// and the registry was not half-loaded.
	if _, err := os.Stat(sp); err != nil {
		t.Error("corrupt registry file must be preserved for manual recovery")
	}
	if ctrl2.Secrets.Size() != 0 {
		t.Errorf("registry must stay empty after failed unlock, got %d entries", ctrl2.Secrets.Size())
	}

	// Manual recovery escape hatch: the operator decides agents will
	// re-register fresh, removes the corrupt file, and unlocks normally.
	if err := os.Remove(sp); err != nil {
		t.Fatal(err)
	}
	if err := ctrl2.Unlock("kernel-pw"); err != nil {
		t.Fatalf("unlock after manual recovery: %v", err)
	}
	if ctrl2.Guard == nil {
		t.Error("guard must be populated after a successful unlock")
	}
}

// TestE2EAgentOnlyRestartOverwrites (P2-2 combo #3): the agent restarts (or
// rotates) while the kernel is alive; the NEW self-generated password
// overwrites the old registration under the same fingerprint, and the old
// password's unlock path dies with it.
func TestE2EAgentOnlyRestartOverwrites(t *testing.T) {
	dir := t.TempDir()
	agentCfg := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"
	if err := os.WriteFile(agentCfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}

	// Kernel-side registry (alive, never restarted).
	reg := NewSecretRegistry()
	if err := reg.Register("fp-agent1", "host-1", "old-pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.EncryptFile("old-pw"); err != nil {
		t.Fatal(err)
	}

	// Agent restarts, rotates to a fresh ephemeral password and re-reports;
	// the kernel overwrites the old registration (same fingerprint, spec
	// §10.1 "新密码覆盖旧登记").
	newPW, err := NewEphemeralPassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RotatePassword("old-pw", newPW); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("fp-agent1", "host-1", newPW); err != nil {
		t.Fatal(err)
	}

	issued, ok := reg.Lookup("fp-agent1")
	if !ok {
		t.Fatal("registration must still exist after re-registration")
	}
	if issued.Password != newPW {
		t.Fatalf("registration must be overwritten with the new password, got %q", issued.Password)
	}
	// The old password is dead: it no longer decrypts the agent config.
	if _, err := v.LoadCiphertext("old-pw"); err == nil {
		t.Error("old password must not decrypt after rotation/overwrite")
	}
	if _, err := v.LoadCiphertext(newPW); err != nil {
		t.Errorf("new password must decrypt the rotated config: %v", err)
	}
}

// TestE2EKernelAgentSimultaneousRestart (P2-2 combo #4): kernel AND agent
// restart together. With an intact registry the kernel recovers it and the
// locked agent unlocks with the recovered password; with an unrecoverable
// registry the kernel refuses run mode and the agent must take the fresh
// registration path (operator restores the plaintext config, the agent
// re-bootstraps with a new password).
func TestE2EKernelAgentSimultaneousRestart(t *testing.T) {
	t.Run("intact registry unlocks agent", func(t *testing.T) {
		dir := t.TempDir()
		kernelCfg := filepath.Join(dir, "config.ini")
		if err := os.WriteFile(kernelCfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		kernelVault := &Vault{DataDir: dir, ConfigPath: kernelCfg, BootstrapHeader: "[bootstrap]"}

		ctrl := NewController(dir, []*Vault{kernelVault})
		if err := ctrl.EnterRun("kernel-pw"); err != nil {
			t.Fatal(err)
		}
		if err := ctrl.Secrets.Register("fp-agent1", "host-1", "agent-pw"); err != nil {
			t.Fatal(err)
		}
		if err := ctrl.PersistSecrets(); err != nil {
			t.Fatal(err)
		}

		// Agent .enc from before the restart.
		agentDir := filepath.Join(dir, "agent")
		if err := os.MkdirAll(agentDir, 0o700); err != nil {
			t.Fatal(err)
		}
		agentCfg := filepath.Join(agentDir, "agent.ini")
		if err := os.WriteFile(agentCfg, []byte("[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		agentVault := &Vault{DataDir: agentDir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}
		if err := agentVault.EncryptFile("agent-pw"); err != nil {
			t.Fatal(err)
		}

		// --- simultaneous restart ---
		ctrl2 := NewController(dir, []*Vault{kernelVault})
		if err := ctrl2.Startup(); err != nil {
			t.Fatal(err)
		}
		if err := ctrl2.Unlock("kernel-pw"); err != nil {
			t.Fatal(err)
		}
		// Locked agent heartbeats: the kernel issues the recovered password.
		issued, ok := ctrl2.Secrets.Lookup("fp-agent1")
		if !ok {
			t.Fatal("kernel must recover the registry after simultaneous restart")
		}
		plain, err := agentVault.LoadCiphertext(issued.Password)
		if err != nil {
			t.Fatalf("agent must unlock with the recovered password: %v", err)
		}
		if !strings.Contains(plain, "heartbeat_sec") {
			t.Error("protected agent config lost after simultaneous restart")
		}
	})

	t.Run("unrecoverable registry -> fresh registration path", func(t *testing.T) {
		// The agent's .enc exists but the kernel's registry is gone (corrupt,
		// deleted, or never persisted). The old ephemeral password is
		// unrecoverable, so the agent cannot decrypt its own .enc. The fresh
		// registration path (spec §10.1): the operator restores the plaintext
		// config; the agent self-generates a NEW password, re-encrypts and
		// re-reports — an entirely new registration.
		dir := t.TempDir()
		agentCfg := filepath.Join(dir, "agent.ini")
		content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"
		if err := os.WriteFile(agentCfg, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		v := &Vault{DataDir: dir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}

		// Prior run-mode state: encrypted with a now-lost password.
		if err := v.EncryptFile("lost-ephemeral-pw"); err != nil {
			t.Fatal(err)
		}
		// Operator restores the plaintext (e.g. from backup) and the stale
		// .enc is discarded — the agent can no longer be unlocked in place.
		if err := os.Remove(v.ConfigPath + ".enc"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(agentCfg, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		// Agent restarts on plaintext: first heartbeat self-generates a fresh
		// password, encrypts, and reports it; the kernel registers it afresh.
		newPW, err := NewEphemeralPassword()
		if err != nil {
			t.Fatal(err)
		}
		if err := v.EncryptFile(newPW); err != nil {
			t.Fatal(err)
		}
		reg := NewSecretRegistry()
		if err := reg.Register("fp-agent1", "host-1", newPW); err != nil {
			t.Fatal(err)
		}
		if _, err := v.LoadCiphertext(newPW); err != nil {
			t.Fatalf("fresh registration must unlock the re-encrypted config: %v", err)
		}
	})
}

// TestE2ECrashTimingResidueBranches (P2-2 combo #5): a crash between the
// three-stage conversion steps leaves different residues; each must route to
// the correct recovery branch.
//
//	Stage 1 (write .enc.tmp) / Stage 2 (verify) crash: plaintext + orphan
//	  .enc.tmp — the plaintext is authoritative and the tmp is inert garbage.
//	Stage 3 (commit .enc, then delete plaintext) crash: plaintext + .enc —
//	  residue, fail-closed, manual recovery validates the .enc.
func TestE2ECrashTimingResidueBranches(t *testing.T) {
	t.Run("plaintext only (no conversion started)", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.ini")
		if err := os.WriteFile(cfg, []byte("[weights]\na=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v := &Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: ""}
		st := v.State()
		if !st.hasPlain || st.hasEnc {
			t.Fatalf("initial state = %+v, want plaintext-only", st)
		}
		// Default-mode startup: plaintext is authoritative.
		ctrl := NewController(dir, []*Vault{v})
		if err := ctrl.Startup(); err != nil {
			t.Fatal(err)
		}
		if ctrl.Mode != ModeDefault {
			t.Fatalf("mode = %q, want default", ctrl.Mode)
		}
	})

	t.Run("stage 1/2 crash: plaintext + orphan .enc.tmp", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.ini")
		if err := os.WriteFile(cfg, []byte("[weights]\na=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v := &Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: ""}
		// Orphaned tmp from a crash before the rename — a partial write that
		// must NEVER be treated as the config or as a residue.
		if err := os.WriteFile(cfg+".enc.tmp", []byte("partial write"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctrl := NewController(dir, []*Vault{v})
		if err := ctrl.Startup(); err != nil {
			t.Fatalf("orphan .enc.tmp must not fail startup: %v", err)
		}
		if ctrl.Mode != ModeDefault {
			t.Fatalf("mode = %q, want default (plaintext authoritative)", ctrl.Mode)
		}
		plain, err := v.LoadPlaintext()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plain, "a=1") {
			t.Error("plaintext must remain authoritative")
		}
	})

	t.Run("stage 3 crash: plaintext + .enc residue", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.ini")
		if err := os.WriteFile(cfg, []byte("[weights]\na=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v := &Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: ""}
		if err := v.EncryptFile("pw"); err != nil {
			t.Fatal(err)
		}
		// Simulate the crash window between ".enc committed" and "plaintext
		// deleted": the stale plaintext reappears alongside the valid .enc.
		if err := os.WriteFile(cfg, []byte("stale plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctrl := NewController(dir, []*Vault{v})
		err := ctrl.Startup()
		if err == nil {
			t.Fatal("plaintext + .enc residue must fail closed on startup")
		}
		if !strings.Contains(err.Error(), "residue") {
			t.Errorf("error = %v, want residue mention", err)
		}
		// Manual recovery: the .enc is valid and decryptable with the known
		// password — the operator validates it, then drops the stale plaintext.
		plain, err := v.LoadCiphertext("pw")
		if err != nil {
			t.Fatalf("valid .enc must decrypt during manual recovery: %v", err)
		}
		if !strings.Contains(plain, "a=1") {
			t.Error("recovered content mismatch")
		}
		if err := os.Remove(cfg); err != nil {
			t.Fatal(err)
		}
		st := v.State()
		if st.hasPlain || !st.hasEnc {
			t.Errorf("after manual recovery state = %+v, want enc-only", st)
		}
	})
}
