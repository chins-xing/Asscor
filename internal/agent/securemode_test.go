package agent

import (
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/securemode"
)

// newSecureTestVault writes an agent.ini with bootstrap + protected sections
// and returns the vault for it.
func newSecureTestVault(t *testing.T) (*securemode.Vault, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n\n[user_check.mysql]\nid = CU-MYSQL-001\ndomain = business_continuity\nname = MySQL Running\ncommand = systemctl is-active mysqld\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &securemode.Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}
	return v, content
}

// TestInitSecureModeFirstStart: plaintext agent.ini → secure state recorded,
// no disk changes yet (encryption is deferred to the first heartbeat so an
// unreachable kernel never locks the config with an unregistered password).
func TestInitSecureModeFirstStart(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if a.secure == nil || a.secure.vault == nil {
		t.Fatal("secure state must be initialized for a plaintext config")
	}
	if a.secure.locked || a.secure.password != "" {
		t.Errorf("first-start state must not be locked or have a password yet, got %+v", a.secure)
	}
	if !v.HasPlaintext() || v.IsEncrypted() {
		t.Error("InitSecureMode must not modify files (encrypt happens on first heartbeat)")
	}
}

// TestInitSecureModeNilVaultNoop: securemode build tag off (nil vault) must
// leave the agent exactly as before.
func TestInitSecureModeNilVaultNoop(t *testing.T) {
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(nil); err != nil {
		t.Fatal(err)
	}
	if a.secure != nil {
		t.Error("nil vault must not create secure state")
	}
}

// TestInitSecureModeRestartLocked: enc-only disk state (run-mode restart) →
// agent is locked and recovers connectivity essentials from the .enc
// bootstrap without the password.
func TestInitSecureModeRestartLocked(t *testing.T) {
	v, _ := newSecureTestVault(t)
	if err := v.EncryptFile("prev-pw"); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.KernelAddr = "127.0.0.1:50051" // flag default, untouched
	a := NewAgent(cfg)
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if a.secure == nil || !a.secure.locked {
		t.Fatalf("enc-only state must be locked, got %+v", a.secure)
	}
	if a.cfg.KernelAddr != "127.0.0.1:50051" {
		t.Errorf("bootstrap kernel_addr should have been applied, got %q", a.cfg.KernelAddr)
	}
}

// TestInitSecureModeResidueFails: plaintext + .enc both present (crash
// residue) must fail closed, matching Controller.Startup semantics.
func TestInitSecureModeResidueFails(t *testing.T) {
	v, _ := newSecureTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v.ConfigPath, []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err == nil {
		t.Fatal("crash residue (plaintext + .enc) must fail closed")
	}
}

// TestSecureMaybeBootstrapEncrypts: first heartbeat of a plaintext config
// self-generates the ephemeral password and encrypts agent.ini.
func TestSecureMaybeBootstrapEncrypts(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	if len(a.secure.password) != 64 {
		t.Errorf("ephemeral password length = %d, want 64", len(a.secure.password))
	}
	if v.HasPlaintext() || !v.IsEncrypted() {
		t.Fatalf("after bootstrap: plaintext=%v enc=%v, want enc-only", v.HasPlaintext(), v.IsEncrypted())
	}
	// Idempotent: a second call must not re-encrypt or change the password.
	pw := a.secure.password
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	if a.secure.password != pw {
		t.Error("second bootstrap must be a no-op")
	}
}

// TestAttachSecureModeReport: the ephemeral password is attached exactly once;
// a locked state (restart) and empty passwords never attach.
func TestAttachSecureModeReport(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	a.cfg.TLSEnabled = true
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	pw := a.secure.password

	req := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req)
	if req.SecureMode == nil || req.SecureMode.Password != pw {
		t.Fatalf("first report must carry the password, got %+v", req.SecureMode)
	}
	// After reporting, further heartbeats must not repeat it.
	a.secure.reported = true
	req2 := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req2)
	if req2.SecureMode != nil {
		t.Error("password must not be re-reported after success")
	}
	// Locked restart: no report until unlocked.
	a.secure = &secureState{vault: v, locked: true, password: pw}
	req3 := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req3)
	if req3.SecureMode != nil {
		t.Error("locked agent must not report a password")
	}
	// No password (post-exit): no report.
	a.secure = &secureState{vault: v}
	req4 := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req4)
	if req4.SecureMode != nil {
		t.Error("agent without a password must not report")
	}
	// No secure state at all (tag off): no report.
	a.secure = nil
	req5 := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req5)
	if req5.SecureMode != nil {
		t.Error("agent without secure state must not report")
	}
}

// TestAttachSecureModeReportNoTLS: without mTLS there is no certificate
// fingerprint for the kernel to key the registration on — the report is
// skipped (dev mode).
func TestAttachSecureModeReportNoTLS(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	a.cfg.TLSEnabled = false
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	req := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req)
	if req.SecureMode != nil {
		t.Error("agent without mTLS must not report (no fingerprint to key on)")
	}
}

// TestExecuteSecureModeExit: kernel-issued exit decrypts the .enc back to
// plaintext and clears the ephemeral password (default mode restored).
func TestExecuteSecureModeExit(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	pw := a.secure.password

	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-exit",
		Command:   "securemode_exit",
		Params:    map[string]string{"password": pw},
	})
	if !v.HasPlaintext() || v.IsEncrypted() {
		t.Errorf("after exit: plaintext=%v enc=%v, want plaintext only", v.HasPlaintext(), v.IsEncrypted())
	}
	if a.secure.password != "" || a.secure.locked || a.secure.reported {
		t.Errorf("after exit secure state must be cleared, got %+v", a.secure)
	}
}

// TestExecuteSecureModeRotate: kernel-issued rotate re-encrypts with a fresh
// self-generated password and arms the next-heartbeat report.
func TestExecuteSecureModeRotate(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	a.cfg.TLSEnabled = true
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	oldPW := a.secure.password

	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-rotate",
		Command:   "securemode_rotate",
		Params:    map[string]string{"password": oldPW},
	})
	if a.secure.password == oldPW || a.secure.password == "" {
		t.Errorf("password must rotate to a fresh value, got %q", a.secure.password)
	}
	if a.secure.reported {
		t.Error("reported flag must reset so the next heartbeat reports the new password")
	}
	if _, err := v.LoadCiphertext(a.secure.password); err != nil {
		t.Fatalf("new password must decrypt the .enc: %v", err)
	}
	// The next heartbeat carries the new password.
	req := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req)
	if req.SecureMode == nil || req.SecureMode.Password != a.secure.password {
		t.Errorf("next report must carry the new password, got %+v", req.SecureMode)
	}
}

// TestExecuteSecureModeUnlockReloadsConfig (handover Ruling 2): a run-mode
// restart agent (locked, only bootstrap available at startup) unlocks with the
// kernel-issued password and RELOADS the protected config so subsequent
// heartbeats carry the correct check set.
func TestExecuteSecureModeUnlockReloadsConfig(t *testing.T) {
	v, content := newSecureTestVault(t)
	if err := v.EncryptFile("registered-pw"); err != nil {
		t.Fatal(err)
	}
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if !a.secure.locked {
		t.Fatal("restart agent must start locked")
	}
	baseline := len(a.checkers) // builtin-only: protected user check not loaded yet

	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-unlock",
		Command:   "securemode_unlock",
		Params:    map[string]string{"password": "registered-pw"},
	})
	if a.secure.locked || a.secure.password != "registered-pw" {
		t.Errorf("unlock must clear locked and store the password, got %+v", a.secure)
	}
	if len(a.checkers) != baseline+1 {
		t.Errorf("after unlock checkers = %d, want %d (user check reloaded)", len(a.checkers), baseline+1)
	}
	found := false
	for _, c := range a.checkers {
		if c.ID == "CU-MYSQL-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("CU-MYSQL-001 must be loaded after unlock")
	}
	// The decrypted content must round-trip to the original agent.ini.
	plain, err := v.LoadCiphertext("registered-pw")
	if err != nil {
		t.Fatal(err)
	}
	if plain != content {
		t.Errorf("unlocked content mismatch:\ngot  %q\nwant %q", plain, content)
	}
}

// TestExecuteSecureModeCommandMissingPassword: a securemode command without a
// password is rejected without touching files.
func TestExecuteSecureModeCommandMissingPassword(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	encBefore, _ := os.ReadFile(v.ConfigPath + ".enc")
	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-nopw",
		Command:   "securemode_exit",
		Params:    map[string]string{},
	})
	encAfter, _ := os.ReadFile(v.ConfigPath + ".enc")
	if string(encBefore) != string(encAfter) {
		t.Error(".enc must be untouched when the password is missing")
	}
	if v.HasPlaintext() {
		t.Error("exit without password must not decrypt")
	}
}

// TestExecuteSecureModeCommandWrongPassword: wrong password must fail without
// modifying the .enc.
func TestExecuteSecureModeCommandWrongPassword(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	encBefore, _ := os.ReadFile(v.ConfigPath + ".enc")
	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-badpw",
		Command:   "securemode_exit",
		Params:    map[string]string{"password": "wrong"},
	})
	encAfter, _ := os.ReadFile(v.ConfigPath + ".enc")
	if string(encBefore) != string(encAfter) {
		t.Error(".enc must be untouched after a wrong-password command")
	}
	if v.HasPlaintext() {
		t.Error("wrong password must not decrypt")
	}
}

// TestExecuteSecureModeCommandNoSecureState: commands arriving on an agent
// without secure state (build tag off) are ignored safely.
func TestExecuteSecureModeCommandNoSecureState(t *testing.T) {
	a := NewAgent(DefaultConfig())
	// Must not panic; no files exist to touch.
	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-x",
		Command:   "securemode_exit",
		Params:    map[string]string{"password": "pw"},
	})
}
