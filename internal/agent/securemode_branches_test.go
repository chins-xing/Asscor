package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/securemode"
)

// ---------------------------------------------------------------------------
// securemode remaining branches (gap report §2.6, low-cost closeout).
// ---------------------------------------------------------------------------

// TestExecuteSecureModeCommandUnknown: an unrecognized securemode command hits
// the default branch — logged warning, no state change, no file writes.
func TestExecuteSecureModeCommandUnknown(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	pw := a.secure.password
	encBefore, _ := os.ReadFile(v.ConfigPath + ".enc")

	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-unknown",
		Command:   "securemode_obliterate",
		Params:    map[string]string{"password": pw},
	})

	if a.secure.password != pw || a.secure.locked {
		t.Errorf("unknown command must not touch state, got %+v", a.secure)
	}
	encAfter, _ := os.ReadFile(v.ConfigPath + ".enc")
	if string(encBefore) != string(encAfter) {
		t.Error(".enc must be untouched by an unknown command")
	}
}

// TestExecuteSecureModeCommandRotateWrongPassword: rotate with the wrong
// password must fail without changing the password or the .enc.
func TestExecuteSecureModeCommandRotateWrongPassword(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	pw := a.secure.password
	encBefore, _ := os.ReadFile(v.ConfigPath + ".enc")

	a.executeSecureModeCommand(&apiv1.Command{
		CommandId: "cmd-rotate-bad",
		Command:   "securemode_rotate",
		Params:    map[string]string{"password": "wrong-pw"},
	})

	if a.secure.password != pw {
		t.Errorf("rotate with wrong password must keep the old password, got %q", a.secure.password)
	}
	if a.secure.reported {
		t.Error("reported flag must not change on a failed rotate")
	}
	encAfter, _ := os.ReadFile(v.ConfigPath + ".enc")
	if string(encBefore) != string(encAfter) {
		t.Error(".enc must be untouched after a wrong-password rotate")
	}
	if _, err := v.LoadCiphertext(pw); err != nil {
		t.Fatalf("old password must still decrypt the .enc: %v", err)
	}
}

// TestSecureMaybeBootstrapResidueAfterStartup: a residue (plaintext + .enc
// both present) appearing between startup and the first heartbeat must fail
// closed — secureMaybeBootstrap refuses to overwrite the .enc (report §2.6).
func TestSecureMaybeBootstrapResidueAfterStartup(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash residue appearing after startup: write an .enc next to
	// the still-present plaintext without touching the plaintext.
	payload, err := v.EncryptContent("residue-pw", []byte("[agent]\nheartbeat_sec = 30\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v.ConfigPath+".enc", payload, 0o600); err != nil {
		t.Fatal(err)
	}

	err = a.secureMaybeBootstrap()
	if err == nil {
		t.Fatal("residue between startup and first heartbeat must fail closed")
	}
	if !strings.Contains(err.Error(), "residue") {
		t.Errorf("error = %v, want residue mention", err)
	}
	if a.secure.password != "" {
		t.Errorf("no password must be generated on residue, got %q", a.secure.password)
	}
	if v.HasPlaintext() && v.IsEncrypted() {
		// still residue — nothing was overwritten
	} else {
		t.Errorf("disk state must stay residue (plain=%v enc=%v)", v.HasPlaintext(), v.IsEncrypted())
	}
}

// TestHandleSecureModeResponseSelfRecoverFailure: when the kernel has no
// secret AND the agent's own self-recovery cannot run (unreadable .enc), the
// error surfaces and the miss counter stays at the threshold so the next
// heartbeat retries recovery immediately (report §2.6).
func TestHandleSecureModeResponseSelfRecoverFailure(t *testing.T) {
	// Locked agent whose .enc is unreadable/missing → self-recovery fails at
	// ReadBootstrap (no way to rebuild the config).
	v := &securemode.Vault{
		DataDir:         t.TempDir(),
		ConfigPath:      filepath.Join(t.TempDir(), "missing.ini"),
		BootstrapHeader: "[bootstrap]",
	}
	a := &Agent{secure: &secureState{vault: v, locked: true, noUnlockCount: secureModeMaxNoUnlock - 1}}

	err := a.handleSecureModeResponse(&apiv1.HeartbeatResponse{SecureModeNoSecret: true})
	if err == nil {
		t.Fatal("failed self-recovery must surface an error")
	}
	if !strings.Contains(err.Error(), "self-recovery failed") {
		t.Errorf("error = %v, want self-recovery failure text", err)
	}
	if a.secure.noUnlockCount < secureModeMaxNoUnlock {
		t.Errorf("counter must stay at/above the threshold, got %d", a.secure.noUnlockCount)
	}
	if !a.secure.locked {
		t.Error("agent must remain locked after a failed self-recovery")
	}
}

// TestReloadProtectedConfigMalformedContent: config.Parse is tolerant, so
// malformed plain must not crash and must leave checkers unchanged.
func TestReloadProtectedConfigMalformedContent(t *testing.T) {
	a := NewAgent(DefaultConfig())
	before := len(a.checkers)

	a.reloadProtectedConfig("[[[[ not a config ==== \x00 binary junk")
	if len(a.checkers) != before {
		t.Errorf("checkers changed on malformed content: %d → %d", before, len(a.checkers))
	}
}

// TestReloadProtectedConfigEmptyPlain: empty plain is a no-op (guard at the
// top of reloadProtectedConfig).
func TestReloadProtectedConfigEmptyPlain(t *testing.T) {
	a := NewAgent(DefaultConfig())
	before := len(a.checkers)
	a.cfg.HMACKey = "pre-existing"

	a.reloadProtectedConfig("")
	if len(a.checkers) != before {
		t.Errorf("checkers changed on empty plain: %d → %d", before, len(a.checkers))
	}
	if a.cfg.HMACKey != "pre-existing" {
		t.Errorf("hmac_key must be untouched by empty plain, got %q", a.cfg.HMACKey)
	}
}

// ---------------------------------------------------------------------------
// parseAgentSectionValue — direct unit tests (report §2.6 tail).
// ---------------------------------------------------------------------------

func TestParseAgentSectionValueBasics(t *testing.T) {
	plain := "# comment\n; also comment\n\n[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nhmac_key = shared-secret\nheartbeat_sec = 30\n\n[other]\nhmac_key = not-agent\n"

	if got := parseAgentSectionValue(plain, "hmac_key"); got != "shared-secret" {
		t.Errorf("hmac_key = %q, want shared-secret", got)
	}
	// Keys outside [agent] must be ignored.
	if got := parseAgentSectionValue(plain, "kernel_addr"); got != "" {
		t.Errorf("kernel_addr (bootstrap section) = %q, want empty", got)
	}
	// Missing key.
	if got := parseAgentSectionValue(plain, "nope"); got != "" {
		t.Errorf("missing key = %q, want empty", got)
	}
}

func TestParseAgentSectionValueEdgeCases(t *testing.T) {
	// Value containing spaces and an inline comment character.
	if got := parseAgentSectionValue("[agent]\nkey =  spaced  value  \n", "key"); got != "spaced  value" {
		t.Errorf("spaced value = %q, want trimmed 'spaced  value'", got)
	}
	// Comment line inside the section must be skipped.
	if got := parseAgentSectionValue("[agent]\n# key = commented\nkey = real\n", "key"); got != "real" {
		t.Errorf("comment handling = %q, want real", got)
	}
	// Line without '=' inside the section.
	if got := parseAgentSectionValue("[agent]\nnot-a-kv\nkey = v\n", "key"); got != "v" {
		t.Errorf("no-= line handling = %q, want v", got)
	}
	// No [agent] section at all.
	if got := parseAgentSectionValue("[bootstrap]\nkey = v\n", "key"); got != "" {
		t.Errorf("no agent section = %q, want empty", got)
	}
	// Empty input.
	if got := parseAgentSectionValue("", "key"); got != "" {
		t.Errorf("empty input = %q, want empty", got)
	}
	// Only comments/blank lines.
	if got := parseAgentSectionValue("# c\n\n; c2\n", "key"); got != "" {
		t.Errorf("comment-only input = %q, want empty", got)
	}
	// Case sensitivity: key matching is exact.
	if got := parseAgentSectionValue("[agent]\nHMAC_KEY = x\n", "hmac_key"); got != "" {
		t.Errorf("case-sensitive key = %q, want empty", got)
	}
}
