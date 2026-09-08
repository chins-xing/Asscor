package securemode

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVaultStateSingleSnapshot (audit RC-M1): State must derive plaintext and
// .enc existence from ONE directory read so a concurrent conversion cannot
// slip a half-state between two independent stats. The behavioral contract:
// whatever exists at snapshot time is what is reported, and a residue
// (both present) is detected in the same read.
func TestVaultStateSingleSnapshot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.ini")
	v := &Vault{DataDir: dir, ConfigPath: cfgPath}

	// Neither file → none.
	st := v.State()
	if st.hasPlain || st.hasEnc {
		t.Fatalf("empty dir state = %+v, want none", st)
	}

	// Only plaintext → default.
	if err := os.WriteFile(cfgPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st = v.State()
	if !st.hasPlain || st.hasEnc {
		t.Fatalf("plaintext-only state = %+v, want hasPlain only", st)
	}

	// Both → residue (single snapshot detects both).
	if err := os.WriteFile(cfgPath+".enc", []byte("enc"), 0o600); err != nil {
		t.Fatal(err)
	}
	st = v.State()
	if !st.hasPlain || !st.hasEnc {
		t.Fatalf("residue state = %+v, want both", st)
	}

	// Remove plaintext → run (enc only).
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	st = v.State()
	if st.hasPlain || !st.hasEnc {
		t.Fatalf("enc-only state = %+v, want hasEnc only", st)
	}
}

// TestVaultStateRelativeConfigPath: the agent builds a Vault with
// DataDir="" and a bare (relative) agent.ini; State must still resolve the
// config's directory correctly (audit RC-M1 regression guard).
func TestVaultStateRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldwd)

	cfgPath := "agent.ini"
	v := &Vault{DataDir: "", ConfigPath: cfgPath}
	if err := os.WriteFile(cfgPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath+".enc", []byte("e"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := v.State()
	if !st.hasPlain || !st.hasEnc {
		t.Fatalf("relative-path residue state = %+v, want both", st)
	}
}
