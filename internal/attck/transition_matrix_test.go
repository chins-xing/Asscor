//go:build attck_ext

package attck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTransitionMatrixOverride(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "matrix.json")
	if err := os.WriteFile(good, []byte(`{"T1190":{"T1059":0.95}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.transitionMatrixFile = good
	m.buildTransitionMatrix()
	if got := m.transMatrix["T1190"]["T1059"]; got != 0.95 {
		t.Fatalf("override T1190->T1059 = %v, want 0.95", got)
	}
	// Unlisted transitions keep the built-in defaults.
	if got := m.transMatrix["T1190"]["T1003"]; got != 0.5 {
		t.Fatalf("default T1190->T1003 = %v, want 0.5", got)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"T1190":{"T1059":1.5}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m2 := New()
	m2.transitionMatrixFile = bad
	m2.buildTransitionMatrix()
	if got := m2.transMatrix["T1190"]["T1059"]; got != 0.7 {
		t.Fatalf("invalid override must fall back to default 0.7, got %v", got)
	}
}
