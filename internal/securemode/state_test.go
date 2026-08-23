package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeRun); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMarker(p)
	if err != nil {
		t.Fatal(err)
	}
	if m != ModeRun {
		t.Errorf("mode = %q, want run", m)
	}
}

func TestMarkerMissingDefaults(t *testing.T) {
	m, err := ReadMarker(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if m != ModeDefault {
		t.Errorf("missing marker should default to default mode, got %q", m)
	}
}

func TestMarkerCorruptFailClosed(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeRun); err != nil {
		t.Fatal(err)
	}
	// Corrupt the mode bytes but keep length.
	data, _ := os.ReadFile(p)
	data[0] = 'X'
	data[1] = 'X'
	os.WriteFile(p, data, 0o600)

	_, err := ReadMarker(p)
	if err == nil {
		t.Fatal("corrupt marker must fail-closed with an error")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should mention corrupt, got: %v", err)
	}
}

func TestMarkerTamperModeByte(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeDefault); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	// Flip a byte inside the hash region: read must fail (hash mismatch).
	data[len(data)-1] ^= 0xFF
	os.WriteFile(p, data, 0o600)
	if _, err := ReadMarker(p); err == nil {
		t.Fatal("tampered marker hash must be detected")
	}
}
