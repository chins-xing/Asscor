//go:build securemode

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/asscor/asscor/internal/securemode"
)

// writeTestConfig creates a realistic config with a [bootstrap] section so
// the vault layout matches the kernel's config.ini.
func writeTestConfig(t *testing.T, dataDir, configPath string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "[bootstrap]\nlisten = :50051\nlog_output = stderr\n\n[main]\nthreshold = 80\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInitSecureModeFreshDir(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	writeTestConfig(t, dataDir, configPath)

	ctrl, err := initSecureMode(nil, dataDir, configPath)
	if err != nil {
		t.Fatalf("initSecureMode on a fresh dir must succeed, got: %v", err)
	}
	if ctrl == nil {
		t.Fatal("securemode tag on: initSecureMode must return a controller")
	}
	if ctrl.Mode != securemode.ModeDefault {
		t.Errorf("no marker means default mode, got %q", ctrl.Mode)
	}
}

func TestInitSecureModeCorruptMarkerFailClosed(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	writeTestConfig(t, dataDir, configPath)
	if err := os.WriteFile(filepath.Join(dataDir, ".asscor-mode"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrl, err := initSecureMode(nil, dataDir, configPath)
	if err == nil {
		t.Fatal("corrupt marker must fail startup (fail-closed)")
	}
	if ctrl != nil {
		t.Error("failed startup must not return a controller")
	}
	if !errors.Is(err, securemode.ErrCorruptMarker) {
		t.Errorf("error must wrap ErrCorruptMarker, got: %v", err)
	}
}

func TestInitSecureModeResidueFailClosed(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	writeTestConfig(t, dataDir, configPath)
	// plaintext + .enc both present = crash residue (spec §6) — fail-closed.
	if err := os.WriteFile(configPath+".enc", []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrl, err := initSecureMode(nil, dataDir, configPath)
	if err == nil {
		t.Fatal("plaintext + .enc residue must fail startup (fail-closed)")
	}
	if ctrl != nil {
		t.Error("failed startup must not return a controller")
	}
	if !errors.Is(err, securemode.ErrResidue) {
		t.Errorf("error must wrap ErrResidue, got: %v", err)
	}
}
