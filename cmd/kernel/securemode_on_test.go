//go:build securemode

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
)

// writeTestConfig creates a realistic config with a [bootstrap] section so
// the vault layout matches the kernel's config.ini.
func writeTestConfig(t *testing.T, dataDir, configPath string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "[bootstrap]\nlisten = :50051\nlog_output = stderr\n\n[acceptability]\nthreshold = 60\n"
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

// newRunController prepares a controller in run mode with a decrypted guard
// (simulating a restart + unlock) over a realistic kernel config.
func newRunController(t *testing.T) (*securemode.Controller, string) {
	t.Helper()
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	content := "[bootstrap]\nlisten = :50051\n\n[acceptability]\nthreshold = 70\n\n[integrity]\nanti_debug = true\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	ctrl := securemode.NewController(dataDir, []*securemode.Vault{{DataDir: dataDir, ConfigPath: configPath, BootstrapHeader: "[bootstrap]"}})
	if err := ctrl.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	return ctrl, configPath
}

// TestLoadKernelConfigFromSecureModeRunUnlocked (I-1): in run mode with a
// populated guard (unlocked), the config reload source must parse the guard
// snapshot — the decrypted protected config — instead of the missing
// plaintext file.
func TestLoadKernelConfigFromSecureModeRunUnlocked(t *testing.T) {
	ctrl, configPath := newRunController(t)
	cfg, err := loadKernelConfigFromSecureMode(ctrl, configPath)
	if err != nil {
		t.Fatalf("run-mode reload source must succeed after unlock: %v", err)
	}
	if cfg.Threshold != 70 {
		t.Errorf("threshold = %v, want 70 (protected content must reach the kernel)", cfg.Threshold)
	}
	if cfg.AdapterConfig["integrity.anti_debug"] != "true" {
		t.Errorf("integrity.anti_debug = %q, want true", cfg.AdapterConfig["integrity.anti_debug"])
	}
}

// TestLoadKernelConfigFromSecureModeRunLockedRefuses (I-1): run mode but NOT
// yet unlocked (guard nil) must refuse the reload with a clear error — never
// silently fall back to config.Load on the missing plaintext (fail-safe, same
// as the watcher's current missing-file behavior).
func TestLoadKernelConfigFromSecureModeRunLockedRefuses(t *testing.T) {
	ctrl, configPath := newRunController(t)
	// Simulate a restart WITHOUT unlock: fresh controller over the same dir.
	ctrl2 := securemode.NewController(ctrl.DataDir, ctrl.Vaults)
	if err := ctrl2.Startup(); err != nil {
		t.Fatal(err)
	}
	if ctrl2.Guard != nil {
		t.Fatal("guard must be nil before unlock")
	}
	_, err := loadKernelConfigFromSecureMode(ctrl2, configPath)
	if err == nil {
		t.Fatal("run-mode reload before unlock must fail")
	}
	if !strings.Contains(err.Error(), "unlock") {
		t.Errorf("error = %v, want unlock mention", err)
	}
}

// TestLoadKernelConfigFromSecureModeDefaultFallsBack (I-1): in default mode
// the loader falls back to config.Load on the plaintext file — the loader is
// installed whenever the securemode tag is on, regardless of the current mode.
func TestLoadKernelConfigFromSecureModeDefaultFallsBack(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	writeTestConfig(t, dataDir, configPath)
	ctrl := securemode.NewController(dataDir, []*securemode.Vault{{DataDir: dataDir, ConfigPath: configPath, BootstrapHeader: "[bootstrap]"}})
	if err := ctrl.Startup(); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadKernelConfigFromSecureMode(ctrl, configPath)
	if err != nil {
		t.Fatalf("default-mode loader must fall back to config.Load: %v", err)
	}
	if cfg.Threshold != 60 { // writeTestConfig: [acceptability] threshold = 60
		t.Errorf("threshold = %v, want 60 (plaintext fallback must be used)", cfg.Threshold)
	}
}

// TestSecureModeConfigReloaderAppliesImmediately (I-1): the unlock / --temp
// hook (immediate=true) feeds the parsed run-mode config into the kernel
// runtime (SetConfigObj) exactly like the agent-side reloadProtectedConfig.
func TestSecureModeConfigReloaderAppliesImmediately(t *testing.T) {
	k := kernel.NewKernel()
	k.SetConfigObj(config.Default())
	r := newSecureModeConfigReloader(k, nil) // nil assessor: no ReloadConfig call

	plain := "[acceptability]\nthreshold = 70\n\n[integrity]\nanti_debug = true\n"
	if err := r(plain, true); err != nil {
		t.Fatal(err)
	}
	got := k.GetConfigObj()
	if got == nil {
		t.Fatal("kernel config object must be set after an immediate apply")
	}
	if got.Threshold != 70 {
		t.Errorf("kernel threshold = %v, want 70", got.Threshold)
	}
	if got.AdapterConfig["integrity.anti_debug"] != "true" {
		t.Errorf("kernel integrity.anti_debug = %q, want true", got.AdapterConfig["integrity.anti_debug"])
	}
}

// TestSecureModeConfigReloaderDeferredForPersist (I-1): config-set --persist
// (immediate=false) must NOT apply to the kernel runtime — spec §9: it takes
// effect only on 'config reload'.
func TestSecureModeConfigReloaderDeferredForPersist(t *testing.T) {
	k := kernel.NewKernel()
	k.SetConfigObj(config.Default())
	r := newSecureModeConfigReloader(k, nil)

	if err := r("[acceptability]\nthreshold = 70\n", false); err != nil {
		t.Fatal(err)
	}
	if got := k.GetConfigObj(); got.Threshold != 80 {
		t.Errorf("kernel threshold = %v, want 80 (persist must not apply immediately)", got.Threshold)
	}
}

// TestSecureModeConfigReloaderRejectsEmpty (I-1): an empty plaintext must be
// rejected — it can never be a real protected config, and applying it would
// silently reset the kernel to defaults. (config.Parse itself is lenient: any
// non-empty text parses to defaults, matching config.Load's behavior on a
// section-less file.)
func TestSecureModeConfigReloaderRejectsEmpty(t *testing.T) {
	k := kernel.NewKernel()
	k.SetConfigObj(config.Default())
	r := newSecureModeConfigReloader(k, nil)
	if err := r("", true); err == nil {
		t.Fatal("empty run-mode config must be rejected")
	}
	if got := k.GetConfigObj(); got.Threshold != 80 {
		t.Errorf("kernel config must stay unchanged after a rejected apply, got threshold %v", got.Threshold)
	}
}
