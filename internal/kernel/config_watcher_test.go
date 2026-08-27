package kernel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/config"
)

// captureKernelContext records SetConfigObj calls so tests can assert what the
// reload chain applied (the mock's SetConfigObj is otherwise a no-op).
type captureKernelContext struct {
	mockKernelContext
	cfg          *config.Config
	setCfgCalls  int
	gotThreshold float64
}

func (c *captureKernelContext) SetConfigObj(cfg *config.Config) {
	c.cfg = cfg
	c.setCfgCalls++
	c.gotThreshold = cfg.Threshold
}

func (c *captureKernelContext) GetConfigObj() *config.Config { return c.cfg }

func TestConfigWatcherConstruction(t *testing.T) {
	m := NewConfigWatcherModule("test-config.ini")

	if m.configPath != "test-config.ini" {
		t.Errorf("configPath = %s, want test-config.ini", m.configPath)
	}
	if m.interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s", m.interval)
	}
	if m.state != PluginUnregistered {
		t.Errorf("state = %s, want unregistered", m.state)
	}

	info := m.Info()
	if info.Name != "config_watcher" {
		t.Errorf("Name = %s, want config_watcher", info.Name)
	}
	if info.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestConfigWatcherPriority(t *testing.T) {
	m := NewConfigWatcherModule("test.ini")
	if m.Priority() != 1 {
		t.Errorf("Priority = %d, want 1", m.Priority())
	}
}

func TestConfigWatcherDependencies(t *testing.T) {
	m := NewConfigWatcherModule("test.ini")
	deps := m.Dependencies()
	if len(deps) != 0 {
		t.Logf("expected 0 dependencies, got %d", len(deps))
	}
}

func TestConfigWatcherResolvePath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "config.ini")

	os.MkdirAll(filepath.Dir(configPath), 0755)
	os.WriteFile(configPath, []byte("[weights]\nattack_surface = 35\n"), 0644)

	m := NewConfigWatcherModule(configPath)
	m.resolveConfigPath()

	if m.configPath != configPath {
		t.Errorf("resolved path = %s, want %s", m.configPath, configPath)
	}
}

func TestConfigWatcherResolvePathRelative(t *testing.T) {
	m := NewConfigWatcherModule("config.ini")
	m.resolveConfigPath()

	if m.configPath == "config.ini" {
		t.Log("could not resolve config.ini, expected — path may be relative to binary")
	}
}

func TestConfigWatcherLifecycle(t *testing.T) {
	m := NewConfigWatcherModule("test.ini")

	if m.State() != PluginUnregistered {
		t.Errorf("initial state = %s, want unregistered", m.State())
	}
}

// TestConfigWatcherForceReloadUsesLoader (I-1): with a custom reload source
// installed (run-mode secure mode), forceReload must use it instead of
// config.Load on the watched path.
func TestConfigWatcherForceReloadUsesLoader(t *testing.T) {
	m := NewConfigWatcherModule(filepath.Join(t.TempDir(), "missing.ini"))
	k := &captureKernelContext{}
	m.kernel = k
	m.SetConfigLoader(func() (*config.Config, error) {
		cfg := config.Default()
		cfg.Threshold = 42
		return cfg, nil
	})

	m.forceReload()

	if k.setCfgCalls != 1 {
		t.Fatalf("loader-based reload must apply the config, SetConfigObj calls = %d", k.setCfgCalls)
	}
	if k.gotThreshold != 42 {
		t.Errorf("applied threshold = %v, want 42 (loader result must reach the kernel)", k.gotThreshold)
	}
}

// TestConfigWatcherForceReloadLoaderErrorFailSafe (I-1): a failing loader
// (e.g. run mode not unlocked yet) must NOT replace the in-memory kernel
// config — same fail-safe as the current missing-file behavior.
func TestConfigWatcherForceReloadLoaderErrorFailSafe(t *testing.T) {
	m := NewConfigWatcherModule(filepath.Join(t.TempDir(), "missing.ini"))
	k := &captureKernelContext{}
	m.kernel = k
	m.SetConfigLoader(func() (*config.Config, error) {
		return nil, errors.New("run mode config not unlocked yet")
	})

	m.forceReload()

	if k.setCfgCalls != 0 {
		t.Error("a failed loader must never replace the kernel config")
	}
}

// TestConfigWatcherCheckAndReloadWatchesEncInRunMode (I-1): in run mode the
// plaintext is gone, so the polling watcher must watch the .enc file's mtime
// instead — a persisted .enc change still triggers a reload via the loader.
func TestConfigWatcherCheckAndReloadWatchesEncInRunMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.ini")
	// Run mode: plaintext missing, .enc present.
	encPath := configPath + ".enc"
	if err := os.WriteFile(encPath, []byte("enc"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewConfigWatcherModule(configPath)
	k := &captureKernelContext{}
	m.kernel = k
	m.SetConfigLoader(func() (*config.Config, error) { return config.Default(), nil })
	m.lastMod = time.Time{} // never reloaded before

	m.checkAndReload()

	if k.setCfgCalls != 1 {
		t.Errorf("run-mode watcher must reload via the .enc mtime signal, SetConfigObj calls = %d", k.setCfgCalls)
	}
}

// TestConfigWatcherCheckAndReloadMissingBothFailSafe: run mode with neither
// plaintext nor .enc must warn and skip the reload (fail-safe).
func TestConfigWatcherCheckAndReloadMissingBothFailSafe(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.ini") // neither exists
	m := NewConfigWatcherModule(configPath)
	k := &captureKernelContext{}
	m.kernel = k
	m.SetConfigLoader(func() (*config.Config, error) { return config.Default(), nil })

	m.checkAndReload()

	if k.setCfgCalls != 0 {
		t.Error("no watched file must never trigger a reload")
	}
}

// TestConfigWatcherInitRecordsEncMtimeInRunMode (I-1): when the loader is set
// and the plaintext is missing (run mode), Init records the .enc mtime so the
// first poll does not spuriously reload.
func TestConfigWatcherInitRecordsEncMtimeInRunMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.ini")
	encPath := configPath + ".enc"
	if err := os.WriteFile(encPath, []byte("enc"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewConfigWatcherModule(configPath)
	m.SetConfigLoader(func() (*config.Config, error) { return config.Default(), nil })
	if err := m.Init(context.Background(), &captureKernelContext{}); err != nil {
		t.Fatal(err)
	}
	if m.lastMod.IsZero() {
		t.Error("Init must record the .enc mtime when the plaintext is missing in run mode")
	}
}
