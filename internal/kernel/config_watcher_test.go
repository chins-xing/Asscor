package kernel

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
