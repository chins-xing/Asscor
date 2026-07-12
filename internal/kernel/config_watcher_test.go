package kernel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigWatcher_WatchLoopStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.ini")
	os.WriteFile(path, []byte("key=value\n"), 0644)

	w := NewConfigWatcherModule(path)
	w.interval = 50 * time.Millisecond
	w.state = PluginStarted
	w.stopCh = make(chan struct{})
	w.lastMod = time.Time{}

	go w.watchLoop()
	time.Sleep(100 * time.Millisecond)

	// Stop should trigger goroutine exit.
	w.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)
}

func TestConfigWatcher_CheckReloadSkipsOnError(t *testing.T) {
	w := NewConfigWatcherModule("/nonexistent/path/config.ini")
	w.lastMod = time.Time{}
	w.checkAndReload() // must not panic, just log warning
}
