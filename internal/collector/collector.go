//go:build collector

package collector

import (
	"github.com/asscor/asscor/internal/kernel"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
)

type Module struct {
	kc  kernel.KernelContext
	logPath string

	mu     sync.RWMutex
	writer io.Writer
	state  kernel.PluginState
	flushDone chan struct{}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "log_collector",
		Version:     "1.2.0",
		Description: "Log collector — receives Agent log streams, writes to append-only file, forwards to SIEM",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 70
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.state = kernel.PluginInitialized

	m.logPath = "ASSCOR-kernel.log"
	if cfg := kc.GetConfigObj(); cfg != nil {
		if cfg.DataDir != "" {
			m.logPath = filepath.Join(cfg.DataDir, "ASSCOR-kernel.log")
		}
	}

	logDir := filepath.Dir(m.logPath)
	if logDir != "." && logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.WithComponent("log_collector").Warn("cannot create log directory, falling back to stdout",
				"dir", logDir, "error", err)
			m.writer = os.Stdout
		}
	}

	if m.writer == nil {
		f, err := os.OpenFile(m.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.WithComponent("log_collector").Warn("cannot open log file, falling back to stdout",
				"path", m.logPath, "error", err)
			m.writer = os.Stdout
		} else {
			m.writer = f
		}
	}

	kc.Container().Bind((*kernel.LogCollectorInterface)(nil), m)

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	m.flushDone = make(chan struct{})
	go m.flushLoop()
	logger.WithComponent("log_collector").Info("started", "path", m.logPath)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	if m.flushDone != nil {
		select {
		case <-m.flushDone:
		default:
			close(m.flushDone)
		}
	}
	m.mu.Lock()
	if f, ok := m.writer.(*os.File); ok && f != os.Stdout && f != os.Stderr {
		f.Sync()
		f.Close()
	}
	m.mu.Unlock()
	m.state = kernel.PluginStopped
	logger.WithComponent("log_collector").Info("stopped")
	return nil
}

func (m *Module) flushLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("log_collector").Error("flushLoop panic", "panic", r)
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.flushDone:
			return
		case <-ticker.C:
			m.mu.RLock()
			if f, ok := m.writer.(*os.File); ok && f != os.Stdout && f != os.Stderr {
				f.Sync()
			}
			m.mu.RUnlock()
		}
	}
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

func (m *Module) Append(entry *apiv1.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer == nil {
		return nil
	}

	record := map[string]interface{}{
		"timestamp": time.Unix(entry.Timestamp, 0).Format(time.RFC3339Nano),
		"level":     sanitizeLogField(entry.Level),
		"host_id":   sanitizeLogField(entry.HostId),
		"message":   sanitizeLogField(entry.Message),
		"source":    "agent",
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = m.writer.Write(data)

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "log.entry_received", map[string]interface{}{
			"host_id":   entry.HostId,
			"level":     entry.Level,
			"timestamp": entry.Timestamp,
		})
	}

	return err
}

func (m *Module) AppendBatch(entries []*apiv1.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer == nil || len(entries) == 0 {
		return nil
	}

	buf := make([]byte, 0, len(entries)*256)
	for _, entry := range entries {
		record := map[string]interface{}{
			"timestamp": time.Unix(entry.Timestamp, 0).Format(time.RFC3339Nano),
			"level":     sanitizeLogField(entry.Level),
			"host_id":   sanitizeLogField(entry.HostId),
			"message":   sanitizeLogField(entry.Message),
			"source":    "agent",
		}

		data, err := json.Marshal(record)
		if err != nil {
			continue
		}
		data = append(data, '\n')
		buf = append(buf, data...)
	}

	_, err := m.writer.Write(buf)

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "agent.log_uploaded", map[string]interface{}{
			"entry_count": len(entries),
		})
	}

	return err
}

func (m *Module) LogPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.logPath
}
// New creates a log collector module instance.
func New() *Module { return &Module{} }
