package kernel

import (
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

type LogCollectorModule struct {
	kernel  KernelContext
	logPath string

	mu     sync.RWMutex
	writer io.Writer
	state  PluginState
	flushDone chan struct{}
}

func (m *LogCollectorModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "log_collector",
		Version:     "1.2.0",
		Description: "Log collector — receives Agent log streams, writes to append-only file, forwards to SIEM",
		Author:      "ASSCOR Core Team",
	}
}

func (m *LogCollectorModule) Dependencies() []PluginDependency {
	return nil
}

func (m *LogCollectorModule) Priority() int {
	return 70
}

func (m *LogCollectorModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

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

	kc.Container().Bind((*LogCollectorInterface)(nil), m)

	return nil
}

func (m *LogCollectorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.flushDone = make(chan struct{})
	go m.flushLoop()
	logger.WithComponent("log_collector").Info("started", "path", m.logPath)
	return nil
}

func (m *LogCollectorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
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
	m.state = PluginStopped
	logger.WithComponent("log_collector").Info("stopped")
	return nil
}

func (m *LogCollectorModule) flushLoop() {
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

func (m *LogCollectorModule) State() PluginState {
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

func (m *LogCollectorModule) Append(entry *apiv1.LogEntry) error {
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

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "log.entry_received", map[string]interface{}{
			"host_id":   entry.HostId,
			"level":     entry.Level,
			"timestamp": entry.Timestamp,
		})
	}

	return err
}

func (m *LogCollectorModule) AppendBatch(entries []*apiv1.LogEntry) error {
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

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "agent.log_uploaded", map[string]interface{}{
			"entry_count": len(entries),
		})
	}

	return err
}

type LogCollectorInterface interface {
	Append(entry *apiv1.LogEntry) error
	AppendBatch(entries []*apiv1.LogEntry) error
	LogPath() string
}

// LogPath returns the path of the collector's log file, enabling readers
// (CLI log command, web ops panel) to tail/stream it.
func (m *LogCollectorModule) LogPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.logPath
}