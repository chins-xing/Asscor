package kernel

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/argus-security/argus/api/v1"
	"github.com/argus-security/argus/internal/logger"
)

type LogCollectorModule struct {
	kernel  *Kernel
	logPath string

	mu     sync.RWMutex
	writer *os.File
	state  PluginState
}

func (m *LogCollectorModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "log_collector",
		Version:     "1.2.0",
		Description: "Log collector — receives Agent log streams, writes to append-only file, forwards to SIEM",
		Author:      "ARGUS Core Team",
	}
}

func (m *LogCollectorModule) Dependencies() []PluginDependency {
	return nil
}

func (m *LogCollectorModule) Priority() int {
	return 70
}

func (m *LogCollectorModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.logPath = "argus-kernel.log"
	m.state = PluginInitialized

	f, err := os.OpenFile(m.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	m.writer = f

	k.Container().Bind((*LogCollectorInterface)(nil), m)

	return nil
}

func (m *LogCollectorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	logger.With("component", "log_collector").Info("started", "path", m.logPath)
	return nil
}

func (m *LogCollectorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.mu.Lock()
	if m.writer != nil {
		m.writer.Close()
	}
	m.mu.Unlock()
	m.state = PluginStopped
	logger.With("component", "log_collector").Info("stopped")
	return nil
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
	if err == nil {
		m.writer.Sync()
	}
	return err
}

func (m *LogCollectorModule) AppendBatch(entries []*apiv1.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer == nil || len(entries) == 0 {
		return nil
	}

	var buf []byte
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
	if err == nil {
		m.writer.Sync()
	}
	return err
}

type LogCollectorInterface interface {
	Append(entry *apiv1.LogEntry) error
	AppendBatch(entries []*apiv1.LogEntry) error
}