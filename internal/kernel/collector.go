package kernel

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	apiv1 "github.com/argus-security/argus/api/v1"
)

type LogCollectorModule struct {
	kernel  *Kernel
	logPath string

	mu     sync.Mutex
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

	f, err := os.OpenFile(m.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	m.writer = f

	k.Container().Bind((*LogCollectorInterface)(nil), m)

	return nil
}

func (m *LogCollectorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	log.Println("log_collector: started, writing to", m.logPath)
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
	log.Println("log_collector: stopped")
	return nil
}

func (m *LogCollectorModule) State() PluginState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *LogCollectorModule) Append(entry *apiv1.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer == nil {
		return nil
	}

	ts := time.Unix(entry.Timestamp, 0).Format(time.RFC3339)
	line := ts + " [" + entry.Level + "] " + entry.HostId + ": " + entry.Message + "\n"
	_, err := m.writer.WriteString(line)
	return err
}

func (m *LogCollectorModule) AppendBatch(entries []*apiv1.LogEntry) error {
	for _, entry := range entries {
		if err := m.Append(entry); err != nil {
			return err
		}
	}
	return nil
}

type LogCollectorInterface interface {
	Append(entry *apiv1.LogEntry) error
	AppendBatch(entries []*apiv1.LogEntry) error
}