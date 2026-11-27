// Package logcollector is the process-isolated log collector (A1 pilot).
//
// The kernel keeps a thin proxy implementing kernel.LogCollectorInterface;
// the append-only file writer runs in the logcollector-mod child process.
package logcollector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/chins-xing/asscor/api/v1"
)

// Writer owns the append-only JSONL log file.
type Writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// NewWriter opens (or creates) the collector log file.
func NewWriter(path string) (*Writer, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Writer{path: path, f: f}, nil
}

func (w *Writer) Path() string { return w.path }

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

func (w *Writer) appendLocked(entry *apiv1.LogEntry) error {
	if entry == nil || w.f == nil {
		return nil
	}
	record := map[string]interface{}{
		"timestamp": time.Unix(entry.Timestamp, 0).Format(time.RFC3339Nano),
		"level":     sanitize(entry.Level),
		"host_id":   sanitize(entry.HostId),
		"message":   sanitize(entry.Message),
		"source":    "agent",
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = w.f.Write(append(data, '\n'))
	return err
}

func (w *Writer) Append(entry *apiv1.LogEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(entry)
}

func (w *Writer) AppendBatch(entries []*apiv1.LogEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range entries {
		if err := w.appendLocked(e); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) Sync() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Sync()
	}
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Sync()
		_ = w.f.Close()
		w.f = nil
	}
}
