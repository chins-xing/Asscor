package logcollector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/chins-xing/asscor/api/v1"
)

func TestWriterAppendAndBatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "collector.log")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(&apiv1.LogEntry{HostId: "h1", Level: "warn", Message: "line1", Timestamp: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendBatch([]*apiv1.LogEntry{{HostId: "h2", Level: "info", Message: "line2"}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n != 2 {
		t.Fatalf("lines = %d, want 2: %s", n, data)
	}
}
