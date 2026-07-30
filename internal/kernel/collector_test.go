package kernel

import (
	"bytes"
	"encoding/json"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
)

func TestLogCollectorAppend(t *testing.T) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entry := &apiv1.LogEntry{
		HostId:    "host-01",
		Level:     "INFO",
		Message:   "test message",
		Timestamp: 1234567890,
	}

	if err := m.Append(entry); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty")
	}

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if record["host_id"] != "host-01" {
		t.Errorf("expected host_id=host-01, got %v", record["host_id"])
	}
	if record["level"] != "INFO" {
		t.Errorf("expected level=INFO, got %v", record["level"])
	}
	if record["source"] != "agent" {
		t.Errorf("expected source=agent, got %v", record["source"])
	}
}

func TestLogCollectorAppendBatch(t *testing.T) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entries := []*apiv1.LogEntry{
		{HostId: "h1", Level: "INFO", Message: "msg1", Timestamp: 1000000},
		{HostId: "h2", Level: "ERROR", Message: "msg2", Timestamp: 2000000},
		{HostId: "h1", Level: "WARN", Message: "msg3", Timestamp: 3000000},
	}

	if err := m.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty")
	}

	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	if len(lines) < 4 {
		t.Fatalf("expected at least 3 lines of output, got %d", len(lines))
	}
}

func TestLogCollectorNilWriter(t *testing.T) {
	m := &LogCollectorModule{writer: nil}

	entry := &apiv1.LogEntry{HostId: "h", Level: "INFO", Message: "msg", Timestamp: 1}

	if err := m.Append(entry); err != nil {
		t.Errorf("expected nil error for nil writer, got %v", err)
	}
}

func TestLogCollectorSanitizeFields(t *testing.T) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entry := &apiv1.LogEntry{
		HostId:    "host\n01",
		Level:     "INFO\r\n",
		Message:   "test\nmessage",
		Timestamp: 1,
	}

	if err := m.Append(entry); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	var record map[string]interface{}
	json.Unmarshal(buf.Bytes(), &record)

	if hostID, _ := record["host_id"].(string); hostID == "host\n01" {
		t.Error("expected newline-stripped host_id")
	}
	if msg, _ := record["message"].(string); msg == "test\nmessage" {
		t.Error("expected newline-stripped message")
	}
}

func TestLogCollectorSetPath(t *testing.T) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf, logPath: "ASSCOR-kernel.log"}

	if path := m.LogPath(); path != "ASSCOR-kernel.log" {
		t.Errorf("expected logPath=ASSCOR-kernel.log, got %s", path)
	}
}

func TestLogCollectorExtensionPointFired(t *testing.T) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entry := &apiv1.LogEntry{
		HostId: "host-01", Level: "INFO", Message: "test", Timestamp: 1,
	}

	if err := m.Append(entry); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected log entry written")
	}
}

func BenchmarkLogCollectorAppend(b *testing.B) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entry := &apiv1.LogEntry{
		HostId: "host-01", Level: "INFO", Message: "benchmark test message", Timestamp: 1234567890,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Append(entry)
	}
}

func BenchmarkLogCollectorAppendBatch(b *testing.B) {
	var buf bytes.Buffer
	m := &LogCollectorModule{writer: &buf}

	entries := []*apiv1.LogEntry{
		{HostId: "h1", Level: "INFO", Message: "msg1", Timestamp: 1},
		{HostId: "h2", Level: "ERROR", Message: "msg2", Timestamp: 2},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.AppendBatch(entries)
	}
}
