package logger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitDefaultConfig(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	cfg := DefaultConfig()
	Init(cfg)

	if globalLogger == nil {
		t.Fatal("globalLogger should not be nil after Init")
	}
	if globalHandler == nil {
		t.Fatal("globalHandler should not be nil after Init")
	}
}

func TestInitJSONFormat(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "json.log")

	Init(Config{Format: "json", Level: "info", Output: logFile})
	L().Info("test message", "key", "value")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("output should be valid JSON: %v, got: %s", err, string(data))
	}
	if entry["msg"] != "test message" {
		t.Errorf("expected msg='test message', got %v", entry["msg"])
	}
}

func TestInitTextFormat(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "text.log")

	Init(Config{Format: "text", Level: "info", Output: logFile})
	L().Info("text test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}
	if !strings.Contains(string(data), "text test") {
		t.Errorf("text output should contain message, got: %s", string(data))
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"", "INFO"},
		{"unknown", "INFO"},
	}

	for _, tt := range tests {
		got := parseLevel(tt.input).String()
		if got != tt.want {
			t.Errorf("parseLevel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWithComponent(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "component.log")

	Init(Config{Format: "json", Level: "debug", Output: logFile})

	l := With("test_component")
	l.Info("with component test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}

	comp, _ := entry["component"].(string)
	if comp != "test_component" {
		t.Errorf("expected component='test_component', got %v", comp)
	}
}

func TestWithExtraArgs(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "extra.log")

	Init(Config{Format: "json", Level: "debug", Output: logFile})

	l := With("comp", "adapter_name", "trivy")
	l.Info("extra args test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}

	comp, _ := entry["component"].(string)
	if comp != "comp" {
		t.Errorf("expected component='comp', got %v", comp)
	}
	adapter, _ := entry["adapter_name"].(string)
	if adapter != "trivy" {
		t.Errorf("expected adapter_name='trivy', got %v", adapter)
	}
}

func TestLogFileOutput(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "output.log")

	Init(Config{Format: "json", Level: "info", Output: logFile})
	L().Info("file output test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}
	if !strings.Contains(string(data), "file output test") {
		t.Errorf("log file should contain message, got: %s", string(data))
	}
}

func TestWithTrace(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "trace.log")

	Init(Config{Format: "json", Level: "debug", Output: logFile})

	ctx := NewContext(context.Background(), "trace-123")
	l := WithTrace(ctx)
	l.Info("trace test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}

	tid, _ := entry["trace_id"].(string)
	if tid != "trace-123" {
		t.Errorf("expected trace_id='trace-123', got %v", tid)
	}
}

func TestLogLevelFiltering(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "filter.log")

	Init(Config{Format: "json", Level: "warn", Output: logFile})
	L().Info("should be filtered")
	L().Warn("should appear")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	output := string(data)
	if strings.Contains(output, "should be filtered") {
		t.Error("info message should be filtered at warn level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("warn message should appear at warn level")
	}
}

func TestTraceIDFromContext(t *testing.T) {
	ctx := NewContext(context.Background(), "abc-456")
	got := TraceID(ctx)
	if got != "abc-456" {
		t.Errorf("TraceID = %q, want %q", got, "abc-456")
	}

	emptyCtx := context.Background()
	got = TraceID(emptyCtx)
	if got != "" {
		t.Errorf("TraceID on empty context = %q, want empty", got)
	}
}

func TestWithComponentAndTrace(t *testing.T) {
	defer ResetForTesting()
	ResetForTesting()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "comp_trace.log")

	Init(Config{Format: "json", Level: "debug", Output: logFile})

	ctx := NewContext(context.Background(), "trace-789")
	l := WithComponentAndTrace("mycomp", ctx)
	l.Info("combined test")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}

	comp, _ := entry["component"].(string)
	if comp != "mycomp" {
		t.Errorf("expected component='mycomp', got %v", comp)
	}
	tid, _ := entry["trace_id"].(string)
	if tid != "trace-789" {
		t.Errorf("expected trace_id='trace-789', got %v", tid)
	}
}
