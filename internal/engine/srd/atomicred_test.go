//go:build engine

package srd

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAtomicRedAdapterParse_Structured(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`{
		"techniques": [
			{
				"technique_id": "T1059.001",
				"technique_name": "PowerShell",
				"tactic": "execution",
				"hostname": "win10-workstation",
				"execution_time": "2026-06-15T10:00:00Z",
				"tests": [
					{
						"test_name": "PowerShell Download and Execute",
						"test_number": "1",
						"status": "succeeded",
						"detection_triggered": false,
						"execution_time": "2026-06-15T10:00:05Z"
					},
					{
						"test_name": "PowerShell Encoded Command",
						"test_number": "2",
						"status": "failed",
						"detection_triggered": true,
						"execution_time": "2026-06-15T10:00:10Z"
					}
				]
			},
			{
				"technique_id": "T1003.001",
				"technique_name": "LSASS Memory Dump",
				"tactic": "credential_access",
				"hostname": "win10-workstation",
				"execution_time": "2026-06-15T10:01:00Z",
				"tests": [
					{
						"test_name": "Procdump LSASS",
						"test_number": "1",
						"status": "succeeded",
						"detection_triggered": true,
						"execution_time": "2026-06-15T10:01:05Z"
					}
				]
			}
		]
	}`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if report.Tool != "atomic_red_team" {
		t.Errorf("expected tool 'atomic_red_team', got '%s'", report.Tool)
	}
	if report.HostID != "win10-workstation" {
		t.Errorf("expected host 'win10-workstation', got '%s'", report.HostID)
	}
	if len(report.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(report.Items))
	}

	// Test 1: succeeded without detection → fail, severity=high
	item1 := report.Items[0]
	if item1.Result != "fail" {
		t.Errorf("test1: expected 'fail', got '%s'", item1.Result)
	}
	if item1.Severity != "high" {
		t.Errorf("test1: expected severity 'high', got '%s'", item1.Severity)
	}
	if item1.Delta != -10.0 {
		t.Errorf("test1: expected delta -10.0, got %.2f", item1.Delta)
	}

	// Test 2: failed → pass, severity=low
	item2 := report.Items[1]
	if item2.Result != "pass" {
		t.Errorf("test2: expected 'pass', got '%s'", item2.Result)
	}
	if item2.Severity != "low" {
		t.Errorf("test2: expected severity 'low', got '%s'", item2.Severity)
	}

	// Test 3: succeeded with detection → fail, severity=medium
	item3 := report.Items[2]
	if item3.Result != "fail" {
		t.Errorf("test3: expected 'fail', got '%s'", item3.Result)
	}
	if item3.Severity != "medium" {
		t.Errorf("test3: expected severity 'medium', got '%s'", item3.Severity)
	}
	if item3.Delta != -7.5 {
		t.Errorf("test3: expected delta -7.5, got %.2f", item3.Delta)
	}

	// Check raw score: 2 failed out of 3 → 33.33
	if report.RawScore < 33.0 || report.RawScore > 34.0 {
		t.Errorf("expected raw score ~33.33, got %.2f", report.RawScore)
	}
}

func TestAtomicRedAdapterParse_FlatArray(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`[
		{
			"technique_id": "T1059.001",
			"test_name": "PowerShell Download",
			"test_number": "1",
			"execution_time": "2026-06-15T10:00:00Z",
			"execution_status": "succeeded",
			"detection_triggered": false,
			"hostname": "win10",
			"tactic": "execution"
		},
		{
			"technique_id": "T1003.001",
			"test_name": "LSASS Dump",
			"test_number": "1",
			"execution_time": "2026-06-15T10:01:00Z",
			"execution_status": "failed",
			"detection_triggered": true,
			"hostname": "win10",
			"tactic": "credential_access"
		}
	]`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(report.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(report.Items))
	}

	// Item 1: succeeded → fail
	if report.Items[0].Result != "fail" {
		t.Errorf("expected 'fail', got '%s'", report.Items[0].Result)
	}

	// Item 2: failed → pass
	if report.Items[1].Result != "pass" {
		t.Errorf("expected 'pass', got '%s'", report.Items[1].Result)
	}
}

func TestAtomicRedAdapterParse_SingleTechnique(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`{
		"technique_id": "T1548.002",
		"test_name": "Bypass UAC",
		"test_number": "1",
		"execution_time": "2026-06-15T10:00:00Z",
		"execution_status": "succeeded",
		"detection_triggered": false,
		"hostname": "win11",
		"tactic": "privilege_escalation"
	}`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(report.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(report.Items))
	}

	item := report.Items[0]
	if item.Result != "fail" {
		t.Errorf("expected 'fail', got '%s'", item.Result)
	}
	if item.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", item.Severity)
	}
	if item.RuleID != "T1548.002" {
		t.Errorf("expected rule_id 'T1548.002', got '%s'", item.RuleID)
	}
}

func TestAtomicRedAdapter_SkippedTest(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`[{
		"technique_id": "T1562.001",
		"test_name": "Disable Windows Defender",
		"test_number": "1",
		"execution_status": "skipped",
		"hostname": "win10",
		"tactic": "defense_evasion"
	}]`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if report.Items[0].Result != "pass" {
		t.Errorf("skipped test: expected 'pass', got '%s'", report.Items[0].Result)
	}
	if report.Items[0].Severity != "info" {
		t.Errorf("skipped test: expected severity 'info', got '%s'", report.Items[0].Severity)
	}
	if report.Items[0].Delta != 0.0 {
		t.Errorf("skipped test: expected delta 0.0, got %.2f", report.Items[0].Delta)
	}
}

func TestAtomicRedAdapter_Properties(t *testing.T) {
	adapter := newAtomicRedAdapter()

	if adapter.ToolID() != "atomic_red_team" {
		t.Errorf("expected ToolID 'atomic_red_team', got '%s'", adapter.ToolID())
	}
	if adapter.ToolName() != "Atomic Red Team" {
		t.Errorf("expected ToolName 'Atomic Red Team', got '%s'", adapter.ToolName())
	}

	// IsEnabled with no config
	if adapter.IsEnabled(Config{}) {
		t.Error("expected IsEnabled false with empty config")
	}

	// IsEnabled with explicit config
	if !adapter.IsEnabled(Config{EnabledAdapters: map[string]bool{"atomic_red_team": true}}) {
		t.Error("expected IsEnabled true")
	}

	// SupportsFormat
	if !adapter.SupportsFormat("atomic-red-team-results.json") {
		t.Error("expected SupportsFormat true for atomic json")
	}
	if !adapter.SupportsFormat("art_results.json") {
		t.Error("expected SupportsFormat true for art json")
	}
	if adapter.SupportsFormat("results.xml") {
		t.Error("expected SupportsFormat false for xml")
	}
}

func TestAtomicRedAdapter_InvalidInput(t *testing.T) {
	adapter := newAtomicRedAdapter()

	_, err := adapter.Parse(context.Background(), []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestAtomicRedAdapter_Metadata(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`[{
		"technique_id": "T1059.001",
		"test_name": "Test",
		"test_number": "1",
		"execution_status": "succeeded",
		"detection_triggered": false,
		"hostname": "win10",
		"tactic": "execution"
	}]`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if report.Metadata["total_tests"] != "1" {
		t.Errorf("expected total_tests=1, got %s", report.Metadata["total_tests"])
	}
	if report.Metadata["failed_tests"] != "1" {
		t.Errorf("expected failed_tests=1, got %s", report.Metadata["failed_tests"])
	}
}

func TestAtomicRedAdapter_CheckIDFormat(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`[{
		"technique_id": "T1059.001",
		"test_name": "PowerShell Test",
		"test_number": "3",
		"execution_status": "succeeded",
		"hostname": "win10"
	}]`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expectedCheckID := "art-T1059.001-3"
	if report.Items[0].CheckID != expectedCheckID {
		t.Errorf("expected check_id '%s', got '%s'", expectedCheckID, report.Items[0].CheckID)
	}

	// Check MITRE ATT&CK reference
	if len(report.Items[0].Refs) != 1 {
		t.Errorf("expected 1 ref, got %d", len(report.Items[0].Refs))
	}
	expectedRef := "https://attack.mitre.org/techniques/T1059.001/"
	if report.Items[0].Refs[0] != expectedRef {
		t.Errorf("expected ref '%s', got '%s'", expectedRef, report.Items[0].Refs[0])
	}
}

func TestAtomicRedAdapter_JSONRoundTrip(t *testing.T) {
	adapter := newAtomicRedAdapter()

	input := []byte(`[{
		"technique_id": "T1059.001",
		"test_name": "PowerShell Test",
		"test_number": "1",
		"execution_time": "2026-06-15T10:00:00Z",
		"execution_status": "succeeded",
		"detection_triggered": true,
		"hostname": "win10",
		"tactic": "execution"
	}]`)

	report, err := adapter.Parse(context.Background(), input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Marshal to JSON and verify
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}