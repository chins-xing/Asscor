package ssam

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIRRoundTrip(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInputV2{
		HostID:    "round-trip-host",
		Hostname:  "server01.example.com",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.70,
			Threat:    0.90,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Root Login", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Name: "Backup Verification", Passed: true, Delta: 0},
			{CheckID: "OT-001", Domain: "operation_trust", Name: "Audit Logging", Passed: false, Delta: -10},
			{CheckID: "RS-001", Domain: "resilience", Name: "Firewall Rules", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	ir := NewIR(input, config, output)

	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	restored, err := UnmarshalIR(data)
	if err != nil {
		t.Fatalf("UnmarshalIR failed: %v", err)
	}

	if restored.Meta.Version != ir.Meta.Version {
		t.Errorf("meta.version mismatch: expected %s, got %s", ir.Meta.Version, restored.Meta.Version)
	}
	if restored.Meta.FormulaID != ir.Meta.FormulaID {
		t.Errorf("meta.formula_id mismatch: expected %s, got %s", ir.Meta.FormulaID, restored.Meta.FormulaID)
	}
	if restored.Meta.Timestamp != ir.Meta.Timestamp {
		t.Errorf("meta.timestamp mismatch: expected %s, got %s", ir.Meta.Timestamp, restored.Meta.Timestamp)
	}
	if restored.Input.HostID != ir.Input.HostID {
		t.Errorf("input.host_id mismatch: expected %s, got %s", ir.Input.HostID, restored.Input.HostID)
	}
	if restored.Input.Hostname != ir.Input.Hostname {
		t.Errorf("input.hostname mismatch: expected %s, got %s", ir.Input.Hostname, restored.Input.Hostname)
	}
	if restored.Input.Threshold != ir.Input.Threshold {
		t.Errorf("input.threshold mismatch: expected %.2f, got %.2f", ir.Input.Threshold, restored.Input.Threshold)
	}
	if restored.Output.FinalScore != ir.Output.FinalScore {
		t.Errorf("output.final_score mismatch: expected %.2f, got %.2f", ir.Output.FinalScore, restored.Output.FinalScore)
	}
	if restored.Output.Acceptable != ir.Output.Acceptable {
		t.Errorf("output.acceptable mismatch: expected %v, got %v", ir.Output.Acceptable, restored.Output.Acceptable)
	}
	if len(restored.Input.Checks) != len(ir.Input.Checks) {
		t.Errorf("input.checks length mismatch: expected %d, got %d", len(ir.Input.Checks), len(restored.Input.Checks))
	}
	if len(restored.Output.DomainScores) != len(ir.Output.DomainScores) {
		t.Errorf("output.domain_scores length mismatch: expected %d, got %d", len(ir.Output.DomainScores), len(restored.Output.DomainScores))
	}
	if len(restored.Output.EdgeFactors) != len(ir.Output.EdgeFactors) {
		t.Errorf("output.edge_factors length mismatch: expected %d, got %d", len(ir.Output.EdgeFactors), len(restored.Output.EdgeFactors))
	}
	if len(restored.Input.Weights) != len(ir.Input.Weights) {
		t.Errorf("input.weights length mismatch: expected %d, got %d", len(ir.Input.Weights), len(restored.Input.Weights))
	}
}

func TestIRCrossLanguageParsable(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "cross-lang-host",
		Hostname:  "node.example.com",
		Threshold: 85,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.75,
			Threat:    0.85,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Config", Passed: false, Delta: -10},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	ir := NewIR(input, config, output)
	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	requiredFields := []string{
		`"meta"`,
		`"input"`,
		`"output"`,
		`"version"`,
		`"formula_id"`,
		`"timestamp"`,
		`"host_id"`,
		`"hostname"`,
		`"threshold"`,
		`"checks"`,
		`"risk_context"`,
		`"weights"`,
		`"edge_factors"`,
		`"final_score"`,
		`"acceptable"`,
		`"domain_scores"`,
		`"risk_layers"`,
	}

	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON output missing field: %s", field)
		}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("JSON is not valid: %v", err)
	}

	meta, ok := raw["meta"].(map[string]interface{})
	if !ok {
		t.Fatal("meta is not an object")
	}
	if _, exists := meta["version"]; !exists {
		t.Error("meta.version missing")
	}
	if _, exists := meta["formula_id"]; !exists {
		t.Error("meta.formula_id missing")
	}
	if _, exists := meta["timestamp"]; !exists {
		t.Error("meta.timestamp missing")
	}

	inputRaw, ok := raw["input"].(map[string]interface{})
	if !ok {
		t.Fatal("input is not an object")
	}
	if _, exists := inputRaw["host_id"]; !exists {
		t.Error("input.host_id missing")
	}

	outputRaw, ok := raw["output"].(map[string]interface{})
	if !ok {
		t.Fatal("output is not an object")
	}
	if _, exists := outputRaw["final_score"]; !exists {
		t.Error("output.final_score missing")
	}
	if _, exists := outputRaw["acceptable"]; !exists {
		t.Error("output.acceptable missing")
	}
	if _, exists := outputRaw["domain_scores"]; !exists {
		t.Error("output.domain_scores missing")
	}
	if _, exists := outputRaw["risk_layers"]; !exists {
		t.Error("output.risk_layers missing")
	}
}

func TestIRInvalidJSONDeserialization(t *testing.T) {
	_, err := UnmarshalIR([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}

	_, err = UnmarshalIR([]byte(`{}`))
	if err != nil {
		t.Errorf("empty object should not error: %v", err)
	}

	_, err = UnmarshalIR([]byte(`{"meta": 123}`))
	if err == nil {
		t.Error("expected error for wrong meta type, got nil")
	}
}

func TestIRTraceabilityInfo(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "trace-host",
		Hostname:  "trace.example.com",
		Threshold: 75,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.80,
			Threat:    0.90,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "Test Check", Passed: false, Delta: -20},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	ir := NewIR(input, config, output)

	if ir.Meta.Version == "" {
		t.Error("meta.version should not be empty")
	}
	if ir.Meta.FormulaID != "ssam_v2.0" {
		t.Errorf("meta.formula_id: expected ssam_v2.0, got %s", ir.Meta.FormulaID)
	}
	if ir.Meta.Timestamp == "" {
		t.Error("meta.timestamp should not be empty")
	}

	if len(ir.Output.DomainScores) == 0 {
		t.Error("output.domain_scores should not be empty")
	}

	if ir.Output.RiskLayers.Intrinsic.Coeff == 0 {
		t.Error("output.risk_layers.intrinsic coeff should not be zero")
	}
	if ir.Output.RiskLayers.Exposure.Coeff == 0 {
		t.Error("output.risk_layers.exposure coeff should not be zero")
	}
	if ir.Output.RiskLayers.Threat.Coeff == 0 {
		t.Error("output.risk_layers.threat coeff should not be zero")
	}

	if len(ir.Output.EdgeFactors) == 0 {
		t.Error("output.edge_factors should not be empty")
	}

	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	jsonStr := string(data)

	traceFields := []string{
		`"formula_id": "ssam_v2.0"`,
		`"domain_scores"`,
		`"risk_layers"`,
		`"intrinsic"`,
		`"exposure"`,
		`"threat"`,
		`"edge_factors"`,
	}
	for _, field := range traceFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON output missing traceability field: %s", field)
		}
	}
}

func TestIREdgeFactorActiveStatusRoundTrip(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "edge-factor-host",
		Hostname:  "edge.example.com",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  1.0,
			Threat:    1.0,
		},
		Checks: []CheckInput{
			{CheckID: "EF-001", Domain: "attack_surface", Name: "2FA Enabled", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	hasActive := false
	hasInactive := false
	for _, ef := range output.EdgeFactors {
		if ef.Active {
			hasActive = true
		}
		if !ef.Active {
			hasInactive = true
		}
	}
	if !hasActive {
		t.Fatal("test requires at least one active edge factor")
	}
	if !hasInactive {
		t.Fatal("test requires at least one inactive edge factor")
	}

	ir := NewIR(input, config, output)
	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	restored, err := UnmarshalIR(data)
	if err != nil {
		t.Fatalf("UnmarshalIR failed: %v", err)
	}

	originalMap := make(map[string]EdgeFactorResult)
	for _, ef := range ir.Output.EdgeFactors {
		originalMap[ef.ID] = ef
	}
	restoredMap := make(map[string]EdgeFactorResult)
	for _, ef := range restored.Output.EdgeFactors {
		restoredMap[ef.ID] = ef
	}

	for id, orig := range originalMap {
		rest, ok := restoredMap[id]
		if !ok {
			t.Errorf("edge factor %s missing after round-trip", id)
			continue
		}
		if rest.Active != orig.Active {
			t.Errorf("edge factor %s active status mismatch: original=%v, restored=%v", id, orig.Active, rest.Active)
		}
		if rest.Factor != orig.Factor {
			t.Errorf("edge factor %s factor mismatch: original=%.2f, restored=%.2f", id, orig.Factor, rest.Factor)
		}
		if rest.Name != orig.Name {
			t.Errorf("edge factor %s name mismatch: original=%s, restored=%s", id, orig.Name, rest.Name)
		}
	}

	activeInJSON := strings.Contains(string(data), `"active": true`)
	if !activeInJSON {
		t.Error("JSON output should contain active=true for triggered edge factors")
	}
}

func TestIRRiskLayersContributorsRoundTrip(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "contrib-host",
		Hostname:  "contrib.example.com",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.70,
			Threat:    0.90,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Check", Passed: false, Delta: -10},
			{CheckID: "EF-001", Domain: "attack_surface", Name: "2FA Check", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	ir := NewIR(input, config, output)

	if len(ir.Output.RiskLayers.Intrinsic.Contributors) == 0 {
		t.Error("intrinsic layer should have contributors")
	}

	hasDomainScores := false
	for _, c := range ir.Output.RiskLayers.Intrinsic.Contributors {
		if c == "domain_scores" {
			hasDomainScores = true
		}
	}
	if !hasDomainScores {
		t.Error("intrinsic layer contributors should include 'domain_scores'")
	}

	if len(ir.Output.RiskLayers.Exposure.Contributors) == 0 {
		t.Error("exposure layer should have contributors")
	}
	foundExposure := false
	for _, c := range ir.Output.RiskLayers.Exposure.Contributors {
		if c == "exposure_coefficient" {
			foundExposure = true
		}
	}
	if !foundExposure {
		t.Error("exposure layer should have 'exposure_coefficient' contributor")
	}

	if len(ir.Output.RiskLayers.Threat.Contributors) == 0 {
		t.Error("threat layer should have contributors")
	}
	foundThreat := false
	for _, c := range ir.Output.RiskLayers.Threat.Contributors {
		if c == "threat_coefficient" {
			foundThreat = true
		}
	}
	if !foundThreat {
		t.Error("threat layer should have 'threat_coefficient' contributor")
	}

	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	restored, err := UnmarshalIR(data)
	if err != nil {
		t.Fatalf("UnmarshalIR failed: %v", err)
	}

	origIntrinsic := ir.Output.RiskLayers.Intrinsic.Contributors
	restIntrinsic := restored.Output.RiskLayers.Intrinsic.Contributors
	if len(origIntrinsic) != len(restIntrinsic) {
		t.Errorf("intrinsic contributors length mismatch: original=%d, restored=%d", len(origIntrinsic), len(restIntrinsic))
	} else {
		origSet := make(map[string]bool)
		for _, c := range origIntrinsic {
			origSet[c] = true
		}
		for _, c := range restIntrinsic {
			if !origSet[c] {
				t.Errorf("unexpected intrinsic contributor after round-trip: %s", c)
			}
		}
	}

	if len(ir.Output.RiskLayers.Exposure.Contributors) != len(restored.Output.RiskLayers.Exposure.Contributors) {
		t.Errorf("exposure contributors length mismatch")
	}
	if len(ir.Output.RiskLayers.Threat.Contributors) != len(restored.Output.RiskLayers.Threat.Contributors) {
		t.Errorf("threat contributors length mismatch")
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"contributors"`) {
		t.Error("JSON output should contain contributors arrays")
	}
	if !strings.Contains(jsonStr, `"domain_scores"`) {
		t.Error("JSON intrinsic contributors should reference domain_scores")
	}
}

func TestNewIR(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:      "test-new-ir",
		Hostname:    "newir.example.com",
		Threshold:   90,
		RiskContext: RiskContext{Intrinsic: 1.0, Exposure: 0.80, Threat: 0.90},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "Check", Passed: true, Delta: 0},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("ComputeScoreV2 failed: %v", err)
	}

	ir := NewIR(input, config, output)

	if ir.Meta.Version != "2.0" {
		t.Errorf("meta.version: expected 2.0, got %s", ir.Meta.Version)
	}
	if ir.Meta.FormulaID != "ssam_v2.0" {
		t.Errorf("meta.formula_id: expected ssam_v2.0, got %s", ir.Meta.FormulaID)
	}
	if ir.Meta.Timestamp == "" {
		t.Error("meta.timestamp should be set")
	}
	if !strings.HasSuffix(ir.Meta.Timestamp, "Z") {
		t.Error("meta.timestamp should be ISO8601 UTC (end with Z)")
	}
	if ir.Input.HostID != "test-new-ir" {
		t.Errorf("input.host_id: expected test-new-ir, got %s", ir.Input.HostID)
	}
	if ir.Input.Hostname != "newir.example.com" {
		t.Errorf("input.hostname mismatch")
	}
	if ir.Input.Threshold != 90 {
		t.Errorf("input.threshold: expected 90, got %.2f", ir.Input.Threshold)
	}
	if len(ir.Input.Checks) != 1 {
		t.Errorf("input.checks: expected 1, got %d", len(ir.Input.Checks))
	}
	if len(ir.Input.Weights) == 0 {
		t.Error("input.weights should have default weights")
	}
	if len(ir.Input.EdgeFactors) == 0 {
		t.Error("input.edge_factors should have default edge factors")
	}
	if ir.Output.FinalScore < 0 || ir.Output.FinalScore > 100 {
		t.Errorf("output.final_score out of range: %.2f", ir.Output.FinalScore)
	}
	if len(ir.Output.DomainScores) == 0 {
		t.Error("output.domain_scores should not be empty")
	}
}

func TestIRValidate(t *testing.T) {
	ir := SSAMIR{
		Meta: IRMeta{
			Version:   "2.0",
			FormulaID: "ssam_v2.0",
			Timestamp: "2024-01-01T00:00:00Z",
		},
		Input: IRInput{
			HostID:    "valid-host",
			Threshold: 80,
		},
		Output: IROutput{
			FinalScore: 85,
		},
	}

	if err := ir.Validate(); err != nil {
		t.Errorf("valid IR should not error: %v", err)
	}

	irEmptyVersion := ir
	irEmptyVersion.Meta.Version = ""
	if err := irEmptyVersion.Validate(); err == nil {
		t.Error("expected error for empty meta.version")
	}

	irEmptyFormula := ir
	irEmptyFormula.Meta.FormulaID = ""
	if err := irEmptyFormula.Validate(); err == nil {
		t.Error("expected error for empty meta.formula_id")
	}

	irEmptyTimestamp := ir
	irEmptyTimestamp.Meta.Timestamp = ""
	if err := irEmptyTimestamp.Validate(); err == nil {
		t.Error("expected error for empty meta.timestamp")
	}

	irEmptyHost := ir
	irEmptyHost.Input.HostID = ""
	if err := irEmptyHost.Validate(); err == nil {
		t.Error("expected error for empty input.host_id")
	}

	irBadThreshold := ir
	irBadThreshold.Input.Threshold = 0
	if err := irBadThreshold.Validate(); err == nil {
		t.Error("expected error for threshold=0")
	}
	irBadThreshold.Input.Threshold = 101
	if err := irBadThreshold.Validate(); err == nil {
		t.Error("expected error for threshold=101")
	}

	irBadScore := ir
	irBadScore.Output.FinalScore = -1
	if err := irBadScore.Validate(); err == nil {
		t.Error("expected error for negative final_score")
	}
	irBadScore.Output.FinalScore = 101
	if err := irBadScore.Validate(); err == nil {
		t.Error("expected error for final_score > 100")
	}
}

func TestIRMarshalJSON_Indented(t *testing.T) {
	ir := SSAMIR{
		Meta: IRMeta{
			Version:   "2.0",
			FormulaID: "ssam_v2.0",
			Timestamp: "2024-06-15T10:30:00Z",
		},
		Input: IRInput{
			HostID:    "format-test",
			Hostname:  "format.example.com",
			Threshold: 80,
		},
		Output: IROutput{
			FinalScore: 100,
			Acceptable: true,
			Threshold:  80,
		},
	}

	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	if !strings.Contains(jsonStr, "\n") {
		t.Error("MarshalJSON should produce indented output with newlines")
	}
	if !strings.Contains(jsonStr, "  ") {
		t.Error("MarshalJSON should produce indented output with spaces")
	}

	var roundtrip map[string]interface{}
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("indented JSON should be valid: %v", err)
	}
}
