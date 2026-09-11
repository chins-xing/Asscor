package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/model"
)

func TestEdgeFactorsCarryProvenance(t *testing.T) {
	ef := model.EdgeFactors{TwoFactorFailure: 0.85, Model: "graph", ParamsHash: "abc123def4567890"}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"model":"graph"`) || !strings.Contains(string(raw), `"params_hash":"abc123def4567890"`) {
		t.Errorf("provenance fields missing: %s", raw)
	}
	empty, _ := json.Marshal(model.EdgeFactors{TwoFactorFailure: 0.85})
	if strings.Contains(string(empty), "params_hash") || strings.Contains(string(empty), `"model"`) {
		t.Errorf("empty provenance must be omitted (backward compatible): %s", empty)
	}
}
