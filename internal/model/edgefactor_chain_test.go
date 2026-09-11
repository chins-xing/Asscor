package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/model"
)

// 本文件钉住输出层的观测链（spec §5.1 的 observed.edge_factor_chain[]）在**模型层**的两条
// 硬约束：零值不输出（默认路径的历史 JSON 一个字节都不能变），以及字段名与 spec §5.1 逐字一致。

func TestEdgeFactorChainIsOmittedWhenEmpty(t *testing.T) {
	var r model.AssessmentResult
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "edge_factor_chain") {
		t.Fatalf("零值必须不输出（默认路径的历史 JSON 一个字节都不能变）: %s", raw)
	}
}

func TestEdgeFactorChainSerializesSpec51Keys(t *testing.T) {
	r := model.AssessmentResult{EdgeFactorChain: []model.EdgeFactorObservation{{
		Factor: "EF-SELINUX", TriggerCheck: "OT-005",
		CTrigger: 0.9, EffectiveFactor: 0.82, TS: "2026-09-12T10:00:03Z",
	}}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"factor":"EF-SELINUX"`, `"trigger_check":"OT-005"`, `"c_trigger":0.9`, `"effective_factor":0.82`, `"ts":"2026-09-12T10:00:03Z"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("输出缺少 spec §5.1 的键 %s：%s", key, raw)
		}
	}
}
