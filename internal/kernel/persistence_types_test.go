package kernel

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/model"
)

// 本文件钉住 AssessmentRecord 上的观测链透出（spec §5.1 的 observed.edge_factor_chain[]）：
//
//   - 零值不输出（omitempty）—— 未启用合成模型的部署，历史记录格式逐位不变；
//   - 非零时 JSON 键与 model.EdgeFactorObservation 的键**逐字**一致（factor /
//     trigger_check / c_trigger / effective_factor / ts），否则采集器读不出它们；
//   - JSON 往返后链逐字段相同（持久化写出的是 JSON，链的浮点与时间戳都不能在往返中失真）。
func TestAssessmentRecordEdgeFactorChainRoundTrip(t *testing.T) {
	chain := []model.EdgeFactorObservation{
		{Factor: "EF-SELINUX", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82, TS: "2026-09-12T10:00:03Z"},
		{Factor: "EF-APPARMOR", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.838, TS: "2026-09-12T10:00:03Z"},
	}
	rec := AssessmentRecord{
		HostID:          "chain-host",
		FinalScore:      80.02,
		Acceptable:      true,
		EdgeFactorChain: chain,
	}

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// 键必须与 spec §5.1 / model.EdgeFactorObservation 逐字一致。
	for _, key := range []string{
		`"edge_factor_chain"`, `"factor":"EF-SELINUX"`, `"trigger_check":"OT-005"`,
		`"c_trigger":0.9`, `"effective_factor":0.82`, `"ts":"2026-09-12T10:00:03Z"`,
	} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("记录 JSON 缺少 %s：%s", key, raw)
		}
	}

	var back AssessmentRecord
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back.EdgeFactorChain, chain) {
		t.Errorf("往返后链不同:\n got %+v\nwant %+v", back.EdgeFactorChain, chain)
	}
}

// TestAssessmentRecordOmitsEmptyEdgeFactorChain：零值（含 nil 与空切片）都不得出现该键 ——
// 默认路径写出的历史记录必须逐位不变。
func TestAssessmentRecordOmitsEmptyEdgeFactorChain(t *testing.T) {
	for name, rec := range map[string]AssessmentRecord{
		"零值记录":   {},
		"空链记录":   {HostID: "h", EdgeFactorChain: []model.EdgeFactorObservation{}},
		"禁用模型记录": {HostID: "h", FinalScore: 73.9, Acceptable: true},
	} {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if strings.Contains(string(raw), "edge_factor_chain") {
			t.Errorf("%s: 不得输出 edge_factor_chain（omitempty）: %s", name, raw)
		}
	}
}
