//go:build engine

package ssam

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// provenanceChecks 是溯源用例的最小检查集（一次失败 + 一次通过）。
func provenanceChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -10},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true},
	}
}

// scoreWithAdapter 用给定配置跑一遍 **ssam 插件路径** 的在线评分，返回结果。
func scoreWithAdapter(t *testing.T, cfg *config.Config) *model.AssessmentResult {
	t.Helper()
	result := &model.AssessmentResult{
		HostID:      "provenance-host",
		Threshold:   60,
		SPCScore:    1.0,
		ThreatCoeff: 1.0,
		Checks:      provenanceChecks(),
	}
	if err := NewEngineAdapter(cfg).ComputeScore(context.Background(), result); err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	return result
}

// TestEngineAdapterStampsProvenanceWhenModelConfigured pin 住「启用 [edge_factors.model]
// 时，输出层必须带上本次评分所用的模型与参数指纹」（spec §4 规则 4）。
//
// 断言不满足于「非空」：指纹必须等于 ParamsFromConfig 装配出的那套参数的 Hash() ——
// 溯源字段的价值全在「能被离线重算复现」，一个随便生成的字符串没有任何审计意义。
func TestEngineAdapterStampsProvenanceWhenModelConfigured(t *testing.T) {
	cfg := graphTestConfig()
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || !enabled {
		t.Fatalf("precondition ParamsFromConfig: enabled=%v err=%v", enabled, err)
	}

	got := scoreWithAdapter(t, cfg)

	if got.EdgeFactors.Model != string(p.Model) {
		t.Errorf("EdgeFactors.Model = %q, want %q", got.EdgeFactors.Model, p.Model)
	}
	if got.EdgeFactors.ParamsHash != p.Hash() {
		t.Errorf("EdgeFactors.ParamsHash = %q, want %q", got.EdgeFactors.ParamsHash, p.Hash())
	}
	if len(got.EdgeFactors.ParamsHash) != 16 {
		t.Errorf("ParamsHash 必须是 16 位十六进制指纹，got %q", got.EdgeFactors.ParamsHash)
	}

	raw, err := json.Marshal(got.EdgeFactors)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"model":"graph"`) {
		t.Errorf("JSON 缺少 model 字段: %s", raw)
	}
	if !strings.Contains(string(raw), `"params_hash":"`+p.Hash()+`"`) {
		t.Errorf("JSON 缺少 params_hash 字段: %s", raw)
	}
}

// TestEngineAdapterLeavesProvenanceEmptyWithoutModelSection 是向后兼容硬要求的执行期守卫：
// 未配置 [edge_factors.model]（出厂配置与全部历史配置都是这样）时，输出层必须保持零值，
// **JSON 里不得出现 model / params_hash 两个键** —— 历史输出逐位不变。
func TestEngineAdapterLeavesProvenanceEmptyWithoutModelSection(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}

	got := scoreWithAdapter(t, cfg)

	if got.EdgeFactors.Model != "" || got.EdgeFactors.ParamsHash != "" {
		t.Errorf("未启用模型段的路径必须留空，got Model=%q ParamsHash=%q",
			got.EdgeFactors.Model, got.EdgeFactors.ParamsHash)
	}
	raw, err := json.Marshal(got.EdgeFactors)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "params_hash") || strings.Contains(string(raw), `"model"`) {
		t.Errorf("零值溯源字段必须被 omitempty 省略（向后兼容）: %s", raw)
	}
}

// TestEngineAdapterNeverFabricatesHashForUnusableParams pin 住「参数不可用时不写指纹」：
// 模型段存在但参数不合法（此处缺 p_floor）⇒ ParamsFromConfig 报错 ⇒ 溯源留空。
// 写一个无法复现的指纹比留空更糟：它会让审计以为这次评分可复现，而实际用的并不是那套参数。
func TestEngineAdapterNeverFabricatesHashForUnusableParams(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.PFloor = 0
	if _, _, err := ParamsFromConfig(cfg); err == nil {
		t.Fatal("precondition: 缺 p_floor 的模型段必须被 ParamsFromConfig 拒绝")
	}

	got := scoreWithAdapter(t, cfg)

	if got.EdgeFactors.Model != "" || got.EdgeFactors.ParamsHash != "" {
		t.Errorf("参数不可用时必须留空，got Model=%q ParamsHash=%q",
			got.EdgeFactors.Model, got.EdgeFactors.ParamsHash)
	}
}
