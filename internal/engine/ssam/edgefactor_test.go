//go:build engine

package ssam

import (
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
	"github.com/chins-xing/asscor/internal/model"
)

// defaultTestEdgeFactors 返回与 config.ini 现状一致的因子权重（测试共享）。
func defaultTestEdgeFactors() model.EdgeFactors {
	return model.EdgeFactors{
		TwoFactorFailure: 0.85, SYNCookieDisabled: 0.75, SELinuxDisabled: 0.80,
		AppArmorDisabled: 0.82, NoSIEM: 0.90, NoIDS: 0.88,
	}
}

func TestDefaultTriggerMapMatchesCurrentHardcoding(t *testing.T) {
	want := map[string]string{
		"EF-002FA": "EF-001", "EF-SYNCOOKIE": "RS-005", "EF-SELINUX": "OT-005",
		"EF-APPARMOR": "OT-005", "EF-NO-SIEM": "RS-007", "EF-NO-IDS": "RS-006",
	}
	got := DefaultTriggerMap()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("trigger[%s] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParamsFromConfigDefaultsToLegacy(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}
	if enabled {
		t.Error("without [edge_factors.model] the new model must stay disabled")
	}
	if p.Model != edgefactor.ModelLegacy {
		t.Errorf("model = %q, want legacy", p.Model)
	}
}

func TestParamsFromConfigEnablesConfiguredModel(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4,
		Lambda: map[string]float64{"attack_surface": 1.5},
		// 装配层的启用路径必须调用 Validate(DefaultDomains())（主控裁定 #4），而
		// Validate 要求「已声明的 vector 覆盖全部传入域」。config 段的 vector.<factor>
		// 语法本身就强制 5 个逗号分隔值，故这里按真实解析结果补全其余 4 个域（0），
		// 其余断言与 brief 逐字一致。
		Vectors: map[string]map[string]float64{"EF-SELINUX": {
			"attack_surface": 0.5, "business_continuity": 0, "operation_trust": 0,
			"resilience": 0, "kernel_security": 0,
		}},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}},
	}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}
	if !enabled || p.Model != edgefactor.ModelGraph || p.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
		t.Fatalf("unexpected params: enabled=%v %+v", enabled, p)
	}
	// 因子权重来自既有 [edge_factors] 段（保持单一事实来源）
	if p.Factors["EF-SELINUX"] != cfg.EdgeFactors.SELinuxDisabled {
		t.Errorf("factor weight must come from [edge_factors], got %v", p.Factors["EF-SELINUX"])
	}
}

// graphTestConfig 返回一个启用 graph 模型的合法装配输入（λ + p_floor 齐备）。
// 调用方按需覆盖 TriggerMap / Vectors / Coupling 来构造各条校验的用例。
func graphTestConfig() *config.Config {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model:  "graph",
		PFloor: 0.4,
		Lambda: map[string]float64{"attack_surface": 1.5},
	}
	return cfg
}

// fiveDomainVector 返回覆盖全部默认域、权重和为 sum 的向量（Validate 要求覆盖）。
func fiveDomainVector(sum float64) map[string]float64 {
	vec := make(map[string]float64, len(edgefactor.DefaultDomains()))
	for i, d := range edgefactor.DefaultDomains() {
		if i == 0 {
			vec[d] = sum
			continue
		}
		vec[d] = 0
	}
	return vec
}

// TestParamsFromConfigRejectsVectorKeyAbsentFromFactors pins 主控裁定 #1：Vectors 的
// 键必须 ⊆ Factors 的键。拼错的因子 ID 会让该向量静默失效（合成层取 fallback 满强度），
// 所以必须在装配层报错，而不是留给运行时的静默降级。
func TestParamsFromConfigRejectsVectorKeyAbsentFromFactors(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.Vectors = map[string]map[string]float64{
		"EF-SELNUX": fiveDomainVector(0.5), // 拼错：应为 EF-SELINUX
	}
	_, _, err := ParamsFromConfig(cfg)
	if err == nil {
		t.Fatal("a vector for an unknown factor id must be rejected")
	}
	if !strings.Contains(err.Error(), "EF-SELNUX") {
		t.Errorf("error must name the offending factor, got %v", err)
	}
}

// TestParamsFromConfigRejectsCouplingKeyAbsentFromFactors pins 裁定 #1 对耦合项的
// 两侧：from 与 to 都必须出现在 Factors 中。
func TestParamsFromConfigRejectsCouplingKeyAbsentFromFactors(t *testing.T) {
	cases := map[string]map[string]map[string]float64{
		"unknown from": {"EF-SELNUX": {"EF-APPARMOR": 0.35}},
		"unknown to":   {"EF-SELINUX": {"EF-APPARMORX": 0.35}},
	}
	for name, coupling := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := graphTestConfig()
			cfg.EdgeFactorModel.Coupling = coupling
			if _, _, err := ParamsFromConfig(cfg); err == nil {
				t.Fatal("a coupling for an unknown factor id must be rejected")
			}
		})
	}
}

// TestParamsFromConfigRejectsAsymmetricGraphCoupling pins 主控裁定 #2：graph 是对称
// 语义，双向配置不同值属于静默决策（取哪一侧未被规定），必须报错。
func TestParamsFromConfigRejectsAsymmetricGraphCoupling(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.Coupling = map[string]map[string]float64{
		"EF-SELINUX":  {"EF-APPARMOR": 0.30},
		"EF-APPARMOR": {"EF-SELINUX": 0.40},
	}
	if _, _, err := ParamsFromConfig(cfg); err == nil {
		t.Fatal("graph coupling with two different values for the same pair must be rejected")
	}
}

// TestParamsFromConfigAcceptsSymmetricGraphCoupling 是上一条的对照：显式双向等值时
// 没有歧义，必须放行（否则对称写法的配置会被无故拒绝）。
func TestParamsFromConfigAcceptsSymmetricGraphCoupling(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.Coupling = map[string]map[string]float64{
		"EF-SELINUX":  {"EF-APPARMOR": 0.35},
		"EF-APPARMOR": {"EF-SELINUX": 0.35},
	}
	if _, _, err := ParamsFromConfig(cfg); err != nil {
		t.Fatalf("symmetric graph coupling must be accepted: %v", err)
	}
}

// TestParamsFromConfigAllowsAsymmetricChainCoupling pins 裁定 #2 的豁免分支：chain 是
// 有向时序语义，双向不同值合法，不得套用 graph 的对称一致性校验。
func TestParamsFromConfigAllowsAsymmetricChainCoupling(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "chain", PFloor: 0.4, ChainWindowSeconds: 300,
		Lambda: map[string]float64{"attack_surface": 1.5},
		Coupling: map[string]map[string]float64{
			"EF-SELINUX":  {"EF-APPARMOR": 0.30},
			"EF-APPARMOR": {"EF-SELINUX": 0.40},
		},
	}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("chain coupling is directional and must be accepted: %v", err)
	}
	if !enabled || p.Model != edgefactor.ModelChain {
		t.Fatalf("unexpected params: enabled=%v model=%v", enabled, p.Model)
	}
	if p.Coupling["EF-APPARMOR"]["EF-SELINUX"] != 0.40 {
		t.Errorf("directional coupling must be preserved, got %v", p.Coupling)
	}
}

// TestParamsFromConfigRejectsEmptyTriggerOverride pins 主控裁定 #5：空 trigger 值不得
// 覆盖默认表（那会让因子静默失去触发检查 ⇒ 永不激活）。必须在装配层报错。
func TestParamsFromConfigRejectsEmptyTriggerOverride(t *testing.T) {
	enabled := graphTestConfig()
	enabled.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": "   "}

	disabled := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	disabled.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": ""}

	for name, cfg := range map[string]*config.Config{"enabled": enabled, "legacy": disabled} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParamsFromConfig(cfg); err == nil {
				t.Fatal("an empty trigger check id must be rejected, not applied")
			}
		})
	}
}

// TestParamsFromConfigRejectsMissingPFloor pins 裁定 #4 的下半句：启用路径必须跑
// Validate，使 p_floor 缺失（零值）之类的错误在装配处暴露，而不是留到运行时的
// P_d = 0 + (1-0)·exp(...)（即惩罚下限 100%，域分被清零）。
func TestParamsFromConfigRejectsMissingPFloor(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.PFloor = 0
	if _, _, err := ParamsFromConfig(cfg); err == nil {
		t.Fatal("missing p_floor must be rejected on the enabled path")
	}
}

// TestParamsFromConfigRejectsVectorSumAboveOne pins 裁定 #4：结构规则由 Validate
// 单点负责，装配层不得自行放宽（Σ_d v_i[d] ≤ 1）。
func TestParamsFromConfigRejectsVectorSumAboveOne(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.Vectors = map[string]map[string]float64{
		"EF-SELINUX": fiveDomainVector(1.5),
	}
	if _, _, err := ParamsFromConfig(cfg); err == nil {
		t.Fatal("vector summing above 1 must be rejected by Validate")
	}
}

// TestParamsFromConfigAbsentSectionStaysInert 记录裁定 #4 的边界：段缺席时不构造、
// 不校验新模型参数，调用方据 enabled=false 保持既有路径。
func TestParamsFromConfigAbsentSectionStaysInert(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || enabled {
		t.Fatalf("absent section must stay inert: enabled=%v err=%v", enabled, err)
	}
	if p.Model != edgefactor.ModelLegacy {
		t.Errorf("model = %q, want legacy", p.Model)
	}
	if len(p.Vectors) != 0 || len(p.Coupling) != 0 || len(p.Lambda) != 0 {
		t.Errorf("absent section must not fabricate model params, got %+v", p)
	}
}

// TestParamsFromConfigRejectsNilConfig 钉住 nil 防护：装配层是配置驱动的入口，
// nil 配置必须变成 error，而不是在 cfg.EdgeFactors 上 panic 打掉调用进程。
func TestParamsFromConfigRejectsNilConfig(t *testing.T) {
	_, enabled, err := ParamsFromConfig(nil)
	if err == nil {
		t.Fatal("nil config must be rejected")
	}
	if enabled {
		t.Error("nil config must not enable the new model")
	}
}

// TestConfigToEdgeFactorsKeepsDefaultTriggers 是改造前的逐字回归：不带覆盖时每个
// 内置因子的 TriggerCheck 与旧硬编码一致。
func TestConfigToEdgeFactorsKeepsDefaultTriggers(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	got := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		got[f.ID] = f.TriggerCheck
	}
	for id, want := range DefaultTriggerMap() {
		if got[id] != want {
			t.Errorf("trigger[%s] = %q, want %q", id, got[id], want)
		}
	}
	if got["EF-3FA"] != "EF-002" {
		t.Errorf("EF-3FA trigger = %q, want EF-002 (cascade entry unchanged)", got["EF-3FA"])
	}
}

// TestConfigToEdgeFactorsAppliesTriggerOverride 覆盖生效且互不串扰。
func TestConfigToEdgeFactorsAppliesTriggerOverride(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": "OT-099"}
	got := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		got[f.ID] = f.TriggerCheck
	}
	if got["EF-SELINUX"] != "OT-099" {
		t.Errorf("override not applied: %q", got["EF-SELINUX"])
	}
	if got["EF-APPARMOR"] != "OT-005" {
		t.Errorf("override leaked to EF-APPARMOR: %q", got["EF-APPARMOR"])
	}
}

// TestConfigToEdgeFactorsIgnoresEmptyTriggerOverride 是裁定 #5 的第二道防线：
// ConfigToEdgeFactors 没有 error 通道，但绝不能把空值写进触发表 —— 否则该因子
// 会静默失去触发检查。报错由 ParamsFromConfig 负责（见上一条测试）。
func TestConfigToEdgeFactorsIgnoresEmptyTriggerOverride(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": ""}
	for _, f := range ConfigToEdgeFactors(cfg) {
		if f.ID == "EF-SELINUX" && f.TriggerCheck != "OT-005" {
			t.Fatalf("empty override must not blank the default trigger, got %q", f.TriggerCheck)
		}
	}
}

// TestActivationFromResultConvertsTriggerConfidenceToEffectiveFactor pins 主控裁定 #3：
// CTrigger 不进 Synthesize，装配层必须用 EffectiveFactor(f, c) 换算后再填入。
// 这里同时钉住「原始 c 被直接塞进 EffectiveFactor」这一错误实现：c=0.5 时
// EffectiveFactor = 0.9 ≠ 0.5。
func TestActivationFromResultConvertsTriggerConfidenceToEffectiveFactor(t *testing.T) {
	a := ActivationFromResult(EdgeFactorResult{
		ID: "EF-SELINUX", Factor: 0.8, Active: true, TriggerConfidence: 0.5,
	}, "OT-005")
	if a.FactorID != "EF-SELINUX" || a.TriggerCheck != "OT-005" {
		t.Fatalf("identity fields must be carried, got %+v", a)
	}
	if a.CTrigger != 0.5 {
		t.Errorf("CTrigger = %v, want the raw confidence 0.5", a.CTrigger)
	}
	if a.EffectiveFactor != 0.9 {
		t.Errorf("EffectiveFactor = %v, want EffectiveFactor(0.8, 0.5) = 0.9", a.EffectiveFactor)
	}

	full := ActivationFromResult(EdgeFactorResult{ID: "EF-NO-IDS", Factor: 0.88, TriggerConfidence: 1}, "")
	if full.EffectiveFactor != 0.88 {
		t.Errorf("c=1 must keep the configured weight, got %v", full.EffectiveFactor)
	}
}
