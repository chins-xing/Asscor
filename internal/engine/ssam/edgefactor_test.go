//go:build engine

package ssam

import (
	"math"
	"sort"
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

// TestDefaultTriggerMapMatchesCurrentHardcoding 现在做**双向**精确比对（Fix round 1 Minor#6）：
// 只遍历 want 查 got[k] 时，多出来的键（例如误把别的因子写进默认表）检测不到。
// want 里加入 EF-3FA 是裁定 A 的要求：它同样是 ConfigToEdgeFactors 的产出项，其默认触发
// "EF-002" 也是改造前的硬编码原值，故一并进默认表 —— 表长因此是 7 而不是 6。
func TestDefaultTriggerMapMatchesCurrentHardcoding(t *testing.T) {
	want := map[string]string{
		"EF-002FA": "EF-001", "EF-SYNCOOKIE": "RS-005", "EF-SELINUX": "OT-005",
		"EF-APPARMOR": "OT-005", "EF-NO-SIEM": "RS-007", "EF-NO-IDS": "RS-006",
		"EF-3FA": "EF-002",
	}
	got := DefaultTriggerMap()
	if len(got) != len(want) {
		t.Errorf("default trigger map has %d entries, want %d — 缺键与多键都必须被发现", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("trigger[%s] = %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected key %q in the default trigger map", k)
		}
	}
}

// TestTriggerMapComesFromConfigSingleSource 锁定「ssam 路径的触发映射来自 config 的
// 单一来源」：默认表是转发薄包装，显式覆盖由 config.ResolveEdgeFactorTriggerMap 解析。
//
// 与 legacy 路径（internal/engine 的 TestEvaluateEdgeFactorChainAppliesTriggerOverride，
// 断言同一份覆盖在旧引擎上也生效）配对，构成「同一个配置 ⇒ 两条路径同一套触发映射」的
// 证据：两处都断言自己消费的是 config 的解析结果，而不是各自内联的表。
func TestTriggerMapComesFromConfigSingleSource(t *testing.T) {
	// 转发薄包装：DefaultTriggerMap 必须逐项等于 config 的默认表。
	for id, check := range config.DefaultEdgeFactorTriggerMap() {
		if got := DefaultTriggerMap()[id]; got != check {
			t.Errorf("DefaultTriggerMap()[%s] = %q, want config 默认表 %q", id, got, check)
		}
	}
	if len(DefaultTriggerMap()) != len(config.DefaultEdgeFactorTriggerMap()) {
		t.Errorf("转发包装条目数 = %d, want %d", len(DefaultTriggerMap()), len(config.DefaultEdgeFactorTriggerMap()))
	}

	// 覆盖生效：ConfigToEdgeFactors 的 TriggerCheck 出自 config 的解析结果。
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": "OT-099", "EF-3FA": "EF-777"}
	resolved := config.ResolveEdgeFactorTriggerMap(cfg)

	got := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		got[f.ID] = f.TriggerCheck
	}
	for _, id := range []string{"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR", "EF-NO-SIEM", "EF-NO-IDS", "EF-3FA"} {
		if got[id] != resolved[id] {
			t.Errorf("%s TriggerCheck = %q, want config 解析结果 %q", id, got[id], resolved[id])
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

// TestParamsFromConfigAbsentSectionStaysInert pins 裁定 #4 的边界（Fix round 1 Important#1
// 之后收紧）：段缺席时不构造、不校验新模型参数，模型字段一律保持零值 —— 装配层不得凭空
// 造出 p_floor=0.5 这类「看起来可用」的下限；未启用的参数一旦被误用，零值 p_floor 会被
// edgefactor.Validate 大声拒绝，而不是带着捏造的下限静默参与计算。
func TestParamsFromConfigAbsentSectionStaysInert(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || enabled {
		t.Fatalf("absent section must stay inert: enabled=%v err=%v", enabled, err)
	}
	if p.Model != edgefactor.ModelLegacy {
		t.Errorf("model = %q, want legacy", p.Model)
	}
	if p.PFloor != 0 || p.ChainWindowSeconds != 0 {
		t.Errorf("model fields must stay at their zero value, got p_floor=%v chain_window=%d",
			p.PFloor, p.ChainWindowSeconds)
	}
	if len(p.Vectors) != 0 || len(p.Coupling) != 0 || len(p.Lambda) != 0 {
		t.Errorf("absent section must not fabricate model params, got %+v", p)
	}
}

// TestParamsFromConfigErrorPathsKeepLegacyModel pins Fix round 1 Minor#6：所有错误返回
// 统一是 {Model: ModelLegacy} 而不是全零值，使「未启用或出错 ⇒ Model == legacy」这条
// 不变式在每一条返回路径上都成立 —— 调用方无需区分「零值」与「legacy」两种失败形态。
func TestParamsFromConfigErrorPathsKeepLegacyModel(t *testing.T) {
	badTriggerKey := graphTestConfig()
	badTriggerKey.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELNUX": "OT-005"}

	badVectorKey := graphTestConfig()
	badVectorKey.EdgeFactorModel.Vectors = map[string]map[string]float64{"EF-SELNUX": fiveDomainVector(0.5)}

	asymmetricCoupling := graphTestConfig()
	asymmetricCoupling.EdgeFactorModel.Coupling = map[string]map[string]float64{
		"EF-SELINUX": {"EF-APPARMOR": 0.30}, "EF-APPARMOR": {"EF-SELINUX": 0.40},
	}

	missingPFloor := graphTestConfig()
	missingPFloor.EdgeFactorModel.PFloor = 0

	emptyTrigger := graphTestConfig()
	emptyTrigger.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": ""}

	cases := map[string]*config.Config{
		"nil config":          nil,
		"unknown trigger key": badTriggerKey,
		"unknown vector key":  badVectorKey,
		"asymmetric coupling": asymmetricCoupling,
		"missing p_floor":     missingPFloor,
		"empty trigger":       emptyTrigger,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			p, enabled, err := ParamsFromConfig(cfg)
			if err == nil {
				t.Fatal("this config must be rejected")
			}
			if enabled {
				t.Error("a rejected config must not enable the new model")
			}
			if p.Model != edgefactor.ModelLegacy {
				t.Errorf("error return must carry Model=legacy, got %q", p.Model)
			}
		})
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
// 因子的 TriggerCheck 与旧硬编码一致（EF-3FA 的 EF-002 现在也来自默认表，裁定 A）。
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

// TestConfigToEdgeFactorsAppliesEF3FATriggerOverride pins 裁定 A：EF-3FA 是
// ConfigToEdgeFactors 的产出项，故 trigger.EF-3FA 不能再是静默 no-op。
func TestConfigToEdgeFactorsAppliesEF3FATriggerOverride(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-3FA": "EF-777"}
	got := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		got[f.ID] = f.TriggerCheck
	}
	if got["EF-3FA"] != "EF-777" {
		t.Errorf("EF-3FA override not applied, got %q", got["EF-3FA"])
	}
	// 级联语义不得被覆盖动作破坏
	for _, f := range ConfigToEdgeFactors(cfg) {
		if f.ID == "EF-3FA" && (!f.CascadeOnly || f.CascadeTo != "EF-002FA" || f.CascadeValue != 0.82) {
			t.Errorf("EF-3FA cascade fields must be untouched, got %+v", f)
		}
	}
}

// TestConfigToEdgeFactorsAppliesCustomFactorTriggerOverride pins 裁定 A 的键面语义：
// trigger.<自定义因子> 既然被装配层允许，就必须真的被消费 —— 否则又是一条「校验通过
// 但静默无效」的路径。自定义因子的默认触发仍来自 [edge_factors.custom_triggers]，
// 且产出的 ID 保持 parseSections 的小写形态（Fix round 3：产出侧不做归一）。
func TestConfigToEdgeFactorsAppliesCustomFactorTriggerOverride(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	// 注意：真实配置经 parseSections 后键是小写的，这里一并覆盖该形态。
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-custom": {Factor: 0.7, TriggerCheck: "RS-001"},
	}

	plain := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		plain[f.ID] = f.TriggerCheck
	}
	if plain["ef-custom"] != "RS-001" {
		t.Fatalf("without an override the custom trigger must come from [edge_factors.custom_triggers], got %q", plain["ef-custom"])
	}

	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-CUSTOM": "RS-042"}
	got := map[string]string{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		got[f.ID] = f.TriggerCheck
	}
	if got["ef-custom"] != "RS-042" {
		t.Errorf("trigger.EF-CUSTOM must override the custom factor's check, got %q", got["ef-custom"])
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
	a, ok := ActivationFromResult(EdgeFactorResult{
		ID: "EF-SELINUX", Factor: 0.8, Active: true, TriggerConfidence: 0.5,
	}, "OT-005")
	if !ok {
		t.Fatal("an active factor must produce an activation item")
	}
	if a.FactorID != "EF-SELINUX" || a.TriggerCheck != "OT-005" {
		t.Fatalf("identity fields must be carried, got %+v", a)
	}
	if a.CTrigger != 0.5 {
		t.Errorf("CTrigger = %v, want the raw confidence 0.5", a.CTrigger)
	}
	if a.EffectiveFactor != 0.9 {
		t.Errorf("EffectiveFactor = %v, want EffectiveFactor(0.8, 0.5) = 0.9", a.EffectiveFactor)
	}

	full, ok := ActivationFromResult(EdgeFactorResult{ID: "EF-NO-IDS", Factor: 0.88, Active: true, TriggerConfidence: 1}, "")
	if !ok {
		t.Fatal("an active factor must produce an activation item")
	}
	if full.EffectiveFactor != 0.88 {
		t.Errorf("c=1 must keep the configured weight, got %v", full.EffectiveFactor)
	}
}

// TestActivationFromResultSkipsInactiveFactors pins Fix round 1 Important#2：未激活因子
// 必须被滤掉。未激活时 Factor 为 0，而 EffectiveFactor(0, c) 在 c >= 1 时恰好等于 0，
// 0 又是 Synthesize 里「未提供，回落到配置权重」的哨兵 —— 于是「未激活 + Factor==0 +
// TriggerConfidence>=1」会让一个根本没触发的因子按配置权重计入惩罚（静默误评分）。
func TestActivationFromResultSkipsInactiveFactors(t *testing.T) {
	inactive := EdgeFactorResult{ID: "EF-NO-IDS", Factor: 0, Active: false, TriggerConfidence: 1}
	if _, ok := ActivationFromResult(inactive, "RS-006"); ok {
		t.Fatal("an inactive factor must not produce an activation item")
	}

	// 整体效果：只喂入「按契约滤过」的激活项，未激活因子不得降低 P。
	p := edgefactor.Params{
		Model: edgefactor.ModelGraph, PFloor: 0.4,
		Lambda:  map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"EF-NO-IDS": {"attack_surface": 1.0}},
		Factors: map[string]float64{"EF-NO-IDS": 0.88},
	}
	in := edgefactor.Input{}
	if a, ok := ActivationFromResult(inactive, "RS-006"); ok {
		in.Factors = append(in.Factors, a)
	}
	res, err := edgefactor.Synthesize(p, []string{"attack_surface"}, in)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if res.P["attack_surface"] != 1 {
		t.Errorf("an inactive factor must not lower P, got %v", res.P["attack_surface"])
	}

	// 反面对照：若把未激活项原样塞进 Input（EffectiveFactor 恰为 0 = 哨兵），合成层会
	// 回落到配置权重 0.88 并真的扣分 —— 这正是过滤要拦住的静默误评分路径。
	leaked := edgefactor.Input{Factors: []edgefactor.FactorActivation{{
		FactorID:        inactive.ID,
		EffectiveFactor: edgefactor.EffectiveFactor(inactive.Factor, inactive.TriggerConfidence),
	}}}
	leakedRes, err := edgefactor.Synthesize(p, []string{"attack_surface"}, leaked)
	if err != nil {
		t.Fatalf("Synthesize(leaked): %v", err)
	}
	if leakedRes.P["attack_surface"] >= 1 {
		t.Fatalf("control case must show the sentinel fallback penalty, got P=%v", leakedRes.P["attack_surface"])
	}
}

// TestParamsFromConfigRejectsUnknownTriggerKey pins 裁定 A 的键面校验：拼错的
// trigger.EF-SELNUX 目前会被静默丢弃（no-op），与裁定 1 属同源失败类，必须报错。
func TestParamsFromConfigRejectsUnknownTriggerKey(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELNUX": "OT-005"}
	_, _, err := ParamsFromConfig(cfg)
	if err == nil {
		t.Fatal("a trigger override for an unknown factor id must be rejected")
	}
	if !strings.Contains(err.Error(), "EF-SELNUX") {
		t.Errorf("error must name the offending factor, got %v", err)
	}
}

// TestParamsFromConfigAcceptsKnownTriggerKeys pins 裁定 A 的合法键集合：
// 六个内置因子、EF-3FA（无权重但确实是产出项）以及 [edge_factors.custom] 的因子。
func TestParamsFromConfigAcceptsKnownTriggerKeys(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{"ef-custom": {Factor: 0.7}}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{
		"EF-SELINUX": "OT-005", "EF-3FA": "EF-002", "EF-CUSTOM": "RS-001",
	}
	if _, _, err := ParamsFromConfig(cfg); err != nil {
		t.Fatalf("known trigger keys must be accepted: %v", err)
	}
}

// TestParamsFromConfigAddsCustomFactors pins 裁定 B：自定义因子必须进入 Factors，
// 否则 vector.<custom> 会被裁定 1 的「键 ⊆ Factors」直接拒绝，「变量化」对自定义
// 因子不完整。键归一为规范大写，以便与 Task 3 归一后的 vector./coupling. 键对上。
func TestParamsFromConfigAddsCustomFactors(t *testing.T) {
	for name, id := range map[string]string{"canonical": "EF-CUSTOM", "lowercase (parseSections 形态)": "ef-custom"} {
		t.Run(name, func(t *testing.T) {
			cfg := graphTestConfig()
			cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{id: {Factor: 0.7}}
			cfg.EdgeFactorModel.Vectors = map[string]map[string]float64{"EF-CUSTOM": fiveDomainVector(0.5)}

			p, enabled, err := ParamsFromConfig(cfg)
			if err != nil {
				t.Fatalf("a custom factor with a full-coverage vector must be accepted: %v", err)
			}
			if !enabled {
				t.Fatal("the model must be enabled")
			}
			if p.Factors["EF-CUSTOM"] != 0.7 {
				t.Errorf("custom factor weight = %v, want 0.7 (from [edge_factors.custom])", p.Factors["EF-CUSTOM"])
			}
			if _, ok := p.Vectors["EF-CUSTOM"]; !ok {
				t.Errorf("custom vector must survive key validation, got %v", p.Vectors)
			}
		})
	}
}

// TestParamsFromConfigStillValidatesCustomVectors pins 裁定 B 的后半句：自定义因子的
// 向量仍要过值域与覆盖率校验，不得因为「自定义」而放宽。
func TestParamsFromConfigStillValidatesCustomVectors(t *testing.T) {
	over := graphTestConfig()
	over.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{"ef-custom": {Factor: 0.7}}
	over.EdgeFactorModel.Vectors = map[string]map[string]float64{"EF-CUSTOM": fiveDomainVector(1.5)}

	partial := graphTestConfig()
	partial.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{"ef-custom": {Factor: 0.7}}
	partial.EdgeFactorModel.Vectors = map[string]map[string]float64{"EF-CUSTOM": {"attack_surface": 0.5}}

	for name, cfg := range map[string]*config.Config{"Σv > 1": over, "缺域": partial} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParamsFromConfig(cfg); err == nil {
				t.Fatal("a custom factor's vector must still obey Validate")
			}
		})
	}
}

// TestParamsFromConfigBuiltinWeightsWinOverCustomDuplicates pins 一条明确的自决：
// 工厂模板把同样 6 个内置 ID 重复写进 [edge_factors.custom]（键经 parseSections 变成
// 小写），若让它们覆盖 Factors 会静默改写内置权重、破坏 brief 的「[edge_factors] 是
// 单一事实来源」约定，也与 legacy 路径的实际行为（大写查表永远查不到小写键 ⇒ 覆盖
// 从未生效）不一致。故同名自定义项不覆盖内置权重。
func TestParamsFromConfigBuiltinWeightsWinOverCustomDuplicates(t *testing.T) {
	cfg := graphTestConfig()
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-selinux": {Factor: 0.10, TriggerCheck: "OT-005"},
	}
	p, _, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}
	if p.Factors["EF-SELINUX"] != cfg.EdgeFactors.SELinuxDisabled {
		t.Errorf("built-in weight must keep coming from [edge_factors], got %v", p.Factors["EF-SELINUX"])
	}
	if len(p.Factors) != 6 {
		t.Errorf("a lowercase duplicate of a built-in must not add a second key, got %v", len(p.Factors))
	}
}

// factoryLikeConfig 复刻出厂模板的形态：[edge_factors.custom] 把 6 个内置 ID 连同 EF-3FA
// 再列一遍（键经 parseSections 后全是小写），触发检查来自 [edge_factors.custom_triggers]
// （出厂模板里该段同样含 EF-3FA = EF-002），其中 ef-selinux 取行业定制值 0.78（内置项 0.80）。
// 用于固定「改造前后产出逐项一致」这条 Fix round 3 的不变式。
func factoryLikeConfig() *config.Config {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-002fa":     {Factor: 0.85, TriggerCheck: "EF-001"},
		"ef-syncookie": {Factor: 0.75, TriggerCheck: "RS-005"},
		"ef-selinux":   {Factor: 0.78, TriggerCheck: "OT-005"},
		"ef-apparmor":  {Factor: 0.82, TriggerCheck: "OT-005"},
		"ef-no-siem":   {Factor: 0.90, TriggerCheck: "RS-007"},
		"ef-no-ids":    {Factor: 0.88, TriggerCheck: "RS-006"},
		"ef-3fa":       {Factor: 0.82, TriggerCheck: "EF-002"},
	}
	return cfg
}

// sortedByID 返回按 ID 排序的副本（custom 部分的产出顺序取决于 map 迭代，比较前必须定序）。
func sortedByID(factors []EdgeFactorConfig) []EdgeFactorConfig {
	out := append([]EdgeFactorConfig(nil), factors...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TestConfigToEdgeFactorsOutputUnchangedByTriggerRefactor pins Fix round 3 的核心验收不变式：
// 触发映射改造只允许改变 TriggerCheck 的**来源**（改为查表），不得改变条目集合、ID 形状或数值。
// 期望值即改造前 adapter.go 的硬编码产出（内联于此），逐字段比对：
// 7 个内置/级联条目 + [edge_factors.custom] 的全部条目（ID/Name 保持 parseSections 小写化后的
// 原样，Factor 取行业定制值，TriggerCheck 取自定义触发段的值——ef-3fa 在该段里没有条目，故为空）。
//
// 这条不变式测试是唯一正确的验收方式：P4 的硬承诺是「默认 legacy 与历史评分逐位一致」，
// 而 ssam-lib 以 ID 为 map 键（ssam.go 的 efMap），所以**条目集合/ID 形状的任何变化**都可能
// 改变出厂配置的乘子 —— 只有逐项比对能把它挡住（数值层面的间接断言挡不住 ID 形状变化）。
func TestConfigToEdgeFactorsOutputUnchangedByTriggerRefactor(t *testing.T) {
	cfg := factoryLikeConfig()
	wantBuiltin := []EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled", Factor: 0.75, TriggerCheck: "RS-005"},
		{ID: "EF-SELINUX", Name: "SELinux Disabled", Factor: 0.80, TriggerCheck: "OT-005"},
		{ID: "EF-APPARMOR", Name: "AppArmor Disabled", Factor: 0.82, TriggerCheck: "OT-005"},
		{ID: "EF-NO-SIEM", Name: "SIEM Integration Missing", Factor: 0.90, TriggerCheck: "RS-007"},
		{ID: "EF-NO-IDS", Name: "IDS/IPS Missing", Factor: 0.88, TriggerCheck: "RS-006"},
		{ID: ef3FAFactorID, Name: "3FA Not Met", Factor: 0.82, TriggerCheck: "EF-002",
			CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true},
	}
	wantCustom := []EdgeFactorConfig{
		{ID: "ef-002fa", Name: "ef-002fa", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "ef-3fa", Name: "ef-3fa", Factor: 0.82, TriggerCheck: "EF-002"},
		{ID: "ef-apparmor", Name: "ef-apparmor", Factor: 0.82, TriggerCheck: "OT-005"},
		{ID: "ef-no-ids", Name: "ef-no-ids", Factor: 0.88, TriggerCheck: "RS-006"},
		{ID: "ef-no-siem", Name: "ef-no-siem", Factor: 0.90, TriggerCheck: "RS-007"},
		{ID: "ef-selinux", Name: "ef-selinux", Factor: 0.78, TriggerCheck: "OT-005"},
		{ID: "ef-syncookie", Name: "ef-syncookie", Factor: 0.75, TriggerCheck: "RS-005"},
	}

	got := ConfigToEdgeFactors(cfg)
	if len(got) != len(wantBuiltin)+len(wantCustom) {
		t.Fatalf("entry count = %d, want %d（内置 7 + custom %d，一个都不能多、不能少）",
			len(got), len(wantBuiltin)+len(wantCustom), len(wantCustom))
	}
	// 内置部分顺序确定，逐位比对
	for i, want := range wantBuiltin {
		if got[i] != want {
			t.Errorf("builtin entry[%d] =\n  %+v\nwant\n  %+v", i, got[i], want)
		}
	}
	// custom 部分按 ID 定序后逐字段比对
	gotCustom := sortedByID(got[len(wantBuiltin):])
	for i, want := range wantCustom {
		if gotCustom[i] != want {
			t.Errorf("custom entry[%d] =\n  %+v\nwant\n  %+v", i, gotCustom[i], want)
		}
	}
}

// TestConfigToEdgeFactorsKeepsEmptyCustomTrigger 固定另一种合法形态：条目只出现在
// [edge_factors.custom] 而 [edge_factors.custom_triggers] 缺该项（例如操作员新加的自定义因子
// 还没配触发检查）。改造前后都必须原样产出该条目、TriggerCheck 为空 —— 在 ssam-lib 里
// TriggerCheck == "" 永不等于任何 check id，故该条目不激活（既有语义，不是本任务引入）。
func TestConfigToEdgeFactorsKeepsEmptyCustomTrigger(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-custom": {Factor: 0.7}, // [edge_factors.custom_triggers] 里没有 ef-custom
	}
	got := ConfigToEdgeFactors(cfg)
	want := EdgeFactorConfig{ID: "ef-custom", Name: "ef-custom", Factor: 0.7, TriggerCheck: ""}
	if len(got) != 8 {
		t.Fatalf("entry count = %d, want 8（内置 7 + 1 个 custom）", len(got))
	}
	if got[7] != want {
		t.Errorf("custom entry = %+v, want %+v", got[7], want)
	}
}

// TestConfigToEdgeFactorsOverrideChangesOnlyTriggerCheck 收紧上一条：允许的改变只有
// TriggerCheck 一处 —— 用整份产出的逐项 diff 证明覆盖没有夹带任何其它字段的改动。
func TestConfigToEdgeFactorsOverrideChangesOnlyTriggerCheck(t *testing.T) {
	cfg := factoryLikeConfig()
	base := sortedByID(ConfigToEdgeFactors(cfg))

	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": "OT-099", ef3FAFactorID: "EF-777"}
	got := sortedByID(ConfigToEdgeFactors(cfg))
	if len(got) != len(base) {
		t.Fatalf("override must not change the entry count: %d vs %d", len(got), len(base))
	}
	for i := range base {
		want := base[i]
		// 覆盖按「归一后的逻辑因子」生效：同名的内地条目与其小写定制副本都属于该因子，
		// 两者都改（否则定制副本会留着旧触发检查，同一逻辑因子的触发来源不一致）。
		switch NormalizeFactorID(want.ID) {
		case "EF-SELINUX":
			want.TriggerCheck = "OT-099"
		case ef3FAFactorID:
			want.TriggerCheck = "EF-777"
		}
		if got[i] != want {
			t.Errorf("entry[%d] =\n  %+v\nwant\n  %+v（覆盖只应改 TriggerCheck，条目集合/ID/数值都不许动）", i, got[i], want)
		}
	}
}

// TestNormalizeFactorIDIsTheConsumerSideNormalization pins Fix round 3 的落点：归一化放在
// **消费侧**（Task 7 查 Params 之前），产出侧保持改造前的 ID 形状。
func TestNormalizeFactorIDIsTheConsumerSideNormalization(t *testing.T) {
	cases := map[string]string{
		"ef-selinux":    "EF-SELINUX",
		"EF-SELINUX":    "EF-SELINUX",
		"  ef-custom  ": "EF-CUSTOM",
		"":              "",
	}
	for in, want := range cases {
		if got := NormalizeFactorID(in); got != want {
			t.Errorf("NormalizeFactorID(%q) = %q, want %q", in, got, want)
		}
	}
	// 产出侧不得再做归一：custom 条目仍以 parseSections 的小写键原样产出。
	emitted := map[string]bool{}
	cfg := factoryLikeConfig()
	for _, f := range ConfigToEdgeFactors(cfg) {
		emitted[f.ID] = true
	}
	for id := range cfg.EdgeFactorsCustom {
		if !emitted[id] {
			t.Errorf("custom entry %q must be emitted with its raw (lowercase) id", id)
		}
	}
}

// TestNormalizeFactorIDBridgesEmittedIDsToParamsKeys pins「产出 ID 经消费者侧归一后必须都能在
// Params 里查到」这条不变式（取代 Fix round 2 的产出侧归一变体）：
// 正向：每个产出 ID 归一后都有权重（EF-3FA 例外，它是无权重的级联入口）；
// 反向：Params.Factors 的每个键都能由某个产出 ID 归一得到（否则是「配了却永不激活」）。
func TestNormalizeFactorIDBridgesEmittedIDsToParamsKeys(t *testing.T) {
	cfg := factoryLikeConfig()
	cfg.EdgeFactorsCustom["ef-custom"] = config.CustomEdgeFactorConfig{Factor: 0.7, TriggerCheck: "RS-001"}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4,
		Lambda:  map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"EF-CUSTOM": fiveDomainVector(0.5)},
	}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || !enabled {
		t.Fatalf("ParamsFromConfig: enabled=%v err=%v", enabled, err)
	}

	normalized := map[string]bool{}
	for _, f := range ConfigToEdgeFactors(cfg) {
		key := NormalizeFactorID(f.ID)
		normalized[key] = true
		if key == ef3FAFactorID {
			continue // 级联入口：产出但不携带权重
		}
		if _, ok := p.Factors[key]; !ok {
			t.Errorf("emitted id %q normalizes to %q with no weight in Params.Factors — Task 7 必须用 NormalizeFactorID 查表", f.ID, key)
		}
	}
	for id := range p.Factors {
		if !normalized[id] {
			t.Errorf("Params.Factors has %q but no emitted id normalizes to it — 配了却永不激活", id)
		}
	}
}

// TestNormalizeFactorIDMakesCustomVectorsReachable 是给 Task 7 的端到端用法示范：
// 引擎以小写 ID 产出自定义因子（改造前的既有形状），消费侧用 NormalizeFactorID 归一后再查
// Params.Vectors 就能命中。断言不满足于「查得到」：用与全强度（1.0）不同的声明向量跑
// Synthesize，L 精确等于 (1−f)·v[i]；若走了「未声明 → 全强度」fallback 会是 0.3。
func TestNormalizeFactorIDMakesCustomVectorsReachable(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-custom": {Factor: 0.7, TriggerCheck: "RS-001"},
	}
	lambda := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		lambda[d] = 1.0
	}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4, Lambda: lambda,
		Vectors: map[string]map[string]float64{"EF-CUSTOM": fiveDomainVector(0.5)},
	}

	var emitted string
	for _, f := range ConfigToEdgeFactors(cfg) {
		if strings.EqualFold(f.ID, "EF-CUSTOM") {
			emitted = f.ID
		}
	}
	if emitted != "ef-custom" {
		t.Fatalf("producer side must keep the parseSections spelling, got %q", emitted)
	}

	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || !enabled {
		t.Fatalf("ParamsFromConfig: enabled=%v err=%v", enabled, err)
	}
	vec, ok := p.Vectors[NormalizeFactorID(emitted)]
	if !ok {
		t.Fatalf("NormalizeFactorID(%q) = %q must be a key of Params.Vectors, got %v",
			emitted, NormalizeFactorID(emitted), p.Vectors)
	}

	act, ok := ActivationFromResult(EdgeFactorResult{ID: emitted, Factor: 0.7, Active: true, TriggerConfidence: 1}, "RS-001")
	if !ok {
		t.Fatal("an active factor must produce an activation item")
	}
	if act.FactorID != "EF-CUSTOM" {
		t.Errorf("ActivationFromResult must normalize FactorID to the canonical key, got %q", act.FactorID)
	}
	// 声明向量是全 5 域，故 Synthesize 也必须按全 5 域调用（Validate 要求键面一致）。
	res, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), edgefactor.Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors:      []edgefactor.FactorActivation{act},
	})
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	// (1−0.7)×0.5 = 0.15（浮点比较带容差）；0.3 说明走了全强度 fallback。
	if got := res.L["attack_surface"]; math.Abs(got-0.15) > 1e-12 {
		t.Errorf("L = %v, want 0.15 = (1−0.7)×%v（声明向量命中）；0.3 说明走了全强度 fallback", got, vec["attack_surface"])
	}

	// 反面对照：把未归一的 ID 直接塞进 FactorActivation（绕过上面的归一），合成层的
	// Vectors 查表落空并静默按全强度处理 —— 这正是 Task 7 必须走 NormalizeFactorID 的原因。
	leaked, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), edgefactor.Input{
		Factors: []edgefactor.FactorActivation{{
			FactorID: emitted, EffectiveFactor: 0.7,
		}},
	})
	if err != nil {
		t.Fatalf("Synthesize(leaked): %v", err)
	}
	if math.Abs(leaked.L["attack_surface"]-0.3) > 1e-12 {
		t.Fatalf("control case must show the full-strength fallback (L = 0.3), got %v", leaked.L["attack_surface"])
	}
}

// TestParamsFromConfigRejectsSelfCoupling pins Fix round 2 第 2 项：coupling.<X>.<X> 没有任何
// 语义（Synthesize 显式跳过 i == j），此前会静默失效；装配层必须报错，错误信息含该因子 ID。
func TestParamsFromConfigRejectsSelfCoupling(t *testing.T) {
	graph := graphTestConfig()
	graph.EdgeFactorModel.Coupling = map[string]map[string]float64{
		"EF-SELINUX": {"EF-SELINUX": 0.30},
	}

	chain := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	chain.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "chain", PFloor: 0.4, ChainWindowSeconds: 300,
		Lambda: map[string]float64{"attack_surface": 1.0},
		Coupling: map[string]map[string]float64{
			"EF-SELINUX": {"EF-SELINUX": 0.30},
		},
	}

	for name, cfg := range map[string]*config.Config{"graph": graph, "chain": chain} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParamsFromConfig(cfg)
			if err == nil {
				t.Fatal("self-coupling must be rejected, not silently ignored")
			}
			if !strings.Contains(err.Error(), "EF-SELINUX") {
				t.Errorf("error must name the offending factor, got %v", err)
			}
		})
	}
}
