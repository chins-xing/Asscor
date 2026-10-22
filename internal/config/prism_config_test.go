package config

import (
	"math"
	"strings"
	"testing"
)

// [prism] default_transmission 是跨主机风险传播的**基数**（assessor 用它构造
// EdgeState.RiskTransmission 的基值）。审计发现该键此前**没有任何解析点**：
// Config.PrismDefaultTransmission 恒为代码默认 0.3，运维改了也不生效。
// 本组用例钉住"解析生效 + 坏值 fail-fast"。
func TestParsePrismDefaultTransmission(t *testing.T) {
	t.Run("explicit value wins", func(t *testing.T) {
		cfg, err := Parse("[weights]\nattack_surface = 35\n\n[prism]\ndefault_transmission = 0.55\n")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := cfg.GetPrismDefaultTransmission(); math.Abs(got-0.55) > 1e-9 {
			t.Errorf("GetPrismDefaultTransmission() = %v, want 0.55", got)
		}
	})

	t.Run("absent keeps code default", func(t *testing.T) {
		cfg, err := Parse("[weights]\nattack_surface = 35\n")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := cfg.GetPrismDefaultTransmission(); math.Abs(got-0.3) > 1e-9 {
			t.Errorf("GetPrismDefaultTransmission() = %v, want default 0.3", got)
		}
	})

	bad := map[string]string{
		"zero (would drop all propagated risk)": "0",
		"negative":                              "-0.2",
		"above one (would amplify)":             "1.5",
		"non-numeric":                           "abc",
		"NaN":                                   "NaN",
	}
	for name, v := range bad {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := Parse("[prism]\ndefault_transmission = " + v + "\n")
			if err == nil {
				t.Fatalf("default_transmission = %q must fail fast, got nil error", v)
			}
			if !strings.Contains(err.Error(), "default_transmission") {
				t.Errorf("error must name the key, got: %v", err)
			}
		})
	}
}

// horizon_days 走的是另一条路：buildAdapterConfig 把 [prism] 展平为
// "prism.horizon_days" 进 AdapterConfig，再由 assessor 消费。这条已工作，
// 此处钉住"不要把两条通路的语义搞混"（default_transmission 进结构体字段，
// horizon_days 进 AdapterConfig）。
func TestParsePrismHorizonDaysStillFlowsThroughAdapterConfig(t *testing.T) {
	cfg, err := Parse("[prism]\nhorizon_days = 14\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.AdapterConfig["prism.horizon_days"]; got != "14" {
		t.Errorf("AdapterConfig[prism.horizon_days] = %q, want \"14\"", got)
	}
}
