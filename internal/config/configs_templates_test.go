package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedConfigTemplatesLoad 防回归：随仓库分发的 7 份配置模板必须全部能
// 被 Load 成功解析。历史上 [check_deltas] 段里的 OT-015 漏写负号（写成正值 3），
// 而校验规则要求 delta <= 0，导致这 7 份模板全部加载即报错。
func TestShippedConfigTemplatesLoad(t *testing.T) {
	pattern := filepath.Join("..", "..", "configs", "config.*.ini")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no config templates found at %s", pattern)
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := Load(path); err != nil {
				t.Errorf("config template %s must load: %v", filepath.Base(path), err)
			}
		})
	}
}

// TestWeightsScoringEngineIsParsedFromWeights 钉住"键写在解析器**会读**的段里"的正向一半：
// 解析器只在 `[weights]` 段读 `scoring_engine`（config.go 的 `sections["weights"]` 分支），
// 写在那里时取值必须真的落到 `cfg.ScoringEngine` 上。
//
// 背景（2026-09-12 实测缺陷）：7 份出厂模板把该键与说明写在 `[extension_weights]` 段，
// 而 `[extension_weights]` 的循环只接受数值、对非数值键**静默跳过** ⇒ 运营者按出厂骨架
// 取消注释并填 `legacy` 会得到一个**静默无效**的配置（评分引擎始终走插件路径）。
// 该缺陷已随模板修复，本用例把"键真的被读"钉成可执行断言。
func TestWeightsScoringEngineIsParsedFromWeights(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"weights 段取值", "[weights]\nscoring_engine = legacy\nattack_surface = 35\n", "legacy"},
		{"weights 段留空 = 装配插件引擎", "[weights]\nscoring_engine =\nattack_surface = 35\n", ""},
		{"weights 段大小写与空白", "[weights]\n  Scoring_Engine  =  SSAM  \n", "SSAM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.content)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.ScoringEngine != tc.want {
				t.Errorf("cfg.ScoringEngine = %q, want %q", cfg.ScoringEngine, tc.want)
			}
		})
	}
}

// TestExtensionWeightsScoringEngineIsSilentNoop 钉住同一缺陷的**反向**一半：
// 该键写在 `[extension_weights]` 段时，非数值项被静默跳过 ⇒ 配置"看起来设过了"，
// 而 `cfg.ScoringEngine` 仍是空串。
//
// 这条**不是**在批准那种写法，而是把"静默无效"固定成可执行的证据：一旦解析器将来扩到
// 读该段的这个键，它会红，提醒改动者同步出厂模板的回归断言。
func TestExtensionWeightsScoringEngineIsSilentNoop(t *testing.T) {
	cfg, err := Parse("[extension_weights]\nkernel_security = 10\nscoring_engine = legacy\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ScoringEngine != "" {
		t.Fatalf("cfg.ScoringEngine = %q：解析器现在会读 [extension_weights] 的该键了 —— 请同步出厂模板回归断言", cfg.ScoringEngine)
	}
	// 数值项照常读出（说明这一段的循环确实在跑，只是不认非数值键）。
	if cfg.ExtensionWeights["kernel_security"] != 10 {
		t.Errorf("ExtensionWeights[kernel_security] = %v, want 10", cfg.ExtensionWeights["kernel_security"])
	}
}

// TestShippedTemplatesDeclareScoringEngineOnlyInWeights 钉住出厂模板侧：任何模板都不得在
// 解析器不读的段里声明 `scoring_engine` —— 那正是一处"模板说的位置与实际解析不符"的静默 no-op
// （与历史上出厂模板 `check_deltas` 符号写错同类）。
//
// 判据用 `parseSections`（与解析器同一份分段实现）而不是字符串搜索：注释里的提及不算声明，
// 而"键出现在哪个段"正是本缺陷的全部。
func TestShippedTemplatesDeclareScoringEngineOnlyInWeights(t *testing.T) {
	pattern := filepath.Join("..", "..", "configs", "config.*.ini")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no templates at %s", pattern)
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			rawBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			raw := string(rawBytes)
			sections := parseSections(raw)
			declared := 0
			for section, kv := range sections {
				value, ok := kv["scoring_engine"]
				if !ok {
					continue
				}
				declared++
				if section != "weights" {
					t.Errorf("模板在 [%s] 段声明了 scoring_engine（值 %q），而解析器只从 [weights] 段读它 —— 运营者按模板填写会得到静默无效的配置；把该键连同注释移到 [weights] 段", section, value)
				}
			}
			if declared == 0 {
				t.Errorf("模板 %s 完全没声明 scoring_engine —— 与出厂骨架的约定（在 [weights] 段留空或填 legacy/ssam）不符", filepath.Base(path))
			}
			if !strings.Contains(raw, "scoring_engine") {
				t.Errorf("模板 %s 里连一次 scoring_engine 都没有 —— 骨架的意图（留空 = 装配插件引擎）无从得知", filepath.Base(path))
			}
		})
	}
}
