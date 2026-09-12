package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// TestEdgeExpConfigTemplatesLoad 把 spec §5 的实验模板纳入既有回归门禁
// （一个包的改动，不新造工具）：configs/edgeexp/*.ini 必须全部能被 Load 解析。
//
// 例外必须显式断言：m0-baseline.ini **必须**含 [edge_factors.model] 且 model = legacy。
// Task 1 评审实测：`[edge_factors.model]` 段缺席时引擎**不装载**合成模型 ⇒ 记录会变成
// "有惩罚、链为空" ⇒ 离线复算（门禁②）必然失败。显式 legacy 与"不写段"在评分上逐位
// 一致（里程碑 A 裁定），差别只在"有没有观测链"。
//
// 实验模板不能只靠"实验跑起来才发现装不上"：这条用例让模板错在 `go test ./internal/...`
// 就红，而不是在 WSL 上跑完一轮采集之后。
func TestEdgeExpConfigTemplatesLoad(t *testing.T) {
	pattern := filepath.Join("..", "..", "configs", "edgeexp", "*.ini")
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatalf("no edge experiment templates at %s (err=%v)", pattern, err)
	}
	// 四份模板一份都不能少（少一份意味着某个候选没有参数来源，而门禁① 会在
	// "候选装载失败"处才报出来）。
	if len(paths) != 4 {
		t.Fatalf("边缘因子实验模板必须是 4 份（m0-baseline/vector/graph/chain），实际 %d 份: %v", len(paths), paths)
	}
	valid := map[string]bool{"legacy": true, "vector": true, "graph": true, "chain": true}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("实验模板必须能加载: %v", err)
			}
			if cfg.EdgeFactorModel.Model == "" {
				t.Error("实验模板必须声明 [edge_factors.model]（含 M0 基线的显式 legacy）—— 否则引擎不装载、记录没有观测链")
			}
			if !valid[cfg.EdgeFactorModel.Model] {
				t.Errorf("实验模板的 model 必须是 legacy|vector|graph|chain 之一，实际 %q", cfg.EdgeFactorModel.Model)
			}
			if filepath.Base(path) == "m0-baseline.ini" && cfg.EdgeFactorModel.Model != "legacy" {
				t.Errorf("M0 基线必须是显式 model = legacy，实际 %q", cfg.EdgeFactorModel.Model)
			}
			// chain 的窗口只在 > 0 时可用（解析层对"缺窗口的 chain"是硬拒，
			// 而 edgefactor.Validate 同样要求 > 0）。
			if cfg.EdgeFactorModel.Model == "chain" && cfg.EdgeFactorModel.ChainWindowSeconds <= 0 {
				t.Errorf("chain 模板必须带 chain.window_seconds > 0，实际 %d", cfg.EdgeFactorModel.ChainWindowSeconds)
			}
			// 实验采集必须走插件评分引擎（只有那条路径才盖溯源戳并回填观测链）：
			// `[weights] scoring_engine = legacy` 会让 edgescen 以"溯源戳为空"拒绝写出。
			if cfg.ScoringEngine == "legacy" {
				t.Error("实验模板不得把 scoring_engine 设成 legacy —— 那会关掉插件评分引擎，采集器会以『引擎没有装载边缘因子合成模型』拒绝写出记录")
			}
		})
	}
}

// TestWeightsScoringEngineIsParsedFromWeights pins ①：键写在解析器**会读**的段里时，
// 取值必须真的落到 cfg.ScoringEngine 上。
//
// TestEdgeExpTemplatesShareDeploymentSkeleton 钉住"四份实验模板共享同一份部署骨架"这句话。
//
// 它此前**只是文档里的一句声明**（报告与 spec §5.4.3 都这么写），而 diff 并不支持它：注释与标题行
// 在四份之间是不同的，只有**键值**相同。评审指出"声明与证据不符"之后，把它变成可执行断言 ——
// 判据用 parseSections（与解析器同一份分段实现），比较除 `[edge_factors.model]` 之外**全部段的
// 键值集**：任何一段在四份模板之间不一致，候选之间的分数差异就不再能归因于模型参数。
func TestEdgeExpTemplatesShareDeploymentSkeleton(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "configs", "edgeexp", "*.ini"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no edge experiment templates (err=%v)", err)
	}
	// 基线取 m0-baseline.ini（M0 是"评分逐位一致"的那份，其余三份是它的模型段替换）。
	var basePath string
	for _, p := range paths {
		if filepath.Base(p) == "m0-baseline.ini" {
			basePath = p
		}
	}
	if basePath == "" {
		t.Fatalf("缺少 m0-baseline.ini：%v", paths)
	}
	if err := assertSkeletonEqual(basePath, basePath); err != nil {
		t.Fatalf("基线与自身不一致（说明断言写错了）：%v", err)
	}
	for _, p := range paths {
		if p == basePath {
			continue
		}
		if err := assertSkeletonEqual(basePath, p); err != nil {
			t.Errorf("部署骨架不一致：%v", err)
		}
	}
}

// assertSkeletonEqual 比较两份模板在 `[edge_factors.model]` 之外的**每个段的键值**。
func assertSkeletonEqual(basePath, otherPath string) error {
	read := func(path string) (map[string]map[string]string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return parseSections(string(raw)), nil
	}
	base, err := read(basePath)
	if err != nil {
		return err
	}
	other, err := read(otherPath)
	if err != nil {
		return err
	}
	delete(base, "edge_factors.model")
	delete(other, "edge_factors.model")
	names := map[string]bool{}
	for name := range base {
		names[name] = true
	}
	for name := range other {
		names[name] = true
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		b, okB := base[name]
		o, okO := other[name]
		if !okB || !okO {
			return fmt.Errorf("%s 与 %s 的段集不同：段 [%s] 只出现在其中一份里",
				filepath.Base(basePath), filepath.Base(otherPath), name)
		}
		if len(b) != len(o) {
			return fmt.Errorf("%s[%s] 的键数不同：%d vs %d",
				filepath.Base(otherPath), name, len(o), len(b))
		}
		for k, bv := range b {
			ov, ok := o[k]
			if !ok {
				return fmt.Errorf("%s[%s] 缺键 %q（基线的值是 %q）", filepath.Base(otherPath), name, k, bv)
			}
			if ov != bv {
				return fmt.Errorf("%s[%s] %s = %q，基线是 %q",
					filepath.Base(otherPath), name, k, ov, bv)
			}
		}
	}
	return nil
}

// TestWeightsScoringEngineIsParsedFromWeights 钉住 ①：键写在解析器**会读**的段里时，
// 取值必须真的落到 cfg.ScoringEngine 上。
//
// 这是出厂模板那处"静默 no-op"缺陷的正向一半：解析器只在 `[weights]` 段读这个键
// （config.go 的 `if sec, ok := sections["weights"]` 分支），而模板把说明与键写在了
// `[extension_weights]` ⇒ 运营者按骨架取消注释并填 legacy 会得到一个**静默无效**的配置。
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

// TestExtensionWeightsScoringEngineIsSilentNoop 钉住缺陷的**反向**一半（为什么必须有这条断言）：
// 同一个键写在 `[extension_weights]` 段时，解析器只取数值、非数值静默跳过 ⇒
// 配置"看起来设过了"，而 cfg.ScoringEngine 仍是空串。
//
// 这条用例**不是**在批准那种写法，而是把"静默无效"这件事固定成可执行的证据：
// 一旦解析器将来扩到读 `[extension_weights]` 的该键，它会红，提醒改动者同步
// 出厂模板的回归断言（TestShippedTemplatesDeclareScoringEngineOnlyInWeights）。
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

// TestShippedTemplatesDeclareScoringEngineOnlyInWeights pins ②：任何**出厂模板**
// 都不得在解析器不读的段里声明 scoring_engine —— 那正是一处"模板说的位置与实际解析不符"
// 的静默 no-op（与历史上出厂模板 check_deltas 符号写错同类）。
//
// 判据用 parseSections（与解析器同一份分段实现）而不是字符串搜索：注释里的提及不算声明，
// 而"键出现在哪个段"正是本缺陷的全部。
func TestShippedTemplatesDeclareScoringEngineOnlyInWeights(t *testing.T) {
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "configs", "config.*.ini"),
		filepath.Join("..", "..", "configs", "edgeexp", "*.ini"),
	} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(found) == 0 {
			t.Fatalf("no templates at %s", pattern)
		}
		paths = append(paths, found...)
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			sections := parseSections(string(raw))
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
			if !strings.Contains(string(raw), "scoring_engine") {
				t.Errorf("模板 %s 里连一次 scoring_engine 都没有 —— 骨架的意图（留空 = 装配插件引擎）无从得知", filepath.Base(path))
			}
		})
	}
}
