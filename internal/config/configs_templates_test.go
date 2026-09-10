package config

import (
	"path/filepath"
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
