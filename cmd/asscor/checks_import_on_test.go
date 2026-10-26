//go:build checks && engine

package main

import (
	"testing"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// `asscor`（standalone / legacy 路径）此前**从不装配 `[user_check.*]`**：
// kernel 侧在组合根显式注册（cmd/kernel/main.go），这条路径只空白导入了 checks。
// 于是配置里的自定义检查被解析成 `user_check.<name>.<field>` 后**没有任何调用点**取用。
//
// ⚠️ 教训：验证这条时必须用**合法**的 user_check 配置（`id`/`domain` 等是必填），
// 否则 `ParseUserChecks` 返回空，会把"配置写错"误判成"代码没消费"（此前就踩过）。
func TestRegisterUserChecksPutsItemsIntoRegistry(t *testing.T) {
	cfg, err := config.Parse(`
[user_check.t_reg_a]
id = CU-T-REG-A
domain = operation_trust
name = reg a
file_path = /etc/hostname
file_regex = .+
delta = -3

[user_check.t_reg_b]
id = CU-T-REG-B
domain = operation_trust
name = reg b
file_path = /etc/definitely-not-here-asscor-test
file_regex = .+
delta = -4
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 先确认配置确实被解析出来（否则下面的断言会被"配置写错"掩盖）。
	parsed := config.ParseUserChecks(cfg.AdapterConfig)
	if len(parsed) != 2 {
		t.Fatalf("ParseUserChecks = %d, want 2（测试配置本身必须合法）", len(parsed))
	}

	before := checks.Count()
	if n := registerUserChecks(cfg); n != 2 {
		t.Fatalf("registerUserChecks = %d, want 2", n)
	}
	if got := checks.Count() - before; got != 2 {
		t.Fatalf("注册表新增 %d 条，want 2", got)
	}
	for _, id := range []string{"CU-T-REG-A", "CU-T-REG-B"} {
		item, ok := checks.GetByID(id)
		if !ok {
			t.Fatalf("检查 %q 未进入注册表（standalone 路径又漏了装配）", id)
		}
		if item.Source != model.CheckSourceUser {
			t.Errorf("%q 的 Source = %q, want %q（来源标签是置信度按来源分档的依据）",
				id, item.Source, model.CheckSourceUser)
		}
	}
	checks.Unregister("CU-T-REG-A", "CU-T-REG-B")

	// 没有 [user_check.*] 时必须返回 0。
	if got := registerUserChecks(&config.Config{}); got != 0 {
		t.Errorf("空配置应返回 0，got %d", got)
	}
}
