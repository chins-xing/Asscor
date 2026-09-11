package config

import "testing"

// TestDefaultEdgeFactorTriggerMapIsTheSingleSource 锁定出厂默认触发表的七个条目。
//
// 这张表此前被硬编码过两次（internal/engine/ssam/adapter.go 与
// internal/engine/assessor.go 的 evaluateEdgeFactorChain）。下沉到 config 之后，两条评分
// 路径消费的是同一个函数，因此这份断言同时守护**两条**路径：任何条目增删或检查 ID 改动
// 都会同时改变 legacy 与 ssam 的行为，必须是有意为之并单独提交（不得夹带在其它改造里）。
func TestDefaultEdgeFactorTriggerMapIsTheSingleSource(t *testing.T) {
	want := map[string]string{
		"EF-002FA":      "EF-001",
		"EF-SYNCOOKIE":  "RS-005",
		"EF-SELINUX":    "OT-005",
		"EF-APPARMOR":   "OT-005",
		"EF-NO-SIEM":    "RS-007",
		"EF-NO-IDS":     "RS-006",
		edgeFactor3FAID: "EF-002",
	}

	got := DefaultEdgeFactorTriggerMap()
	if len(got) != len(want) {
		t.Fatalf("默认表条目数 = %d, want %d (%v)", len(got), len(want), got)
	}
	for id, check := range want {
		if got[id] != check {
			t.Errorf("默认表[%s] = %q, want %q", id, got[id], check)
		}
	}

	// 每次调用必须是独立 map：adapter 会在返回值上叠加操作员覆盖，
	// 若共享同一份底层 map，第二次调用就会读到上一次的覆盖（跨配置串味）。
	got["EF-SELINUX"] = "OT-999"
	if again := DefaultEdgeFactorTriggerMap(); again["EF-SELINUX"] != "OT-005" {
		t.Errorf("默认表被调用方修改后污染了后续调用：EF-SELINUX = %q", again["EF-SELINUX"])
	}
}

// TestResolveEdgeFactorTriggerMapOverlaysExplicitOverrides 锁定「默认表 + 显式覆盖」的
// 解析语义：覆盖项胜出、未覆盖项保持默认、空值不覆盖、nil 配置退化为纯默认表。
//
// 空值那一项与解析层（ParseEdgeFactorModel 拒绝空 trigger 值）构成两道防线，
// 也与 ssam 装配层的裁定 #5 一致：空值不是「无覆盖」，而是让因子永不激活的静默失效。
func TestResolveEdgeFactorTriggerMapOverlaysExplicitOverrides(t *testing.T) {
	t.Run("覆盖项胜出且不影响其它条目", func(t *testing.T) {
		cfg := Default()
		cfg.EdgeFactorModel.TriggerMap = map[string]string{
			"EF-NO-IDS":  "RS-999",
			"EF-3FA":     "EF-777",
			"EF-SELINUX": "   ", // 空值：不得覆盖
		}

		got := ResolveEdgeFactorTriggerMap(cfg)

		if got["EF-NO-IDS"] != "RS-999" {
			t.Errorf("覆盖项未生效：EF-NO-IDS = %q", got["EF-NO-IDS"])
		}
		if got["EF-3FA"] != "EF-777" {
			t.Errorf("覆盖项未生效：EF-3FA = %q", got["EF-3FA"])
		}
		if got["EF-SELINUX"] != "OT-005" {
			t.Errorf("空白覆盖必须保留默认表值，got %q", got["EF-SELINUX"])
		}
		def := DefaultEdgeFactorTriggerMap()
		for id, want := range def {
			if id == "EF-NO-IDS" || id == "EF-3FA" {
				continue
			}
			if got[id] != want {
				t.Errorf("未覆盖项 %s = %q, want 默认值 %q", id, got[id], want)
			}
		}
		if len(got) != len(def) {
			t.Errorf("解析结果条目数 = %d, want %d（覆盖不得增删条目）", len(got), len(def))
		}
	})

	t.Run("无覆盖时与默认表逐项相等", func(t *testing.T) {
		got := ResolveEdgeFactorTriggerMap(Default())
		def := DefaultEdgeFactorTriggerMap()
		if len(got) != len(def) {
			t.Fatalf("条目数 = %d, want %d", len(got), len(def))
		}
		for id, want := range def {
			if got[id] != want {
				t.Errorf("%s = %q, want %q", id, got[id], want)
			}
		}
	})

	t.Run("nil 配置退化为纯默认表", func(t *testing.T) {
		got := ResolveEdgeFactorTriggerMap(nil)
		def := DefaultEdgeFactorTriggerMap()
		if len(got) != len(def) {
			t.Fatalf("条目数 = %d, want %d", len(got), len(def))
		}
		for id, want := range def {
			if got[id] != want {
				t.Errorf("%s = %q, want %q", id, got[id], want)
			}
		}
	})
}
