//go:build persistence

package persistence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/model"
)

func TestPersistenceModule(t *testing.T) {
	pm := New(t.TempDir())

	if pm.Info().Name != "persistence" {
		t.Fatalf("expected name 'persistence', got '%s'", pm.Info().Name)
	}

	rec := kernel.AssessmentRecord{
		Timestamp:  time.Now(),
		HostID:     "test-01",
		FinalScore: 85.5,
		Acceptable: true,
	}
	err := pm.Append("test_assessments", rec)
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}

	audit := kernel.AuditEntry{
		Timestamp: time.Now(),
		Actor:     "test",
		Action:    "write",
		Target:    "test",
		Success:   true,
	}
	err = pm.WriteAudit(audit)
	if err != nil {
		t.Fatalf("write audit failed: %v", err)
	}

	pm.mu.Lock()
	for _, w := range pm.writers {
		w.sync()
		w.close()
	}
	pm.mu.Unlock()
}

func TestPersistenceInterface_Completeness(t *testing.T) {
	pm := New(t.TempDir())
	var iface kernel.PersistenceInterface = pm
	_ = iface

	dir := pm.DataDir()
	if dir == "" {
		t.Error("DataDir should not be empty")
	}
}

// closePersistenceWriters 关闭全部 jsonl writer：Windows 上不释放句柄会让 t.TempDir 的
// 清理失败（unlinkat: being used by another process）。既有用例在末尾显式 sync+close，
// 这里收成一个助手，避免每个用例重复。
func closePersistenceWriters(pm *Module) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, w := range pm.writers {
		w.sync()
		w.close()
	}
}

// TestOnAssessmentResultPersistsEdgeFactorChain 是观测链的**持久化往返**用例：
// 走生产入口（assessor.result 消息 → AssessmentRecord → JSONL），再从落盘文件读回来，
// 断言链逐字段存活。它同时钉住「构造处真的把 ar.EdgeFactorChain 透出」这一步 ——
// 只加结构体字段而漏掉赋值时，采集器会读到一份永远为空的链（静默失效）。
func TestOnAssessmentResultPersistsEdgeFactorChain(t *testing.T) {
	dir := t.TempDir()
	pm := New(dir)
	pm.cfg = config.Default() // 构造处会读权重生成 dashboard report
	t.Cleanup(func() { closePersistenceWriters(pm) })

	chain := []model.EdgeFactorObservation{
		{Factor: "EF-SELINUX", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82, TS: "2026-09-12T10:00:03Z"},
		{Factor: "EF-APPARMOR", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.838, TS: "2026-09-12T10:00:03Z"},
	}
	ar := &model.AssessmentResult{
		HostID:      "chain-host",
		Threshold:   60,
		FinalScore:  80.02,
		Acceptable:  true,
		ThreatCoeff: 1.4,
		SPCScore:    0.93,
		DomainScores: model.DomainScores{
			AttackSurface: 82, BusinessContinuity: 75, OperationTrust: 68, Resilience: 71,
		},
		EdgeFactors: model.EdgeFactors{
			SELinuxDisabled: 0.82, AppArmorDisabled: 0.838,
			TwoFactorFailure: 1, SYNCookieDisabled: 1, NoSIEM: 1, NoIDS: 1,
		},
		Checks: []model.CheckResult{
			{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -15},
		},
		EdgeFactorChain: chain,
	}

	if err := pm.onAssessmentResult(t.Context(), kernel.Message{Payload: ar}); err != nil {
		t.Fatalf("onAssessmentResult: %v", err)
	}
	pm.flushAll()

	path := filepath.Join(dir, "assessments-"+time.Now().Format("20060102")+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回落盘记录失败（%s）: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("落盘文件没有记录: %q", data)
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, `"edge_factor_chain"`) {
		t.Fatalf("落盘记录里没有观测链（构造处漏了赋值）: %s", last)
	}

	var rec kernel.AssessmentRecord
	if err := json.Unmarshal([]byte(last), &rec); err != nil {
		t.Fatalf("unmarshal 落盘记录: %v", err)
	}
	if !reflect.DeepEqual(rec.EdgeFactorChain, chain) {
		t.Errorf("落盘往返后链不同:\n got %+v\nwant %+v", rec.EdgeFactorChain, chain)
	}
}

// TestOnAssessmentResultOmitsEmptyEdgeFactorChain：未启用合成模型时（链为 nil），
// 落盘记录不得出现 edge_factor_chain 键 —— 历史记录格式逐位不变。
func TestOnAssessmentResultOmitsEmptyEdgeFactorChain(t *testing.T) {
	dir := t.TempDir()
	pm := New(dir)
	pm.cfg = config.Default()
	t.Cleanup(func() { closePersistenceWriters(pm) })

	ar := &model.AssessmentResult{
		HostID: "plain-host", Threshold: 60, FinalScore: 73.9, Acceptable: true,
		ThreatCoeff: 1, SPCScore: 1,
		DomainScores: model.DomainScores{AttackSurface: 90},
		EdgeFactors:  model.EdgeFactors{TwoFactorFailure: 1, SYNCookieDisabled: 1, SELinuxDisabled: 1, AppArmorDisabled: 1, NoSIEM: 1, NoIDS: 1},
	}
	if err := pm.onAssessmentResult(t.Context(), kernel.Message{Payload: ar}); err != nil {
		t.Fatalf("onAssessmentResult: %v", err)
	}
	pm.flushAll()

	path := filepath.Join(dir, "assessments-"+time.Now().Format("20060102")+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回落盘记录失败（%s）: %v", path, err)
	}
	if strings.Contains(string(data), "edge_factor_chain") {
		t.Errorf("未启用模型时不得写出 edge_factor_chain: %s", data)
	}
}
