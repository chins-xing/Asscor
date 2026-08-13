//go:build persistence

package persistence

import (
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
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
