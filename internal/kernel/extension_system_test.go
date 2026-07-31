package kernel

import (
	"context"
	"sync"
	"testing"
)

// TestExtensionSystemE2E verifies the complete extension system flow:
// RegisterPoint → RegisterExtension → Execute → handler called
func TestExtensionSystemE2E(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "assessor.post_evaluate", Description: "test", Version: "1.0"})

	var mu sync.Mutex
	called := 0

	// Simulate extmgr bridge: installation triggers RegisterExtension
	r.RegisterExtension("test-plugin", "assessor.post_evaluate", func(ctx context.Context, data interface{}) error {
		mu.Lock()
		called++
		mu.Unlock()
		return nil
	}, 50)

	// Simulate assessor firing the extension point after evaluation
	errs := r.Execute(context.Background(), "assessor.post_evaluate", map[string]interface{}{
		"host_id": "test-host", "final_score": 85.5,
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	mu.Lock()
	if called != 1 {
		t.Fatalf("expected handler to be called once, got %d", called)
	}
	mu.Unlock()
}

// TestExtensionSystemMultiplePlugins verifies multiple plugins can subscribe to the same point
func TestExtensionSystemMultiplePlugins(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "assessor.outbound"})

	order := make(chan int, 3)

	// Plugin A (priority 10, runs first)
	r.RegisterExtension("plugin-a", "assessor.outbound", func(ctx context.Context, data interface{}) error {
		order <- 1
		return nil
	}, 10)

	// Plugin B (priority 20)
	r.RegisterExtension("plugin-b", "assessor.outbound", func(ctx context.Context, data interface{}) error {
		order <- 2
		return nil
	}, 20)

	// Plugin C (priority 30, runs last)
	r.RegisterExtension("plugin-c", "assessor.outbound", func(ctx context.Context, data interface{}) error {
		order <- 3
		return nil
	}, 30)

	r.Execute(context.Background(), "assessor.outbound", nil)
	close(order)

	var results []int
	for o := range order {
		results = append(results, o)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(results))
	}
	for i, expected := range []int{1, 2, 3} {
		if results[i] != expected {
			t.Errorf("position %d: expected %d, got %d", i, expected, results[i])
		}
	}
}

// TestExtensionSystemUnregisterThenRefire verifies unregistered plugins don't fire
func TestExtensionSystemUnregisterThenRefire(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "spc.cve_updated"})

	count := 0
	r.RegisterExtension("removable", "spc.cve_updated", func(ctx context.Context, data interface{}) error {
		count++
		return nil
	}, 50)

	r.Execute(context.Background(), "spc.cve_updated", nil)
	if count != 1 {
		t.Fatalf("expected 1 call, got %d", count)
	}

	r.UnregisterPlugin("removable")

	r.Execute(context.Background(), "spc.cve_updated", nil)
	if count != 1 {
		t.Fatalf("expected still 1 call after unregister, got %d", count)
	}
}
