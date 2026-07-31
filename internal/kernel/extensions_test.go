package kernel

import (
	"context"
	"errors"
	"testing"
)

func TestExtensionRegistryRegisterPoint(t *testing.T) {
	r := NewExtensionRegistry()

	r.RegisterPoint(ExtensionPoint{Name: "test.point", Description: "test", Version: "1.0"})

	p, ok := r.GetPoint("test.point")
	if !ok {
		t.Fatal("expected point to be registered")
	}
	if p.Name != "test.point" {
		t.Errorf("Name = %q, want test.point", p.Name)
	}

	_, ok = r.GetPoint("nonexistent")
	if ok {
		t.Error("expected nonexistent point to not exist")
	}
}

func TestExtensionRegistryRegisterAndExecute(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "test.execute"})

	called := make(chan string, 2)
	r.RegisterExtension("p1", "test.execute", func(ctx context.Context, data interface{}) error {
		called <- "p1"
		return nil
	}, 10)
	r.RegisterExtension("p2", "test.execute", func(ctx context.Context, data interface{}) error {
		called <- "p2"
		return nil
	}, 50)

	errs := r.Execute(context.Background(), "test.execute", "data")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	close(called)
	var calls []string
	for c := range called {
		calls = append(calls, c)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	if calls[0] != "p1" || calls[1] != "p2" {
		t.Errorf("expected [p1 p2] (priority order), got %v", calls)
	}
}

func TestExtensionRegistryExecuteNoHandlers(t *testing.T) {
	r := NewExtensionRegistry()

	errs := r.Execute(context.Background(), "nonexistent", nil)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors for no handlers, got %d", len(errs))
	}
}

func TestExtensionRegistryExecuteWithError(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "test.err"})

	r.RegisterExtension("p1", "test.err", func(ctx context.Context, data interface{}) error {
		return errors.New("handler error")
	}, 50)

	errs := r.Execute(context.Background(), "test.err", nil)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}

func TestExtensionRegistryUnregisterPlugin(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "test.unreg"})

	r.RegisterExtension("p1", "test.unreg", func(ctx context.Context, data interface{}) error {
		return nil
	}, 50)
	r.RegisterExtension("p2", "test.unreg", func(ctx context.Context, data interface{}) error {
		return nil
	}, 60)

	exts := r.ListExtensions("test.unreg")
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}

	r.UnregisterPlugin("p1")

	exts = r.ListExtensions("test.unreg")
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension after unregister, got %d", len(exts))
	}
	if exts[0] != "p2" {
		t.Errorf("expected p2 to remain, got %s", exts[0])
	}
}

func TestExtensionRegistryExecuteUntilFirst(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "test.first"})

	r.RegisterExtension("p1", "test.first", func(ctx context.Context, data interface{}) error {
		return errors.New("fail")
	}, 10)
	r.RegisterExtension("p2", "test.first", func(ctx context.Context, data interface{}) error {
		return nil
	}, 20)

	pluginID, _, err := r.ExecuteUntilFirst(context.Background(), "test.first", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pluginID != "p2" {
		t.Errorf("expected p2 (first non-error), got %s", pluginID)
	}
}

func TestExtensionRegistryListPoints(t *testing.T) {
	r := NewExtensionRegistry()

	r.RegisterPoint(ExtensionPoint{Name: "a.point"})
	r.RegisterPoint(ExtensionPoint{Name: "b.point"})
	r.RegisterPoint(ExtensionPoint{Name: "c.point"})

	points := r.ListPoints()
	if len(points) != 3 {
		t.Fatalf("expected 3 points, got %d", len(points))
	}

	names := make(map[string]bool)
	for _, p := range points {
		names[p.Name] = true
	}
	if !names["a.point"] || !names["b.point"] || !names["c.point"] {
		t.Error("expected all 3 points in list")
	}
}

func TestExtensionRegistryPriorityOrdering(t *testing.T) {
	r := NewExtensionRegistry()
	r.RegisterPoint(ExtensionPoint{Name: "test.prio"})

	order := make(chan int, 4)
	r.RegisterExtension("p", "test.prio", func(ctx context.Context, data interface{}) error {
		order <- 3
		return nil
	}, 30)
	r.RegisterExtension("p", "test.prio", func(ctx context.Context, data interface{}) error {
		order <- 1
		return nil
	}, 10)
	r.RegisterExtension("p", "test.prio", func(ctx context.Context, data interface{}) error {
		order <- 2
		return nil
	}, 20)

	r.Execute(context.Background(), "test.prio", nil)

	close(order)
	var results []int
	for o := range order {
		results = append(results, o)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(results))
	}
	if results[0] != 1 || results[1] != 2 || results[2] != 3 {
		t.Errorf("expected [1 2 3] (ascending priority), got %v", results)
	}
}
