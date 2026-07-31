package kernel

import (
	"testing"
)

type testService interface {
	Name() string
}
type testServiceImpl struct{ name string }

func (s *testServiceImpl) Name() string { return s.name }

func TestDIContainerBindResolve(t *testing.T) {
	c := NewContainer()

	c.Bind((*testService)(nil), &testServiceImpl{name: "test"})

	got, ok := c.Resolve((*testService)(nil))
	if !ok {
		t.Fatal("resolve failed")
	}
	impl, ok := got.(testService)
	if !ok {
		t.Fatal("type assertion failed")
	}
	if impl.Name() != "test" {
		t.Errorf("Name() = %q, want %q", impl.Name(), "test")
	}
}

func TestDIContainerBindNamed(t *testing.T) {
	c := NewContainer()

	c.BindNamed("my-service", (*testService)(nil), &testServiceImpl{name: "named"})

	got, ok := c.ResolveNamed("my-service")
	if !ok {
		t.Fatal("resolve named failed")
	}
	impl, ok := got.(testService)
	if !ok {
		t.Fatal("type assertion failed")
	}
	if impl.Name() != "named" {
		t.Errorf("Name() = %q, want %q", impl.Name(), "named")
	}

	_, ok = c.ResolveNamed("nonexistent")
	if ok {
		t.Fatal("expected resolve named to fail for nonexistent")
	}
}

func TestDIContainerResolveMissing(t *testing.T) {
	c := NewContainer()
	_, ok := c.Resolve((*testService)(nil))
	if ok {
		t.Fatal("expected resolve to fail for unregistered service")
	}
}

func TestDIContainerInject(t *testing.T) {
	c := NewContainer()
	c.Bind((*testService)(nil), &testServiceImpl{name: "injected"})

	type consumer struct {
		Svc testService `inject:"true"`
	}
	cons := &consumer{}

	if err := c.Inject(cons); err != nil {
		t.Fatalf("inject failed: %v", err)
	}
	if cons.Svc == nil {
		t.Fatal("expected Svc to be injected")
	}
	if cons.Svc.Name() != "injected" {
		t.Errorf("Name() = %q, want %q", cons.Svc.Name(), "injected")
	}
}

func TestDIContainerOverwrite(t *testing.T) {
	c := NewContainer()

	c.Bind((*testService)(nil), &testServiceImpl{name: "first"})
	c.Bind((*testService)(nil), &testServiceImpl{name: "second"})

	got, ok := c.Resolve((*testService)(nil))
	if !ok {
		t.Fatal("resolve failed")
	}
	if got.(testService).Name() != "second" {
		t.Errorf("expected 'second' after overwrite, got %q", got.(testService).Name())
	}
}

func TestDIContainerBindThenNamedResolve(t *testing.T) {
	c := NewContainer()

	c.BindNamed("svc", (*testService)(nil), &testServiceImpl{name: "named"})

	got, ok := c.Resolve((*testService)(nil))
	if !ok {
		t.Fatal("anonymous resolve after named bind failed")
	}
	if got.(testService).Name() != "named" {
		t.Errorf("expected 'named', got %q", got.(testService).Name())
	}
}
