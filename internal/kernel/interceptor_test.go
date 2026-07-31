package kernel

import (
	"context"
	"testing"
)

func TestInterceptorChainNoInterceptors(t *testing.T) {
	chain := NewInterceptorChain()

	handler := chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	})

	resp, err := handler(context.Background(), "svc", "method", []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "hello" {
		t.Errorf("expected 'hello', got %s", resp)
	}
}

func TestInterceptorChainSingleInterceptor(t *testing.T) {
	chain := NewInterceptorChain()

	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		resp, err := handler(ctx, service, method, append(payload, []byte("-enriched")...))
		return resp, err
	})

	final := chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	})

	resp, err := final(context.Background(), "svc", "method", []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "hello-enriched" {
		t.Errorf("expected 'hello-enriched', got %s", resp)
	}
}

func TestInterceptorChainMultipleInterceptors(t *testing.T) {
	chain := NewInterceptorChain()

	callOrder := make([]string, 0)

	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		callOrder = append(callOrder, "first")
		return handler(ctx, service, method, payload)
	})
	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		callOrder = append(callOrder, "second")
		return handler(ctx, service, method, payload)
	})

	final := chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		callOrder = append(callOrder, "final")
		return payload, nil
	})

	_, err := final(context.Background(), "svc", "method", []byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(callOrder) != 3 {
		t.Fatalf("expected 3 calls, got %d: %v", len(callOrder), callOrder)
	}
	if callOrder[0] != "first" || callOrder[1] != "second" || callOrder[2] != "final" {
		t.Errorf("expected [first second final], got %v", callOrder)
	}
}

func TestInterceptorChainShortCircuit(t *testing.T) {
	chain := NewInterceptorChain()

	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		return []byte("short-circuited"), nil
	})
	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		t.Error("second interceptor should not be called")
		return handler(ctx, service, method, payload)
	})

	final := chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		t.Error("final handler should not be called")
		return payload, nil
	})

	resp, err := final(context.Background(), "svc", "method", []byte("original"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "short-circuited" {
		t.Errorf("expected 'short-circuited', got %s", resp)
	}
}

func TestInterceptorChainInterceptors(t *testing.T) {
	chain := NewInterceptorChain()
	chain.Use(func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		return handler(ctx, service, method, payload)
	})

	list := chain.Interceptors()
	if len(list) != 1 {
		t.Fatalf("expected 1 interceptor, got %d", len(list))
	}
}

func TestDefaultInterceptorHooks(t *testing.T) {
	hooks := DefaultInterceptorHooks()

	if hooks.OnRejected == nil {
		t.Error("OnRejected should not be nil")
	}
	if hooks.OnBroken == nil {
		t.Error("OnBroken should not be nil")
	}
	if hooks.OnAudit == nil {
		t.Error("OnAudit should not be nil")
	}

	hooks.OnRejected("test", "op", "test reason")
	hooks.OnBroken("test", "op")
	hooks.OnAudit(InterceptorEvent{
		Service: "test", Method: "op", Success: true,
	})
}

func TestInterceptorChainUseMultipleAtOnce(t *testing.T) {
	chain := NewInterceptorChain()

	count := 0
	chain.Use(
		func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
			count++
			return handler(ctx, service, method, payload)
		},
		func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
			count++
			return handler(ctx, service, method, payload)
		},
	)

	final := chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	})

	_, _ = final(context.Background(), "svc", "m", nil)

	if count != 2 {
		t.Errorf("expected 2 interceptor calls, got %d", count)
	}
}
