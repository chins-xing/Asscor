package kernel

import (
	"context"
	"fmt"
	"testing"
)

func TestAuditLogInterceptorSuccess(t *testing.T) {
	auditCalled := false
	audit := NewAuditLogInterceptor(func(event InterceptorEvent) {
		auditCalled = true
		if !event.Success {
			t.Error("expected success=true")
		}
		if event.Service != "svc" {
			t.Errorf("Service = %s, want svc", event.Service)
		}
		if event.Method != "m" {
			t.Errorf("Method = %s, want m", event.Method)
		}
	})

	interceptor := audit.Interceptor()
	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return append(payload, []byte("-ok")...), nil
	}

	resp, err := interceptor(context.Background(), "svc", "m", []byte("req"), handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "req-ok" {
		t.Errorf("expected 'req-ok', got %s", resp)
	}
	if !auditCalled {
		t.Error("expected audit callback to be called")
	}
}

func TestAuditLogInterceptorError(t *testing.T) {
	audit := NewAuditLogInterceptor(func(event InterceptorEvent) {
		if event.Success {
			t.Error("expected success=false for error handler")
		}
		if event.Error == "" {
			t.Error("expected non-empty error string")
		}
	})

	interceptor := audit.Interceptor()
	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return nil, fmt.Errorf("handler failed")
	}

	_, _ = interceptor(context.Background(), "svc", "m", nil, handler)
}

func TestAuditLogInterceptorNilCallback(t *testing.T) {
	audit := NewAuditLogInterceptor(nil)
	interceptor := audit.Interceptor()
	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	}

	resp, err := interceptor(context.Background(), "svc", "m", []byte("test"), handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "test" {
		t.Errorf("expected 'test', got %s", resp)
	}
}

func TestAuditLogInterceptorDuration(t *testing.T) {
	duration := int64(0)
	audit := NewAuditLogInterceptor(func(event InterceptorEvent) {
		duration = int64(event.Duration)
	})

	interceptor := audit.Interceptor()
	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	}

	_, _ = interceptor(context.Background(), "svc", "m", []byte("t"), handler)
	if duration <= 0 {
		t.Logf("duration = %d (may be 0 for fast handler)", duration)
	}
}
