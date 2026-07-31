package kernel

import (
	"context"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.ListenAddr != ":50051" {
		t.Errorf("ListenAddr = %s, want :50051", cfg.ListenAddr)
	}
	if cfg.MaxRecvMsgSize != 16*1024*1024 {
		t.Errorf("MaxRecvMsgSize = %d, want 16MB", cfg.MaxRecvMsgSize)
	}
	if cfg.KeepaliveTime != 60*time.Second {
		t.Errorf("KeepaliveTime = %v, want 60s", cfg.KeepaliveTime)
	}
	if cfg.MaxConns != 100 {
		t.Errorf("MaxConns = %d, want 100", cfg.MaxConns)
	}
}

func TestNewServerDefaults(t *testing.T) {
	k := NewKernel()
	srv := NewServer(DefaultServerConfig(), k)

	if srv.registry == nil {
		t.Error("registry should not be nil")
	}
	if srv.codec == nil {
		t.Error("codec should not be nil")
	}
	if cap(srv.connSem) != 100 {
		t.Errorf("connSem cap = %d, want 100", cap(srv.connSem))
	}
}

func TestNewServerMaxConnsClamp(t *testing.T) {
	k := NewKernel()
	cfg := ServerConfig{MaxConns: 0}
	srv := NewServer(cfg, k)

	if cap(srv.connSem) != 100 {
		t.Errorf("connSem cap = %d, want 100 (clamped from 0)", cap(srv.connSem))
	}
}

func TestServerRegisterService(t *testing.T) {
	k := NewKernel()
	srv := NewServer(DefaultServerConfig(), k)

	srv.RegisterService(&apiv1.ServiceDesc{
		ServiceName: "TestService",
		Methods: map[string]apiv1.MethodHandler{
			"TestMethod": func(ctx context.Context, payload []byte) ([]byte, error) {
				return payload, nil
			},
		},
	})

	result, _ := srv.registry.Dispatch(context.Background(), "TestService", "TestMethod", []byte("hello"))
	if string(result) != "hello" {
		t.Errorf("dispatch result = %s, want hello", result)
	}
}

func TestServerSetInterceptors(t *testing.T) {
	k := NewKernel()
	srv := NewServer(DefaultServerConfig(), k)

	interceptors := &Interceptors{}
	srv.SetInterceptors(interceptors)

	if srv.interceptors != interceptors {
		t.Error("interceptors not set correctly")
	}
}
