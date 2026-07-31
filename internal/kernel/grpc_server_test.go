package kernel

import (
	"testing"
	"time"
)

func TestDefaultGRPCServerConfig(t *testing.T) {
	cfg := DefaultGRPCServerConfig()

	if cfg.Enabled {
		t.Error("expected gRPC to be disabled by default")
	}
	if cfg.ListenAddr != ":50052" {
		t.Errorf("ListenAddr = %s, want :50052", cfg.ListenAddr)
	}
	if cfg.TLSEnabled {
		t.Error("expected TLS to be disabled by default")
	}
	if cfg.MaxRecvSize != 4*1024*1024 {
		t.Errorf("MaxRecvSize = %d, want 4MB", cfg.MaxRecvSize)
	}
	if cfg.KeepaliveMin != 30*time.Second {
		t.Errorf("KeepaliveMin = %v, want 30s", cfg.KeepaliveMin)
	}
	if cfg.CertFile != "certs/server.crt" {
		t.Errorf("CertFile = %s, want certs/server.crt", cfg.CertFile)
	}
}

func TestGRPCServerConstruction(t *testing.T) {
	svc := NewKernelServiceImpl(nil, nil, nil, nil, nil, nil)
	cfg := DefaultGRPCServerConfig()

	srv := NewGRPCServer(cfg, svc, nil)

	if srv == nil {
		t.Fatal("expected non-nil gRPC server")
	}
	if srv.kernelSvc == nil {
		t.Error("expected kernel service to be set")
	}
}

func TestGRPCServerNotEnabledByDefault(t *testing.T) {
	svc := NewKernelServiceImpl(nil, nil, nil, nil, nil, nil)
	cfg := DefaultGRPCServerConfig()
	srv := NewGRPCServer(cfg, svc, nil)

	if srv.cfg.Enabled {
		t.Error("gRPC server should be disabled by default")
	}
}

