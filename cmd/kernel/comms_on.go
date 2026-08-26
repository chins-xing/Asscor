//go:build comms

package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/asscor/asscor/internal/comms"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/securemode"
)

// commsRuntime owns the JSONRPC and gRPC servers. It is compiled only when the
// comms build tag is enabled (kernel zero-bloat otherwise).
type commsRuntime struct {
	server        *comms.Server
	grpcServer    *comms.GRPCServer
	serverStarted bool
	grpcStarted   bool
}

// newCommsRuntime builds and registers the JSONRPC + gRPC servers.
func newCommsRuntime(
	k *kernel.Kernel,
	cfg *config.Config,
	listenAddr string,
	tlsCfg *tls.Config,
	certDir string,
	heartbeat kernel.HeartbeatInterface,
	commander kernel.CommanderInterface,
	cti kernel.CTIInterface,
	assessor kernel.AssessorInterface,
	persistence kernel.PersistenceInterface,
	spc kernel.SPCInterface,
	logCollector kernel.LogCollectorInterface,
	sourceManager kernel.SourceManagerInterface,
) *commsRuntime {
	log := logger.WithComponent("kernel")

	kernelSvc := comms.NewKernelServiceImpl(heartbeat, commander, cti, assessor, persistence, spc)
	// Sync check-item configuration (user checks + delta overrides) to agents
	// via heartbeat so config.ini is the single source of truth.
	kernelSvc.SetConfig(cfg)
	// Secure Mode: wire the controller (registered by initSecureMode under
	// the "securemode" name) so heartbeat responses can register agent
	// ephemeral passwords. No-op when the securemode build tag is off.
	if ctrlVal, ok := k.Container().ResolveNamed("securemode"); ok {
		if ctrl, ok := ctrlVal.(*securemode.Controller); ok {
			kernelSvc.SetSecureMode(ctrl)
		}
	}
	agentSvc := comms.NewAgentServiceImpl(assessor, commander, logCollector)

	serverCfg := comms.DefaultServerConfig()
	serverCfg.ListenAddr = listenAddr
	if tlsCfg != nil {
		serverCfg.TLSConfig = tlsCfg
	}

	server := comms.NewServer(serverCfg, k)
	for _, desc := range comms.BuildServiceDesc(kernelSvc, agentSvc) {
		server.RegisterService(desc)
	}

	sourceManagerSvc := kernel.NewSourceManagerServiceImpl(sourceManager)
	server.RegisterService(kernel.BuildSourceManagerServiceDesc(sourceManagerSvc))

	interceptorCfg := kernel.ResolveInterceptorConfig(k.Config())
	server.SetInterceptors(kernel.NewInterceptors(interceptorCfg))
	if interceptorCfg.RateLimitEnabled || interceptorCfg.CircuitBreakerEnabled {
		log.Info("interceptors configured",
			"rate_limit", interceptorCfg.RateLimitEnabled,
			"circuit_breaker", interceptorCfg.CircuitBreakerEnabled,
			"audit_log", interceptorCfg.AuditLogEnabled)
	}

	grpcCfg := comms.DefaultGRPCServerConfig()
	if v := cfg.AdapterConfig["grpc.enabled"]; v == "on" || v == "true" || v == "1" {
		grpcCfg.Enabled = true
	}
	if v := cfg.AdapterConfig["grpc.listen_addr"]; v != "" {
		grpcCfg.ListenAddr = v
	}
	if v := cfg.AdapterConfig["grpc.tls_enabled"]; v == "on" || v == "true" || v == "1" {
		grpcCfg.TLSEnabled = true
		grpcCfg.CertFile = filepath.Join(certDir, "server.crt")
		grpcCfg.KeyFile = filepath.Join(certDir, "server.key")
		grpcCfg.CAFile = filepath.Join(certDir, "ca.crt")
	}

	return &commsRuntime{
		server:     server,
		grpcServer: comms.NewGRPCServer(grpcCfg, kernelSvc, agentSvc),
	}
}

// Start launches both servers. Returns the started flags for each.
func (r *commsRuntime) Start() (serverStarted, grpcStarted bool) {
	log := logger.WithComponent("kernel")

	if err := r.server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: server start failed: %v (running in CLI-only mode)\n", err)
		log.Error("start microkernel server failed", "error", err)
	} else {
		r.serverStarted = true
	}

	if err := r.grpcServer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: gRPC server start failed: %v\n", err)
		log.Error("start gRPC server failed", "error", err)
	} else {
		r.grpcStarted = true
	}

	return r.serverStarted, r.grpcStarted
}

// Stop shuts down both servers.
func (r *commsRuntime) Stop() {
	if r.serverStarted {
		r.server.Stop()
	}
	if r.grpcStarted {
		r.grpcServer.Stop()
	}
}
