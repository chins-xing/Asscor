package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/kernel"
	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/version"

	_ "github.com/argus-security/argus/internal/checks"
)

func main() {
	configPath := flag.String("config", "config.ini", "configuration file path")
	listenAddr := flag.String("listen", ":50051", "microkernel listen address")
	noMTLS := flag.Bool("no-mtls", false, "disable mTLS (DEVELOPMENT ONLY — not for production)")
	certDir := flag.String("cert-dir", "certs", "TLS certificate directory")
	daemon := flag.Bool("daemon", false, "run as background daemon")
	pidFile := flag.String("pid-file", "", "PID file path (default: argus-kernel.pid in current directory)")
	logFormat := flag.String("log-format", "json", "log format: json, text")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	logOutput := flag.String("log-output", "stderr", "log output: stderr, stdout, or file path")
	flag.Parse()

	logCfg := logger.Config{
		Format: *logFormat,
		Level:  *logLevel,
		Output: *logOutput,
	}
	logger.Init(logCfg)
	log := logger.With("component", "kernel")

	if *daemon {
		if err := daemonize(*pidFile); err != nil {
			log.Error("failed to daemonize", "error", err)
			os.Exit(1)
		}
		return
	}

	if *noMTLS {
		log.Warn("mTLS is DISABLED — this mode is intended for development only, do not use in production")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Warn("cannot load config, using defaults", "path", *configPath, "error", err)
		cfg = config.Default()
	}

	if cfgLogLevel := cfg.AdapterConfig["log.level"]; cfgLogLevel != "" && *logLevel == "info" {
		logCfg.Level = cfgLogLevel
		logger.Init(logCfg)
	}
	if cfgLogFormat := cfg.AdapterConfig["log.format"]; cfgLogFormat != "" && *logFormat == "json" {
		logCfg.Format = cfgLogFormat
		logger.Init(logCfg)
	}
	if cfgLogOutput := cfg.AdapterConfig["log.output"]; cfgLogOutput != "" && *logOutput == "stderr" {
		logCfg.Output = cfgLogOutput
		logger.Init(logCfg)
	}

	k := kernel.NewKernel()
	k.SetConfigObj(cfg)

	k.SetConfig("config_path", *configPath)
	k.SetConfig("listen_addr", *listenAddr)
	k.SetConfig("cert_dir", *certDir)

	interceptorKeys := []string{
		"rate_limit_enabled", "rate_limit_per_sec", "rate_limit_burst",
		"circuit_breaker_enabled", "circuit_breaker_ratio",
		"circuit_breaker_min_req", "circuit_breaker_timeout_s",
		"audit_log_enabled",
	}
	for _, key := range interceptorKeys {
		if val := cfg.AdapterConfig["interceptor."+key]; val != "" {
			k.SetConfig("interceptor."+key, val)
		}
	}

	k.Container().BindNamed("config", (*config.Config)(nil), cfg)

	assessor := &kernel.AssessorModule{}
	policy := &kernel.PolicyModule{}
	spc := kernel.NewSPCModule()
	cti := &kernel.CTIModule{}
	commander := &kernel.CommanderModule{}
	logCollector := &kernel.LogCollectorModule{}
	heartbeat := &kernel.HeartbeatModule{}
	persistence := kernel.NewPersistenceModule("data")
	concurrency := kernel.NewConcurrencyModule(10)
	attck := kernel.NewATTACKModule()
	configWatcher := kernel.NewConfigWatcherModule(*configPath)
	adapterIntegration := kernel.NewAdapterIntegrationModule()

	for _, p := range []kernel.Plugin{heartbeat, spc, cti, assessor, policy, commander, logCollector, persistence, concurrency, attck, configWatcher, adapterIntegration} {
		if err := k.RegisterPlugin(p); err != nil {
			log.Error("register plugin failed", "error", err)
			os.Exit(1)
		}
	}

	kernelSvc := kernel.NewKernelServiceImpl(heartbeat, commander, cti, assessor, persistence)
	agentSvc := kernel.NewAgentServiceImpl(assessor, commander, logCollector)

	serverCfg := kernel.DefaultServerConfig()
	serverCfg.ListenAddr = *listenAddr

	if !*noMTLS {
		serverCfg.TLSConfig = setupTLS(*certDir)
	}

	server := kernel.NewServer(serverCfg, k)
	for _, desc := range kernel.BuildServiceDesc(kernelSvc, agentSvc) {
		server.RegisterService(desc)
	}

	interceptorCfg := kernel.ResolveInterceptorConfig(k.Config())
	interceptors := kernel.NewInterceptors(interceptorCfg)
	server.SetInterceptors(interceptors)

	if interceptorCfg.RateLimitEnabled || interceptorCfg.CircuitBreakerEnabled {
		log.Info("interceptors configured",
			"rate_limit", interceptorCfg.RateLimitEnabled,
			"circuit_breaker", interceptorCfg.CircuitBreakerEnabled,
			"audit_log", interceptorCfg.AuditLogEnabled)
	}

	if err := k.Bootstrap(); err != nil {
		log.Error("kernel bootstrap failed", "error", err)
		os.Exit(1)
	}

	if err := server.Start(); err != nil {
		log.Error("start microkernel server failed", "error", err)
		os.Exit(1)
	}

	grpcCfg := kernel.DefaultGRPCServerConfig()
	if v := cfg.AdapterConfig["grpc.enabled"]; v == "on" || v == "true" || v == "1" {
		grpcCfg.Enabled = true
	}
	if v := cfg.AdapterConfig["grpc.listen_addr"]; v != "" {
		grpcCfg.ListenAddr = v
	}
	if v := cfg.AdapterConfig["grpc.tls_enabled"]; v == "on" || v == "true" || v == "1" {
		grpcCfg.TLSEnabled = true
		grpcCfg.CertFile = filepath.Join(*certDir, "server.crt")
		grpcCfg.KeyFile = filepath.Join(*certDir, "server.key")
		grpcCfg.CAFile = filepath.Join(*certDir, "ca.crt")
	}
	grpcServer := kernel.NewGRPCServer(grpcCfg, kernelSvc, agentSvc)
	if err := grpcServer.Start(); err != nil {
		log.Error("start gRPC server failed", "error", err)
		os.Exit(1)
	}

	log.Info("ARGUS μKernel started",
		"version", version.ARGUSVersion,
		"ssam_version", version.SSAMVersion,
		"listen", *listenAddr,
		"mtls", !*noMTLS,
		"plugins", len(k.ListPlugins()))

	fmt.Println()
	fmt.Println("ARGUS \u00b5Kernel")
	fmt.Printf("  Framework: %s   SSAM: %s\n", version.ARGUSVersion, version.SSAMVersion)
	fmt.Println()
	fmt.Printf("  Listen:   %s (mTLS: %v)\n", *listenAddr, !*noMTLS)
	fmt.Printf("  Log:      %s (%s) -> %s\n", *logFormat, *logLevel, *logOutput)
	fmt.Printf("  Plugins:  %d loaded\n", len(k.ListPlugins()))
	for _, info := range k.ListPlugins() {
		fmt.Printf("    {%s} v%s — %s\n", info.Name, info.Version, info.Description)
	}
	fmt.Println()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("shutting down", "signal", sig.String())
	signal.Stop(sigCh)

	server.Stop()
	grpcServer.Stop()
	k.Shutdown()
	log.Info("kernel stopped")
}

func daemonize(pidFilePath string) error {
	if pidFilePath == "" {
		pidFilePath = "argus-kernel.pid"
	}

	absPidFile, err := filepath.Abs(pidFilePath)
	if err != nil {
		return fmt.Errorf("resolve pid file path: %w", err)
	}

	return daemonizePlatform(absPidFile)
}

func setupTLS(certDir string) *tls.Config {
	log := logger.With("component", "tls")

	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Warn("cannot create cert dir, starting without mTLS", "dir", certDir, "error", err)
		return nil
	}

	caPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	serverCertPath := filepath.Join(certDir, "server.crt")
	serverKeyPath := filepath.Join(certDir, "server.key")

	caPair, err := kernel.LoadCertPair(caPath, caKeyPath)
	if err != nil {
		log.Info("generating new CA certificate")
		caPair, err = kernel.GenerateCA(kernel.DefaultCAConfig())
		if err != nil {
			log.Warn("cannot generate CA, starting without mTLS", "error", err)
			return nil
		}
		if err := os.WriteFile(caPath, caPair.CertPEM, 0600); err != nil {
			log.Warn("cannot write CA cert, starting without mTLS", "path", caPath, "error", err)
			return nil
		}
		if err := os.WriteFile(caKeyPath, caPair.KeyPEM, 0600); err != nil {
			log.Warn("cannot write CA key, starting without mTLS", "path", caKeyPath, "error", err)
			return nil
		}
	}

	serverPair, err := kernel.LoadCertPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Info("generating new server certificate")
		serverPair, err = kernel.IssueServerCert(caPair, kernel.DefaultServerCertConfig())
		if err != nil {
			log.Warn("cannot issue server cert, starting without mTLS", "error", err)
			return nil
		}
		if err := os.WriteFile(serverCertPath, serverPair.CertPEM, 0600); err != nil {
			log.Warn("cannot write server cert, starting without mTLS", "path", serverCertPath, "error", err)
			return nil
		}
		if err := os.WriteFile(serverKeyPath, serverPair.KeyPEM, 0600); err != nil {
			log.Warn("cannot write server key, starting without mTLS", "path", serverKeyPath, "error", err)
			return nil
		}
	}

	agentCertPath := filepath.Join(certDir, "agent.crt")
	agentKeyPath := filepath.Join(certDir, "agent.key")
	if _, err := os.Stat(agentCertPath); os.IsNotExist(err) {
		log.Info("generating new agent certificate")
		agentPair, err := kernel.IssueAgentCert(caPair, kernel.DefaultAgentConfig("agent"), "agent")
		if err != nil {
			log.Warn("cannot issue agent cert", "error", err)
		} else {
			if err := os.WriteFile(agentCertPath, agentPair.CertPEM, 0600); err != nil {
				log.Warn("cannot write agent cert", "path", agentCertPath, "error", err)
			}
			if err := os.WriteFile(agentKeyPath, agentPair.KeyPEM, 0600); err != nil {
				log.Warn("cannot write agent key", "path", agentKeyPath, "error", err)
			}
			log.Info("agent certificate generated", "cert", agentCertPath, "key", agentKeyPath)
		}
	}

	return kernel.NewServerTLSConfig(serverPair, caPair)
}
