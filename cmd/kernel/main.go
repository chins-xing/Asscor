package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/asscor/asscor/internal/cli"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/prism"
	"github.com/asscor/asscor/internal/version"
	"github.com/asscor/asscor/internal/webui"

	_ "github.com/asscor/asscor/internal/checks"
)

func main() {
	configPath := flag.String("config", "config.ini", "configuration file path")
	listenAddr := flag.String("listen", ":50051", "microkernel listen address")
	noMTLS := flag.Bool("no-mtls", false, "disable mTLS (DEVELOPMENT ONLY — not for production)")
	certDir := flag.String("cert-dir", "certs", "TLS certificate directory")
	verifyCerts := flag.Bool("verify-certs", false, "verify certificate chain consistency and exit")
	forceRegenCerts := flag.Bool("force-regen-certs", false, "force regenerate all TLS certificates")
	daemon := flag.Bool("daemon", false, "run as background daemon")
	pidFile := flag.String("pid-file", "", "PID file path (default: ASSCOR-kernel.pid in current directory)")
	install := flag.Bool("install", false, "install as systemd service (requires root)")
	uninstall := flag.Bool("uninstall", false, "remove systemd service and stop kernel")
	checkInstall := flag.Bool("check-install", false, "verify installation and exit")
	installPath := flag.String("install-path", "/opt/asscor", "installation target directory")
	cliConnect := flag.String("cli", "", "connect to CLI socket (unix socket path, e.g. /opt/asscor/asscor-cli.sock)")
	logFormat := flag.String("log-format", "json", "log format: json, text")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	logOutput := flag.String("log-output", "stderr", "log output: stderr, stdout, or file path")
	webuiPort := flag.Int("webui-port", 8087, "Web UI dashboard port (0 to disable)")
	flag.Parse()

	if *install {
		if err := installService(*installPath); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ASSCOR kernel installed successfully at %s\n", *installPath)
		fmt.Fprintf(os.Stderr, "Run: sudo systemctl start asscor-kernel\n")
		os.Exit(0)
	}
	if *uninstall {
		if err := uninstallService(*installPath); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ASSCOR kernel uninstalled successfully\n")
		os.Exit(0)
	}
	if *checkInstall {
		if err := checkInstallation(*installPath); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "OK: installation verified at %s\n", *installPath)
		os.Exit(0)
	}
	if *cliConnect != "" {
		runCLIClient(*cliConnect)
		os.Exit(0)
	}

	resolvedConfigPath := *configPath
	if abs, err := filepath.Abs(*configPath); err == nil {
		resolvedConfigPath = abs
	}

	logCfg := logger.Config{
		Format: *logFormat,
		Level:  *logLevel,
		Output: *logOutput,
	}
	logger.Init(logCfg)
	log := logger.WithComponent("kernel")

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

	if *forceRegenCerts {
		certDirPath := *certDir
		fmt.Fprintf(os.Stderr, "Force regenerating all certificates in %s\n", certDirPath)
		if err := os.RemoveAll(certDirPath); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cannot remove cert dir: %v\n", err)
			os.Exit(1)
		}
		tlsCfg := setupTLS(certDirPath)
		if tlsCfg == nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to generate certificates\n")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Certificates regenerated successfully.\n")
		return
	}

	if *verifyCerts {
		certDirPath := *certDir
		ok := verifyCertificates(certDirPath)
		if !ok {
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		log.Warn("cannot load config, using defaults", "path", resolvedConfigPath, "error", err)
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

k.SetConfig("config_path", resolvedConfigPath)
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

	scoringEngine := kernel.NewScoringEngineModule(cfg)
	k.Container().Bind((*kernel.ScoringEngineProvider)(nil), scoringEngine)

	k.Container().Bind((*kernel.PrismEngineProvider)(nil), prism.NewEngine())

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
	configWatcher := kernel.NewConfigWatcherModule(resolvedConfigPath)
	adapterIntegration := kernel.NewAdapterIntegrationModule()
	sourceManager := kernel.NewSourceManagerModule()
	cliModule := cli.NewCLIModule()

	plugins := []kernel.Plugin{heartbeat, spc, cti, scoringEngine, assessor, policy, commander, logCollector, persistence, concurrency, attck, configWatcher, adapterIntegration, sourceManager, cliModule, kernel.NewSRDPlugin()}

	if *webuiPort > 0 {
		webuiModule := webui.New(*webuiPort)
		plugins = append(plugins, webuiModule)
	}

	for _, p := range plugins {
		if err := k.RegisterPlugin(p); err != nil {
			log.Error("register plugin failed", "error", err)
			os.Exit(1)
		}
	}

	kernelSvc := kernel.NewKernelServiceImpl(heartbeat, commander, cti, assessor, persistence, spc)
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

	sourceManagerSvc := kernel.NewSourceManagerServiceImpl(sourceManager)
	server.RegisterService(kernel.BuildSourceManagerServiceDesc(sourceManagerSvc))

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
		fmt.Fprintf(os.Stderr, "FATAL: kernel bootstrap failed: %v\n", err)
		log.Error("kernel bootstrap failed", "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nASSCOR \u00b5Kernel\n")
	fmt.Fprintf(os.Stderr, "  Framework: %s   SSAM: %s\n", version.ASSCORVersion, version.SSAMVersion)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Listen:   %s (mTLS: %v)\n", *listenAddr, !*noMTLS)
	fmt.Fprintf(os.Stderr, "  Log:      %s (%s) -> %s\n", *logFormat, *logLevel, logger.CurrentOutput())
	fmt.Fprintf(os.Stderr, "  Plugins:  %d loaded\n", len(k.ListPlugins()))
	for _, info := range k.ListPlugins() {
		fmt.Fprintf(os.Stderr, "    {%s} v%s — %s\n", info.Name, info.Version, info.Description)
	}
	fmt.Fprintf(os.Stderr, "\n")

	serverStarted := false
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: server start failed: %v (running in CLI-only mode)\n", err)
		log.Error("start microkernel server failed", "error", err)
	} else {
		serverStarted = true
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
	grpcStarted := false
	if err := grpcServer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: gRPC server start failed: %v\n", err)
		log.Error("start gRPC server failed", "error", err)
	} else {
		grpcStarted = true
	}

	log.Info("ASSCOR μKernel started",
		"version", version.ASSCORVersion,
		"ssam_version", version.SSAMVersion,
		"listen", *listenAddr,
		"mtls", !*noMTLS,
		"plugins", len(k.ListPlugins()),
		"server", serverStarted,
		"grpc", grpcStarted)

	var cliDone <-chan struct{}
	if iface, ok := k.Container().Resolve((*cli.CLIInterface)(nil)); ok {
		if cliMod, ok := iface.(cli.CLIInterface); ok {
			cliDone = cliMod.Done()
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	writePIDFile(*pidFile)

loop:
	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				log.Info("received SIGHUP, reloading configuration")
				if cfg, err := config.Load(resolvedConfigPath); err == nil {
					k.SetConfigObj(cfg)
				}
				signal.Stop(sigCh)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
				continue loop
			default:
				log.Info("shutting down", "signal", sig.String())
				signal.Stop(sigCh)
				break loop
			}
		case <-cliDone:
			log.Info("shutting down", "reason", "cli_terminal_exited")
			break loop
		}
	}

	if serverStarted {
		server.Stop()
	}
	if grpcStarted {
		grpcServer.Stop()
	}
	k.Shutdown()
	log.Info("kernel stopped")
}

func daemonize(pidFilePath string) error {
	if pidFilePath == "" {
		pidFilePath = "ASSCOR-kernel.pid"
	}

	absPidFile, err := filepath.Abs(pidFilePath)
	if err != nil {
		return fmt.Errorf("resolve pid file path: %w", err)
	}

	return daemonizePlatform(absPidFile)
}

func writePIDFile(pidFilePath string) {
	if pidFilePath == "" {
		return
	}
	abs, err := filepath.Abs(pidFilePath)
	if err != nil {
		return
	}
	if err := os.WriteFile(abs, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: cannot write PID file %s: %v\n", abs, err)
	}
}

func setupTLS(certDir string) *tls.Config {
	log := logger.WithComponent("tls")

	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Warn("cannot create cert dir, starting without mTLS", "dir", certDir, "error", err)
		return nil
	}

	caPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	serverCertPath := filepath.Join(certDir, "server.crt")
	serverKeyPath := filepath.Join(certDir, "server.key")
	agentCertPath := filepath.Join(certDir, "agent.crt")
	agentKeyPath := filepath.Join(certDir, "agent.key")

	caPair, err := kernel.LoadCertPair(caPath, caKeyPath)
	if err != nil {
		log.Info("generating new CA certificate", "reason", "load failed")
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
	} else if err := kernel.ValidateCertPair(caPair); err != nil {
		log.Warn("CA certificate invalid, regenerating all certificates", "error", err)
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
		os.Remove(serverCertPath)
		os.Remove(serverKeyPath)
		os.Remove(agentCertPath)
		os.Remove(agentKeyPath)
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
	} else if !kernel.VerifyCertChain(serverPair, caPair) {
		log.Warn("server certificate chain invalid (CA regenerated?), re-issuing server certificate")
		serverPair, err = kernel.IssueServerCert(caPair, kernel.DefaultServerCertConfig())
		if err != nil {
			log.Warn("cannot re-issue server cert, starting without mTLS", "error", err)
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
	} else {
		agentPair, err := kernel.LoadCertPair(agentCertPath, agentKeyPath)
		if err == nil && !kernel.VerifyCertChain(agentPair, caPair) {
			log.Warn("agent certificate chain invalid (CA regenerated?), re-issuing agent certificate")
			agentPair, err = kernel.IssueAgentCert(caPair, kernel.DefaultAgentConfig("agent"), "agent")
			if err != nil {
				log.Warn("cannot re-issue agent cert", "error", err)
			} else {
				if err := os.WriteFile(agentCertPath, agentPair.CertPEM, 0600); err != nil {
					log.Warn("cannot write agent cert", "path", agentCertPath, "error", err)
				}
				if err := os.WriteFile(agentKeyPath, agentPair.KeyPEM, 0600); err != nil {
					log.Warn("cannot write agent key", "path", agentKeyPath, "error", err)
				}
				log.Info("agent certificate re-issued", "cert", agentCertPath, "key", agentKeyPath)
			}
		}
	}

	caFingerprint := sha256.Sum256(caPair.CertPEM)
	serverFingerprint := sha256.Sum256(serverPair.CertPEM)
	fmt.Fprintf(os.Stderr, "  CA SHA256:     %s\n", hex.EncodeToString(caFingerprint[:])[:16]+"...")
	fmt.Fprintf(os.Stderr, "  Server SHA256: %s\n", hex.EncodeToString(serverFingerprint[:])[:16]+"...")
	fmt.Fprintf(os.Stderr, "  Cert dir:      %s\n", certDir)

	if sigErr := kernel.VerifySignature(serverPair, caPair); sigErr != nil {
		fmt.Fprintf(os.Stderr, "  SELF-CHECK FAILED: server cert signature invalid: %v\n", sigErr)
		fmt.Fprintf(os.Stderr, "  Force regenerating all certificates...\n")
		log.Error("TLS self-check failed, regenerating all certificates", "error", sigErr)

		caPair, err = kernel.GenerateCA(kernel.DefaultCAConfig())
		if err != nil {
			log.Warn("cannot generate CA, starting without mTLS", "error", err)
			return nil
		}
		if err := os.WriteFile(caPath, caPair.CertPEM, 0600); err != nil {
			log.Error("FATAL: cannot write CA cert to disk", "path", caPath, "error", err)
			return nil
		}
		if err := os.WriteFile(caKeyPath, caPair.KeyPEM, 0600); err != nil {
			log.Error("FATAL: cannot write CA key to disk", "path", caKeyPath, "error", err)
			return nil
		}

		serverPair, err = kernel.IssueServerCert(caPair, kernel.DefaultServerCertConfig())
		if err != nil {
			log.Warn("cannot issue server cert, starting without mTLS", "error", err)
			return nil
		}
		if err := os.WriteFile(serverCertPath, serverPair.CertPEM, 0600); err != nil {
			log.Error("FATAL: cannot write server cert to disk", "path", serverCertPath, "error", err)
			return nil
		}
		if err := os.WriteFile(serverKeyPath, serverPair.KeyPEM, 0600); err != nil {
			log.Error("FATAL: cannot write server key to disk", "path", serverKeyPath, "error", err)
			return nil
		}

		agentPair, err := kernel.IssueAgentCert(caPair, kernel.DefaultAgentConfig("agent"), "agent")
		if err != nil {
			log.Warn("cannot issue agent cert", "error", err)
		} else {
			if err := os.WriteFile(agentCertPath, agentPair.CertPEM, 0600); err != nil {
				log.Error("FATAL: cannot write agent cert to disk", "path", agentCertPath, "error", err)
				return nil
			}
			if err := os.WriteFile(agentKeyPath, agentPair.KeyPEM, 0600); err != nil {
				log.Error("FATAL: cannot write agent key to disk", "path", agentKeyPath, "error", err)
				return nil
			}
		}

		caFingerprint = sha256.Sum256(caPair.CertPEM)
		serverFingerprint = sha256.Sum256(serverPair.CertPEM)
		fmt.Fprintf(os.Stderr, "  CA SHA256:     %s (regenerated)\n", hex.EncodeToString(caFingerprint[:])[:16]+"...")
		fmt.Fprintf(os.Stderr, "  Server SHA256: %s (regenerated)\n", hex.EncodeToString(serverFingerprint[:])[:16]+"...")
	} else {
		fmt.Fprintf(os.Stderr, "  Self-check:    OK (server cert signed by CA)\n")
	}

	writeCertFingerprint := func(path string, pemData []byte) {
		fp := sha256.Sum256(pemData)
		fmt.Fprintf(os.Stderr, "  %s  SHA256: %s\n", filepath.Base(path), hex.EncodeToString(fp[:])[:16]+"...")
	}
	writeCertFingerprint(caPath, caPair.CertPEM)
	writeCertFingerprint(serverCertPath, serverPair.CertPEM)

	diskCA, err := os.ReadFile(caPath)
	if err == nil {
		diskFP := sha256.Sum256(diskCA)
		memFP := sha256.Sum256(caPair.CertPEM)
		if diskFP != memFP {
			log.Error("CRITICAL: CA cert on disk does not match in-memory cert, rewriting",
				"disk_sha256", hex.EncodeToString(diskFP[:])[:16],
				"mem_sha256", hex.EncodeToString(memFP[:])[:16])
			if err := os.WriteFile(caPath, caPair.CertPEM, 0600); err != nil {
				log.Error("FATAL: cannot rewrite CA cert", "error", err)
				return nil
			}
		}
	}

	diskServer, err := os.ReadFile(serverCertPath)
	if err == nil {
		diskFP := sha256.Sum256(diskServer)
		memFP := sha256.Sum256(serverPair.CertPEM)
		if diskFP != memFP {
			log.Error("CRITICAL: server cert on disk does not match in-memory cert, rewriting",
				"disk_sha256", hex.EncodeToString(diskFP[:])[:16],
				"mem_sha256", hex.EncodeToString(memFP[:])[:16])
			if err := os.WriteFile(serverCertPath, serverPair.CertPEM, 0600); err != nil {
				log.Error("FATAL: cannot rewrite server cert", "error", err)
				return nil
			}
		}
	}

	return kernel.NewServerTLSConfig(serverPair, caPair)
}

func verifyCertificates(certDir string) bool {
	caPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	serverCertPath := filepath.Join(certDir, "server.crt")
	serverKeyPath := filepath.Join(certDir, "server.key")
	agentCertPath := filepath.Join(certDir, "agent.crt")
	agentKeyPath := filepath.Join(certDir, "agent.key")

	allOK := true

	caPair, err := kernel.LoadCertPair(caPath, caKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot load CA cert: %v\n", err)
		allOK = false
	} else {
		caFP := sha256.Sum256(caPair.CertPEM)
		fmt.Fprintf(os.Stderr, "  CA cert:      OK  SHA256=%s...\n", hex.EncodeToString(caFP[:])[:16])

		if err := kernel.ValidateCertPair(caPair); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: CA cert validation: %v\n", err)
			allOK = false
		} else {
			fmt.Fprintf(os.Stderr, "  CA integrity: OK\n")
		}
	}

	serverPair, err := kernel.LoadCertPair(serverCertPath, serverKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot load server cert: %v\n", err)
		allOK = false
	} else {
		srvFP := sha256.Sum256(serverPair.CertPEM)
		fmt.Fprintf(os.Stderr, "  Server cert:  OK  SHA256=%s...\n", hex.EncodeToString(srvFP[:])[:16])

		if caPair != nil {
			if kernel.VerifyCertChain(serverPair, caPair) {
				fmt.Fprintf(os.Stderr, "  Server chain: OK (signed by CA)\n")
			} else {
				fmt.Fprintf(os.Stderr, "FAIL: server cert NOT signed by current CA\n")
				allOK = false
			}
		}
	}

	agentPair, err := kernel.LoadCertPair(agentCertPath, agentKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot load agent cert: %v\n", err)
		allOK = false
	} else {
		agFP := sha256.Sum256(agentPair.CertPEM)
		fmt.Fprintf(os.Stderr, "  Agent cert:   OK  SHA256=%s...\n", hex.EncodeToString(agFP[:])[:16])

		if caPair != nil {
			if kernel.VerifyCertChain(agentPair, caPair) {
				fmt.Fprintf(os.Stderr, "  Agent chain:  OK (signed by CA)\n")
			} else {
				fmt.Fprintf(os.Stderr, "FAIL: agent cert NOT signed by current CA\n")
				allOK = false
			}
		}
	}

	if allOK {
		fmt.Fprintf(os.Stderr, "\nAll certificates are consistent.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nCertificate inconsistencies detected. Run with --force-regen-certs to regenerate.\n")
	}

	return allOK
}
