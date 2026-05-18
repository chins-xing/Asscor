package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/kernel"
	"github.com/argus-security/argus/internal/version"

	_ "github.com/argus-security/argus/internal/checks"
)

func main() {
	configPath := flag.String("config", "config.ini", "configuration file path")
	listenAddr := flag.String("listen", "0.0.0.0:50051", "microkernel listen address")
	noMTLS := flag.Bool("no-mtls", false, "disable mTLS (development only)")
	certDir := flag.String("cert-dir", "certs", "TLS certificate directory")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("warning: cannot load config %s: %v, using defaults", *configPath, err)
		cfg = config.Default()
	}

	k := kernel.NewKernel()
	k.SetConfigObj(cfg)

	k.SetConfig("config_path", *configPath)
	k.SetConfig("listen_addr", *listenAddr)
	k.SetConfig("cert_dir", *certDir)

	// inject interceptor config from INI into kernel config map
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

	for _, p := range []kernel.Plugin{heartbeat, spc, cti, assessor, policy, commander, logCollector, persistence, concurrency, attck} {
		if err := k.RegisterPlugin(p); err != nil {
			log.Fatalf("register plugin: %v", err)
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
		log.Printf("interceptors: rate_limit=%v circuit_breaker=%v audit_log=%v",
			interceptorCfg.RateLimitEnabled,
			interceptorCfg.CircuitBreakerEnabled,
			interceptorCfg.AuditLogEnabled)
	}

	if err := k.Run(); err != nil {
		log.Fatalf("kernel error: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("start microkernel server: %v", err)
	}

	fmt.Println()
	fmt.Println("ARGUS \u00b5Kernel")
	fmt.Printf("  Framework: %s   SSAM: %s\n", version.ARGUSVersion, version.SSAMVersion)
	fmt.Println()
	fmt.Printf("  Listen:   %s (mTLS: %v)\n", *listenAddr, !*noMTLS)
	fmt.Printf("  Plugins:  %d loaded\n", len(k.ListPlugins()))
	for _, info := range k.ListPlugins() {
		fmt.Printf("    {%s} v%s — %s\n", info.Name, info.Version, info.Description)
	}
	fmt.Println()

	server.Stop()
}

func setupTLS(certDir string) *tls.Config {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Printf("warning: cannot create cert dir %s: %v, starting without mTLS", certDir, err)
		return nil
	}

	caPath := certDir + "/ca.crt"
	caKeyPath := certDir + "/ca.key"
	serverCertPath := certDir + "/server.crt"
	serverKeyPath := certDir + "/server.key"

	caPair, err := kernel.LoadCertPair(caPath, caKeyPath)
	if err != nil {
		log.Printf("generating new CA certificate...")
		caPair, err = kernel.GenerateCA(kernel.DefaultCAConfig())
		if err != nil {
			log.Printf("warning: cannot generate CA: %v, starting without mTLS", err)
			return nil
		}
		os.WriteFile(caPath, caPair.CertPEM, 0600)
		os.WriteFile(caKeyPath, caPair.KeyPEM, 0600)
	}

	serverPair, err := kernel.LoadCertPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Printf("generating new server certificate...")
		serverPair, err = kernel.IssueServerCert(caPair, kernel.DefaultServerCertConfig())
		if err != nil {
			log.Printf("warning: cannot issue server cert: %v, starting without mTLS", err)
			return nil
		}
		os.WriteFile(serverCertPath, serverPair.CertPEM, 0600)
		os.WriteFile(serverKeyPath, serverPair.KeyPEM, 0600)
	}

	agentCertPath := certDir + "/agent.crt"
	agentKeyPath := certDir + "/agent.key"
	if _, err := os.Stat(agentCertPath); os.IsNotExist(err) {
		log.Printf("generating new agent certificate...")
		agentPair, err := kernel.IssueAgentCert(caPair, kernel.DefaultAgentConfig("agent"), "agent")
		if err != nil {
			log.Printf("warning: cannot issue agent cert: %v", err)
		} else {
			os.WriteFile(agentCertPath, agentPair.CertPEM, 0600)
			os.WriteFile(agentKeyPath, agentPair.KeyPEM, 0600)
			log.Printf("agent certificate generated: %s, %s", agentCertPath, agentKeyPath)
		}
	}

	return kernel.NewServerTLSConfig(serverPair, caPair)
}