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

	if err := k.Run(); err != nil {
		log.Fatalf("kernel error: %v", err)
	}

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

	return kernel.NewServerTLSConfig(serverPair, caPair)
}