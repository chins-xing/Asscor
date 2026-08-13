//go:build !comms

package main

import (
	"crypto/tls"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
)

// commsRuntime is a no-op when the comms build tag is disabled.
type commsRuntime struct{}

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
	return &commsRuntime{}
}

func (r *commsRuntime) Start() (serverStarted, grpcStarted bool) {
	return false, false
}

func (r *commsRuntime) Stop() {}
