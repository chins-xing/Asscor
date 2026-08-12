package kernel

import (
	"context"

	"github.com/asscor/asscor/internal/engine/srd"
)

// SRDPlugin wraps srd.Manager to implement kernel.Plugin.
// Bridges the gap between srd's local shadow types and kernel types.
type SRDPlugin struct {
	manager *srd.Manager
}

func NewSRDPlugin() *SRDPlugin {
	return &SRDPlugin{
		manager: srd.NewManager(),
	}
}

func (s *SRDPlugin) Info() PluginInfo {
	info := s.manager.Info()
	return PluginInfo{
		Name:        info.Name,
		Version:     info.Version,
		Description: info.Description,
		Author:      info.Author,
	}
}

func (s *SRDPlugin) Dependencies() []PluginDependency {
	return nil
}

func (s *SRDPlugin) Priority() int {
	return s.manager.Priority()
}

func (s *SRDPlugin) Init(ctx context.Context, kc KernelContext) error {
	adapter := &srdKernelAdapter{kc: kc}
	return s.manager.Init(ctx, adapter)
}

func (s *SRDPlugin) Start(ctx context.Context) error {
	// Real-time topology sync: register a listener so every heartbeat-driven
	// recordTopology immediately updates the SRD pipeline (no one-shot snapshot).
	setTopologyListener(func(hostID string, subnets []string) {
		s.manager.SetTopology(hostID, subnets, "")
	})
	// Seed with any topology already recorded before Start.
	s.syncTopology()
	return s.manager.Start(ctx)
}

func (s *SRDPlugin) Stop(ctx context.Context) error {
	setTopologyListener(nil)
	return s.manager.Stop(ctx)
}

func (s *SRDPlugin) State() PluginState {
	return PluginState(s.manager.State())
}

// SetTopology records a host's network position for SRD real-edge construction.
func (s *SRDPlugin) SetTopology(hostID string, subnets []string, zone string) {
	s.manager.SetTopology(hostID, subnets, zone)
}

// syncTopology pulls the kernel's shared topology registry into the SRD pipeline.
func (s *SRDPlugin) syncTopology() {
	for hostID, subnets := range getTopology() {
		s.manager.SetTopology(hostID, subnets, "")
	}
}

// srdKernelAdapter bridges kernel.KernelContext to srd.KernelContext.
type srdKernelAdapter struct {
	kc KernelContext
}

func (a *srdKernelAdapter) Context() context.Context {
	return a.kc.Context()
}

func (a *srdKernelAdapter) Bus() srd.BusAccess {
	return &srdBusAdapter{kc: a.kc}
}

func (a *srdKernelAdapter) GetConfigObj() srd.ConfigGetter {
	return &srdConfigAdapter{kc: a.kc}
}

type srdBusAdapter struct {
	kc KernelContext
}

func (b *srdBusAdapter) Publish(ctx context.Context, topic string, payload interface{}) {
	b.kc.Bus().Publish(ctx, Message{
		Topic:   topic,
		Payload: payload,
		Source:  "srd_adapters",
	})
	if b.kc.Extensions() != nil {
		b.kc.Extensions().Execute(ctx, "srd.result_processed", payload)
	}
}

type srdConfigAdapter struct {
	kc KernelContext
}

func (c *srdConfigAdapter) GetConfigObj() interface{} {
	return c.kc.GetConfigObj()
}
