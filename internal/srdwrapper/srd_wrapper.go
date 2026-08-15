//go:build srdwrapper

// Package srdwrapper adapts the SRD pipeline (internal/engine/srd) into a
// kernel.Plugin. It is a thin facade over the SRD implementation.
//
// Build-tag note: this module REQUIRES the `engine` build tag — it imports
// internal/engine/srd (the SRD pipeline implementation) whose types
// (KernelContext, PluginState, Manager) are defined in that package. Build it
// with `-tags "srdwrapper,engine"`. See docs/REMAINING_ARCHITECTURE_PLAN.md
// for the module tag dependency matrix.

package srdwrapper

import (
	"context"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/topology"

	"github.com/asscor/asscor/internal/engine/srd"
)

// Module wraps srd.Manager to implement kernel.Plugin.
// Bridges the gap between srd's local shadow types and kernel types.
type Module struct {
	manager *srd.Manager
}

func New() *Module {
	return &Module{
		manager: srd.NewManager(),
	}
}

func (s *Module) Info() kernel.PluginInfo {
	info := s.manager.Info()
	return kernel.PluginInfo{
		Name:        info.Name,
		Version:     info.Version,
		Description: info.Description,
		Author:      info.Author,
	}
}

func (s *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (s *Module) Priority() int {
	return s.manager.Priority()
}

func (s *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	adapter := &srdKernelAdapter{kc: kc}
	return s.manager.Init(ctx, adapter)
}

func (s *Module) Start(ctx context.Context) error {
	// Real-time topology sync: register a listener so every heartbeat-driven
	// recordTopology immediately updates the SRD pipeline (no one-shot snapshot).
	topology.SetTopologyListener(func(hostID string, subnets []string) {
		s.manager.SetTopology(hostID, subnets, "")
	})
	// Seed with any topology already recorded before Start.
	s.syncTopology()
	return s.manager.Start(ctx)
}

func (s *Module) Stop(ctx context.Context) error {
	topology.SetTopologyListener(nil)
	return s.manager.Stop(ctx)
}

func (s *Module) State() kernel.PluginState {
	return kernel.PluginState(s.manager.State())
}

// SetTopology records a host's network position for SRD real-edge construction.
func (s *Module) SetTopology(hostID string, subnets []string, zone string) {
	s.manager.SetTopology(hostID, subnets, zone)
}

// GetReachableHosts returns hosts sharing a subnet with hostID — the
// lateral-movement scope for the lifecycle Locator.
func (s *Module) GetReachableHosts(hostID string) []string {
	return s.manager.GetReachableHosts(hostID)
}

// syncTopology pulls the kernel's shared topology registry into the SRD pipeline.
func (s *Module) syncTopology() {
	for hostID, subnets := range topology.GetTopology() {
		s.manager.SetTopology(hostID, subnets, "")
	}
}

// srdKernelAdapter bridges kernel.kernel.KernelContext to srd.kernel.KernelContext.
type srdKernelAdapter struct {
	kc kernel.KernelContext
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
	kc kernel.KernelContext
}

func (b *srdBusAdapter) Publish(ctx context.Context, topic string, payload interface{}) {
	b.kc.Bus().Publish(ctx, kernel.Message{
		Topic:   topic,
		Payload: payload,
		Source:  "srd_adapters",
	})
	if b.kc.Extensions() != nil {
		b.kc.Extensions().Execute(ctx, "srd.result_processed", payload)
	}
}

type srdConfigAdapter struct {
	kc kernel.KernelContext
}

func (c *srdConfigAdapter) GetConfigObj() interface{} {
	return c.kc.GetConfigObj()
}
