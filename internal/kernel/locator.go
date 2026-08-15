package kernel

import (
	"context"
	"github.com/asscor/asscor/internal/topology"

	"github.com/asscor/asscor/internal/logger"
)

// KernelLocator is a white-box deterministic implementation of the Locator
// interface. It aggregates attacker-location evidence from kernel-internal
// data sources (policy status + topology registry), producing subnet-level
// location — sufficient for the "rough scope" requirement.
//
// It is deliberately minimal: SRD propagation-path and ATT&CK attribution
// enrichment can be layered on later via the Locator interface without
// changing the LifecycleEngine.
type KernelLocator struct {
	kernel KernelContext
}

// NewKernelLocator creates a locator backed by kernel policy + topology state.
func NewKernelLocator(kc KernelContext) *KernelLocator {
	return &KernelLocator{kernel: kc}
}

// Locate aggregates subnet + policy + SRD-propagation evidence into an AttackerLocation.
func (l *KernelLocator) Locate(ctx context.Context, hostID string) (*AttackerLocation, error) {
	loc := &AttackerLocation{}

	// Subnet-level location from the topology registry.
	if subnets := topology.GetTopology()[hostID]; len(subnets) > 0 {
		loc.ActiveSubnets = subnets
	}

	// Lateral-movement scope from the SRD pipeline (subnet-overlap reachability).
	if reachable := l.reachableHosts(hostID); len(reachable) > 0 {
		loc.LateralPath = reachable
	}

	// Foothold: the host itself, if its policy status indicates a threat.
	if status, ok := l.hostStatus(hostID); ok {
		switch status {
		case HostCritical, HostIsolated:
			loc.FootholdHost = hostID
			loc.Confidence = 0.7
		case HostWarning:
			loc.Confidence = 0.4
		default:
			loc.Confidence = 0.0
		}
	}

	return loc, nil
}

// reachableHosts queries the SRD plugin for lateral-movement scope.
func (l *KernelLocator) reachableHosts(hostID string) []string {
	if l.kernel == nil {
		return nil
	}
	plugin, ok := l.kernel.GetPlugin("srd_adapters")
	if !ok {
		return nil
	}
	p, ok := plugin.(interface{ GetReachableHosts(hostID string) []string })
	if !ok {
		return nil
	}
	return p.GetReachableHosts(hostID)
}

// HasActiveThreat reports whether the host still shows an active threat
// (policy status Critical or Isolated) — the loop-continuation condition.
func (l *KernelLocator) HasActiveThreat(ctx context.Context, hostID string) bool {
	status, ok := l.hostStatus(hostID)
	if !ok {
		return false
	}
	active := status == HostCritical || status == HostIsolated
	if active {
		logger.WithComponent("locator").Debug("active threat detected", "host_id", hostID, "status", status.String())
	}
	return active
}

func (l *KernelLocator) hostStatus(hostID string) (HostStatus, bool) {
	if l.kernel == nil {
		return HostOK, false
	}
	plugin, ok := l.kernel.GetPlugin("policy")
	if !ok {
		return HostOK, false
	}
	p, ok := plugin.(interface {
		GetHostStatus(hostID string) HostStatus
	})
	if !ok {
		return HostOK, false
	}
	return p.GetHostStatus(hostID), true
}

// Compile-time assertion that KernelLocator satisfies Locator.
var _ Locator = (*KernelLocator)(nil)
