package kernel

import (
	"context"

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

// Locate aggregates subnet + policy evidence into an AttackerLocation.
func (l *KernelLocator) Locate(ctx context.Context, hostID string) (*AttackerLocation, error) {
	loc := &AttackerLocation{}

	// Subnet-level location from the topology registry.
	if subnets := getTopology()[hostID]; len(subnets) > 0 {
		loc.ActiveSubnets = subnets
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
	p, ok := plugin.(interface{ GetHostStatus(hostID string) HostStatus })
	if !ok {
		return HostOK, false
	}
	return p.GetHostStatus(hostID), true
}

// Compile-time assertion that KernelLocator satisfies Locator.
var _ Locator = (*KernelLocator)(nil)
