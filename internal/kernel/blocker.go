package kernel

import (
	"context"

	"github.com/asscor/asscor/internal/logger"
)

// KernelBlocker is a white-box deterministic Blocker that dispatches isolation
// commands via the Commander module. It is the default blocker for the
// LifecycleEngine; optional extensions (e.g. MITRE Engage) can replace it via
// SetBlocker without changing the engine.
type KernelBlocker struct {
	kernel KernelContext
}

// NewKernelBlocker creates a blocker backed by the commander's isolate_host command.
func NewKernelBlocker(kc KernelContext) *KernelBlocker {
	return &KernelBlocker{kernel: kc}
}

// Block enqueues an isolate_host command for the attacker's foothold host.
func (b *KernelBlocker) Block(ctx context.Context, loc *AttackerLocation) (*BlockResult, error) {
	if loc == nil || loc.FootholdHost == "" {
		return &BlockResult{Blocked: false, Err: "no foothold host to block"}, nil
	}

	if c, ok := b.commander(); ok {
		cmdID := c.EnqueueCommand(loc.FootholdHost, "isolate_host", map[string]string{"host_id": loc.FootholdHost})
		logger.WithComponent("blocker").Info("isolation command enqueued",
			"host_id", loc.FootholdHost, "command_id", cmdID)
		return &BlockResult{Blocked: true, RuleID: "kernel-isolate"}, nil
	}

	return &BlockResult{Blocked: false, Err: "commander unavailable"}, nil
}

// Unblock enqueues a de-isolate command (restore network access).
func (b *KernelBlocker) Unblock(ctx context.Context, loc *AttackerLocation) error {
	if loc == nil || loc.FootholdHost == "" {
		return nil
	}
	if c, ok := b.commander(); ok {
		c.EnqueueCommand(loc.FootholdHost, "deisolate_host", map[string]string{"host_id": loc.FootholdHost})
	}
	return nil
}

// IsBlocked reports isolation via the policy status (Isolated).
func (b *KernelBlocker) IsBlocked(ctx context.Context, hostID string) bool {
	if b.kernel == nil {
		return false
	}
	plugin, ok := b.kernel.GetPlugin("policy")
	if !ok {
		return false
	}
	p, ok := plugin.(interface{ GetHostStatus(hostID string) HostStatus })
	if !ok {
		return false
	}
	return p.GetHostStatus(hostID) == HostIsolated
}

func (b *KernelBlocker) commander() (CommanderInterface, bool) {
	if b.kernel == nil {
		return nil, false
	}
	plugin, ok := b.kernel.GetPlugin("commander")
	if !ok {
		return nil, false
	}
	c, ok := plugin.(CommanderInterface)
	return c, ok
}

// Compile-time assertion that KernelBlocker satisfies Blocker.
var _ Blocker = (*KernelBlocker)(nil)
