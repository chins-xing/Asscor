//go:build policy

package policy

import (
	"context"
	"fmt"
	"sync"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

// Module evaluates host scores against thresholds and triggers automated
// actions. It is a build-tag optional plugin (//go:build policy); the kernel
// keeps only the PolicyInterface contract and PolicyAction/HostStatus types.
type Module struct {
	kc  kernel.KernelContext
	cfg *config.Config

	mu          sync.RWMutex
	hostStatus  map[string]kernel.HostStatus
	actionQueue []kernel.PolicyAction

	state kernel.PluginState
}

// New creates a policy module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "policy",
		Version:     "1.2.0",
		Description: "Policy manager — evaluates scores against thresholds and triggers automated actions",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 50
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.hostStatus = make(map[string]kernel.HostStatus)
	m.actionQueue = make([]kernel.PolicyAction, 0)
	m.state = kernel.PluginInitialized

	if impl, ok := kc.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	kc.Container().Bind((*kernel.PolicyInterface)(nil), m)

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	m.kc.Bus().Subscribe(kernel.TopicAssessorResult, "policy", m.onAssessmentResult)
	logger.WithComponent("policy").Info("started")
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	m.kc.Bus().UnsubscribeAll("policy")
	m.state = kernel.PluginStopped
	logger.WithComponent("policy").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) EvaluateHost(hostID string, score float64) (kernel.HostStatus, []kernel.PolicyAction) {
	threshold := m.cfg.Threshold

	var status kernel.HostStatus
	var actions []kernel.PolicyAction

	switch {
	case score >= threshold:
		status = kernel.HostOK
	case score >= threshold-10:
		status = kernel.HostWarning
		actions = append(actions, kernel.PolicyAction{
			HostID:  hostID,
			Action:  "notify_admin",
			Message: fmt.Sprintf("host %s score %.2f below threshold %.2f", hostID, score, threshold),
		})
	case score >= threshold-30:
		status = kernel.HostCritical
		actions = append(actions, kernel.PolicyAction{
			HostID:  hostID,
			Action:  "notify_admin",
			Message: fmt.Sprintf("CRITICAL: host %s score %.2f", hostID, score),
		}, kernel.PolicyAction{
			HostID: hostID,
			Action: "increase_assessment",
			Params: map[string]string{"host_id": hostID},
		})
	default:
		status = kernel.HostIsolated
		actions = append(actions, kernel.PolicyAction{
			HostID:  hostID,
			Action:  "isolate_host",
			Params:  map[string]string{"host_id": hostID},
			Message: fmt.Sprintf("ISOLATING host %s: score %.2f", hostID, score),
		}, kernel.PolicyAction{
			HostID:  hostID,
			Action:  "notify_admin",
			Message: fmt.Sprintf("ISOLATED: host %s", hostID),
		})
	}

	m.mu.Lock()
	prevStatus := m.hostStatus[hostID]
	m.hostStatus[hostID] = status
	m.mu.Unlock()

	if prevStatus != status && m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "policy.status_changed", map[string]interface{}{
			"host_id":     hostID,
			"score":       score,
			"prev_status": prevStatus.String(),
			"new_status":  status.String(),
			"actions":     actions,
		})
	}

	for _, action := range actions {
		if m.kc != nil && m.kc.Extensions() != nil {
			m.kc.Extensions().Execute(m.kc.Context(), "policy.action_decided", map[string]interface{}{
				"host_id": hostID,
				"score":   score,
				"status":  status.String(),
				"action":  action,
			})

			m.kc.Extensions().Execute(m.kc.Context(), "policy.notify", map[string]interface{}{
				"host_id": hostID,
				"score":   score,
				"status":  status.String(),
				"action":  action.Action,
				"message": action.Message,
			})
		}

		if m.kc != nil {
			if errs := m.kc.Bus().PublishSync(m.kc.Context(), kernel.Message{
				Topic:   kernel.TopicPolicyAction,
				Payload: action,
				Source:  "policy",
			}); len(errs) > 0 {
				logger.WithComponent("policy").Warn("sync publish errors", "count", len(errs))
			}
		}
	}

	return status, actions
}

func (m *Module) GetHostStatus(hostID string) kernel.HostStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.hostStatus[hostID]; ok {
		return s
	}
	return kernel.HostOK
}

func (m *Module) onAssessmentResult(ctx context.Context, msg kernel.Message) error {
	result, ok := msg.Payload.(*model.AssessmentResult)
	if !ok {
		return nil
	}

	status, _ := m.EvaluateHost(result.HostID, result.FinalScore)

	if result.PrismInferenceTrend == "collapsing" && result.PrismInferenceCollapseRisk > 0.7 {
		// Update host status so IsBlocked/HasActiveThreat reflect the preemptive
		// isolation (fixes the feedback loop where isolation wasn't recorded).
		m.mu.Lock()
		m.hostStatus[result.HostID] = kernel.HostIsolated
		m.mu.Unlock()

		preemptive := []kernel.PolicyAction{
			{
				HostID:  result.HostID,
				Action:  "isolate_host",
				Params:  map[string]string{"host_id": result.HostID},
				Message: fmt.Sprintf("PREEMPTIVE ISOLATION: host %s Prism collapse risk %.2f (trend: %s, SSAM score: %.2f)",
					result.HostID, result.PrismInferenceCollapseRisk, result.PrismInferenceTrend, result.FinalScore),
			},
			{
				HostID:  result.HostID,
				Action:  "notify_admin",
				Message: fmt.Sprintf("Prism preemptive: host %s collapse risk %.2f",
					result.HostID, result.PrismInferenceCollapseRisk),
			},
		}
		for _, action := range preemptive {
			if m.kc != nil {
				if errs := m.kc.Bus().PublishSync(m.kc.Context(), kernel.Message{
					Topic:   kernel.TopicPolicyAction,
					Payload: action,
					Source:  "policy",
				}); len(errs) > 0 {
					logger.WithComponent("policy").Warn("preemptive publish errors", "count", len(errs))
				}
			}
		}
		logger.WithComponent("policy").Warn("Prism preemptive isolation triggered",
			"host_id", result.HostID,
			"prism_collapse_risk", result.PrismInferenceCollapseRisk,
			"prism_trend", result.PrismInferenceTrend,
			"policy_status", status)
	}

	return nil
}
