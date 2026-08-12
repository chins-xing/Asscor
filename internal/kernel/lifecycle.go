package kernel

import (
	"context"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

// LifecyclePhase enumerates the automated security lifecycle phases.
// 探测→定位→响应→报告→阻断→修复→验证→定位→归档→重复(循环)
type LifecyclePhase int

const (
	PhaseDetect LifecyclePhase = iota
	PhaseLocate
	PhaseRespond
	PhaseReport
	PhaseBlock
	PhaseRemediate
	PhaseVerify
	PhaseRelocate
	PhaseArchive
)

func (p LifecyclePhase) String() string {
	switch p {
	case PhaseDetect:
		return "detect"
	case PhaseLocate:
		return "locate"
	case PhaseRespond:
		return "respond"
	case PhaseReport:
		return "report"
	case PhaseBlock:
		return "block"
	case PhaseRemediate:
		return "remediate"
	case PhaseVerify:
		return "verify"
	case PhaseRelocate:
		return "relocate"
	case PhaseArchive:
		return "archive"
	default:
		return "unknown"
	}
}

// AttackerLocation is the attacker-location aggregation result.
type AttackerLocation struct {
	FootholdHost  string   `json:"foothold_host"`
	EntryHost     string   `json:"entry_host"`
	LateralPath   []string `json:"lateral_path"`
	ActiveSubnets []string `json:"active_subnets"`
	C2Indicators  []string `json:"c2_indicators"`
	APTGroup      string   `json:"apt_group,omitempty"`
	Confidence    float64  `json:"confidence"`
}

// BlockResult reports a blocking action outcome.
type BlockResult struct {
	Blocked bool   `json:"blocked"`
	RuleID  string `json:"rule_id"`
	Err     string `json:"error,omitempty"`
}

// ActivityState tracks attacker-activity status for the loop condition.
type ActivityState struct {
	HostID   string    `json:"host_id"`
	Active   bool      `json:"active"`
	LastSeen time.Time `json:"last_seen"`
}

// Locator aggregates attacker location from ATT&CK + SRD (white-box, deterministic).
type Locator interface {
	Locate(ctx context.Context, hostID string) (*AttackerLocation, error)
	HasActiveThreat(ctx context.Context, hostID string) bool
}

// Blocker executes active blocking actions (white-box, auditable).
type Blocker interface {
	Block(ctx context.Context, loc *AttackerLocation) (*BlockResult, error)
	Unblock(ctx context.Context, loc *AttackerLocation) error
	IsBlocked(ctx context.Context, hostID string) bool
}

// ThreatActivityStore tracks attacker-activity state to drive the loop condition.
type ThreatActivityStore interface {
	MarkActive(hostID string)
	IsActive(hostID string) bool
	Clear(hostID string)
}

// inMemActivityStore is the default in-memory implementation of ThreatActivityStore.
type inMemActivityStore struct {
	mu   sync.Mutex
	data map[string]ActivityState
}

func newInMemActivityStore() *inMemActivityStore {
	return &inMemActivityStore{data: make(map[string]ActivityState)}
}

func (s *inMemActivityStore) MarkActive(hostID string) {
	s.mu.Lock()
	s.data[hostID] = ActivityState{HostID: hostID, Active: true, LastSeen: time.Now()}
	s.mu.Unlock()
}

func (s *inMemActivityStore) IsActive(hostID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.data[hostID]
	return ok && st.Active
}

func (s *inMemActivityStore) Clear(hostID string) {
	s.mu.Lock()
	delete(s.data, hostID)
	s.mu.Unlock()
}

// LifecycleEngine drives the automated security lifecycle state machine.
// It is a kernel Plugin that subscribes to assessment results and runs the
// lifecycle (探测→定位→响应→报告→阻断→修复→验证→定位→归档→重复) per host.
type LifecycleEngine struct {
	kernel   KernelContext
	locator  Locator
	blocker  Blocker
	activity ThreatActivityStore

	mu     sync.Mutex
	state  PluginState
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewLifecycleEngine creates a lifecycle state machine with default components.
func NewLifecycleEngine(kc KernelContext) *LifecycleEngine {
	return &LifecycleEngine{
		kernel:   kc,
		activity: newInMemActivityStore(),
		state:    PluginUnregistered,
	}
}

// ── kernel.Plugin implementation ──

func (e *LifecycleEngine) Info() PluginInfo {
	return PluginInfo{Name: "lifecycle_engine", Version: "0.1.0", Description: "Automated security lifecycle state machine"}
}

func (e *LifecycleEngine) Dependencies() []PluginDependency { return nil }

func (e *LifecycleEngine) Init(ctx context.Context, kc KernelContext) error {
	e.kernel = kc
	if e.locator == nil {
		e.locator = NewKernelLocator(kc)
	}
	if e.blocker == nil {
		e.blocker = NewKernelBlocker(kc)
	}
	e.mu.Lock()
	e.state = PluginInitialized
	e.mu.Unlock()
	return nil
}

func (e *LifecycleEngine) Start(ctx context.Context) error {
	e.ctx, e.cancel = context.WithCancel(ctx)
	// Subscribe to assessment results: run the lifecycle per assessed host.
	e.kernel.Bus().Subscribe(TopicAssessorResult, "lifecycle_engine", func(ctx context.Context, msg Message) error {
		if r, ok := msg.Payload.(*model.AssessmentResult); ok && r != nil {
			e.wg.Add(1)
			go func(hostID string) {
				defer e.wg.Done()
				e.Run(e.ctx, hostID)
			}(r.HostID)
		}
		return nil
	})
	e.mu.Lock()
	e.state = PluginStarted
	e.mu.Unlock()
	logger.WithComponent("lifecycle").Info("started")
	return nil
}

func (e *LifecycleEngine) Stop(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	// Unsubscribe before waiting so late assessment results don't trigger new
	// goroutines after shutdown begins (matches policy.go / commander.go).
	if e.kernel != nil && e.kernel.Bus() != nil {
		e.kernel.Bus().UnsubscribeAll("lifecycle_engine")
	}
	e.wg.Wait()
	e.mu.Lock()
	e.state = PluginStopped
	e.mu.Unlock()
	return nil
}

func (e *LifecycleEngine) State() PluginState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// ── Configuration ──

func (e *LifecycleEngine) SetLocator(l Locator)            { e.locator = l }
func (e *LifecycleEngine) SetBlocker(b Blocker)            { e.blocker = b }
func (e *LifecycleEngine) SetActivityStore(s ThreatActivityStore) { e.activity = s }

func (e *LifecycleEngine) enterPhase(p LifecyclePhase) {
	if e.kernel != nil && e.kernel.Extensions() != nil {
		e.kernel.Extensions().Execute(e.kernel.Context(), "lifecycle.phase_entered", map[string]interface{}{"phase": p.String()})
	}
}

func (e *LifecycleEngine) exitPhase(p LifecyclePhase) {
	if e.kernel != nil && e.kernel.Extensions() != nil {
		e.kernel.Extensions().Execute(e.kernel.Context(), "lifecycle.phase_exited", map[string]interface{}{"phase": p.String()})
	}
}

// Run executes one full lifecycle pass for a host, looping on persistent threat.
// maxIterations bounds the loop to prevent a busy-loop if the locator keeps
// reporting active threats; ctx cancellation also aborts the loop.
func (e *LifecycleEngine) Run(ctx context.Context, hostID string) {
	const maxIterations = 100
	for iter := 0; iter < maxIterations; iter++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 1. 探测 — assessment is driven externally; this phase signals readiness
		e.enterPhase(PhaseDetect)
		e.exitPhase(PhaseDetect)

		// 2. 定位
		e.enterPhase(PhaseLocate)
		var loc *AttackerLocation
		if e.locator != nil {
			if l, err := e.locator.Locate(ctx, hostID); err == nil {
				loc = l
			}
		}
		if loc != nil && loc.FootholdHost != "" {
			if e.kernel != nil && e.kernel.Extensions() != nil {
				e.kernel.Extensions().Execute(ctx, "locate.completed", loc)
			}
		}
		e.exitPhase(PhaseLocate)

		// 3. 响应
		e.enterPhase(PhaseRespond)
		e.exitPhase(PhaseRespond)

		// 4. 报告
		e.enterPhase(PhaseReport)
		e.exitPhase(PhaseReport)

		// 5. 阻断
		if e.blocker != nil && loc != nil {
			e.enterPhase(PhaseBlock)
			if e.kernel != nil && e.kernel.Extensions() != nil {
				e.kernel.Extensions().Execute(ctx, "block.pre_apply", loc)
			}
			if res, err := e.blocker.Block(ctx, loc); err == nil && res != nil {
				if e.kernel != nil && e.kernel.Extensions() != nil {
					e.kernel.Extensions().Execute(ctx, "block.post_apply", res)
					if res.Blocked {
						e.kernel.Extensions().Execute(ctx, "block.confirmed", res)
					}
				}
			}
			e.exitPhase(PhaseBlock)
		}

		// 6. 修复
		e.enterPhase(PhaseRemediate)
		e.exitPhase(PhaseRemediate)

		// 7. 验证
		e.enterPhase(PhaseVerify)
		e.exitPhase(PhaseVerify)

		// 8. 定位(再次) — re-locate to check if attacker activity persists
		e.enterPhase(PhaseRelocate)
		stillActive := false
		if e.locator != nil {
			stillActive = e.locator.HasActiveThreat(ctx, hostID)
		}
		if stillActive {
			if e.kernel != nil && e.kernel.Extensions() != nil {
				e.kernel.Extensions().Execute(ctx, "locate.threat_active", map[string]interface{}{"host_id": hostID})
			}
			if e.activity != nil {
				e.activity.MarkActive(hostID)
			}
		}
		e.exitPhase(PhaseRelocate)

		// 9. 归档
		e.enterPhase(PhaseArchive)
		e.exitPhase(PhaseArchive)

		// 10. 循环判断: 定位中仍存在攻击者活动 → 重复
		if stillActive && e.activity != nil && e.activity.IsActive(hostID) {
			if e.kernel != nil && e.kernel.Extensions() != nil {
				e.kernel.Extensions().Execute(ctx, "lifecycle.repeat", map[string]interface{}{"host_id": hostID})
			}
			logger.WithComponent("lifecycle").Warn("attacker activity persists, repeating lifecycle", "host_id", hostID)
			// Backoff to avoid a busy-loop while the threat persists.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		if e.activity != nil {
			e.activity.Clear(hostID)
		}
		break
	}

	if e.kernel != nil && e.kernel.Extensions() != nil {
		e.kernel.Extensions().Execute(ctx, "lifecycle.completed", map[string]interface{}{"host_id": hostID})
	}
}
