package webui

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

const defaultWebUIPort = 8087

// Module is the web UI plugin for ASSCOR.
// It subscribes to assessment results via the Bus and serves a read-only dashboard via HTTP.
//
// Architecture: Plugin (lifecycle) + in-memory cache + embedded HTTP server + SPA frontend.
// Data source: Bus topic "assessor.result" (in-memory only, no persistence dependency).
type Module struct {
	kernel kernel.KernelContext

	mu    sync.RWMutex
	state kernel.PluginState

	// HTTP
	server     *http.Server
	listenPort int

	// In-memory result cache
	history    map[string][]model.AssessmentResult // hostID -> ordered history (newest last)
	latest     map[string]*model.AssessmentResult  // hostID -> latest
	hostnames  map[string]string                   // hostID -> hostname

	// Extension-registered HTTP handlers (populated via webui.route.register).
	extraRoutes map[string]http.Handler

	done chan struct{}
}

const maxHistoryPerHost = 200

func New(listenPort int) *Module {
	if listenPort <= 0 {
		listenPort = defaultWebUIPort
	}
	return &Module{
		listenPort:  listenPort,
		history:     make(map[string][]model.AssessmentResult),
		latest:      make(map[string]*model.AssessmentResult),
		hostnames:   make(map[string]string),
		extraRoutes: make(map[string]http.Handler),
		done:       make(chan struct{}),
	}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "webui",
		Version:     "1.0.0",
		Description: "Web Dashboard — read-only visualization of SSAM assessment results",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

// Priority returns 90 — starts after all core assessment modules.
func (m *Module) Priority() int {
	return 90
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kernel = kc
	m.mu.Lock()
	m.state = kernel.PluginInitialized
	m.mu.Unlock()

	logger.WithComponent("webui").Info("initialized", "port", m.listenPort)
	return nil
}

// RegisterHandler registers an additional HTTP handler at the given pattern.
// Intended for extension plugins (web ops panels, custom API endpoints).
// Patterns under /api/ext/ are recommended to avoid collision with core routes.
func (m *Module) RegisterHandler(pattern string, h http.Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extraRoutes[pattern] = h
	logger.WithComponent("webui").Info("registered extension route", "pattern", pattern)
}

func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	m.state = kernel.PluginStarted
	m.mu.Unlock()

	// Subscribe to assessment results
	m.kernel.Bus().Subscribe(kernel.TopicAssessorResult, "webui", m.onAssessmentResult)

	// Let extension plugins register additional routes before the server starts.
	if errs := m.kernel.Extensions().Execute(m.kernel.Context(), "webui.route.register", m); len(errs) > 0 {
		logger.WithComponent("webui").Warn("webui.route.register extension errors", "count", len(errs))
	}

	// Start HTTP server
	mux := http.NewServeMux()
	m.registerRoutes(mux)

	m.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", m.listenPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.WithComponent("webui").Info("HTTP server starting", "addr", m.server.Addr)
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithComponent("webui").Error("HTTP server error", "error", err)
		}
	}()

	logger.WithComponent("webui").Info("started", "port", m.listenPort)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.state = kernel.PluginStopping
	m.mu.Unlock()

	m.kernel.Bus().UnsubscribeAll("webui")

	if m.server != nil {
		if err := m.server.Shutdown(ctx); err != nil {
			logger.WithComponent("webui").Error("HTTP shutdown error", "error", err)
		}
	}

	m.mu.Lock()
	if m.done != nil {
		select {
		case <-m.done:
		default:
			close(m.done)
		}
	}
	m.mu.Unlock()

	m.mu.Lock()
	m.state = kernel.PluginStopped
	m.mu.Unlock()

	logger.WithComponent("webui").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// onAssessmentResult handles the "assessor.result" Bus event.
func (m *Module) onAssessmentResult(ctx context.Context, msg kernel.Message) error {
	ar, ok := msg.Payload.(*model.AssessmentResult)
	if !ok {
		return nil
	}

	copy_ := *ar // shallow copy

	m.mu.Lock()
	defer m.mu.Unlock()

	m.hostnames[ar.HostID] = ar.Hostname
	m.latest[ar.HostID] = &copy_

	hostHistory := m.history[ar.HostID]
	hostHistory = append(hostHistory, copy_)
	if len(hostHistory) > maxHistoryPerHost {
		hostHistory = hostHistory[len(hostHistory)-maxHistoryPerHost:]
	}
	m.history[ar.HostID] = hostHistory

	logger.WithComponent("webui").Debug("cached assessment",
		"host_id", ar.HostID,
		"score", ar.FinalScore,
		"history_len", len(hostHistory),
	)

	return nil
}