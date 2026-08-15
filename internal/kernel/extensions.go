package kernel

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/asscor/asscor/internal/logger"
)

// ModuleExtensions is the extension surface exposed to plugins.
// Modules can subscribe handlers and fire events, but CANNOT define extension points.
// Extension point definitions are owned by the ASSCOR platform via RegisterAllExtensionPoints.
//
// Priority semantics: handlers are executed in ascending priority order (lower numbers first).
// Default priority is 50. No "run-last" sentinel exists — use a large value like 999.
type ModuleExtensions interface {
	RegisterExtension(pluginID string, pointName string, handler ExtensionHandler, priority int) error
	UnregisterPlugin(pluginID string)
	Execute(ctx context.Context, pointName string, data interface{}) []error
	ExecuteUntilFirst(ctx context.Context, pointName string, data interface{}) (string, interface{}, error)
	ListPoints() []ExtensionPoint
	ListExtensions(pointName string) []string
	GetPoint(name string) (ExtensionPoint, bool)
}

type ExtensionPoint struct {
	Name        string
	Description string
	Version     string
}

type ExtensionHandler func(ctx context.Context, data interface{}) error

type registeredExtension struct {
	pluginID string
	point    string
	handler  ExtensionHandler
	priority int
}

type ExtensionRegistry struct {
	mu         sync.RWMutex
	extensions map[string][]registeredExtension
	points     map[string]ExtensionPoint
}

func NewExtensionRegistry() *ExtensionRegistry {
	return &ExtensionRegistry{
		extensions: make(map[string][]registeredExtension),
		points:     make(map[string]ExtensionPoint),
	}
}

func (r *ExtensionRegistry) RegisterPoint(point ExtensionPoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.points[point.Name] = point
}

func (r *ExtensionRegistry) GetPoint(name string) (ExtensionPoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.points[name]
	return p, ok
}

func (r *ExtensionRegistry) RegisterExtension(pluginID string, pointName string, handler ExtensionHandler, priority int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.points[pointName]; !ok {
		return fmt.Errorf("extension point %s is not registered", pointName)
	}

	r.extensions[pointName] = append(r.extensions[pointName], registeredExtension{
		pluginID: pluginID,
		point:    pointName,
		handler:  handler,
		priority: priority,
	})

	sort.Slice(r.extensions[pointName], func(i, j int) bool {
		return r.extensions[pointName][i].priority < r.extensions[pointName][j].priority
	})

	return nil
}

func (r *ExtensionRegistry) UnregisterPlugin(pluginID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for point, exts := range r.extensions {
		filtered := exts[:0]
		for _, ext := range exts {
			if ext.pluginID != pluginID {
				filtered = append(filtered, ext)
			}
		}
		if len(filtered) == 0 {
			delete(r.extensions, point)
		} else {
			r.extensions[point] = filtered
		}
	}
}

func (r *ExtensionRegistry) Execute(ctx context.Context, pointName string, data interface{}) []error {
	r.mu.RLock()
	exts := make([]registeredExtension, len(r.extensions[pointName]))
	copy(exts, r.extensions[pointName])
	r.mu.RUnlock()

	errs := make([]error, 0)
	for _, ext := range exts {
		if err := ext.handler(ctx, data); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ext.pluginID, err))
			logger.WithComponent("extensions").Warn("extension handler error",
				"point", pointName, "plugin", ext.pluginID, "error", err)
		}
	}
	return errs
}

func (r *ExtensionRegistry) ExecuteUntilFirst(ctx context.Context, pointName string, data interface{}) (string, interface{}, error) {
	r.mu.RLock()
	exts := make([]registeredExtension, len(r.extensions[pointName]))
	copy(exts, r.extensions[pointName])
	r.mu.RUnlock()

	if len(exts) == 0 {
		return "", nil, fmt.Errorf("no extension registered for point %s", pointName)
	}

	for _, ext := range exts {
		if err := ext.handler(ctx, data); err != nil {
			continue
		}
		return ext.pluginID, nil, nil
	}
	return "", nil, fmt.Errorf("all handlers returned errors for point %s", pointName)
}

func (r *ExtensionRegistry) ListPoints() []ExtensionPoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	points := make([]ExtensionPoint, 0, len(r.points))
	for _, p := range r.points {
		points = append(points, p)
	}
	return points
}

func (r *ExtensionRegistry) ListExtensions(pointName string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exts := r.extensions[pointName]
	ids := make([]string, len(exts))
	for i, ext := range exts {
		ids[i] = ext.pluginID
	}
	return ids
}
