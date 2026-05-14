package kernel

import "context"

type PluginState int

const (
	PluginUnregistered PluginState = iota
	PluginRegistered
	PluginInitialized
	PluginStarted
	PluginStopping
	PluginStopped
	PluginFailed
)

func (s PluginState) String() string {
	switch s {
	case PluginUnregistered:
		return "unregistered"
	case PluginRegistered:
		return "registered"
	case PluginInitialized:
		return "initialized"
	case PluginStarted:
		return "started"
	case PluginStopping:
		return "stopping"
	case PluginStopped:
		return "stopped"
	case PluginFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type PluginInfo struct {
	Name        string
	Version     string
	Description string
	Author      string
}

type PluginDependency struct {
	Interface interface{}
	Name      string
}

type Plugin interface {
	Info() PluginInfo

	Dependencies() []PluginDependency

	Init(ctx context.Context, kernel *Kernel) error

	Start(ctx context.Context) error

	Stop(ctx context.Context) error

	State() PluginState
}

type PriorityPlugin interface {
	Plugin
	Priority() int
}

type HealthCheckable interface {
	HealthCheck(ctx context.Context) error
}

type ConfigurablePlugin interface {
	Plugin
	Configure(config map[string]string) error
}