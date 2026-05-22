package kernel

import (
	"context"
	"time"

	"github.com/argus-security/argus/internal/config"
)

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

type KernelContext interface {
	Container() *Container
	Bus() *Bus
	Extensions() *ExtensionRegistry
	Context() context.Context
	Config() map[string]string
	SetConfig(key, value string)
	GetConfigObj() *config.Config
	SetConfigObj(c *config.Config)
	GetPlugin(name string) (Plugin, bool)
	ListPlugins() []PluginInfo
	HealthCheck(ctx context.Context) []PluginHealthStatus
}

type BusAccess interface {
	Publish(ctx context.Context, topic string, payload interface{})
	Subscribe(topic, subscriberID string) <-chan interface{}
}

type MessageProtocol struct {
	Version   string                 `json:"version"`
	Topic     string                 `json:"topic"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   interface{}            `json:"payload"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
}

const (
	TopicAssessorResult  = "assessor.result"
	TopicPolicyAction    = "policy.action"
	TopicAgentRegistered = "agent.registered"
	TopicAgentTimeout    = "agent.timeout"
	TopicConfigChanged   = "config.changed"
	TopicSPCUpdated      = "spc.updated"
	TopicCTIUpdated      = "cti.updated"
	TopicCommandEnqueued = "command.enqueued"
	TopicCommandResult   = "command.result"

	MessageProtocolVersion = "1.0"
)

type Plugin interface {
	Info() PluginInfo

	Dependencies() []PluginDependency

	Init(ctx context.Context, kc KernelContext) error

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