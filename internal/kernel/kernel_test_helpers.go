package kernel

import (
	"context"

	"github.com/asscor/asscor/internal/config"
)

type mockKernelContext struct{}

func (m *mockKernelContext) Container() *Container                { return NewContainer() }
func (m *mockKernelContext) Bus() *Bus                            { return NewBus(512) }
func (m *mockKernelContext) Extensions() ModuleExtensions         { return NewExtensionRegistry() }
func (m *mockKernelContext) Context() context.Context             { return context.Background() }
func (m *mockKernelContext) Config() map[string]string            { return make(map[string]string) }
func (m *mockKernelContext) SetConfig(key, value string)          {}
func (m *mockKernelContext) GetConfigObj() *config.Config         { return nil }
func (m *mockKernelContext) SetConfigObj(c *config.Config)        {}
func (m *mockKernelContext) GetPlugin(name string) (Plugin, bool) { return nil, false }
func (m *mockKernelContext) ListPlugins() []PluginInfo            { return nil }
func (m *mockKernelContext) HealthCheck(ctx context.Context) []PluginHealthStatus {
	return nil
}
