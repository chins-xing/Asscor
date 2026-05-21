package kernel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"

	apiv1 "github.com/argus-security/argus/api/v1"
	"github.com/argus-security/argus/internal/logger"
)

type CommanderModule struct {
	kernel  *Kernel
	hmacKey []byte

	mu          sync.RWMutex
	pendingCmds map[string]map[string]*apiv1.Command
	state       PluginState
}

func (m *CommanderModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "commander",
		Version:     "1.2.0",
		Description: "Command dispatcher — signs and distributes commands to Agents via gRPC, manages retry and timeout",
		Author:      "ARGUS Core Team",
	}
}

func (m *CommanderModule) Dependencies() []PluginDependency {
	return nil
}

func (m *CommanderModule) Priority() int {
	return 60
}

func (m *CommanderModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.pendingCmds = make(map[string]map[string]*apiv1.Command)

	key := k.Config()["hmac_key"]
	if key == "" {
		key = os.Getenv("ARGUS_HMAC_KEY")
	}
	if key == "" {
		keyPath := filepath.Join(os.TempDir(), "argus-hmac-key")
		savedKey, err := os.ReadFile(keyPath)
		if err == nil && len(savedKey) > 0 {
			key = string(savedKey)
			logger.With("component", "commander").Info("loaded persisted HMAC key", "path", keyPath)
		} else {
			key = randomHex(32)
			if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
				logger.With("component", "commander").Warn("failed to persist HMAC key", "path", keyPath, "error", err)
			} else {
				logger.With("component", "commander").Warn("no HMAC key configured, generated and persisted random key", "path", keyPath, "key_length", len(key))
			}
		}
	}
	m.hmacKey = []byte(key)

	m.state = PluginInitialized

	k.Container().Bind((*CommanderInterface)(nil), m)

	return nil
}

func (m *CommanderModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.kernel.Bus().Subscribe("policy.action", "commander", m.onPolicyAction)
	logger.With("component", "commander").Info("started")
	return nil
}

func (m *CommanderModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("commander")
	m.state = PluginStopped
	logger.With("component", "commander").Info("stopped")
	return nil
}

func (m *CommanderModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *CommanderModule) EnqueueCommand(hostID string, action string, params map[string]string) string {
	cmdID := generateCmdID(hostID, action)
	cmd := &apiv1.Command{
		CommandId: cmdID,
		Command:   action,
		Params:    params,
		Signature: m.sign(cmdID, action),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingCmds[hostID] == nil {
		m.pendingCmds[hostID] = make(map[string]*apiv1.Command)
	}
	m.pendingCmds[hostID][cmdID] = cmd

	return cmdID
}

func (m *CommanderModule) DequeueCommands(hostID string) []*apiv1.Command {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmds, ok := m.pendingCmds[hostID]
	if !ok {
		return nil
	}

	result := make([]*apiv1.Command, 0, len(cmds))
	for _, cmd := range cmds {
		result = append(result, cmd)
	}

	delete(m.pendingCmds, hostID)
	return result
}

func (m *CommanderModule) AckCommand(hostID string, cmdID string, success bool, output string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.With("component", "commander").Info("command executed", "command_id", cmdID, "host_id", hostID, "success", success)
}

func (m *CommanderModule) sign(cmdID, action string) []byte {
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write([]byte(cmdID + ":" + action))
	return mac.Sum(nil)
}

func (m *CommanderModule) onPolicyAction(ctx context.Context, msg Message) error {
	hostID := ""
	actionStr := ""
	params := map[string]string{}

	if v, ok := msg.Payload.(map[string]interface{}); ok {
		if id, ok2 := v["HostID"].(string); ok2 {
			hostID = id
		}
		if a, ok2 := v["Action"].(string); ok2 {
			actionStr = a
		}
		if p, ok2 := v["Params"].(map[string]string); ok2 {
			params = p
		}
	}

	m.EnqueueCommand(hostID, actionStr, params)
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCmdID(hostID, action string) string {
	h := sha256.Sum256([]byte(hostID + ":" + action + ":" + randomHex(8)))
	return hex.EncodeToString(h[:8])
}

type CommanderInterface interface {
	EnqueueCommand(hostID string, action string, params map[string]string) string
	DequeueCommands(hostID string) []*apiv1.Command
	AckCommand(hostID string, cmdID string, success bool, output string)
}