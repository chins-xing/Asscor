package kernel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	apiv1 "github.com/argus-security/argus/api/v1"
	"github.com/argus-security/argus/internal/logger"
)

type CommanderModule struct {
	kernel  KernelContext
	hmacKey []byte

	mu          sync.RWMutex
	pendingCmds map[string]map[string]*apiv1.Command
	state       PluginState

	keyMeta     keyMetadata
	prevHMACKey []byte
	keyRotatedAt time.Time
}

type keyMetadata struct {
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyHash   string    `json:"key_hash"`
}

const hmacKeyMaxAge = 90 * 24 * time.Hour

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

func (m *CommanderModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.pendingCmds = make(map[string]map[string]*apiv1.Command)

	keyPath := filepath.Join("certs", "argus-hmac-key")
	metaPath := filepath.Join("certs", "argus-hmac-key-meta.json")

	key := kc.Config()["hmac_key"]
	if key == "" {
		key = os.Getenv("ARGUS_HMAC_KEY")
	}
	if key == "" {
		savedKey, err := os.ReadFile(keyPath)
		if err == nil && len(savedKey) > 0 {
			key = string(savedKey)
			logger.WithComponent("commander").Info("loaded persisted HMAC key", "path", keyPath)

			metaData, err := os.ReadFile(metaPath)
			if err == nil {
				var meta keyMetadata
				if json.Unmarshal(metaData, &meta) == nil {
					m.keyMeta = meta
					if time.Now().After(meta.ExpiresAt) {
						logger.WithComponent("commander").Warn("HMAC key expired, rotating", "expired_at", meta.ExpiresAt)
						m.rotateKey(keyPath, metaPath)
						key = string(m.hmacKey)
					}
				}
			}
		} else {
			m.generateAndPersistKey(keyPath, metaPath)
			key = string(m.hmacKey)
		}
	}
	if m.hmacKey == nil {
		m.hmacKey = []byte(key)
		if m.keyMeta.CreatedAt.IsZero() {
			m.keyMeta = keyMetadata{
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(hmacKeyMaxAge),
				KeyHash:   sha256Hex([]byte(key)),
			}
		}
	}

	m.state = PluginInitialized

	kc.Container().Bind((*CommanderInterface)(nil), m)

	return nil
}

func (m *CommanderModule) generateAndPersistKey(keyPath, metaPath string) {
	key := randomHex(32)
	m.hmacKey = []byte(key)
	m.keyMeta = keyMetadata{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(hmacKeyMaxAge),
		KeyHash:   sha256Hex([]byte(key)),
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		logger.WithComponent("commander").Warn("failed to create key directory", "error", err)
		return
	}
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist HMAC key", "path", keyPath, "error", err)
	} else {
		logger.WithComponent("commander").Info("generated and persisted HMAC key", "path", keyPath)
	}
	metaData, _ := json.Marshal(m.keyMeta)
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist key metadata", "path", metaPath, "error", err)
	}
}

func (m *CommanderModule) rotateKey(keyPath, metaPath string) {
	m.prevHMACKey = make([]byte, len(m.hmacKey))
	copy(m.prevHMACKey, m.hmacKey)
	m.keyRotatedAt = time.Now()

	newKey := randomHex(32)
	m.hmacKey = []byte(newKey)
	m.keyMeta = keyMetadata{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(hmacKeyMaxAge),
		KeyHash:   sha256Hex([]byte(newKey)),
	}

	if err := os.WriteFile(keyPath, []byte(newKey), 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist rotated HMAC key", "error", err)
	}
	metaData, _ := json.Marshal(m.keyMeta)
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist rotated key metadata", "error", err)
	}
	logger.WithComponent("commander").Info("HMAC key rotated", "expires_at", m.keyMeta.ExpiresAt)
}

func (m *CommanderModule) KeyExpiry() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keyMeta.ExpiresAt
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (m *CommanderModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.kernel.Bus().Subscribe(TopicPolicyAction, "commander", m.onPolicyAction)
	logger.WithComponent("commander").Info("started")
	return nil
}

func (m *CommanderModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("commander")
	m.state = PluginStopped
	logger.WithComponent("commander").Info("stopped")
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
		Signature: m.sign(cmdID, action, params),
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

	if cmds, ok := m.pendingCmds[hostID]; ok {
		if _, exists := cmds[cmdID]; !exists {
			logger.WithComponent("commander").Warn("ack for unknown command", "command_id", cmdID, "host_id", hostID)
			return
		}
		delete(cmds, cmdID)
		if len(cmds) == 0 {
			delete(m.pendingCmds, hostID)
		}
	} else {
		logger.WithComponent("commander").Warn("ack for unknown host", "command_id", cmdID, "host_id", hostID)
		return
	}

	logger.WithComponent("commander").Info("command executed", "command_id", cmdID, "host_id", hostID, "success", success)
}

func (m *CommanderModule) sign(cmdID, action string, params map[string]string) []byte {
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write([]byte(cmdID + ":" + action))
	keys := sortedKeys(params)
	for _, k := range keys {
		mac.Write([]byte(":" + k + "=" + params[k]))
	}
	return mac.Sum(nil)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	if _, err := rand.Read(b); err != nil {
		logger.WithComponent("commander").Error("crypto/rand read failed", "error", err)
		for i := range b {
			b[i] = byte(i)
		}
	}
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