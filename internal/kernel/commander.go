package kernel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
)

type CommanderModule struct {
	kernel  KernelContext
	hmacKey []byte

	mu          sync.RWMutex
	pendingCmds map[string]map[string]*pendingCommand
	state       PluginState

	keyMeta     keyMetadata
	prevHMACKey []byte
	keyRotatedAt time.Time

	cmdTTL      time.Duration
	cleanupDone chan struct{}
}

type pendingCommand struct {
	Cmd         *apiv1.Command
	EnqueuedAt  time.Time
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
		Author:      "ASSCOR Core Team",
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
	m.pendingCmds = make(map[string]map[string]*pendingCommand)
	m.cmdTTL = 30 * time.Minute

	keyPath := filepath.Join("certs", "ASSCOR-hmac-key")
	metaPath := filepath.Join("certs", "ASSCOR-hmac-key-meta.json")

	key := kc.Config()["hmac_key"]
	if key == "" {
		key = os.Getenv("ASSCOR_HMAC_KEY")
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
	key, err := randomHex(32)
	if err != nil {
		logger.WithComponent("commander").Error("failed to generate HMAC key, HMAC signing disabled", "error", err)
		return
	}
	m.mu.Lock()
	m.hmacKey = []byte(key)
	m.keyMeta = keyMetadata{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(hmacKeyMaxAge),
		KeyHash:   sha256Hex([]byte(key)),
	}
	m.mu.Unlock()

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
	m.mu.Lock()
	m.prevHMACKey = make([]byte, len(m.hmacKey))
	copy(m.prevHMACKey, m.hmacKey)
	m.keyRotatedAt = time.Now()

	newKey, err := randomHex(32)
	if err != nil {
		logger.WithComponent("commander").Error("failed to rotate HMAC key, keeping previous key", "error", err)
		m.mu.Unlock()
		return
	}
	m.hmacKey = []byte(newKey)
	m.keyMeta = keyMetadata{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(hmacKeyMaxAge),
		KeyHash:   sha256Hex([]byte(newKey)),
	}
	m.mu.Unlock()

	if err := os.WriteFile(keyPath, []byte(newKey), 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist rotated HMAC key", "error", err)
	}
	metaData, _ := json.Marshal(m.keyMeta)
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		logger.WithComponent("commander").Warn("failed to persist rotated key metadata", "error", err)
	}
	logger.WithComponent("commander").Info("HMAC key rotated", "expires_at", m.keyMeta.ExpiresAt)

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "commander.key_rotated", map[string]interface{}{
			"expires_at": m.keyMeta.ExpiresAt.Format(time.RFC3339),
		})
	}
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
	m.cleanupDone = make(chan struct{})
	m.kernel.Bus().Subscribe(TopicPolicyAction, "commander", m.onPolicyAction)
	go m.cleanupExpiredCommands()
	logger.WithComponent("commander").Info("started")
	return nil
}

func (m *CommanderModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.mu.Lock()
	if m.cleanupDone != nil {
		select {
		case <-m.cleanupDone:
		default:
			close(m.cleanupDone)
		}
	}
	m.mu.Unlock()
	m.kernel.Bus().UnsubscribeAll("commander")
	m.state = PluginStopped
	logger.WithComponent("commander").Info("stopped")
	return nil
}

func (m *CommanderModule) cleanupExpiredCommands() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-m.cleanupDone:
			return
		case <-ticker.C:
			m.expireStaleCommands()
		}
	}
}

func (m *CommanderModule) expireStaleCommands() {
	m.mu.Lock()
	cutoff := time.Now().Add(-m.cmdTTL)
	var expired []map[string]string
	for hostID, cmds := range m.pendingCmds {
		for cmdID, pc := range cmds {
			if pc.EnqueuedAt.Before(cutoff) {
				expired = append(expired, map[string]string{
					"host_id": hostID, "cmd_id": cmdID,
				})
				delete(cmds, cmdID)
				logger.WithComponent("commander").Info("expired stale command",
					"host_id", hostID, "cmd_id", cmdID, "enqueued_at", pc.EnqueuedAt.Format(time.RFC3339))
			}
		}
		if len(cmds) == 0 {
			delete(m.pendingCmds, hostID)
		}
	}
	m.mu.Unlock()

	for _, e := range expired {
		if m.kernel != nil && m.kernel.Extensions() != nil {
			m.kernel.Extensions().Execute(m.kernel.Context(), "commander.command_expired", map[string]interface{}{
				"host_id": e["host_id"],
				"cmd_id":  e["cmd_id"],
			})
		}
	}
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
		m.pendingCmds[hostID] = make(map[string]*pendingCommand)
	}
	m.pendingCmds[hostID][cmdID] = &pendingCommand{Cmd: cmd, EnqueuedAt: time.Now()}

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "remediation.pre_apply", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"action":     action,
			"params":     params,
		})
	}

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
	for _, pc := range cmds {
		result = append(result, pc.Cmd)
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

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "remediation.post_apply", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"success":    success,
			"output":     output,
		})

		m.kernel.Extensions().Execute(m.kernel.Context(), "remediation.action_resolved", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"success":    success,
			"output":     output,
		})
	}
}

func (m *CommanderModule) sign(cmdID, action string, params map[string]string) []byte {
	m.mu.RLock()
	key := make([]byte, len(m.hmacKey))
	copy(key, m.hmacKey)
	m.mu.RUnlock()

	mac := hmac.New(sha256.New, key)
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
	action, ok := msg.Payload.(PolicyAction)
	if !ok {
		logger.WithComponent("commander").Warn("policy action payload type mismatch", "payload_type", fmt.Sprintf("%T", msg.Payload))
		return nil
	}
	m.EnqueueCommand(action.HostID, action.Action, action.Params)
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generateCmdID(hostID, action string) string {
	rnd, err := randomHex(8)
	if err != nil {
		rnd = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	h := sha256.Sum256([]byte(hostID + ":" + action + ":" + rnd))
	return hex.EncodeToString(h[:8])
}