//go:build commander

package commander

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
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
)

// Module signs and distributes commands to Agents via gRPC, managing retry
// and timeout. It is a build-tag optional plugin (//go:build commander); the
// kernel keeps only the CommanderInterface contract.
type Module struct {
	kc      kernel.KernelContext
	hmacKey []byte

	mu          sync.RWMutex
	pendingCmds map[string]map[string]*pendingCommand
	state       kernel.PluginState

	keyMeta      keyMetadata
	prevHMACKey  []byte
	keyRotatedAt time.Time

	cmdTTL      time.Duration
	cleanupDone chan struct{}
}

type pendingCommand struct {
	Cmd        *apiv1.Command
	EnqueuedAt time.Time
}

type keyMetadata struct {
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyHash   string    `json:"key_hash"`
}

const hmacKeyMaxAge = 90 * 24 * time.Hour

// New creates a commander module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "commander",
		Version:     "1.2.0",
		Description: "Command dispatcher — signs and distributes commands to Agents via gRPC, manages retry and timeout",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 60
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
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

	m.state = kernel.PluginInitialized

	kc.Container().Bind((*kernel.CommanderInterface)(nil), m)

	return nil
}

func (m *Module) generateAndPersistKey(keyPath, metaPath string) {
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

func (m *Module) rotateKey(keyPath, metaPath string) {
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

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "commander.key_rotated", map[string]interface{}{
			"expires_at": m.keyMeta.ExpiresAt.Format(time.RFC3339),
		})
	}
}

func (m *Module) KeyExpiry() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keyMeta.ExpiresAt
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	m.cleanupDone = make(chan struct{})
	m.kc.Bus().Subscribe(kernel.TopicPolicyAction, "commander", m.onPolicyAction)
	go m.cleanupExpiredCommands()
	logger.WithComponent("commander").Info("started")
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	m.mu.Lock()
	if m.cleanupDone != nil {
		select {
		case <-m.cleanupDone:
		default:
			close(m.cleanupDone)
		}
	}
	m.mu.Unlock()
	m.kc.Bus().UnsubscribeAll("commander")
	m.state = kernel.PluginStopped
	logger.WithComponent("commander").Info("stopped")
	return nil
}

func (m *Module) cleanupExpiredCommands() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.kc.Context().Done():
			return
		case <-m.cleanupDone:
			return
		case <-ticker.C:
			m.expireStaleCommands()
		}
	}
}

func (m *Module) expireStaleCommands() {
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
		if m.kc != nil && m.kc.Extensions() != nil {
			m.kc.Extensions().Execute(m.kc.Context(), "commander.command_expired", map[string]interface{}{
				"host_id": e["host_id"],
				"cmd_id":  e["cmd_id"],
			})
		}
	}
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) EnqueueCommand(hostID string, action string, params map[string]string) string {
	cmdID := generateCmdID(hostID, action)

	// Copy params and inject an anti-replay timestamp (required by the agent's
	// verifyCommandSignature). The timestamp is part of the HMAC signature.
	full := make(map[string]string, len(params)+1)
	for k, v := range params {
		full[k] = v
	}
	full["_timestamp"] = time.Now().UTC().Format(time.RFC3339)

	cmd := &apiv1.Command{
		CommandId: cmdID,
		Command:   action,
		Params:    full,
		Signature: m.sign(cmdID, action, full),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingCmds[hostID] == nil {
		m.pendingCmds[hostID] = make(map[string]*pendingCommand)
	}
	m.pendingCmds[hostID][cmdID] = &pendingCommand{Cmd: cmd, EnqueuedAt: time.Now()}

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "remediation.pre_apply", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"action":     action,
			"params":     params,
		})
	}

	return cmdID
}

func (m *Module) DequeueCommands(hostID string) []*apiv1.Command {
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

func (m *Module) AckCommand(hostID string, cmdID string, success bool, output string) {
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

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "remediation.post_apply", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"success":    success,
			"output":     output,
		})

		m.kc.Extensions().Execute(m.kc.Context(), "remediation.action_resolved", map[string]interface{}{
			"host_id":    hostID,
			"command_id": cmdID,
			"success":    success,
			"output":     output,
		})
	}
}

func (m *Module) sign(cmdID, action string, params map[string]string) []byte {
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

func (m *Module) onPolicyAction(ctx context.Context, msg kernel.Message) error {
	action, ok := msg.Payload.(kernel.PolicyAction)
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
