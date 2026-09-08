//go:build integrity

package integrity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/chins-xing/asscor/internal/logger"
	"github.com/chins-xing/asscor/internal/model"
)

type Signer struct {
	mu  sync.RWMutex
	key []byte
}

var (
	signer     *Signer
	signerOnce sync.Once
	// keyDir is where the assessment signing key is persisted. Audit M-3:
	// defaulting to a cwd-relative "certs" breaks under systemd (working
	// directory differs → fresh key every start, signatures unverifiable
	// across restarts). cmd/kernel injects its --cert-dir value via
	// SetKeyDir; the "certs" fallback preserves default-mode behavior when
	// nothing was injected.
	keyDir   = "certs"
	keyDirMu sync.RWMutex
)

// SetKeyDir overrides the directory used to persist the assessment signing
// key (audit M-3). Call before the first GetSigner; a later call only affects
// keys created afterwards.
func SetKeyDir(dir string) {
	keyDirMu.Lock()
	defer keyDirMu.Unlock()
	if dir != "" {
		keyDir = dir
	}
}

func currentKeyDir() string {
	keyDirMu.RLock()
	defer keyDirMu.RUnlock()
	return keyDir
}

func GetSigner() *Signer {
	signerOnce.Do(func() {
		signer = &Signer{}
		signer.loadOrCreateKey()
	})
	return signer
}

func (s *Signer) loadOrCreateKey() {
	dir := currentKeyDir()
	keyPath := filepath.Join(dir, "ASSCOR-assessment-key")
	if data, err := os.ReadFile(keyPath); err == nil && len(data) >= 32 {
		s.mu.Lock()
		s.key = data
		s.mu.Unlock()
		return
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		logger.WithComponent("integrity").Error("failed to generate assessment signing key", "error", err)
		return
	}
	os.MkdirAll(dir, 0700)
	os.WriteFile(keyPath, key, 0600)
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	logger.WithComponent("integrity").Info("assessment result signing enabled", "key_dir", dir)
}

func canonicalPayload(r *model.AssessmentResult) []byte {
	return []byte(fmt.Sprintf(
		"v1|%s|%s|%d|%.6f|%t|%.6f|%.4f|%.4f|%.4f|%.4f|%.4f|%.6f|%d",
		r.HostID, r.Hostname, r.Timestamp.UnixNano(),
		r.FinalScore, r.Acceptable, r.Threshold,
		r.DomainScores.AttackSurface, r.DomainScores.BusinessContinuity,
		r.DomainScores.OperationTrust, r.DomainScores.Resilience,
		r.DomainScores.KernelSecurity, r.SPCScore, len(r.Checks),
	))
}

func (s *Signer) Sign(r *model.AssessmentResult) {
	if !IsSigningEnabled() {
		return
	}
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if len(key) == 0 || r == nil {
		return
	}
	r.Signature = ""
	mac := hmac.New(sha256.New, key)
	mac.Write(canonicalPayload(r))
	r.Signature = hex.EncodeToString(mac.Sum(nil))
}

func (s *Signer) Verify(r *model.AssessmentResult) bool {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if len(key) == 0 || r == nil || r.Signature == "" {
		return false
	}
	provided, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonicalPayload(r))
	return hmac.Equal(provided, mac.Sum(nil))
}
