package kernel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

type resultSigner struct {
	mu  sync.RWMutex
	key []byte
}

var (
	globalResultSigner *resultSigner
	resultSignerOnce   sync.Once
)

func GetResultSigner() *resultSigner {
	resultSignerOnce.Do(func() {
		globalResultSigner = &resultSigner{}
		globalResultSigner.loadOrCreateKey()
	})
	return globalResultSigner
}

func (s *resultSigner) loadOrCreateKey() {
	keyPath := filepath.Join("certs", "ASSCOR-assessment-key")
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
	os.MkdirAll("certs", 0700)
	os.WriteFile(keyPath, key, 0600)
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	logger.WithComponent("integrity").Info("assessment result signing enabled")
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

func (s *resultSigner) Sign(r *model.AssessmentResult) {
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

func (s *resultSigner) Verify(r *model.AssessmentResult) bool {
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
