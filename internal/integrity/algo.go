//go:build integrity

package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	ssam "github.com/chins-xing/ssam"
	prismlib "github.com/chins-xing/prism"

	"github.com/asscor/asscor/internal/logger"
)

var (
	expectedAlgoDigest string
	algoDigestOnce     sync.Once
)

func init() {
	algoDigestOnce.Do(func() {
		expectedAlgoDigest = computeAlgoDigest()
	})
}

func computeAlgoDigest() string {
	var payload string
	for _, w := range ssam.DefaultWeights {
		payload += fmt.Sprintf("dw:%s=%.4f|", w.Domain, w.Weight)
	}
	for _, ef := range ssam.DefaultEdgeFactors {
		payload += fmt.Sprintf("ef:%s=%.4f|", ef.ID, ef.Factor)
	}
	payload += "fid:" + ssam.DefaultScoringConfig.FormulaID + "|"

	pc := prismlib.DefaultConfig()
	payload += fmt.Sprintf("prism:sf=%.4f,da=%.4f,pc=%.4f,dc=%.4f,cb=%.4f,st=%.4f,dt=%.4f,ut=%.4f|",
		pc.ScoreFloor, pc.DebtAlpha, pc.PropCap, pc.DebtCap, pc.CollapseBeta,
		pc.StableThreshold, pc.DegradedThreshold, pc.UntrustedThreshold)

	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func VerifyAlgo() bool {
	if !IsAlgoVerifyEnabled() {
		return true
	}
	algoDigestOnce.Do(func() { expectedAlgoDigest = computeAlgoDigest() })
	digest := computeAlgoDigest()
	if digest != expectedAlgoDigest {
		logger.WithComponent("integrity").Error("ALGORITHM INTEGRITY VIOLATION", "expected", expectedAlgoDigest, "actual", digest)
		return false
	}
	return true
}
