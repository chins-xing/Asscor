//go:build integrity

package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	prismlib "github.com/chins-xing/prism"
	ssam "github.com/chins-xing/ssam"

	"github.com/chins-xing/asscor/internal/logger"
)

// expectedAlgoDigest is the SHA-256 of the canonical SSAM/Prism algorithm
// constant set, frozen at BUILD time (see the note below for regeneration).
//
// It deliberately does NOT recompute itself from the live constants at
// runtime: the whole point of the check is to detect runtime tampering with
// the default weights/edge factors/scoring config. If the expected value were
// derived from the same in-memory constants it protects (the pre-fix design),
// mutating those constants would silently change both sides of the comparison
// and the check could never fail. Freezing the digest here moves the
// reference outside the protected data, so a runtime mutation of the weights
// now makes computeAlgoDigest() diverge and VerifyAlgo() reports the breach.
//
// Regeneration: whenever ssam.DefaultWeights / DefaultEdgeFactors /
// DefaultScoringConfig or prismlib.DefaultConfig() change legitimately, run
// `go test -tags integrity -run TestAlgoDigestMatchesFrozen` — it prints the
// current digest on failure — and update this constant (or regenerate via
// cmd/algodigest if present). The test TestAlgoDigestMatchesFrozen enforces
// that the frozen value and the canonical constants never drift apart.
const expectedAlgoDigest = "b534f8c1e4b4d9491641b81992fadc53b5f5a82460187f0e942c0c8fd82f1620"

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
	digest := computeAlgoDigest()
	if digest != expectedAlgoDigest {
		logger.WithComponent("integrity").Error("ALGORITHM INTEGRITY VIOLATION", "expected", expectedAlgoDigest, "actual", digest)
		return false
	}
	return true
}
