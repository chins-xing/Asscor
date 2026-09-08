//go:build integrity

package integrity

import (
	"testing"

	ssam "github.com/chins-xing/ssam"
)

// TestAlgoDigestMatchesFrozen ensures the build-time frozen digest always
// matches the canonical constant set. When SSAM/Prism defaults change
// legitimately, this test fails with the new digest so the author can update
// expectedAlgoDigest consciously (C-1 fix: the expected value must not be
// derived at runtime from the very constants it protects).
func TestAlgoDigestMatchesFrozen(t *testing.T) {
	actual := computeAlgoDigest()
	if actual != expectedAlgoDigest {
		t.Errorf("algo digest drifted from frozen constant:\n  frozen: %s\n  actual: %s\nRegenerate expectedAlgoDigest in algo.go from the actual value.",
			expectedAlgoDigest, actual)
	}
}

// TestVerifyAlgoDetectsMutation proves the C-1 fix: mutating the live
// constants must make VerifyAlgo() fail (pre-fix it compared the digest to
// itself and always returned true). The tamper is restored right after so the
// shared package-level defaults are not left dirty for other tests.
func TestVerifyAlgoDetectsMutation(t *testing.T) {
	if !VerifyAlgo() {
		t.Fatal("precondition: clean constants must verify")
	}

	// Mutate the last domain weight in place. DefaultWeights is a package
	// slice whose backing array we can touch; this simulates runtime memory
	// tampering with the algorithm constants.
	if len(ssam.DefaultWeights) == 0 {
		t.Skip("no default weights to mutate")
	}
	w := &ssam.DefaultWeights[len(ssam.DefaultWeights)-1]
	orig := w.Weight
	w.Weight = orig + 1.0
	tampered := !VerifyAlgo()
	w.Weight = orig // restore

	if !tampered {
		t.Error("VerifyAlgo returned true after constant mutation — integrity check is still self-referential")
	}
	if !VerifyAlgo() {
		t.Error("restore failed: constants must verify again after undoing the mutation")
	}
}
