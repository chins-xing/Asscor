//go:build !integrity

package integrity

import (
	"github.com/asscor/asscor/internal/model"
)

// Signer is a no-op signer used when the integrity module is disabled.
type Signer struct{}

// GetSigner returns a no-op signer.
func GetSigner() *Signer { return &Signer{} }

// Sign is a no-op.
func (s *Signer) Sign(r *model.AssessmentResult) {}

// Verify always returns false (no signature is generated when disabled).
func (s *Signer) Verify(r *model.AssessmentResult) bool { return false }

// VerifyAlgo always returns true (no algorithm integrity check when disabled).
func VerifyAlgo() bool { return true }
