package version

import "testing"

// TestVersionConstants (audit L-1: internal/version had zero coverage): the
// version constants are what agents/kernels report and what release tooling
// keys on — assert their shape so an accidental change is caught.
func TestVersionConstants(t *testing.T) {
	if ASSCORVersion == "" {
		t.Error("ASSCORVersion must not be empty")
	}
	if SSAMVersion == "" {
		t.Error("SSAMVersion must not be empty")
	}
	// ASSCOR uses semver-ish "vX.Y.Z".
	if ASSCORVersion[0] != 'v' {
		t.Errorf("ASSCORVersion %q should start with 'v'", ASSCORVersion)
	}
	// SSAM is a plain "major.minor".
	for _, r := range SSAMVersion {
		if !(r >= '0' && r <= '9' || r == '.') {
			t.Errorf("SSAMVersion %q must be numeric dotted", SSAMVersion)
			break
		}
	}
}
