package kernel

import "testing"

func TestMatchTypeFactor(t *testing.T) {
	if f := MatchType(MatchExactVersion).Factor(); f != 1.0 {
		t.Errorf("ExactVersion = %.2f, want 1.0", f)
	}
	if f := MatchType(MatchVersionRange).Factor(); f != 0.7 {
		t.Errorf("VersionRange = %.2f, want 0.7", f)
	}
	if f := MatchType(MatchCPEProduct).Factor(); f != 0.3 {
		t.Errorf("CPEProduct = %.2f, want 0.3", f)
	}
	if f := MatchType(MatchCPEVendor).Factor(); f != 0.15 {
		t.Errorf("CPEVendor = %.2f, want 0.15", f)
	}
	if f := MatchType(MatchNone).Factor(); f != 0.0 {
		t.Errorf("None = %.2f, want 0.0", f)
	}
}

func TestExposureLevelFactor(t *testing.T) {
	if f := ExposureLevel(ExposurePublic).Factor(); f != 1.0 {
		t.Errorf("Public = %.2f, want 1.0", f)
	}
	if f := ExposureLevel(ExposureDMZ).Factor(); f != 0.70 {
		t.Errorf("DMZ = %.2f, want 0.70", f)
	}
	if f := ExposureLevel(ExposureInternal).Factor(); f != 0.40 {
		t.Errorf("Internal = %.2f, want 0.40", f)
	}
	if f := ExposureLevel(ExposureLocalhost).Factor(); f != 0.1 {
		t.Errorf("Localhost = %.2f, want 0.1", f)
	}
}
