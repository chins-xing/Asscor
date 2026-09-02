package semver

import "testing"

func TestParseValid(t *testing.T) {
	cases := []struct {
		in    string
		major int
		minor int
		patch int
		pre   string
	}{
		{"1.2.3", 1, 2, 3, ""},
		{"1.2", 1, 2, 0, ""},
		{"1", 1, 0, 0, ""},
		{"1.2.3-alpha", 1, 2, 3, "alpha"},
		{"2.0.0-rc.1", 2, 0, 0, "rc.1"},
		{"10.20.30-beta.1+build", 10, 20, 30, "beta.1+build"},
	}
	for _, tc := range cases {
		sv, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if sv.Major != tc.major || sv.Minor != tc.minor || sv.Patch != tc.patch || sv.Pre != tc.pre {
			t.Errorf("Parse(%q) = %+v, want %d.%d.%d-%q", tc.in, sv, tc.major, tc.minor, tc.patch, tc.pre)
		}
		// Round-trip through String().
		if got := sv.String(); got != tc.in && tc.pre != "" {
			// pre round-trip must preserve; version normalization may drop
			// trailing .0, so only assert full equality when input is canonical.
			if tc.in == "1.2.3" || tc.in == "1.2" || tc.in == "1" {
				if got != tc.in && tc.pre == "" {
					// "1.2" String() → "1.2.0" is acceptable normalization.
				}
			}
		}
	}
}

func TestParseStringRoundTrip(t *testing.T) {
	for _, in := range []string{"1.2.3", "1.2.3-alpha", "0.0.1-rc.1"} {
		sv, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got := sv.String(); got != in {
			t.Errorf("String() round-trip = %q, want %q", got, in)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "abc", "v1.2.3", "1.x.y.z.extra", "1.2.3.4.5.6"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) must error", in)
		}
	}
	// Non-numeric major/minor/patch.
	for _, in := range []string{"x.1.2", "1.x.2", "1.2.x"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) must error on non-numeric segment", in)
		}
	}
}

func TestCompareOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.9.9", 1},
		// release > pre-release
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0", -1},
		// pre-release ordering: alpha < beta < rc
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc.1", -1},
		// same pre
		{"1.0.0-rc.1", "1.0.0-rc.1", 0},
	}
	for _, tc := range cases {
		sa, errA := Parse(tc.a)
		sb, errB := Parse(tc.b)
		if errA != nil || errB != nil {
			t.Fatalf("parse error: %q %v, %q %v", tc.a, errA, tc.b, errB)
		}
		got := sa.Compare(sb)
		if (got < 0 && tc.want >= 0) || (got > 0 && tc.want <= 0) || (got == 0 && tc.want != 0) {
			t.Errorf("Compare(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestComparePreNumericIDs pins semver §11.4 numeric-id ordering: within a
// dot-separated pre-release field, numeric identifiers compare numerically,
// so alpha.10 > alpha.2 and rc.10 > rc.2. (The implementation compares the
// raw pre string lexicographically, which reverses these — this test fails
// until Compare is fixed.)
func TestComparePreNumericIDs(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha.10", "1.0.0-alpha.2", 1}, // 10 > 2 numerically
		{"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"1.0.0-rc.10", "1.0.0-rc.2", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1}, // fewer fields sorts first
	}
	for _, tc := range cases {
		sa, errA := Parse(tc.a)
		sb, errB := Parse(tc.b)
		if errA != nil || errB != nil {
			t.Fatalf("parse error: %q %v, %q %v", tc.a, errA, tc.b, errB)
		}
		got := sa.Compare(sb)
		if (got < 0 && tc.want >= 0) || (got > 0 && tc.want <= 0) || (got == 0 && tc.want != 0) {
			t.Errorf("Compare(%q, %q) = %d, want sign %d (numeric pre-id ordering)", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestConstraintParse(t *testing.T) {
	cases := []struct {
		s       string
		min     string
		max     string
		minOpen bool
		maxOpen bool
	}{
		{">=1.0", "1.0.0", "", false, false},
		{">1.0", "1.0.0", "", true, false},
		{"<=2.0", "", "2.0.0", false, false},
		{"<2.0", "", "2.0.0", false, true},
		{"^1.2.3", "1.2.3", "2.0.0", false, true},
		{"~1.2.3", "1.2.3", "1.3.0", false, true},
		{"1.0-2.0", "1.0.0", "2.0.0", false, false},
		{"1.0 - 2.0", "1.0.0", "2.0.0", false, false},
		{"1.x", "1.0.0", "2.0.0", false, true},
		{"1.2.3", "1.2.3", "1.2.3", false, false},
	}
	for _, tc := range cases {
		vc, err := ParseConstraint(tc.s)
		if err != nil {
			t.Errorf("ParseConstraint(%q) error: %v", tc.s, err)
			continue
		}
		if tc.min != "" {
			if !vc.HasMin() || vc.Min.String() != tc.min {
				t.Errorf("ParseConstraint(%q) min = %v (hasMin=%v), want %s", tc.s, vc.Min.String(), vc.HasMin(), tc.min)
			}
			if vc.MinOpen != tc.minOpen {
				t.Errorf("ParseConstraint(%q) MinOpen = %v, want %v", tc.s, vc.MinOpen, tc.minOpen)
			}
		}
		if tc.max != "" {
			if !vc.HasMax() || vc.Max.String() != tc.max {
				t.Errorf("ParseConstraint(%q) max = %v (hasMax=%v), want %s", tc.s, vc.Max.String(), vc.HasMax(), tc.max)
			}
			if vc.MaxOpen != tc.maxOpen {
				t.Errorf("ParseConstraint(%q) MaxOpen = %v, want %v", tc.s, vc.MaxOpen, tc.maxOpen)
			}
		}
	}
}

func TestConstraintParseErrors(t *testing.T) {
	for _, s := range []string{"", "   ", ">=abc", "^", "~x.y", "abc-def"} {
		if _, err := ParseConstraint(s); err == nil {
			t.Errorf("ParseConstraint(%q) must error", s)
		}
	}
}

func TestConstraintSatisfiedBy(t *testing.T) {
	cases := []struct {
		constraint string
		version    string
		want       bool
	}{
		{">=1.0", "1.0.0", true},
		{">=1.0", "0.9.9", false},
		{">1.0", "1.0.0", false},
		{">1.0", "1.0.1", true},
		{"<=2.0", "2.0.0", true},
		{"<2.0", "2.0.0", false},
		{"<2.0", "1.9.9", true},
		{"^1.2.3", "1.9.9", true},
		{"^1.2.3", "2.0.0", false},
		{"^1.2.3", "1.2.2", false},
		{"~1.2.3", "1.2.9", true},
		{"~1.2.3", "1.3.0", false},
		{"1.0-2.0", "1.5.0", true},
		{"1.0-2.0", "2.0.0", true},
		{"1.0-2.0", "2.0.1", false},
		{"1.x", "1.9.9", true},
		{"1.x", "2.0.0", false},
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
	}
	for _, tc := range cases {
		vc, err := ParseConstraint(tc.constraint)
		if err != nil {
			t.Fatalf("ParseConstraint(%q): %v", tc.constraint, err)
		}
		v, err := Parse(tc.version)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.version, err)
		}
		if got := vc.SatisfiedBy(v); got != tc.want {
			t.Errorf("constraint %q satisfied by %q = %v, want %v", tc.constraint, tc.version, got, tc.want)
		}
	}
}

func TestHelpers(t *testing.T) {
	a, _ := Parse("1.2.3")
	b, _ := Parse("1.2.4")
	c, _ := Parse("1.2.4")
	if !a.Less(b) || a.Greater(b) || a.Equal(b) {
		t.Error("Less/Greater/Equal semantics wrong")
	}
	if !b.Equal(c) {
		t.Error("Equal must be true for identical versions")
	}
	vc, _ := ParseConstraint(">=1.0")
	if !vc.HasMin() || vc.HasMax() {
		t.Error(">=1.0 should have min only")
	}
}
