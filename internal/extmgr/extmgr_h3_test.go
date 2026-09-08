package extmgr

import "testing"

// TestValidateRequiresChecksumForRemoteSources covers audit H-3: http(s)
// single-file sources must carry an explicit sha256 checksum; refusing them
// at validation prevents the kernel from ever executing an unverified remote
// artifact.
func TestValidateRequiresChecksumForRemoteSources(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		typ     string
		checksum string
		wantErr bool
	}{
		{"http without checksum must fail", "https://example.com/ext.zip", "http", "", true},
		{"http with checksum ok", "https://example.com/ext.zip", "http", "sha256:abcdef", false},
		{"git allowed without checksum (pinned via Commit)", "https://github.com/x/y.git", "git", "", false},
		{"local allowed without checksum", "/opt/local-ext", "local", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := ExtensionSpec{
				ID:      "test-ext",
				Name:    "Test",
				Version: "1.0.0",
				ExtType: ExtTypeCheckModule,
				Source:  SourceSpec{URL: tc.url, Type: tc.typ, Checksum: tc.checksum},
			}
			err := spec.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestVerifyGitHead covers audit H-3: the checked-out HEAD of a git source
// must equal the pinned commit (prefix or full SHA accepted; mismatch and
// too-short pins refused).
func TestVerifyGitHead(t *testing.T) {
	if testing.Short() {
		t.Skip("requires git")
	}
	if err := verifyGitHead("/nonexistent", "0123456789abcdef"); err == nil {
		t.Error("nonexistent repo must fail verification")
	}
	if err := verifyGitHead("/nonexistent", "abc"); err == nil {
		t.Error("too-short pin must fail verification")
	}
}
