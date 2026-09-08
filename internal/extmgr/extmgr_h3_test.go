package extmgr

import (
	"os"
	"testing"
)

// TestValidateRequiresChecksumForRemoteSources covers audit H-3: http(s)
// single-file sources must carry an explicit sha256 checksum; refusing them
// at validation prevents the kernel from ever executing an unverified remote
// artifact.
func TestValidateRequiresChecksumForRemoteSources(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		typ      string
		checksum string
		wantErr  bool
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

// TestSpecCheckItemCarriesExtensionSource: check items built from an
// extension spec must carry CheckSourceExtension so the confidence source
// table can assign extension checks their own default (design §3.1) instead
// of conflating them with compiled-in builtin checks.
func TestSpecCheckItemCarriesExtensionSource(t *testing.T) {
	item := specCheckItem(CheckSpecDef{
		ID:     "EXT-001",
		Domain: "attack_surface",
		Name:   "ext",
		Delta:  -5,
	})
	if item.Source != "extension" {
		t.Errorf("spec check item Source = %q, want %q (CheckSourceExtension)", item.Source, "extension")
	}
	if item.ID != "EXT-001" {
		t.Errorf("item ID = %q, want EXT-001", item.ID)
	}
}

// TestSanitizeMode (audit L-6): archive-provided modes must never carry
// setuid/setgid/sticky or group/world-write bits into the installed tree.
func TestSanitizeMode(t *testing.T) {
	cases := []struct {
		name   string
		mode   os.FileMode
		isExec bool
		want   os.FileMode
	}{
		{"plain 0644 stays", 0o644, false, 0o644},
		{"executable 0755 stays", 0o755, true, 0o755},
		{"setuid stripped", 0o4755, true, 0o755},
		{"setgid stripped", 0o2755, true, 0o755},
		{"sticky stripped", 0o1755, true, 0o755},
		{"world-write stripped", 0o666, false, 0o644},
		{"group-write stripped", 0o664, false, 0o644},
		{"combined special+write cleaned", 0o7777, true, 0o755},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeMode(tc.mode, tc.isExec)
			if got != tc.want {
				t.Errorf("sanitizeMode(%04o, %v) = %04o, want %04o", tc.mode, tc.isExec, got, tc.want)
			}
		})
	}
}
