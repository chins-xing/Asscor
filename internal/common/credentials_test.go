package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandEnv: ${VAR} placeholders expand from the environment; unresolved
// placeholders stay visible; non-identifier content passes through.
func TestExpandEnv(t *testing.T) {
	t.Setenv("TEST_CRED", "secret-value")

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"expand", "${TEST_CRED}", "secret-value"},
		{"expand-inline", "tok=${TEST_CRED}!", "tok=secret-value!"},
		{"unresolved-kept", "${NO_SUCH_VAR_XYZ}", "${NO_SUCH_VAR_XYZ}"},
		{"mixed", "a=${TEST_CRED}-${NO_SUCH_VAR_XYZ}", "a=secret-value-${NO_SUCH_VAR_XYZ}"},
		{"non-identifier", "${not a var}", "${not a var}"},
		{"empty-name", "${}", "${}"},
		{"unterminated", "a${B", "a${B"},
	}
	for _, c := range cases {
		if got := ExpandEnv(c.in); got != c.want {
			t.Errorf("%s: ExpandEnv(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestResolveCredentialPriority: env beats file beats config.
func TestResolveCredentialPriority(t *testing.T) {
	t.Setenv("PRIO_TOKEN", "from-env")
	dir := t.TempDir()
	filePath := filepath.Join(dir, "token")
	if err := os.WriteFile(filePath, []byte("from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRIO_TOKEN_FILE", filePath)

	// env wins over both file and config.
	if v, src := ResolveCredential("PRIO_TOKEN", "from-config", filePath); v != "from-env" || src != CredFromEnv {
		t.Errorf("env priority failed: v=%q src=%s", v, src)
	}
	// file wins over config when env unset.
	t.Setenv("PRIO_TOKEN", "")
	os.Unsetenv("PRIO_TOKEN")
	t.Setenv("PRIO_TOKEN_FILE", filePath)
	if v, src := ResolveCredential("PRIO_TOKEN", "from-config", ""); v != "from-file" || src != CredFromFile {
		t.Errorf("file priority failed: v=%q src=%s", v, src)
	}
	// config fallback when env and file are both unset.
	os.Unsetenv("PRIO_TOKEN_FILE")
	if v, src := ResolveCredential("PRIO_TOKEN", "from-config", ""); v != "from-config" || src != CredFromConfig {
		t.Errorf("config fallback failed: v=%q src=%s", v, src)
	}
	// config fileConfig path used when env _FILE unset.
	t.Setenv("PRIO_TOKEN_FILE", "")
	if v, src := ResolveCredential("PRIO_TOKEN", "from-config", filePath); v != "from-file" || src != CredFromFile {
		t.Errorf("config file path failed: v=%q src=%s", v, src)
	}
}

// TestResolveCredentialConfigPlaceholder: config values with ${VAR} expand.
func TestResolveCredentialConfigPlaceholder(t *testing.T) {
	t.Setenv("TEST_PLACEHOLDER", "expanded")
	if v, src := ResolveCredential("UNRELATED_ENV", "${TEST_PLACEHOLDER}", ""); v != "expanded" || src != CredFromConfig {
		t.Errorf("placeholder expansion failed: v=%q src=%s", v, src)
	}
}

// TestResolveCredentialUnreadableFile: an unreadable/missing secret file
// falls back to the config value (and warns) instead of failing hard.
func TestResolveCredentialUnreadableFile(t *testing.T) {
	t.Setenv("FALLBACK_TOKEN", "")
	os.Unsetenv("FALLBACK_TOKEN")
	t.Setenv("FALLBACK_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if v, src := ResolveCredential("FALLBACK_TOKEN", "cfg-token", ""); v != "cfg-token" || src != CredFromConfig {
		t.Errorf("unreadable file must fall back to config: v=%q src=%s", v, src)
	}
}

// TestResolveCredentialEmptyFile: an empty secret file falls back to config.
func TestResolveCredentialEmptyFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("EMPTY_TOKEN")
	t.Setenv("EMPTY_TOKEN_FILE", empty)
	if v, _ := ResolveCredential("EMPTY_TOKEN", "cfg-token", ""); v != "cfg-token" {
		t.Errorf("empty file must fall back to config, got %q", v)
	}
}

// TestIsSecretKey: only credential-carrying keys match.
func TestIsSecretKey(t *testing.T) {
	secrets := []string{"netbox.api_token", "snipe_it.api_token", "wazuh_siem.password", "spc.nvd.api_key", "client_secret", "db.credential"}
	for _, k := range secrets {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false, want true", k)
		}
	}
	plain := []string{"netbox.api_url", "wazuh_siem.username", "jira.url", "trivy.target_images"}
	for _, k := range plain {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true, want false", k)
		}
	}
}

// TestSecretEnvName: convention derivation.
func TestSecretEnvName(t *testing.T) {
	cases := map[string]string{
		"netbox.api_token":   "NETBOX_API_TOKEN",
		"snipe_it.api_token": "SNIPE_IT_API_TOKEN",
		"wazuh.password":     "WAZUH_PASSWORD",
		"key":                "KEY",
	}
	for in, want := range cases {
		if got := SecretEnvName(in); got != want {
			t.Errorf("SecretEnvName(%q) = %q, want %q", in, got, want)
		}
	}
	if !strings.Contains(SecretEnvName("a.b-c d"), "_") {
		t.Error("separators must become underscores")
	}
}
