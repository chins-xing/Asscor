package config

import (
	"os"
	"path/filepath"
	"testing"
)

const netboxSection = `
[netbox]
api_url = https://netbox.internal
api_token = ${NETBOX_TOKEN}
`

// TestAdapterSecretEnvOverride: the documented environment variable
// (NETBOX_TOKEN) overrides the adapter config value, matching the SPC/CTI
// env-priority mechanism (audit I-04/I-05).
func TestAdapterSecretEnvOverride(t *testing.T) {
	t.Setenv("NETBOX_TOKEN", "env-token-value")
	cfg, err := Parse(netboxSection)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["netbox.api_token"]; got != "env-token-value" {
		t.Errorf("netbox.api_token = %q, want env-token-value", got)
	}
	// Non-secret keys are untouched.
	if got := cfg.AdapterConfig["netbox.api_url"]; got != "https://netbox.internal" {
		t.Errorf("netbox.api_url = %q", got)
	}
}

// TestAdapterSecretPlaceholderExpansion: ${NETBOX_TOKEN} in the config value
// expands from the environment even without the override pass (the documented
// behavior that was previously unimplemented).
func TestAdapterSecretPlaceholderExpansion(t *testing.T) {
	t.Setenv("NETBOX_TOKEN", "placeholder-expanded")
	cfg, err := Parse(netboxSection)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["netbox.api_token"]; got != "placeholder-expanded" {
		t.Errorf("netbox.api_token = %q, want placeholder-expanded", got)
	}
}

// TestAdapterSecretPlaceholderUnresolvedStaysVisible: with no env var, the
// unresolved placeholder stays in the config value (visible misconfiguration)
// instead of silently becoming empty.
func TestAdapterSecretPlaceholderUnresolvedStaysVisible(t *testing.T) {
	os.Unsetenv("NETBOX_TOKEN")
	cfg, err := Parse(netboxSection)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["netbox.api_token"]; got != "${NETBOX_TOKEN}" {
		t.Errorf("netbox.api_token = %q, want ${NETBOX_TOKEN} kept visible", got)
	}
}

// TestAdapterSecretConventionEnvName: a secret key without a documented alias
// uses the conventional <KEY>_upper env name (e.g. TRIVY_API_TOKEN).
func TestAdapterSecretConventionEnvName(t *testing.T) {
	t.Setenv("TRIVY_API_TOKEN", "convention-token")
	cfg, err := Parse(`
[trivy]
api_token = literal
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["trivy.api_token"]; got != "convention-token" {
		t.Errorf("trivy.api_token = %q, want convention-token", got)
	}
}

// TestAdapterSecretFile: a secret file referenced by <key>_file in the config
// is read (docker-secrets style); env still wins over it.
func TestAdapterSecretFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "netbox_token")
	if err := os.WriteFile(secretPath, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("NETBOX_TOKEN")
	os.Unsetenv("NETBOX_TOKEN_FILE")

	cfg, err := Parse(netboxSection + "\napi_token_file = " + secretPath + "\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["netbox.api_token"]; got != "file-token" {
		t.Errorf("netbox.api_token = %q, want file-token", got)
	}

	// env wins over the file.
	t.Setenv("NETBOX_TOKEN", "env-wins")
	cfg2, err := Parse(netboxSection + "\napi_token_file = " + secretPath + "\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg2.AdapterConfig["netbox.api_token"]; got != "env-wins" {
		t.Errorf("netbox.api_token = %q, want env-wins", got)
	}
}

// TestSPCSecretUsesUnifiedResolution: SPC module keys resolve through the
// same env-priority path (and gain _FILE support).
func TestSPCSecretUsesUnifiedResolution(t *testing.T) {
	t.Setenv("NVD_API_KEY", "nvd-env-key")
	cfg, err := Parse(`
[spc.nvd]
base_url = https://nvd.example
api_key = cfg-key
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SPC.NVD.APIKey != "nvd-env-key" {
		t.Errorf("SPC.NVD.APIKey = %q, want nvd-env-key", cfg.SPC.NVD.APIKey)
	}
}

// TestNonSecretPlaceholderExpansion: ${VAR} placeholders also expand in
// non-secret adapter values (e.g. api_url).
func TestNonSecretPlaceholderExpansion(t *testing.T) {
	t.Setenv("NETBOX_URL", "https://netbox.example")
	cfg, err := Parse(`
[netbox]
api_url = ${NETBOX_URL}
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.AdapterConfig["netbox.api_url"]; got != "https://netbox.example" {
		t.Errorf("netbox.api_url = %q, want https://netbox.example", got)
	}
}
