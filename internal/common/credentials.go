package common

import (
	"os"
	"strings"

	"github.com/asscor/asscor/internal/logger"
)

// CredentialSource describes where a resolved credential came from.
type CredentialSource string

const (
	CredFromEnv    CredentialSource = "env"    // environment variable
	CredFromFile   CredentialSource = "file"   // secret file (env <NAME>_FILE or config <key>_file)
	CredFromConfig CredentialSource = "config" // config value (with ${VAR} placeholders expanded)
)

// ExpandEnv expands ${VAR} placeholders in s from the process environment.
// A placeholder whose variable is unset or empty is left as-is and a warning
// is logged, so a misconfigured secret stays visibly unresolved instead of
// silently sending an empty credential. Non-identifier content inside ${...}
// is passed through untouched.
func ExpandEnv(s string) string {
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		tail := rest[i+2:]
		j := strings.Index(tail, "}")
		if j < 0 {
			b.WriteString(rest[i:])
			break
		}
		name := tail[:j]
		if !isEnvName(name) {
			// Not a ${IDENTIFIER} pattern — keep literally.
			b.WriteString("${")
			b.WriteString(tail)
			break
		}
		if v, ok := os.LookupEnv(name); ok && v != "" {
			b.WriteString(v)
		} else {
			// Keep the unresolved placeholder visible; warn once per call.
			b.WriteString("${" + name + "}")
			logger.WithComponent("common").Warn("credential placeholder unresolved", "var", name)
		}
		rest = tail[j+1:]
	}
	return b.String()
}

func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '_':
		default:
			return false
		}
	}
	return true
}

// ResolveCredential resolves a credential with the unified priority used
// across SPC/CTI/adapters (audit I-04/I-05):
//
//	1. the environment variable envName, when set and non-empty;
//	2. a secret file — the env var envName+"_FILE" or, when fileConfig is
//	   non-empty, that config-provided path; the file's trimmed content is
//	   used (a missing/empty/unreadable file falls through with a warning);
//	3. configValue, with ${VAR} placeholders expanded.
//
// It returns the resolved value and its source so callers can emit audit
// logs in their own component/format.
func ResolveCredential(envName, configValue, fileConfig string) (string, CredentialSource) {
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return v, CredFromEnv
		}
	}

	filePath := ""
	if envName != "" {
		filePath = os.Getenv(envName + "_FILE")
	}
	if filePath == "" {
		filePath = fileConfig
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.WithComponent("common").Warn("credential secret file unreadable, falling back",
				"var", envName, "path", filePath, "error", err)
		} else if v := strings.TrimSpace(string(data)); v != "" {
			return v, CredFromFile
		} else {
			logger.WithComponent("common").Warn("credential secret file empty, falling back",
				"var", envName, "path", filePath)
		}
	}

	return ExpandEnv(configValue), CredFromConfig
}

// IsSecretKey reports whether a config key carries a credential (token,
// password, API key, secret...). Only such keys participate in the
// environment-override pass; non-secret values never read from env.
func IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, marker := range []string{"token", "password", "api_key", "secret", "credential"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

// SecretEnvName derives the conventional environment variable name for a
// config key: "netbox.api_token" → "NETBOX_API_TOKEN" (dots, dashes and
// spaces become underscores).
func SecretEnvName(key string) string {
	var b strings.Builder
	for _, ch := range key {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch - 'a' + 'A')
		case ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
