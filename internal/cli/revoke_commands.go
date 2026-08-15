package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// certCmdInfo manages certificate revocations (audit I-03): revoke a
// compromised certificate fingerprint, list revocations, and restore a
// mistakenly revoked one.
var certCmdInfo = CommandInfo{
	Name:         "cert",
	Short:        "Manage certificate revocations",
	Description:  "Revoke compromised certificate fingerprints, list revocations, and restore mistakenly revoked certificates (audit I-03)",
	Usage:        "cert <revoke|unrevoke|revocations> <fingerprint> [--reason ...]",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: revoke, unrevoke, revocations", Required: true, EnumValues: []string{"revoke", "unrevoke", "revocations"}},
		{Name: "fingerprint", Description: "SHA-256 fingerprint of the certificate (hex, no colons)", Required: false},
	},
	Options: []CommandOption{
		{Name: "reason", Short: "r", Description: "Why the certificate is being revoked (e.g. compromised)"},
	},
	Examples: []string{
		"cert revoke 8936cf10c6354dfa529ab2f3a6160cc98f4860e541a94dfcf2b0afc978be269e --reason=compromised",
		"cert revocations",
		"cert unrevoke 8936cf10c6354dfa529ab2f3a6160cc98f4860e541a94dfcf2b0afc978be269e",
	},
}

func certCmdHandler(ctx *CommandContext) *CommandResult {
	if len(ctx.Args) == 0 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("cert: action required"),
			Output:   formatHelp(certCmdInfo),
		}
	}

	action := ctx.Args[0]
	revocations := ctx.Kernel.Revocations()

	switch action {
	case "revoke":
		if !ctx.Kernel.CheckPermission(PermAdmin) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: cert revoke requires admin level access"), Output: "Permission denied: cert revoke requires admin level access\n"}
		}
		return certRevokeHandler(ctx, revocations)
	case "unrevoke":
		if !ctx.Kernel.CheckPermission(PermAdmin) {
			return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("permission denied: cert unrevoke requires admin level access"), Output: "Permission denied: cert unrevoke requires admin level access\n"}
		}
		return certUnrevokeHandler(ctx, revocations)
	case "revocations":
		return certListHandler(ctx, revocations)
	default:
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("unknown cert action: %s", action),
			Output:   fmt.Sprintf("Unknown action '%s'. Use: revoke, unrevoke, revocations\n", action),
		}
	}
}

func certCompletions(ctx *CommandContext, partial string) []string {
	return []string{"revoke", "unrevoke", "revocations"}
}

// normalizeFingerprint strips colons/whitespace and lowercases, so the
// openssl "AA:BB:..." output can be pasted directly.
func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f', ch >= 'A' && ch <= 'F':
			b.WriteRune(ch)
		}
	}
	return strings.ToLower(b.String())
}

func certRevokeHandler(ctx *CommandContext, revocations RevocationAccess) *CommandResult {
	fp := ""
	if len(ctx.Args) > 1 {
		fp = normalizeFingerprint(ctx.Args[1])
	}
	if fp == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("cert revoke: fingerprint required"),
			Output:   "Usage: cert revoke <fingerprint> [--reason <text>]\n  Fingerprint: SHA-256 hex (colons optional), e.g. from 'openssl x509 -noout -fingerprint -sha256'\n",
		}
	}
	if len(fp) != 64 {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("cert revoke: invalid fingerprint length %d (expected 64 hex chars)", len(fp)),
			Output:   fmt.Sprintf("Invalid fingerprint: %q — expected a 64-character SHA-256 hex digest.\n", fp),
		}
	}

	reason, _ := ctx.Options["reason"]
	if err := revocations.Revoke(fp, reason); err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Revocation failed: %v\n", err),
		}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"fingerprint": fp,
			"reason":      reason,
			"status":      "revoked",
		}, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Certificate revoked: %s\n", fp))
	if reason != "" {
		b.WriteString(fmt.Sprintf("  Reason:             %s\n", reason))
	}
	b.WriteString("  The fingerprint is now rejected at registration, heartbeat, and command execution.\n")
	b.WriteString("  Any host previously bound to it must re-register with a freshly issued certificate.\n\n")
	return &CommandResult{ExitCode: ExitOK, Output: b.String()}
}

func certUnrevokeHandler(ctx *CommandContext, revocations RevocationAccess) *CommandResult {
	fp := ""
	if len(ctx.Args) > 1 {
		fp = normalizeFingerprint(ctx.Args[1])
	}
	if fp == "" {
		return &CommandResult{
			ExitCode: ExitUsage,
			Err:      fmt.Errorf("cert unrevoke: fingerprint required"),
			Output:   "Usage: cert unrevoke <fingerprint>\n",
		}
	}

	if err := revocations.Unrevoke(fp); err != nil {
		return &CommandResult{
			ExitCode: ExitError,
			Err:      err,
			Output:   fmt.Sprintf("Unrevoke failed: %v\n", err),
		}
	}

	if ctx.JSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"fingerprint": fp,
			"status":      "unrevoked",
		}, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n"}
	}

	return &CommandResult{
		ExitCode: ExitOK,
		Output:   fmt.Sprintf("Certificate %s is no longer revoked.\n", fp),
	}
}

func certListHandler(ctx *CommandContext, revocations RevocationAccess) *CommandResult {
	list := revocations.ListRevoked()

	if ctx.JSON {
		data, _ := json.MarshalIndent(list, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(data) + "\n", Data: list}
	}

	var b strings.Builder
	b.WriteString("\n  Revoked Certificates\n")
	b.WriteString("  ──────────────────────────────────────────────────────────────────────\n")
	if len(list) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, rc := range list {
			b.WriteString(fmt.Sprintf("  %s\n", rc.Fingerprint))
			meta := rc.RevokedAt.Format(time.RFC3339)
			if rc.Reason != "" {
				meta += "  — " + rc.Reason
			}
			b.WriteString(fmt.Sprintf("    revoked %s\n", meta))
		}
	}
	b.WriteString(fmt.Sprintf("\n  Total: %d revoked\n\n", len(list)))
	return &CommandResult{ExitCode: ExitOK, Output: b.String(), Data: list}
}
