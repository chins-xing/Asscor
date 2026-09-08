package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

// userCheckCommandTimeout bounds execution of a user-defined check command.
// User checks run via direct exec of a whitelisted command (no shell), so a
// hard timeout still guards against a hung command stalling checks.
const userCheckCommandTimeout = 30 * time.Second

// userCheckAllowedCommands is the supplemental allowlist for user_check
// commands beyond the common execution whitelist (internal/common/exec.go).
// Only safe, read-only diagnostic commands are allowed: no network egress
// (curl/wget), no file mutation (rm/mv/cp/tee), no recursive shells, no
// interpreters with arbitrary execution (python/perl/node), no privilege
// escalation (sudo). This tightens the `sh -c` execution surface that
// otherwise accepts any command string from configuration.
var userCheckAllowedCommands = map[string]bool{
	"echo": true, "true": true, "false": true, "test": true, "[": true,
	"cat": true, "ls": true, "grep": true, "head": true, "tail": true,
	"cut": true, "wc": true, "date": true, "stat": true, "df": true,
	"free": true, "uptime": true, "hostname": true, "id": true, "whoami": true,
	"basename": true, "dirname": true, "uniq": true, "sort": true, "tr": true,
	"md5sum": true, "sha256sum": true, "pgrep": true, "pidof": true,
	"readlink": true, "du": true, "printenv": true,
	"journalctl": true, "loginctl": true,
}

// isUserCheckCommandAllowed reports whether a user_check command's first
// token is an allowed command: either in the common execution whitelist
// (systemctl/ss/iptables/…, see internal/common/exec.go) or in the
// supplemental read-only diagnostic set above. Path prefixes and quotes are
// stripped before matching.
func isUserCheckCommandAllowed(cmd string) bool {
	first := strings.TrimSpace(cmd)
	if i := strings.IndexAny(first, " \t"); i > 0 {
		first = first[:i]
	}
	first = strings.Trim(first, "'\"")
	first = filepath.Base(first)
	return common.IsCommandAllowed(first) || userCheckAllowedCommands[first]
}

// parseUserCheckCommand splits a user_check command into an executable name
// and argument array WITHOUT invoking a shell: the whole string must be free
// of shell metacharacters (pipes, redirection, command substitution, job
// control), and the first token must be whitelisted. Any shell feature is
// rejected at construction time, closing the sh -c bypass where a whitelisted
// first token was followed by arbitrary shell syntax.
func parseUserCheckCommand(cmd string) (name string, args []string, ok bool) {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" || common.ContainsShellMetachar(trimmed) {
		return "", nil, false
	}
	parts, valid := splitUserCheckArgs(trimmed)
	if !valid || len(parts) == 0 {
		return "", nil, false
	}
	name = filepath.Base(strings.Trim(parts[0], "'\""))
	if !isUserCheckCommandAllowed(name) {
		return "", nil, false
	}
	return name, parts[1:], true
}

// splitUserCheckArgs splits a command string on whitespace, honoring single
// and double quotes. Unbalanced quotes yield ok=false.
func splitUserCheckArgs(s string) (parts []string, ok bool) {
	var cur []rune
	inQuote := false
	var quote rune
	for _, c := range s {
		switch {
		case c == '\'' || c == '"':
			if inQuote {
				if c == quote {
					inQuote = false
				} else {
					cur = append(cur, c)
				}
			} else {
				inQuote = true
				quote = c
			}
		case c == ' ' || c == '\t':
			if inQuote {
				cur = append(cur, c)
			} else if len(cur) > 0 {
				parts = append(parts, string(cur))
				cur = cur[:0]
			}
		default:
			cur = append(cur, c)
		}
	}
	if inQuote {
		return nil, false
	}
	if len(cur) > 0 {
		parts = append(parts, string(cur))
	}
	return parts, true
}

var registered = make(map[string]bool)

// RegisterUserChecks registers user-defined checks from the configuration's
// flattened user_check.* keys into the checks registry. It is a no-op for a
// nil config or when no valid user_check entries exist.
func RegisterUserChecks(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, item := range ParseUserChecks(cfg.AdapterConfig) {
		if registered[item.ID] {
			continue
		}
		checks.Register(item)
		registered[item.ID] = true
	}
}

// ParseUserChecks builds model.CheckItem values from flattened configuration
// keys of the form "user_check.<name>.<field>" (see buildAdapterConfig). It is
// a pure function with no registry side effects, shared by the kernel
// (RegisterUserChecks) and the agent (which appends the items to its checkers).
//
// Supported fields: id, domain, name, description, delta, command,
// output_match, file_path, file_regex. An entry is skipped when it lacks
// id/domain/name or has neither command nor file_path.
//
// Enforced separation from builtin checks:
//   - ID must use the reserved prefix checks.UserCheckIDPrefix ("CU-"); any
//     other prefix is rejected with a warning so a user check can never
//     collide with the compiled-in platform checks (AS-/OT-/RS-/BC-/EF-/KS-…).
//   - Every returned item carries Source=model.CheckSourceUser, letting
//     consumers tell configuration-defined checks apart from builtins.
func ParseUserChecks(adapterConfig map[string]string) []model.CheckItem {
	type entry struct {
		id, domain, name, desc, command, outputMatch, filePath, fileRegex string
		delta                                                             float64
	}
	entries := make(map[string]*entry)

	for k, v := range adapterConfig {
		if !strings.HasPrefix(k, "user_check.") {
			continue
		}
		parts := strings.SplitN(k, ".", 3)
		if len(parts) < 3 {
			continue
		}
		suffix := parts[1]
		field := parts[2]

		e, ok := entries[suffix]
		if !ok {
			e = &entry{}
			entries[suffix] = e
		}

		switch field {
		case "id":
			e.id = v
		case "domain":
			e.domain = v
		case "name":
			e.name = v
		case "description":
			e.desc = v
		case "command":
			e.command = v
		case "output_match":
			e.outputMatch = v
		case "file_path":
			e.filePath = v
		case "file_regex":
			e.fileRegex = v
		case "delta":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				e.delta = f
			}
		}
	}

	var items []model.CheckItem
	for _, e := range entries {
		if e.id == "" || e.domain == "" || e.name == "" {
			continue
		}
		if e.command == "" && e.filePath == "" {
			continue
		}
		if !strings.HasPrefix(e.id, checks.UserCheckIDPrefix) {
			logger.WithComponent("config").Warn("user check ID must use reserved prefix CU-, check skipped",
				"check_id", e.id)
			continue
		}

		item := model.CheckItem{
			ID:          e.id,
			Domain:      e.domain,
			Name:        e.name,
			Description: e.desc,
			Delta:       e.delta,
			Source:      model.CheckSourceUser,
		}

		if e.command != "" {
			// Reject at construction time any command that is not a simple
			// "whitelisted command + args" invocation. Shell features (pipes,
			// redirection, ; && ||, $(), backticks) are not allowed: the check
			// runs via direct exec (no `sh -c`), so a whitelisted first token
			// can never be followed by arbitrary shell syntax.
			name, args, ok := parseUserCheckCommand(e.command)
			if !ok {
				logger.WithComponent("config").Warn("user check command rejected: must be a whitelisted command with no shell metacharacters",
					"check_id", e.id, "command", e.command)
				continue
			}
			cmdName := name
			cmdArgs := args
			fullCmd := e.command
			match := e.outputMatch
			item.Check = func() (bool, string) {
				logger.WithComponent("config").Info("user check command executing",
					"check_id", item.ID, "command", fullCmd)
				ctx, cancel := context.WithTimeout(context.Background(), userCheckCommandTimeout)
				defer cancel()
				out, err := exec.CommandContext(ctx, cmdName, cmdArgs...).CombinedOutput()
				if err != nil {
					if ctx.Err() == context.DeadlineExceeded {
						return false, fmt.Sprintf("command timed out after %s", userCheckCommandTimeout)
					}
					return false, fmt.Sprintf("command failed: %v (output: %s)", err, strings.TrimSpace(string(out)))
				}
				if match != "" {
					if strings.Contains(string(out), match) {
						return true, fmt.Sprintf("output matched: %s", match)
					}
					return false, fmt.Sprintf("output did not contain: %s", match)
				}
				return true, "command succeeded"
			}
		} else if e.filePath != "" {
			path := e.filePath
			reStr := e.fileRegex
			item.Check = func() (bool, string) {
				data, err := os.ReadFile(path)
				if err != nil {
					return false, fmt.Sprintf("cannot read %s: %v", path, err)
				}
				if reStr == "" {
					return true, fmt.Sprintf("file %s exists (%d bytes)", path, len(data))
				}
				re, err := regexp.Compile(reStr)
				if err != nil {
					return false, fmt.Sprintf("invalid regex: %v", err)
				}
				if re.Match(data) {
					return true, fmt.Sprintf("file %s matches pattern", path)
				}
				return false, fmt.Sprintf("file %s does not match pattern", path)
			}
		}

		items = append(items, item)
	}
	return items
}
