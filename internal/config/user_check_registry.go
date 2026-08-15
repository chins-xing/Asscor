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
// User checks run through the shell (`sh -c`) to support pipes/globs, so a
// hard timeout is mandatory to prevent a hung command from stalling checks.
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
	"readlink": true, "du": true, "find": true, "env": true, "printenv": true,
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
			// Tighten the sh -c surface: reject commands whose first token is
			// not in the combined allowlist at construction time, so a bad
			// configuration is surfaced immediately instead of failing at
			// check execution (or worse, executing an arbitrary command).
			if !isUserCheckCommandAllowed(e.command) {
				logger.WithComponent("config").Warn("user check command rejected: first token not in allowlist",
					"check_id", e.id, "command", e.command)
				continue
			}
			cmd := e.command
			match := e.outputMatch
			item.Check = func() (bool, string) {
				logger.WithComponent("config").Info("user check command executing",
					"check_id", item.ID, "command", cmd)
				ctx, cancel := context.WithTimeout(context.Background(), userCheckCommandTimeout)
				defer cancel()
				out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
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
