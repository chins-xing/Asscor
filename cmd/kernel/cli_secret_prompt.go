package main

import "strings"

// Interactive password prompting (deferred minor #9).
//
// The kernel CLI is a unix-socket client-server: asscor-cli (runCLIClient)
// owns the operator's TTY and encodes whole lines over the socket, and the
// kernel side (internal/cli socket sessions) executes them INSIDE the kernel
// process. The kernel's os.Stdin is the DAEMON's stdin, not the operator's
// terminal, so a handler-side prompt would read the wrong stream (and
// /dev/tty fails for a daemon without a controlling terminal). The only safe
// interactive channel is the CLIENT: it already runs the operator's /dev/tty
// in raw mode with echo suppressed, so a no-echo prompt there is trivial.
//
// These two pure helpers (tag-free so they are testable everywhere) drive the
// prompt: needsSecretPrompt decides which secret options to ask for, and
// spliceSecret injects the answered value back into the command line without
// disturbing the rest of it. The --password/--old/--new options stay
// supported as the scripted/headless channel; the prompt only fires for
// missing or empty values on an interactive TTY.
//
// Decision (recorded in deferred-fix-report.md): mode enter/exit/unlock/
// set-password ALWAYS require their secrets, so an absent flag prompts;
// config-set only needs a password in run mode, which the client cannot know,
// so it prompts ONLY when --password was given but left empty (explicit
// intent) — a default-mode config-set must not trigger an unexpected prompt.

// modeSecretFlags lists the secret options of each password-gated `mode`
// subcommand, in prompt order.
var modeSecretFlags = map[string][]string{
	"enter":        {"password"},
	"exit":         {"password"},
	"unlock":       {"password"},
	"set-password": {"old", "new"},
}

// needsSecretPrompt returns the secret flags of cmd that should be prompted
// for interactively (in prompt order), or nil when the command needs no
// prompt. See the package comment for the per-command rules.
func needsSecretPrompt(cmd string) []string {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return nil
	}
	var flags []string
	switch tokens[0] {
	case "mode":
		if len(tokens) < 2 {
			return nil
		}
		flags = modeSecretFlags[tokens[1]]
	case "config-set":
		// Conservative: only when the operator explicitly left --password
		// empty (typed `--password` or `--password=`), never when absent.
		flags = []string{"password"}
	default:
		return nil
	}
	if len(flags) == 0 {
		return nil
	}

	hasValue := map[string]bool{}
	seen := map[string]bool{}
	sub := tokens[1:]
	for i, tok := range sub {
		for _, f := range flags {
			marker := "--" + f
			switch {
			case tok == marker:
				// Bare flag: the value is the next token when it does not
				// start with '-'; otherwise the flag is empty.
				seen[f] = true
				if i+1 < len(sub) && !strings.HasPrefix(sub[i+1], "-") {
					hasValue[f] = true
				}
			case strings.HasPrefix(tok, marker+"="):
				seen[f] = true
				if v := strings.TrimPrefix(tok, marker+"="); v != "" {
					hasValue[f] = true
				}
			}
		}
	}

	var need []string
	for _, f := range flags {
		if seen[f] && hasValue[f] {
			continue // value provided inline (scripted channel)
		}
		if !seen[f] && tokens[0] == "config-set" {
			continue // config-set prompts only on explicit empty --password
		}
		need = append(need, f)
	}
	return need
}

// spliceSecret injects --flag=<value> into a command line: the flag is either
// absent (append at the end), present as bare `--flag` (insert `=<value>`
// right after it), or present as empty `--flag=` (replace the empty value up
// to the next whitespace). Everything else — quoting and spacing of unrelated
// arguments — is preserved byte-for-byte.
func spliceSecret(cmd, flag, value string) string {
	eq := "--" + flag + "="
	if i := strings.Index(cmd, eq); i >= 0 {
		j := i + len(eq)
		for j < len(cmd) && cmd[j] != ' ' && cmd[j] != '\t' {
			j++
		}
		return cmd[:i+len(eq)] + value + cmd[j:]
	}
	bare := "--" + flag
	if i := strings.Index(cmd, bare); i >= 0 {
		after := i + len(bare)
		if after == len(cmd) || cmd[after] == ' ' || cmd[after] == '\t' {
			return cmd[:after] + "=" + value + cmd[after:]
		}
	}
	if strings.TrimSpace(cmd) == "" {
		return "--" + flag + "=" + value
	}
	return cmd + " --" + flag + "=" + value
}

// secretPromptLabel returns the human prompt label for a secret option.
func secretPromptLabel(flag string) string {
	switch flag {
	case "password":
		return "Password"
	case "old":
		return "Current password"
	case "new":
		return "New password"
	}
	return flag
}
