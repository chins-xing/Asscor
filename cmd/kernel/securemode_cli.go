package main

import (
	"fmt"

	"github.com/asscor/asscor/internal/cli"
	"github.com/asscor/asscor/internal/securemode"
)

// registerSecureModeCLI wires the mode/config-set handlers into the kernel
// CLI. Safe to call with a nil cliModule or nil mcli (no-op). When the CLI
// module is disabled (cli.enabled=off) its engine is never created, so the
// registration is skipped — a headless kernel is not a startup error.
//
// The handlers forward to ModeCLI's exported methods only (no internal/cli
// import of internal/securemode; no import cycle). Command parsing follows
// the existing CLI convention: positional args in ctx.Args, long options in
// ctx.Options (--key=value or --key value), boolean switches in ctx.Flags.
func registerSecureModeCLI(cliModule *cli.CLIModule, mcli *securemode.ModeCLI) error {
	if cliModule == nil || mcli == nil {
		return nil
	}
	if cliModule.Engine() == nil {
		// CLI unavailable (disabled or not yet initialized) — nothing to
		// register; the kernel can run headless without mode commands.
		return nil
	}

	modeCmd := cli.NewBaseCommand(cli.CommandInfo{
		Name:        "mode",
		Short:       "Secure mode control",
		Description: "Secure mode control (status/enter/exit/unlock/set-password/agent)",
		Usage:       "mode <status|enter|exit|unlock|set-password|agent> [options]",
		Category:    cli.CategorySystem,
		Params: []cli.CommandParam{
			{Name: "subcommand", Description: "status, enter, exit, unlock, set-password, agent", Required: true},
		},
		Options: []cli.CommandOption{
			{Name: "password", Description: "Run-mode password (required for enter/exit/unlock)"},
			{Name: "old", Description: "Current password (set-password)"},
			{Name: "new", Description: "New password (set-password)"},
		},
		Examples: []string{
			"mode status",
			"mode enter --password=secret",
			"mode exit --password=secret",
			"mode unlock --password=secret",
			"mode set-password --old=secret --new=newsecret",
			"mode agent web01 status",
			"mode agent web01 exit",
		},
	}, func(ctx *cli.CommandContext) *cli.CommandResult {
		if len(ctx.Args) == 0 {
			return &cli.CommandResult{
				ExitCode: cli.ExitUsage,
				Err:      fmt.Errorf("mode: subcommand required"),
				Output:   "Usage: mode <status|enter|exit|unlock|set-password|agent>\n",
			}
		}
		out, err := mcli.HandleMode(ctx.Args[0], ctx.Args[1:], ctx.Options)
		if err != nil {
			return &cli.CommandResult{ExitCode: cli.ExitError, Err: err, Output: err.Error() + "\n"}
		}
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: out}
	}).WithCompletions(func(ctx *cli.CommandContext, partial string) []string {
		return []string{"status", "enter", "exit", "unlock", "set-password", "agent"}
	})

	if err := cliModule.RegisterCommand(modeCmd); err != nil {
		return fmt.Errorf("register mode command: %w", err)
	}

	// config-set is a standalone mutation command. The builtin `config`
	// command stays a read-only view (internal/cli untouched), so the
	// securemode wiring adds no behavior to off (no-tag) builds and cannot
	// shadow the existing key-lookup semantics of `config <key>`.
	configSetCmd := cli.NewBaseCommand(cli.CommandInfo{
		Name:        "config-set",
		Short:       "Set a configuration value",
		Description: "Update a configuration value: --temp applies it to the in-memory config immediately (run mode), --persist writes it to disk in the current mode's format (takes effect after 'config reload')",
		Usage:       "config-set <key> <value> [--temp|--persist] [--password <pw>]",
		Category:    cli.CategorySystem,
		Params: []cli.CommandParam{
			{Name: "key", Description: "Configuration key (dot-separated path)", Required: true},
			{Name: "value", Description: "New value", Required: true},
		},
		Options: []cli.CommandOption{
			{Name: "password", Description: "Run-mode password (required when in run mode)"},
			{Name: "temp", Description: "Apply to in-memory config only (default)", IsBool: true},
			{Name: "persist", Description: "Write to disk in the current mode's format", IsBool: true},
		},
		Examples: []string{
			"config-set threshold 80 --persist",
			"config-set interceptor.rate_limit_per_sec 100 --temp",
		},
	}, func(ctx *cli.CommandContext) *cli.CommandResult {
		// --persist / --temp may arrive as a bare switch (Flags) or as
		// --key=true (Options); normalize both into HandleConfigSet's
		// string flags contract.
		flags := make(map[string]string)
		if ctx.Flags["persist"] || ctx.Options["persist"] == "true" || ctx.Options["persist"] == "1" {
			flags["persist"] = "true"
		}
		if ctx.Flags["temp"] || ctx.Options["temp"] == "true" || ctx.Options["temp"] == "1" {
			flags["temp"] = "true"
		}
		if pw := ctx.Options["password"]; pw != "" {
			flags["password"] = pw
		}
		out, err := mcli.HandleConfigSet(ctx.Args, flags)
		if err != nil {
			return &cli.CommandResult{ExitCode: cli.ExitError, Err: err, Output: err.Error() + "\n"}
		}
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: out}
	})

	if err := cliModule.RegisterCommand(configSetCmd); err != nil {
		return fmt.Errorf("register config-set command: %w", err)
	}
	return nil
}
