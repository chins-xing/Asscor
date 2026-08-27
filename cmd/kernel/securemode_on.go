//go:build securemode

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/securemode"
)

// initSecureMode assembles the kernel-side secure-mode controller. The
// config.ini path comes from the kernel's resolved -config flag; the
// bootstrap section stays plaintext for connectivity essentials.
func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error) {
	if dataDir == "" {
		dataDir = "/var/lib/asscor"
	}
	vault := &securemode.Vault{
		DataDir:         dataDir,
		ConfigPath:      configPath,
		BootstrapHeader: "[bootstrap]",
	}
	ctrl := securemode.NewController(dataDir, []*securemode.Vault{vault})
	if err := ctrl.Startup(); err != nil {
		return nil, fmt.Errorf("secure mode startup: %w", err)
	}
	if ctrl.Mode == securemode.ModeRun {
		// I-1 (final review): run-mode restart. The plaintext config was
		// encrypted at shutdown, so config.Load above fell back to defaults —
		// the kernel is serving on DEFAULT configuration until the operator
		// unlocks. We deliberately do NOT block serving (an unattended start
		// without the password must still come up; a blocked boot would strand
		// a headless/无人值守 deployment), but the operator must see a loud,
		// unambiguous notice. `mode unlock --password <pw>` loads the protected
		// config into the memory guard AND feeds it back into the kernel
		// runtime (wireSecureModeConfigApply), closing the I-1 gap.
		logger.WithComponent("kernel").Warn("kernel is in run mode — config.ini is encrypted; run 'mode unlock --password <pw>' to load the protected config into the kernel runtime",
			"config_path", configPath)
		fmt.Fprintf(os.Stderr, "\nWARN: run mode active — %s is encrypted (.enc).\n", configPath)
		fmt.Fprintf(os.Stderr, "      The kernel is running on DEFAULT config until you run:\n")
		fmt.Fprintf(os.Stderr, "        mode unlock --password <pw>\n")
		fmt.Fprintf(os.Stderr, "      (protected settings — weights, threshold, interceptor/user_check/check_deltas,\n")
		fmt.Fprintf(os.Stderr, "       exclude_cidrs, anti_debug — stay inactive until unlocked.)\n\n")
	}
	return ctrl, nil
}

// loadKernelConfigFromSecureMode is the config-watcher reload source for run
// mode (I-1): instead of config.Load on the missing plaintext, it parses the
// controller's decrypted in-memory guard (the protected config the operator
// unlocked). In default mode it falls back to config.Load(path) — the loader
// is installed whenever the securemode tag is on, regardless of the current
// mode. In run mode BEFORE unlock the reload refuses with a clear error (the
// watcher's fail-safe: the in-memory kernel config is never overwritten by a
// failed reload).
func loadKernelConfigFromSecureMode(ctrl *securemode.Controller, path string) (*config.Config, error) {
	ctrl.Mu.RLock()
	mode := ctrl.Mode
	guard := ctrl.Guard
	ctrl.Mu.RUnlock()
	if mode == securemode.ModeRun {
		if guard == nil {
			return nil, errors.New("run mode config not unlocked yet — run 'mode unlock --password <pw>' first")
		}
		if !guard.IntegrityOK() {
			return nil, errors.New("run mode in-memory config integrity check failed — reload refused (fail-safe)")
		}
		cfg, err := config.Parse(string(guard.Snapshot()))
		if err != nil {
			return nil, fmt.Errorf("parse run-mode config: %w", err)
		}
		return cfg, nil
	}
	return config.Load(path)
}

// newSecureModeConfigReloader builds the OnConfigChanged hook wired into the
// secure-mode CLI (I-1): after `mode unlock` or `config-set`, feed the
// run-mode config back into the kernel runtime — SetConfigObj + (optional)
// assessor.ReloadConfig + the config.reloaded bus event — mirroring the
// config watcher's reload chain and the agent-side reloadProtectedConfig.
// immediate=true applies now (unlock / config-set --temp, spec §9);
// immediate=false is a no-op (config-set --persist applies only on 'config
// reload', which re-invokes this via the watcher's loader).
func newSecureModeConfigReloader(k *kernel.Kernel, assessor kernel.AssessorInterface) func(plain string, immediate bool) error {
	return func(plain string, immediate bool) error {
		if !immediate {
			return nil
		}
		if plain == "" {
			return errors.New("empty run-mode config")
		}
		cfg, err := config.Parse(plain)
		if err != nil {
			return fmt.Errorf("parse run-mode config: %w", err)
		}
		k.SetConfigObj(cfg)
		if assessor != nil {
			assessor.ReloadConfig(cfg)
		}
		k.Bus().Publish(k.Context(), kernel.Message{
			Topic:   kernel.TopicConfigReloaded,
			Payload: map[string]interface{}{"path": "(secure-mode guard)"},
			Source:  "securemode",
		})
		logger.WithComponent("kernel").Info("run-mode config applied to kernel runtime",
			"threshold", cfg.Threshold, "user_checks", len(config.ParseUserChecks(cfg.AdapterConfig)))
		return nil
	}
}

// wireSecureModeConfigLoader makes `config reload` (SIGHUP and the polling
// watcher) run-mode aware (I-1): the reload source becomes the controller's
// decrypted guard instead of the missing plaintext file. Called before plugin
// Init so the watcher records the correct watched file's mtime.
func wireSecureModeConfigLoader(cw *kernel.ConfigWatcherModule, ctrl *securemode.Controller, configPath string) {
	cw.SetConfigLoader(func() (*config.Config, error) {
		return loadKernelConfigFromSecureMode(ctrl, configPath)
	})
}

// wireSecureModeConfigApply hooks the secure-mode CLI's post-unlock and
// post-config-set callback into the kernel runtime (I-1).
func wireSecureModeConfigApply(k *kernel.Kernel, assessor kernel.AssessorInterface, mcli *securemode.ModeCLI) {
	mcli.OnConfigChanged = newSecureModeConfigReloader(k, assessor)
}
