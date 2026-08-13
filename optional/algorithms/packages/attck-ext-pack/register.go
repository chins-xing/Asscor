//go:build attck_ext

package attckext

import "github.com/asscor/asscor/internal/kernel"

// Register activates the ATT&CK V19 module and injects it into the assessor.
// Call this during kernel bootstrap (after assessor construction, before Bootstrap):
//
//	if cfg.ATTACK.Enabled {
//	    attckext.Register(assessor)
//	}
func Register(target kernel.ATTACKInjectionTarget) {
	attck := kernel.NewATTACKModule()
	target.SetATTACKProvider(attck.AsEngineProvider())
}
