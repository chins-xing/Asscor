//go:build attck_ext

// Package attckext provides the MITRE ATT&CK V19 threat analysis extension for ASSCOR.
//
// This extension is activated via the //go:build attck_ext build tag.
// When compiled, it adds the ATT&CK module (7,115 LOC, 13 files) to the kernel.
//
// Build:
//
//	go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/
//
// When compiled without the build tag, assessment proceeds normally without ATT&CK analysis.
// The CLI "attck" command shows "ATT&CK module is not loaded" and the dashboard omits ATT&CK sections.
//
// Public API:
//
//	import attckext "github.com/asscor/asscor/optional/algorithms/packages/attck-ext-pack"
//	attckext.Register(assessor)
//
// See package.json for extension point hooks and register.go for the registration implementation.
package attckext
