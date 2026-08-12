//go:build attck_ext

// Package attckext is the ATT&CK V19 threat analysis extension package for ASSCOR.
//
// This extension is compiled into the kernel via the //go:build attck_ext build tag:
//
//	go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/
//
// The ATT&CK module (7,115 LOC, 13 files) provides:
//   - ATT&CK V19 coverage analysis (14 tactics, 180+ techniques)
//   - Kill chain assessment (9 stages)
//   - APT group matching and Bayesian attribution
//   - Threat intelligence integration (IOC management, TTP tracking)
//   - Adversary emulation and threat hunting
//   - Predictive risk assessment (Markov chain 4×4 transition matrix)
//
// When compiled without the build tag, the kernel evaluates and scores normally
// but omits ATT&CK analyses. The assessment pipeline gracefully degrades:
//   - assessor.applyATTACK() skips when ATTACKProvider is nil
//   - CLI "attck" command shows "ATT&CK module is not loaded"
//   - Web dashboard omits ATT&CK coverage/kill chain sections
//
// Source files: internal/kernel/attck*.go (13 files behind //go:build attck_ext)
package attckext

// This package serves as the extension entry point.
// All ATT&CK module source files live in internal/kernel/attck*.go
// and are activated by the //go:build attck_ext tag.
//
// To use this extension:
//  1. Verify the build tag on all 13 attck*.go files
//  2. Build with: go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/
//  3. Kernel startup automatically wires ATT&CK via AsEngineProvider()
//
// The kernel code at cmd/kernel/attck_ext.go handles registration:
//   if registeredATTACKInit != nil { registeredATTACKInit(assessor) }
//
// cmd/kernel/main.go line 269-272 bridges extensions to kernel extension points:
//   if mgr := extmgr.GetManager(); mgr != nil {
//       mgr.SetKernelExtensions(k.PlatformExtensionRegistry())
//   }
