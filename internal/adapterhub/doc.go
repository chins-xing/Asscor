// Package adapterhub is FROZEN (2026-11-27, ADR-001).
//
// It has no kernel/cmd consumers; adapter integration is handled by
// internal/kernel/adapter_integration.go. Do not wire this package into the
// kernel: its manager lifecycle overlaps with adapter_integration/extmgr.
//
// The package is kept only as a reference implementation for rules/builder
// behavior. If no consumer appears before 2.4, it will be deleted or merged
// into adapter_integration (see docs/1-current/design/ARCH_DECISIONS_2026-11-27.md).
package adapterhub
