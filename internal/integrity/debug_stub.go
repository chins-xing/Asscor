//go:build !linux

package integrity

func IsDebugged() bool { return false }
