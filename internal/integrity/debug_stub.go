//go:build !linux || !integrity

package integrity

func IsDebugged() bool { return false }
