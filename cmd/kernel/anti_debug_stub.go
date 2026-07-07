//go:build !linux

package main

func isDebugged() bool {
	return false
}
