//go:build !securemode

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitSecureModeOff(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.ini")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[bootstrap]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrl, err := initSecureMode(nil, dataDir, configPath)
	if err != nil {
		t.Fatalf("off build initSecureMode must return nil without error, got: %v", err)
	}
	if ctrl != nil {
		t.Error("off build must return a nil controller")
	}
}
