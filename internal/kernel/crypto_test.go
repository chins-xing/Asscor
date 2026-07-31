package kernel

import (
	"encoding/pem"
	"testing"
)

func TestDefaultConfigs(t *testing.T) {
	ca := DefaultCAConfig()
	if ca.Organization != "ASSCOR Security CA" {
		t.Errorf("CA Org = %s", ca.Organization)
	}
	if ca.ValidDays != 3650 {
		t.Errorf("CA ValidDays = %d, want 3650", ca.ValidDays)
	}

	server := DefaultServerCertConfig()
	if server.CommonName != "ASSCOR Kernel Server" {
		t.Errorf("Server CN = %s", server.CommonName)
	}

	agent := DefaultAgentConfig("host-01")
	if agent.CommonName != "ASSCOR Agent host-01" {
		t.Errorf("Agent CN = %s", agent.CommonName)
	}
}

func TestGenerateCA(t *testing.T) {
	pair, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if len(pair.CertPEM) == 0 {
		t.Fatal("expected non-empty CertPEM")
	}
	if len(pair.KeyPEM) == 0 {
		t.Fatal("expected non-empty KeyPEM")
	}

	if pair.Cert == nil {
		t.Fatal("expected Cert to be loaded")
	}

	// Verify PEM format
	block, _ := pem.Decode(pair.CertPEM)
	if block == nil {
		t.Fatal("failed to decode PEM cert")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE, got %s", block.Type)
	}

	block, _ = pem.Decode(pair.KeyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM key")
	}
}

func TestValidateCertPair(t *testing.T) {
	pair, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if err := ValidateCertPair(pair); err != nil {
		t.Errorf("ValidateCertPair failed: %v", err)
	}

	invalidPair := &CertPair{CertPEM: []byte("invalid"), KeyPEM: []byte("invalid")}
	if err := ValidateCertPair(invalidPair); err == nil {
		t.Error("expected error for invalid cert pair")
	}
}

func TestIssueServerCert(t *testing.T) {
	ca, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	serverPair, err := IssueServerCert(ca, DefaultServerCertConfig())
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	if serverPair.Cert == nil {
		t.Fatal("expected server Cert to be loaded")
	}

	if !VerifyCertChain(serverPair, ca) {
		t.Fatal("expected server cert to be verified by CA")
	}
}

func TestVerifySignature(t *testing.T) {
	ca, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	serverPair, err := IssueServerCert(ca, DefaultServerCertConfig())
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	if err := VerifySignature(serverPair, ca); err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

func TestCertPool(t *testing.T) {
	ca, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	pool := ca.CertPool()
	if pool == nil {
		t.Fatal("expected non-nil cert pool")
	}
}
