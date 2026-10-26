package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chins-xing/asscor/internal/kernel"
)

// 多 agent 部署（一 CT 一 agent）时，每个 agent 必须有一张由同一 CA 签发的独立证书，
// 否则 kernel 的 host-id ↔ 证书指纹绑定会拒绝第二个 agent。
// 本测试钉住 `--issue-agent-cert` 的核心：签出来的证书能通过 CA 链验证、且文件落盘。
func TestIssueAgentCertificateWritesVerifiablePair(t *testing.T) {
	dir := t.TempDir()
	ca, err := kernel.GenerateCA(kernel.DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca.CertPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), ca.KeyPEM, 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}

	out := filepath.Join(dir, "issued")
	if err := issueAgentCertificate(dir, "ct-test", out); err != nil {
		t.Fatalf("issueAgentCertificate: %v", err)
	}
	certPath := filepath.Join(out, "ct-test.crt")
	keyPath := filepath.Join(out, "ct-test.key")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s: %v", p, err)
		}
	}
	issued, err := kernel.LoadCertPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCertPair: %v", err)
	}
	if !kernel.VerifyCertChain(issued, ca) {
		t.Error("签出的 agent 证书未通过 CA 链验证（多 agent 会注册失败）")
	}

	// 两个不同 host 签出的证书必须不同（否则又会撞指纹绑定）。
	if err := issueAgentCertificate(dir, "ct-test-2", out); err != nil {
		t.Fatalf("issue second: %v", err)
	}
	a, _ := os.ReadFile(certPath)
	b, _ := os.ReadFile(filepath.Join(out, "ct-test-2.crt"))
	if string(a) == string(b) {
		t.Error("两个 host 的证书内容相同 —— 每个 agent 必须是独立证书")
	}
}
