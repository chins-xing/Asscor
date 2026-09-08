package kernel

import (
	"crypto/x509"
	"net"
	"os"
	"strings"
	"testing"
)

// TestIssueServerCertSANs covers audit H-4: the kernel server certificate
// must carry SANs for the localhost legacy default, the issuing host's own
// hostname, and any configured SANHosts/SANIPs — so an agent that names the
// kernel by its real hostname or IP can verify without --tls-skip-verify.
func TestIssueServerCertSANs(t *testing.T) {
	cfg := DefaultServerCertConfig()
	cfg.SANHosts = []string{"kernel.internal", "as-kernel-01"}
	cfg.SANIPs = []string{"10.0.0.1", "2001:db8::1"}

	ca, err := GenerateCA(DefaultCAConfig())
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	pair, err := IssueServerCert(ca, cfg)
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	leaf, err := x509.ParseCertificate(pair.Cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	hostname, _ := os.Hostname()
	wantDNS := []string{"ASSCOR Kernel Server", "localhost", hostname, "kernel.internal", "as-kernel-01"}
	for _, dns := range wantDNS {
		if !containsString(leaf.DNSNames, dns) {
			t.Errorf("server cert SAN missing DNS name %q (have %v)", dns, leaf.DNSNames)
		}
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("127.0.0.1")) {
		t.Errorf("server cert SAN missing 127.0.0.1 (have %v)", leaf.IPAddresses)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("10.0.0.1")) {
		t.Errorf("server cert SAN missing configured IP 10.0.0.1 (have %v)", leaf.IPAddresses)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("2001:db8::1")) {
		t.Errorf("server cert SAN missing configured IPv6 (have %v)", leaf.IPAddresses)
	}
}

func TestServerCertSANHelpersDeduplicate(t *testing.T) {
	cfg := DefaultServerCertConfig()
	cfg.SANHosts = []string{"localhost", "dup", "dup"}
	cfg.SANIPs = []string{"127.0.0.1", "10.0.0.2", "10.0.0.2"}

	dns := serverCertDNSNames(cfg)
	if countString(dns, "localhost") != 1 {
		t.Errorf("localhost must appear exactly once, got %v", dns)
	}
	if countString(dns, "dup") != 1 {
		t.Errorf("dup must appear exactly once, got %v", dns)
	}
	ips := serverCertIPs(cfg)
	if countIP(ips, net.ParseIP("127.0.0.1")) != 1 {
		t.Errorf("127.0.0.1 must appear exactly once, got %v", ips)
	}
	if countIP(ips, net.ParseIP("10.0.0.2")) != 1 {
		t.Errorf("10.0.0.2 must appear exactly once, got %v", ips)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, v := range list {
		if v.Equal(ip) {
			return true
		}
	}
	return false
}

func countString(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}

func countIP(list []net.IP, ip net.IP) int {
	n := 0
	for _, v := range list {
		if v.Equal(ip) {
			n++
		}
	}
	return n
}

func TestServerCertDNSNamesNoBlanks(t *testing.T) {
	dns := serverCertDNSNames(DefaultServerCertConfig())
	for _, d := range dns {
		if strings.TrimSpace(d) == "" {
			t.Error("SAN list must not contain blank entries")
		}
	}
}
