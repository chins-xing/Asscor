package kernel

import (
	"crypto/tls"
)

type CertConfig struct {
	Organization string
	CommonName   string
	ValidDays    int
	// SANHosts are extra DNS names to embed in the certificate (in addition
	// to CommonName, "localhost" and the issuing host's own hostname). For
	// remote deployments the operator should list every DNS name agents use
	// to reach this kernel, so TLS ServerName verification succeeds without
	// --tls-skip-verify (audit H-4).
	SANHosts []string
	// SANIPs are extra IP addresses to embed in the certificate (in addition
	// to 127.0.0.1). Useful when agents reach the kernel by IP.
	SANIPs []string
}

type CertPair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *tls.Certificate
}
