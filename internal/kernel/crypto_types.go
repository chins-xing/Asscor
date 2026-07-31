package kernel

import (
	"crypto/tls"
)

type CertConfig struct {
	Organization string
	CommonName   string
	ValidDays    int
}

type CertPair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *tls.Certificate
}
