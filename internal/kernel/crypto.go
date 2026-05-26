package kernel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
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

func DefaultCAConfig() CertConfig {
	return CertConfig{
		Organization: "ASSCOR Security CA",
		CommonName:   "ASSCOR Root CA",
		ValidDays:    3650,
	}
}

func DefaultServerCertConfig() CertConfig {
	return CertConfig{
		Organization: "ASSCOR Security",
		CommonName:   "ASSCOR Kernel Server",
		ValidDays:    365,
	}
}

func DefaultAgentConfig(hostID string) CertConfig {
	return CertConfig{
		Organization: "ASSCOR Security",
		CommonName:   fmt.Sprintf("ASSCOR Agent %s", hostID),
		ValidDays:    365,
	}
}

func GenerateCA(config CertConfig) (*CertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(config.ValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	return encodePair(der, key)
}

func IssueServerCert(caPair *CertPair, config CertConfig) (*CertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(config.ValidDays) * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{config.CommonName, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	caCert, err := x509.ParseCertificate(caPair.Cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caPair.Cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}

	return encodePair(der, key)
}

func IssueAgentCert(caPair *CertPair, config CertConfig, hostID string) (*CertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(config.ValidDays) * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	caCert, err := x509.ParseCertificate(caPair.Cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caPair.Cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create agent cert: %w", err)
	}

	return encodePair(der, key)
}

func encodePair(der []byte, key *rsa.PrivateKey) (*CertPair, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("encode cert pair: %w", err)
	}

	return &CertPair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    &tlsCert,
	}, nil
}

func LoadCertPair(certPath, keyPath string) (*CertPair, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert pair: %w", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return &CertPair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    &cert,
	}, nil
}

func (cp *CertPair) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cp.CertPEM)
	return pool
}

func ValidateCertPair(pair *CertPair) error {
	if pair == nil || pair.Cert == nil {
		return fmt.Errorf("nil cert pair")
	}
	if len(pair.Cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	x509Cert, err := x509.ParseCertificate(pair.Cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not valid yet (notBefore=%s)", x509Cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired (notAfter=%s)", x509Cert.NotAfter.Format(time.RFC3339))
	}

	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}

	privKey, ok := pair.Cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}

	if pubKey.N.Cmp(privKey.N) != 0 || pubKey.E != privKey.E {
		return fmt.Errorf("certificate public key does not match private key")
	}

	return nil
}

func VerifyCertChain(certPair *CertPair, caPair *CertPair) bool {
	cert, err := x509.ParseCertificate(certPair.Cert.Certificate[0])
	if err != nil {
		return false
	}

	caCert, err := x509.ParseCertificate(caPair.Cert.Certificate[0])
	if err != nil {
		return false
	}

	if err := ValidateCertPair(caPair); err != nil {
		return false
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return false
	}
	return true
}

func VerifySignature(certPair *CertPair, caPair *CertPair) error {
	if len(certPair.Cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate chain")
	}
	if len(caPair.Cert.Certificate) == 0 {
		return fmt.Errorf("empty CA certificate chain")
	}

	cert, err := x509.ParseCertificate(certPair.Cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caPair.Cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func NewServerTLSConfig(serverCert, caCert *CertPair) *tls.Config {
	clientPool := caCert.CertPool()

	serverTLSCert := *serverCert.Cert
	if len(serverTLSCert.Certificate) > 0 {
		serverTLSCert.Certificate = append(serverTLSCert.Certificate, caCert.Cert.Certificate[0])
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func NewClientTLSConfig(agentCert, caCert *CertPair) *tls.Config {
	serverPool := caCert.CertPool()

	return &tls.Config{
		Certificates: []tls.Certificate{*agentCert.Cert},
		RootCAs:      serverPool,
		MinVersion:   tls.VersionTLS12,
	}
}