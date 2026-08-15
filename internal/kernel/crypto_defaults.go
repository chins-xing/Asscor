package kernel

import "fmt"

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
