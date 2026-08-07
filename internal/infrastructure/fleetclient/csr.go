package fleetclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateKeyAndCSR creates a fresh P-256 key pair and a PKCS#10 certificate-signing request for
// commonName, returning both PEM-encoded. The private key never leaves the agent; only the CSR is
// sent to the control plane, which signs it with the fleet CA (see internal/infrastructure/fleetca).
// P-256 satisfies the CA's minimum key-strength check (ECDSA >= 256 bits).
func GenerateKeyAndCSR(commonName string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetclient: generate key: %w", err)
	}
	tmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetclient: create csr: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetclient: marshal key: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM, nil
}
