// Package fleetca is the control-plane certificate authority for fleet agents (#408). It verifies a
// certificate signing request an agent generates locally (the agent's private key never leaves the
// host) and issues a short-lived client certificate whose subject encodes the agent id and tenant.
// The SHA-256 fingerprint of the issued certificate is the agent's cryptographic identity used by
// mutual-TLS authentication. This is a control-plane issued intermediate, not an external PKI.
package fleetca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.CertificateIssuer = (*CA)(nil)

// minRSABits is the smallest RSA key the CA will sign a certificate for; weaker keys are refused.
const minRSABits = 2048

// CA issues client certificates from a control-plane signing certificate and key.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	ttl  time.Duration
}

// New builds a CA from PEM-encoded certificate and private key and a certificate lifetime.
func New(certPEM, keyPEM []byte, ttl time.Duration) (*CA, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("fleetca: certificate ttl must be positive")
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("fleetca: signing certificate is not a CA")
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, ttl: ttl}, nil
}

// Issue verifies csrPEM and issues a client certificate bound to (agentID, tenantID). It returns
// the certificate PEM and its SHA-256 fingerprint. The CSR's signature is checked and its public
// key must meet the strength floor; the agent's private key is never seen.
func (c *CA) Issue(csrPEM []byte, agentID, tenantID string, now time.Time) (certPEM []byte, fingerprint string, err error) {
	if agentID == "" || tenantID == "" {
		return nil, "", fmt.Errorf("fleetca: agent id and tenant id are required")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", fmt.Errorf("fleetca: not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("fleetca: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("fleetca: csr signature invalid: %w", err)
	}
	if err := checkKeyStrength(csr.PublicKey); err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("fleetca: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// CN = agent id, OU = tenant id: the auth path reads both from the verified certificate.
		Subject:     pkix.Name{CommonName: agentID, OrganizationalUnit: []string{tenantID}},
		NotBefore:   now.Add(-time.Minute), // small backdate for clock skew
		NotAfter:    now.Add(c.ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, "", fmt.Errorf("fleetca: create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), FingerprintDER(der), nil
}

// FingerprintDER returns the hex SHA-256 of a certificate's DER bytes.
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func checkKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return fmt.Errorf("fleetca: rsa key too small (%d bits, need >= %d)", k.N.BitLen(), minRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		return nil
	default:
		return fmt.Errorf("fleetca: unsupported csr public key type %T (use RSA >= 2048 or ECDSA)", pub)
	}
}

func parseCertPEM(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("fleetca: not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKeyPEM(p []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("fleetca: not a PEM private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("fleetca: PKCS8 key is not a signer")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("fleetca: unsupported private key format")
}

// GenerateCA creates a fresh self-signed control-plane CA (ECDSA P-256) valid for validity. It is
// used to bootstrap a dev/test CA and to let operators mint one; the returned key PEM is secret.
func GenerateCA(commonName string, validity time.Duration, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetca: generate ca key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetca: create ca cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("fleetca: marshal ca key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
