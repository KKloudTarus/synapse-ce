package fleetca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	now := time.Now()
	certPEM, keyPEM, err := GenerateCA("synapse-fleet-ca", 24*time.Hour, now)
	if err != nil {
		t.Fatalf("generate ca: %v", err)
	}
	ca, err := New(certPEM, keyPEM, time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	return ca
}

func makeCSR(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueAndVerify(t *testing.T) {
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := makeCSR(t, key)

	certPEM, fp, err := ca.Issue(csr, "ag-1", "tenant-1", time.Now())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if cert.Subject.CommonName != "ag-1" {
		t.Fatalf("CN should be agent id, got %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "tenant-1" {
		t.Fatalf("OU should be tenant id, got %v", cert.Subject.OrganizationalUnit)
	}
	if FingerprintDER(cert.Raw) != fp {
		t.Fatalf("returned fingerprint must match the issued cert")
	}
	// Client-auth EKU present.
	var clientAuth bool
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		t.Fatalf("issued cert must carry client-auth EKU")
	}
	// Verifiable against the CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert must verify against the CA: %v", err)
	}
}

func TestIssueRejects(t *testing.T) {
	ca := testCA(t)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Not a CSR PEM.
	if _, _, err := ca.Issue([]byte("garbage"), "ag", "t", time.Now()); err == nil {
		t.Fatalf("non-CSR PEM must be rejected")
	}
	// Missing identity.
	if _, _, err := ca.Issue(makeCSR(t, ecKey), "", "t", time.Now()); err == nil {
		t.Fatalf("missing agent id must be rejected")
	}
	// Weak RSA key.
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, _, err := ca.Issue(makeCSR(t, weak), "ag", "t", time.Now()); err == nil {
		t.Fatalf("weak RSA key must be rejected")
	}
	// Strong RSA key is accepted.
	strong, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, err := ca.Issue(makeCSR(t, strong), "ag", "t", time.Now()); err != nil {
		t.Fatalf("2048-bit RSA should be accepted: %v", err)
	}
}

func TestNewRejectsNonCA(t *testing.T) {
	// A leaf (non-CA) cert used as a signer must be rejected.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}, &key.PublicKey, key)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := New(leafPEM, keyPEM, time.Hour); err == nil {
		t.Fatalf("a non-CA signing certificate must be rejected")
	}
}
