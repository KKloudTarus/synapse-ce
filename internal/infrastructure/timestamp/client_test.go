package timestamp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rfc3161 "github.com/digitorus/timestamp"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// tsaTime is the instant the fake TSA asserts. It is anchored to the real clock
// (truncated to the second so the genTime round-trips exactly) because the CMS
// verification checks the signing time against the cert validity window.
var tsaTime = time.Now().UTC().Truncate(time.Second)

// fakeTSA stands up an in-process RFC-3161 authority backed by a real 2-cert chain (a
// root CA + a TSA leaf it signs) – no network, fully deterministic. The leaf signs the
// timestamp tokens; both certs are embedded so the token self-verifies.
func fakeTSA(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synapse Test Root CA"},
		NotBefore:             tsaTime.Add(-time.Hour),
		NotAfter:              tsaTime.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Synapse Test TSA"},
		NotBefore:             tsaTime.Add(-time.Hour),
		NotAfter:              tsaTime.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req, err := rfc3161.ParseRequest(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ts := rfc3161.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              tsaTime,
			Nonce:             req.Nonce,
			SerialNumber:      big.NewInt(42),
			Policy:            []int{1, 3, 6, 1, 4, 1, 99999, 1},
			Certificates:      []*x509.Certificate{root}, // parent chain (the signing leaf is added separately)
			AddTSACertificate: true,
		}
		respDER, err := ts.CreateResponse(leaf, leafKey)
		if err != nil {
			http.Error(w, "tsa error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(respDER)
	}))
	return srv, leaf
}

func TestTimestampRoundTrip(t *testing.T) {
	srv, _ := fakeTSA(t)
	defer srv.Close()
	c, err := NewClient(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	// A chain head (the hex sha256 string the evidence/audit vault produces).
	head := []byte("c476b9ea833e91e1a8e386288788d26b5b885f1ee19adab12a025e24b02abde3")

	tok, err := c.Timestamp(context.Background(), head)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if tok.Authority != srv.URL || tok.Token == "" {
		t.Fatalf("unexpected token: %+v", tok)
	}

	// The token verifies against the same head and asserts the TSA's time.
	when, err := VerifyToken(tok, head)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !when.Equal(tsaTime) {
		t.Errorf("asserted time = %s, want %s", when, tsaTime)
	}
}

func TestVerifyTokenRejectsWrongDigest(t *testing.T) {
	srv, _ := fakeTSA(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, 5*time.Second)
	tok, err := c.Timestamp(context.Background(), []byte("the-real-head"))
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	// A token presented against a DIFFERENT head must not verify.
	if _, err := VerifyToken(tok, []byte("a-different-head")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a token must not verify for a different digest, got %v", err)
	}
}

func TestVerifyTokenRejectsCorruptToken(t *testing.T) {
	srv, _ := fakeTSA(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, 5*time.Second)
	head := []byte("head")
	tok, _ := c.Timestamp(context.Background(), head)
	tok.Token = tok.Token[:len(tok.Token)-8] + "AAAAAAAA" // corrupt the DER
	if _, err := VerifyToken(tok, head); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a corrupt token must fail verification, got %v", err)
	}
}

func TestTimestampEmptyDigestRejected(t *testing.T) {
	c, _ := NewClient("http://tsa.example", time.Second)
	if _, err := c.Timestamp(context.Background(), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty digest must be rejected, got %v", err)
	}
}

func TestNewClientRequiresURL(t *testing.T) {
	if _, err := NewClient("  ", time.Second); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank url must be ErrValidation, got %v", err)
	}
}
