package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// The decode pass exists to find a secret carried inside an encoded value, and its contract is that a hit
// requires a real detector with its distinctive keyword to fire on the decoded bytes. The keyword-free
// entropy rule broke that: decoded bytes are high-entropy by construction, so an EKS cluster's base64 CA
// certificate decoded to a PEM whose DER body is a perfect high-entropy token. That was 19 findings on one
// Terraform module repository, one per rendered fixture, for a value that is public by definition.
func TestDecodedPassIgnoresEncodedCertificate(t *testing.T) {
	line := "B64_CLUSTER_CA=" + base64.StdEncoding.EncodeToString([]byte(certificatePEM()))

	for _, id := range scanOneFile(t, "bootstrap.sh", line) {
		if id == "generic-high-entropy" {
			t.Errorf("a base64-encoded certificate is public material, not a secret; rule %s fired", id)
		}
	}
}

// A credential really hidden inside a base64 value is still found, because its own keyword travels with it
// in the decoded text.
func TestDecodedPassStillFindsEncodedCredential(t *testing.T) {
	inner := `{"password": "S3cr3t-Value-For-The-Decode-Pass-Test"}`
	line := "data: " + base64.StdEncoding.EncodeToString([]byte(inner))

	hits := scanOneFile(t, "secret.yaml", line)
	for _, id := range hits {
		if strings.Contains(id, "secret") || strings.Contains(id, "password") || id == "generic-secret" {
			return
		}
	}
	t.Errorf("a keyword-anchored credential inside base64 must still be found; rules that fired: %v", hits)
}

// certificatePEM builds a PEM certificate whose body carries real DER-like entropy, which is what made the
// keyword-free entropy rule fire on it. The bytes are hash-derived so no real certificate appears here.
func certificatePEM() string {
	var body []byte
	digest := sha256.Sum256([]byte("synapse-decode-pass-fixture"))
	for len(body) < 600 {
		body = append(body, digest[:]...)
		digest = sha256.Sum256(digest[:])
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	var out strings.Builder
	out.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(encoded) > 64 {
		out.WriteString(encoded[:64] + "\n")
		encoded = encoded[64:]
	}
	out.WriteString(encoded + "\n-----END CERTIFICATE-----\n")
	return out.String()
}

// scanOneFile runs the scanner over one file and returns the rule ids that fired.
func scanOneFile(t *testing.T, name, content string) []string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, name, content+"\n")
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ids := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		ids = append(ids, f.RuleID)
	}
	if len(ids) == 0 {
		ids = append(ids, "(none)")
	}
	return ids
}
