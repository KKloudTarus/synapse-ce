package oidc

import (
	"encoding/json"
	"testing"
)

func TestHTTPSIssuer(t *testing.T) {
	for _, input := range []string{"http://issuer.example", "https://", "https://issuer.example/?x=1", "https://issuer.example/#x"} {
		if _, err := httpsIssuer(input); err == nil {
			t.Errorf("httpsIssuer(%q) succeeded", input)
		}
	}
	got, err := httpsIssuer("https://issuer.example/")
	if err != nil || got != "https://issuer.example" {
		t.Fatalf("httpsIssuer() = %q, %v", got, err)
	}
}

// An operator-approved link stores the issuer exactly as the provider compares it, so the
// normalization the link command uses must be the verifier's own.
func TestNormalizeIssuerMatchesVerifierForm(t *testing.T) {
	for input, want := range map[string]string{
		"https://issuer.example":        "https://issuer.example",
		"https://issuer.example/":       "https://issuer.example",
		" https://issuer.example/realm": "https://issuer.example/realm",
	} {
		got, err := NormalizeIssuer(input)
		if err != nil || got != want {
			t.Errorf("NormalizeIssuer(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeIssuer("http://issuer.example"); err == nil {
		t.Fatal("a non-HTTPS issuer must be rejected")
	}
}

func TestVerifiedEmailClaimRequiresBooleanTrue(t *testing.T) {
	for _, claim := range []json.RawMessage{nil, []byte(`null`), []byte(`false`), []byte(`"true"`), []byte(`1`)} {
		email, verified, err := verifiedEmailClaim("alice@example.com", claim)
		if err != nil || verified || email != "" {
			t.Fatalf("claim %s imported %q/%t: %v", claim, email, verified, err)
		}
	}
	email, verified, err := verifiedEmailClaim("Alice@EXAMPLE.COM", []byte(`true`))
	if err != nil || !verified || email != "Alice@example.com" {
		t.Fatalf("verified claim = %q/%t: %v", email, verified, err)
	}
	if _, _, err := verifiedEmailClaim("bad\r\nBcc: x@example.com", []byte(`true`)); err == nil {
		t.Fatal("accepted unsafe verified email")
	}
}
