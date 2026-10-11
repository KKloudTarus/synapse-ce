package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuditTextRemovesCredentialURLsAndKnownSecretEncodings(t *testing.T) {
	secret := "test-signing-value"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	in := "Fixed HTTPS://hooks.example.test/private-path?opaque=value and " + secret + " / " + encoded
	got := AuditText(in, []string{secret})
	for _, value := range []string{"private-path", "opaque=value", secret, encoded} {
		if strings.Contains(got, value) {
			t.Fatal("audit text retained credential material")
		}
	}
	if !strings.HasPrefix(got, "Fixed ") || AuditText(got, []string{secret}) != got {
		t.Fatal("redaction lost context or was not idempotent")
	}
	knownURL := "https://example.test/hook"
	if strings.Contains(AuditText(knownURL+"?opaque=extra-credential", []string{knownURL}), "extra-credential") {
		t.Fatal("known URL prefix replacement exposed the appended query")
	}
}
