package jira

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestExternalTicketTextRedactsConfiguredCredentialsAndURLs(t *testing.T) {
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		t.Fatal("local redaction made HTTP request")
		return nil, nil
	})
	text := "Đã kiểm tra @admin secret-token " + base64.StdEncoding.EncodeToString([]byte("secret-token")) + " https://unit.example/hooks/opaque-secret"
	out, err := a.RedactExternalTicketText(text)
	if err != nil || !strings.Contains(out, "Đã kiểm tra @admin") || strings.Contains(out, "secret-token") || strings.Contains(out, "c2VjcmV0LXRva2Vu") || strings.Contains(out, "opaque-secret") {
		t.Fatalf("redaction result=%q err=%v", out, err)
	}
	for _, bad := range []string{strings.Repeat("x", (16<<10)+1), "control\x00", string([]byte{0xff})} {
		if _, err := a.RedactExternalTicketText(bad); err == nil {
			t.Fatal("accepted invalid external text")
		}
	}
}
