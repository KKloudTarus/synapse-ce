package egressbroker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPGrantAuthorityValidatesEndpoint(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		token    string
		wantErr  bool
	}{
		{name: "HTTPS", endpoint: "https://issuer.internal/internal/v1/egress-grants", token: "token"},
		{name: "loopback HTTP", endpoint: "http://127.0.0.1:8082/internal/v1/egress-grants", token: "token"},
		{name: "non-loopback HTTP", endpoint: "http://issuer.internal/internal/v1/egress-grants", token: "token", wantErr: true},
		{name: "localhost HTTP", endpoint: "http://localhost:8082/internal/v1/egress-grants", token: "token", wantErr: true},
		{name: "credentials", endpoint: "https://user@issuer.internal/internal/v1/egress-grants", token: "token", wantErr: true},
		{name: "query", endpoint: "https://issuer.internal/internal/v1/egress-grants?q=1", token: "token", wantErr: true},
		{name: "missing token", endpoint: "https://issuer.internal/internal/v1/egress-grants", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewHTTPGrantAuthority(test.endpoint, test.token, time.Second)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestHTTPGrantAuthoritySendsBoundedAuthenticatedRequest(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/egress-grants" {
			t.Errorf("method=%s path=%s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer machine-token" {
			t.Errorf("authorization=%q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type=%q", got)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"tenant_id":"tenant-test"`, `"execution_kind":"recon"`, `"execution_id":"execution-1"`, `"run_id":"syn1"`, `"pid":1234`} {
			if !strings.Contains(string(body), want) {
				t.Errorf("request body missing %s: %s", want, body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"grant":"signed-grant"}`)
	}))
	defer server.Close()

	authority, err := NewHTTPGrantAuthority(strings.Replace(server.URL, "localhost", "127.0.0.1", 1)+"/internal/v1/egress-grants", "machine-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Authorize(context.Background(), GrantRequest{
		TenantID: "tenant-test", ExecutionKind: "recon", ExecutionID: "execution-1",
		RunID: "syn1", Slot: 1, PID: 1234,
		Rules: []CanonicalRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called || grant != "signed-grant" {
		t.Fatalf("called=%t grant=%q", called, grant)
	}
}

func TestHTTPGrantAuthorityRejectsInvalidResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "denied", status: http.StatusForbidden, body: `{"error":"denied"}`},
		{name: "unknown field", status: http.StatusOK, body: `{"grant":"signed","unknown":true}`},
		{name: "trailing JSON", status: http.StatusOK, body: `{"grant":"signed"}{}`},
		{name: "empty grant", status: http.StatusOK, body: `{"grant":""}`},
		{name: "oversized response", status: http.StatusOK, body: `{"grant":"` + strings.Repeat("x", 40<<10) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			authority, err := NewHTTPGrantAuthority(strings.Replace(server.URL, "localhost", "127.0.0.1", 1), "token", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.Authorize(context.Background(), GrantRequest{}); err == nil {
				t.Fatal("expected response rejection")
			}
		})
	}
}
