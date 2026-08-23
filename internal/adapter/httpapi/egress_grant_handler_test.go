package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type egressGrantAuthorizerStub struct {
	calls int
	ctx   context.Context
	req   ports.EgressGrantRequest
	err   error
}

func (s *egressGrantAuthorizerStub) Authorize(ctx context.Context, req ports.EgressGrantRequest) (string, error) {
	s.calls++
	s.ctx, s.req = ctx, req
	if s.err != nil {
		return "", s.err
	}
	return "signed-grant", nil
}

func TestEgressGrantHandlerAuthenticatesMachineAndInstallsTenant(t *testing.T) {
	authorizer := &egressGrantAuthorizerStub{}
	handler, err := NewEgressGrantHandler("machine-token", authorizer)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(egressGrantRequest{
		TenantID: "tenant-test", ExecutionKind: "recon", ExecutionID: "run-1",
		RunID: "syn1", Slot: 1, PID: 1234,
		Rules: []ports.CanonicalEgressRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	})
	req := httptest.NewRequest(http.MethodPost, EgressGrantPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer machine-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || authorizer.calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", res.Code, authorizer.calls, res.Body.String())
	}
	if tenant, ok := shared.TenantFrom(authorizer.ctx); !ok || tenant != "tenant-test" {
		t.Fatalf("tenant=%q ok=%t", tenant, ok)
	}
	if authorizer.req.ExecutionID != "run-1" || authorizer.req.PID != 1234 {
		t.Fatalf("request=%+v", authorizer.req)
	}
}

func TestEgressGrantHandlerFailsClosed(t *testing.T) {
	validBody := `{"tenant_id":"tenant-test","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":1,"pid":1234}`
	for _, tt := range []struct {
		name        string
		token       string
		body        string
		method      string
		contentType string
		want        int
	}{
		{name: "missing token", body: `{}`, method: http.MethodPost, want: http.StatusUnauthorized},
		{name: "wrong token", token: "wrong", body: `{}`, method: http.MethodPost, want: http.StatusUnauthorized},
		{name: "unknown field", token: "machine-token", body: `{"tenant_id":"tenant-test","unknown":true}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "missing tenant", token: "machine-token", body: `{}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "missing execution identity", token: "machine-token", body: `{"tenant_id":"tenant-test"}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "invalid pid", token: "machine-token", body: `{"tenant_id":"tenant-test","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":1,"pid":1}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "invalid slot", token: "machine-token", body: `{"tenant_id":"tenant-test","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":64,"pid":1234}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "oversized tenant", token: "machine-token", body: `{"tenant_id":"` + strings.Repeat("t", 201) + `","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":1,"pid":1234}`, method: http.MethodPost, want: http.StatusBadRequest},
		{name: "wrong content type", token: "machine-token", body: validBody, method: http.MethodPost, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "wrong method", token: "machine-token", body: `{}`, method: http.MethodGet, want: http.StatusMethodNotAllowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := &egressGrantAuthorizerStub{}
			handler, err := NewEgressGrantHandler("machine-token", authorizer)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(tt.method, EgressGrantPath, bytes.NewBufferString(tt.body))
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tt.want || authorizer.calls != 0 {
				t.Fatalf("status=%d want=%d calls=%d", res.Code, tt.want, authorizer.calls)
			}
		})
	}
}

func TestEgressGrantHandlerDoesNotLeakAuthorizationFailure(t *testing.T) {
	authorizer := &egressGrantAuthorizerStub{err: errors.New("secret internal authorization detail")}
	handler, err := NewEgressGrantHandler("machine-token", authorizer)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tenant_id":"tenant-test","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":1,"pid":1234}`
	req := httptest.NewRequest(http.MethodPost, EgressGrantPath, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer machine-token")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || authorizer.calls != 1 {
		t.Fatalf("status=%d calls=%d", res.Code, authorizer.calls)
	}
	if strings.Contains(res.Body.String(), "secret internal") {
		t.Fatalf("response leaked authorization detail: %s", res.Body.String())
	}
}

func TestEgressGrantHandlerRateLimitsAuthenticatedRequests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authorizer := &egressGrantAuthorizerStub{}
	handler, err := newEgressGrantHandler("machine-token", authorizer, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tenant_id":"tenant-test","execution_kind":"recon","execution_id":"execution-1","run_id":"syn1","slot":1,"pid":1234}`
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, EgressGrantPath, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	if res := request("machine-token"); res.Code != http.StatusOK {
		t.Fatalf("first status = %d", res.Code)
	}
	if res := request("machine-token"); res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") != "60" {
		t.Fatalf("limited status = %d retry-after = %q", res.Code, res.Header().Get("Retry-After"))
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
	now = now.Add(time.Minute)
	if res := request("machine-token"); res.Code != http.StatusOK || authorizer.calls != 2 {
		t.Fatalf("reset status = %d calls = %d", res.Code, authorizer.calls)
	}
}
