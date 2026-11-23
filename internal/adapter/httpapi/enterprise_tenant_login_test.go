package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type tenantContextStore struct {
	identityenterprise.BrowserStore
	declared       map[shared.ID]bool
	policyFor      shared.ID
	connectionsFor shared.ID
}

func (s *tenantContextStore) CutoverState(_ context.Context, tenant shared.ID) (ports.IdentityCutoverState, error) {
	return ports.IdentityCutoverState{TenantID: tenant, Declared: s.declared[tenant]}, nil
}

func (s *tenantContextStore) GetIdentityRecoveryPolicy(_ context.Context, tenant shared.ID) (ports.IdentityRecoveryPolicy, error) {
	s.policyFor = tenant
	return ports.IdentityRecoveryPolicy{TenantID: tenant}, nil
}

func (s *tenantContextStore) ListIdentityConnections(_ context.Context, tenant shared.ID, active bool) ([]ports.IdentityConnection, error) {
	s.connectionsFor = tenant
	if !active {
		return nil, shared.ErrValidation
	}
	return []ports.IdentityConnection{{TenantID: tenant, ID: shared.ID("connection-" + tenant.String()), DisplayName: "Sandbox"}}, nil
}

func tenantContextRouter(t *testing.T, declared, read, mutate bool) (*Router, *tenantContextStore) {
	t.Helper()
	store := &tenantContextStore{declared: map[shared.ID]bool{"default": true, "sandbox-secondary": declared}}
	clock := enterpriseSecurityClock{now: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)}
	browser, err := identityenterprise.NewBrowser(store, &identityenterprise.Service{}, &identityenterprise.AdmissionService{}, enterpriseSecurityProtector{}, clock, handlerIDs{}, identityenterprise.BrowserConfig{
		TenantID: "default",
		ReadEnabled: func(tenant string) bool {
			return tenant == "default" || tenant == "sandbox-secondary" && read
		},
		MutationEnabled: func(tenant string) bool {
			return tenant == "default" || tenant == "sandbox-secondary" && mutate
		},
		SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Router{log: discardLog(), enterprise: &enterpriseDeps{browser: browser, store: store, tenant: "default", frontend: "https://console.example.test", limit: newEnterpriseAdmissionLimit(), clock: clock}}, store
}

func TestEnterpriseContext_ExplicitTenantUsesOnlyDeclaredReadAndMutationAuthority(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		declared, read, mutate bool
		wantStatus             int
	}{
		{name: "allowed", declared: true, read: true, mutate: true, wantStatus: http.StatusOK},
		{name: "undeclared", declared: false, read: true, mutate: true, wantStatus: http.StatusServiceUnavailable},
		{name: "read disabled", declared: true, read: false, mutate: true, wantStatus: http.StatusServiceUnavailable},
		{name: "mutation disabled", declared: true, read: true, mutate: false, wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, store := tenantContextRouter(t, tc.declared, tc.read, tc.mutate)
			rec := httptest.NewRecorder()
			rt.enterpriseContext(rec, httptest.NewRequest(http.MethodGet, "/api/auth/enterprise/context?tenant_id=sandbox-secondary", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				var body struct {
					TenantID shared.ID `json:"tenant_id"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.TenantID != "sandbox-secondary" || store.policyFor != "sandbox-secondary" || store.connectionsFor != "sandbox-secondary" {
					t.Fatalf("selected context leaked or fell back: body=%s policy=%q connections=%q err=%v", rec.Body.String(), store.policyFor, store.connectionsFor, err)
				}
			}
		})
	}
}

func TestEnterpriseContext_ExplicitTenantRejectsAmbiguousAndInvalidSelector(t *testing.T) {
	rt, _ := tenantContextRouter(t, true, true, true)
	for _, target := range []string{
		"/api/auth/enterprise/context?tenant_id=sandbox-secondary&tenant_id=default",
		"/api/auth/enterprise/context?tenant_id=",
		"/api/auth/enterprise/context?tenant_id=%zz",
		"/api/auth/enterprise/context?tenant_id=sandbox-secondary;ignored=1",
		"/api/auth/enterprise/context?tenant_id=%20sandbox-secondary",
		"/api/auth/enterprise/context?tenant_id=sandbox-secondary%0Aother",
		"/api/auth/enterprise/context?tenant_id=" + strings.Repeat("x", 129),
	} {
		rec := httptest.NewRecorder()
		rt.enterpriseContext(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("target=%q status=%d body=%s", target, rec.Code, rec.Body.String())
		}
	}
}

func TestEnterpriseContext_OmittedTenantKeepsDefault(t *testing.T) {
	rt, store := tenantContextRouter(t, true, true, true)
	rec := httptest.NewRecorder()
	rt.enterpriseContext(rec, httptest.NewRequest(http.MethodGet, "/api/auth/enterprise/context", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		TenantID shared.ID `json:"tenant_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.TenantID != "default" || store.policyFor != "default" || store.connectionsFor != "default" {
		t.Fatalf("omitted tenant did not use default: body=%s policy=%q connections=%q err=%v", rec.Body.String(), store.policyFor, store.connectionsFor, err)
	}
}

func TestEnterpriseBegin_SelectorIsAcceptedOnlyForLogin(t *testing.T) {
	for _, purpose := range []string{"test", "invitation", "link", "step_up"} {
		t.Run(purpose, func(t *testing.T) {
			rt := &Router{log: discardLog()}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/begin", strings.NewReader(`{"tenant_id":"sandbox-secondary","purpose":"`+purpose+`"}`))
			r.RemoteAddr = "203.0.113.9:1234"
			rt.enterpriseBeginAllowed(rec, r)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestEnterpriseFrontendURL_UsesSealedTenantInsteadOfCallbackQuery(t *testing.T) {
	destination, ok := enterpriseFrontendURL("https://console.example.test/settings/authentication?tenant_id=forged", "sandbox-secondary", "access_denied")
	if !ok || !strings.Contains(destination, "tenant_id=sandbox-secondary") || strings.Contains(destination, "forged") || !strings.Contains(destination, "auth_error=access_denied") {
		t.Fatalf("unsafe callback destination %q", destination)
	}
}
