package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrecovery"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type enterpriseSecurityClock struct{ now time.Time }

func (c enterpriseSecurityClock) Now() time.Time { return c.now }

type recoveryAuthorityStore struct {
	identityenterprise.BrowserStore
	declared bool
	consumed int
}

type enterpriseSecurityProtector struct{}

func (enterpriseSecurityProtector) Seal(_ context.Context, value, _ []byte) (string, error) {
	return string(value), nil
}
func (enterpriseSecurityProtector) Open(_ context.Context, value string, _ []byte) ([]byte, error) {
	return []byte(value), nil
}

func (s *recoveryAuthorityStore) ResolveIdentityRecoveryActivationTenant(context.Context, string) (shared.ID, error) {
	return "organization-b", nil
}
func (s *recoveryAuthorityStore) CutoverState(_ context.Context, tenant shared.ID) (ports.IdentityCutoverState, error) {
	return ports.IdentityCutoverState{TenantID: tenant, Declared: s.declared}, nil
}
func (s *recoveryAuthorityStore) ConsumeIdentityRecoveryActivation(_ context.Context, c ports.IdentityRecoveryConsume) (identity.EnterpriseSession, error) {
	s.consumed++
	v := c.Issue.Session
	v.TenantID = "organization-b"
	return v, nil
}

func TestRecoveryActivationChecksExactTenantAuthorityBeforeConsumption(t *testing.T) {
	for _, tc := range []struct {
		name              string
		declared, enabled bool
	}{
		{"mutation disabled", true, false},
		{"undeclared", false, true},
		{"declared and enabled", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			st := &recoveryAuthorityStore{declared: tc.declared}
			clock := enterpriseSecurityClock{now}
			browser, err := identityenterprise.NewBrowser(st, &identityenterprise.Service{}, &identityenterprise.AdmissionService{}, enterpriseSecurityProtector{}, clock, handlerIDs{}, identityenterprise.BrowserConfig{
				TenantID: "organization-a", ReadEnabled: func(string) bool { return true },
				MutationEnabled: func(tenant string) bool {
					return tenant == "organization-a" || (tenant == "organization-b" && tc.enabled)
				}, SessionTTL: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			recovery, err := identityrecovery.NewService(st, clock, handlerIDs{})
			if err != nil {
				t.Fatal(err)
			}
			rt := &Router{log: discardLog(), enterprise: &enterpriseDeps{browser: browser, recovery: recovery, clock: clock, frontend: "https://console.example.test", limit: newEnterpriseAdmissionLimit()}}
			r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/recovery", strings.NewReader(`{"secret":"opaque-activation"}`))
			r.RemoteAddr = "203.0.113.14:1234"
			rec := httptest.NewRecorder()
			rt.enterpriseRecovery(rec, r)
			if tc.declared && tc.enabled {
				if rec.Code != http.StatusOK || st.consumed != 1 {
					t.Fatalf("enabled status=%d consumed=%d", rec.Code, st.consumed)
				}
			} else if rec.Code == http.StatusOK || st.consumed != 0 || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("refused activation status=%d consumed=%d cookies=%d", rec.Code, st.consumed, len(rec.Result().Cookies()))
			}
		})
	}
}

func enterpriseSecurityRequest(method, target string, body string, p Principal) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), principalKey, p))
}

func TestEnterpriseNativeAdministrationRefusesNonAdministratorsBeforeDependencies(t *testing.T) {
	rt := &Router{log: discardLog()}
	handlers := map[string]http.HandlerFunc{
		"roster":            rt.enterpriseRoster,
		"membership change": rt.enterpriseChangeMembership,
	}
	for role, p := range map[string]Principal{
		"member":            {ID: "member", Role: string(user.RoleMember), TenantID: "acme", Credential: authz.KindBrowserSession},
		"integration admin": {ID: "integrator", Role: string(user.RoleIntegrationAdmin), TenantID: "acme", Credential: authz.KindBrowserSession},
	} {
		for name, handler := range handlers {
			t.Run(role+" "+name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, enterpriseSecurityRequest(http.MethodPost, "/api/v1/identity/memberships/change", `{}`, p))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("direct handler status=%d body=%s", rec.Code, rec.Body.String())
				}
			})
		}
	}

	// The route wrapper is a separate chokepoint. It must refuse before it can call the
	// direct handler or access the intentionally absent enterprise dependencies.
	for role, p := range map[string]Principal{
		"member":            {ID: "member", Role: string(user.RoleMember), TenantID: "acme", Credential: authz.KindBrowserSession},
		"integration admin": {ID: "integrator", Role: string(user.RoleIntegrationAdmin), TenantID: "acme", Credential: authz.KindBrowserSession},
	} {
		t.Run("wrapped "+role, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rt.recoverable(user.PermAdminister, authz.RecoveryListUsers, rt.enterpriseRoster)(rec, enterpriseSecurityRequest(http.MethodGet, "/api/v1/identity/roster", "", p))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("wrapped status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestBreakGlassCannotReachNativeAdminMintInvitationBootstrapOrOwnLink(t *testing.T) {
	rt := &Router{log: discardLog()}
	p := Principal{ID: "emergency", Role: string(user.RoleAdmin), TenantID: "acme", Credential: authz.KindBreakGlass}
	for name, handler := range map[string]http.HandlerFunc{
		"bootstrap":                rt.enterpriseBootstrap,
		"invitation list":          rt.enterpriseInvitations,
		"invitation create":        rt.enterpriseCreateInvitation,
		"recovery activation mint": rt.enterpriseRecoveryCode,
		"own connection link":      rt.enterpriseLinkConnections,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, enterpriseSecurityRequest(http.MethodPost, "/api/v1/identity/blocked", `{}`, p))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("break-glass direct handler status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	for name, action := range map[string]authz.Action{
		"bootstrap":  {Permission: user.PermAdminister},
		"invitation": {Permission: user.PermAdminister},
		"mint":       {Permission: user.PermAdminister},
		"switch":     {Permission: user.PermAdminister},
		"own link":   {},
	} {
		if authz.Decide(p.authz(), action).Allowed {
			t.Errorf("break-glass unexpectedly allowed %s", name)
		}
	}
}

func TestEnterpriseDecodeRejectsAmbiguousBodiesAndSetsPrivateHeaders(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"known":true}`,
		"trailing": `{} {}`,
		"oversize": `{"value":"` + strings.Repeat("x", 16<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var dst struct{}
			rec := httptest.NewRecorder()
			if enterpriseDecode(rec, httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/begin", strings.NewReader(body)), &dst) {
				t.Fatal("decoder accepted invalid body")
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("private headers cache=%q referrer=%q", rec.Header().Get("Cache-Control"), rec.Header().Get("Referrer-Policy"))
			}
		})
	}
}

func TestEnterpriseAdmissionUsesSocketIPAndRejectsCrossSite(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	deps := func() *enterpriseDeps {
		return &enterpriseDeps{clock: enterpriseSecurityClock{now: now}, frontend: "https://console.example.test", limit: newEnterpriseAdmissionLimit()}
	}
	t.Run("forwarded address cannot rescue invalid socket", func(t *testing.T) {
		rt := &Router{log: discardLog(), enterprise: deps()}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/begin", nil)
		r.RemoteAddr = "untrusted.example:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.10")
		rec := httptest.NewRecorder()
		if rt.enterpriseAdmissionAllowed(rec, r) || rec.Code != http.StatusTooManyRequests {
			t.Fatalf("invalid socket status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("forwarded address does not replace valid socket", func(t *testing.T) {
		rt := &Router{log: discardLog(), enterprise: deps()}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/begin", nil)
		r.RemoteAddr = "203.0.113.11:1234"
		r.Header.Set("X-Forwarded-For", "not-an-ip")
		rec := httptest.NewRecorder()
		if !rt.enterpriseAdmissionAllowed(rec, r) || rec.Code != http.StatusOK {
			t.Fatalf("valid socket status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("cross site", func(t *testing.T) {
		rt := &Router{log: discardLog(), enterprise: deps()}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/begin", nil)
		r.RemoteAddr = "203.0.113.12:1234"
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		if rt.enterpriseAdmissionAllowed(rec, r) || rec.Code != http.StatusForbidden {
			t.Fatalf("cross-site status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestEnterpriseSwitchRequiresAUPBeforeBrowserMutation(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	rt := &Router{
		log:        discardLog(),
		aup:        newTestAUP(newFakeAUPStore(), &fakeAudit{}),
		enterprise: &enterpriseDeps{clock: enterpriseSecurityClock{now: now}, frontend: "https://console.example.test", limit: newEnterpriseAdmissionLimit()},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/enterprise/switch", strings.NewReader(`{}`))
	r.RemoteAddr = "203.0.113.13:1234"
	rec := httptest.NewRecorder()
	rt.enterpriseSwitch(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("switch without AUP status=%d body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorContract(t, rec); ErrorCode(body.Code) != CodeAUPRequired {
		t.Fatalf("switch without AUP code=%q", body.Code)
	}
}
