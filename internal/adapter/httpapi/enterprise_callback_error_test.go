package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type callbackErrorStore struct {
	identityenterprise.BrowserStore
}

type callbackCookieProtector struct{}

func (callbackCookieProtector) Seal(_ context.Context, value, _ []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (callbackCookieProtector) Open(_ context.Context, value string, _ []byte) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func (callbackErrorStore) CutoverState(context.Context, shared.ID) (ports.IdentityCutoverState, error) {
	return ports.IdentityCutoverState{TenantID: "default", Declared: true}, nil
}

type callbackErrorConnections struct{ ports.IdentityConnectionStore }

func (callbackErrorConnections) GetIdentityConnection(_ context.Context, tenant, id shared.ID, revision int) (ports.IdentityConnection, error) {
	return ports.IdentityConnection{TenantID: tenant, ID: id, Issuer: "https://issuer.example", Enabled: true, Revision: revision, DraftRevision: revision, TestPassed: true}, nil
}

type callbackErrorTransactions struct {
	ports.IdentityAuthorizationStore
	transaction ports.IdentityAuthorizationTransaction
	consumed    bool
}

func (s *callbackErrorTransactions) CreateIdentityAuthorization(_ context.Context, transaction ports.IdentityAuthorizationTransaction) error {
	s.transaction = transaction
	return nil
}

func (s *callbackErrorTransactions) ConsumeIdentityAuthorization(_ context.Context, tenant shared.ID, state, caller string, now time.Time) (ports.IdentityAuthorizationTransaction, error) {
	if s.consumed || tenant != s.transaction.TenantID || state != s.transaction.StateDigest || caller != s.transaction.CallerNonceDigest {
		return ports.IdentityAuthorizationTransaction{}, shared.ErrNotFound
	}
	s.consumed = true
	s.transaction.ConsumedAt = &now
	return s.transaction, nil
}

type callbackErrorProvider struct{ err error }

func (callbackErrorProvider) GenerateVerifier() string { return "verifier" }
func (callbackErrorProvider) AuthorizationURL(state, _, _ string) (string, error) {
	return "https://issuer.example/authorize?state=" + state, nil
}
func (p callbackErrorProvider) ExchangeAndVerify(context.Context, string, string, string) (ports.OIDCIdentity, error) {
	return ports.OIDCIdentity{}, p.err
}
func (callbackErrorProvider) AuthorizationURLWithMaxAge(_ context.Context, state, _, _ string, _ time.Duration) (string, error) {
	return "https://issuer.example/authorize?state=" + state, nil
}
func (p callbackErrorProvider) ExchangeAndVerifyWithMaxAge(context.Context, string, string, string, time.Duration) (ports.OIDCIdentity, error) {
	return ports.OIDCIdentity{}, p.err
}

type callbackErrorFactory struct{ err error }

func (f callbackErrorFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	return callbackErrorProvider(f), nil
}

func newEnterpriseCallbackErrorRouter(t *testing.T, providerError error) (*Router, *callbackErrorTransactions, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	clock := enterpriseSecurityClock{now: now}
	transactions := &callbackErrorTransactions{}
	protector := callbackCookieProtector{}
	protocol, err := identityenterprise.NewService(callbackErrorConnections{}, transactions, callbackErrorFactory{err: providerError}, protector, clock, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := identityenterprise.NewBrowser(callbackErrorStore{}, protocol, &identityenterprise.AdmissionService{}, protector, clock, handlerIDs{}, identityenterprise.BrowserConfig{
		TenantID: "default", ReadEnabled: func(string) bool { return true }, MutationEnabled: func(string) bool { return true }, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Router{log: discardLog(), enterprise: &enterpriseDeps{browser: browser, protector: protector, clock: clock, tenant: "default", frontend: "https://console.example.test", limit: newEnterpriseAdmissionLimit()}}, transactions, now
}

func TestEnterpriseCallbackClassifiesTokenEndpointOutageWithoutIssuingSession(t *testing.T) {
	cause := errors.New("token endpoint returned 503")
	rt, transactions, now := newEnterpriseCallbackErrorRouter(t, fmt.Errorf("%w: %w", authz.ErrAuthenticationUnavailable, cause))
	started, err := rt.enterprise.browser.Begin(t.Context(), identityenterprise.BrowserAuthorization{ConnectionID: "connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "caller"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := json.Marshal(enterpriseNonce{Tenant: "default", CallerNonce: "caller", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/enterprise/callback?state="+url.QueryEscape(state.Query().Get("state"))+"&code=code", nil)
	req.AddCookie(&http.Cookie{Name: enterpriseNonceCookie, Value: base64.RawURLEncoding.EncodeToString(nonce)})
	rec := httptest.NewRecorder()
	rt.enterpriseCallback(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://console.example.test?auth_error=unavailable&tenant_id=default" {
		t.Fatalf("callback status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if !transactions.consumed {
		t.Fatal("outage callback did not burn authorization state")
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName || cookie.Name == enterpriseInvitationCookie {
			t.Fatalf("outage callback issued credential cookie %q", cookie.Name)
		}
	}
}

func TestEnterpriseCallbackKeepsProtocolDenialAccessDenied(t *testing.T) {
	rt, _, now := newEnterpriseCallbackErrorRouter(t, shared.ErrForbidden)
	started, err := rt.enterprise.browser.Begin(t.Context(), identityenterprise.BrowserAuthorization{ConnectionID: "connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "caller"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := json.Marshal(enterpriseNonce{Tenant: "default", CallerNonce: "caller", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/enterprise/callback?state="+url.QueryEscape(state.Query().Get("state"))+"&code=code", nil)
	req.AddCookie(&http.Cookie{Name: enterpriseNonceCookie, Value: base64.RawURLEncoding.EncodeToString(nonce)})
	rec := httptest.NewRecorder()
	rt.enterpriseCallback(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://console.example.test?auth_error=access_denied&tenant_id=default" {
		t.Fatalf("callback status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}
