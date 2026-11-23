package identityenterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// loginAuthorityStore supplies only the durable authority read used before a public login.
// The embedded port stays deliberately unused by these tests.
type loginAuthorityStore struct {
	BrowserStore
	declared map[shared.ID]bool
}

func (s loginAuthorityStore) CutoverState(_ context.Context, tenant shared.ID) (ports.IdentityCutoverState, error) {
	return ports.IdentityCutoverState{TenantID: tenant, Declared: s.declared[tenant]}, nil
}

type tenantLoginConnections struct{ authConnections }

func (tenantLoginConnections) GetIdentityConnection(_ context.Context, tenant, id shared.ID, revision int) (ports.IdentityConnection, error) {
	if tenant != "sandbox-secondary" || id != "secondary-connection" {
		return ports.IdentityConnection{}, shared.ErrNotFound
	}
	return ports.IdentityConnection{TenantID: tenant, ID: id, Issuer: "https://issuer.example", Enabled: true, Revision: revision, DraftRevision: revision, TestPassed: true}, nil
}

func newTenantLoginBrowser(t *testing.T, declared, read, mutate bool) (*Browser, *authTransactions) {
	t.Helper()
	tx := &authTransactions{}
	service, err := NewService(tenantLoginConnections{}, tx, authFactory{}, authProtector{}, authClock{now: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := NewBrowser(loginAuthorityStore{declared: map[shared.ID]bool{"sandbox-secondary": declared}}, service, &AdmissionService{}, authProtector{}, authClock{now: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}, &authIDs{}, BrowserConfig{
		TenantID: "default",
		ReadEnabled: func(tenant string) bool {
			return tenant == "sandbox-secondary" && read
		},
		MutationEnabled: func(tenant string) bool {
			return tenant == "sandbox-secondary" && mutate
		},
		SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return browser, tx
}

func TestBrowserBegin_ExplicitLoginUsesDeclaredTenantAndItsConnection(t *testing.T) {
	browser, tx := newTenantLoginBrowser(t, true, true, true)
	started, err := browser.Begin(t.Context(), BrowserAuthorization{
		TenantID: "sandbox-secondary", ConnectionID: "secondary-connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser", ExplicitTenant: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.AuthorizationURL == "" || tx.v.TenantID != "sandbox-secondary" || tx.v.ConnectionID != "secondary-connection" {
		t.Fatalf("login did not bind the selected tenant and connection: %+v", tx.v)
	}
	if _, err = browser.Begin(t.Context(), BrowserAuthorization{
		TenantID: "sandbox-secondary", ConnectionID: "default-connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser", ExplicitTenant: true,
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("connection from another tenant was accepted: %v", err)
	}
}

func TestBrowserBegin_LoginWithoutSelectorKeepsDefaultTenant(t *testing.T) {
	tx := &authTransactions{}
	clock := authClock{now: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
	service, err := NewService(authConnections{}, tx, authFactory{}, authProtector{}, clock, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := NewBrowser(loginAuthorityStore{declared: map[shared.ID]bool{"default": true}}, service, &AdmissionService{}, authProtector{}, clock, &authIDs{}, BrowserConfig{
		TenantID:        "default",
		ReadEnabled:     func(string) bool { return true },
		MutationEnabled: func(string) bool { return true },
		SessionTTL:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Begin(t.Context(), BrowserAuthorization{ConnectionID: "default-connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser"}); err != nil {
		t.Fatal(err)
	}
	if tx.v.TenantID != "default" {
		t.Fatalf("omitted selector changed default login tenant to %q", tx.v.TenantID)
	}
}

func TestBrowserBegin_ExplicitLoginRefusesUndeclaredOrUnservedTenant(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		declared, read, mutate bool
	}{
		{name: "undeclared", declared: false, read: true, mutate: true},
		{name: "read disabled", declared: true, read: false, mutate: true},
		{name: "mutation disabled", declared: true, read: true, mutate: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser, tx := newTenantLoginBrowser(t, tc.declared, tc.read, tc.mutate)
			_, err := browser.Begin(t.Context(), BrowserAuthorization{
				TenantID: "sandbox-secondary", ConnectionID: "secondary-connection", Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser", ExplicitTenant: true,
			})
			if err == nil || tx.v.ID != "" {
				t.Fatalf("unserved tenant began an authorization: err=%v tx=%+v", err, tx.v)
			}
		})
	}
}

func TestBrowserComplete_ExplicitLoginDoesNotIssueSessionWhenReadAuthorityIsRemoved(t *testing.T) {
	readEnabled := true
	tx := &authTransactions{}
	clock := authClock{now: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
	service, err := NewService(tenantLoginConnections{}, tx, authFactory{}, authProtector{}, clock, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := NewBrowser(loginAuthorityStore{declared: map[shared.ID]bool{"sandbox-secondary": true}}, service, &AdmissionService{}, authProtector{}, clock, &authIDs{}, BrowserConfig{
		TenantID: "default",
		ReadEnabled: func(tenant string) bool {
			return tenant == "sandbox-secondary" && readEnabled
		},
		MutationEnabled: func(tenant string) bool { return tenant == "sandbox-secondary" },
		SessionTTL:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	started, err := browser.Begin(t.Context(), BrowserAuthorization{TenantID: "sandbox-secondary", ConnectionID: "secondary-connection", Purpose: ports.IdentityAuthorizationLogin, ExplicitTenant: true, CallerNonce: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	readEnabled = false
	state := strings.TrimPrefix(started.AuthorizationURL, "https://issuer.example/auth?state=")
	if _, err = browser.Complete(t.Context(), BrowserCallback{TenantID: "sandbox-secondary", State: state, Code: "code", CallerNonce: "browser"}); err == nil {
		t.Fatal("callback issued a session after selected tenant lost read authority")
	}
}
