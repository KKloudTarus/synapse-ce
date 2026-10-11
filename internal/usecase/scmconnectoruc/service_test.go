package scmconnectoruc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID("conn-" + string(rune('0'+s.n))) }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC) }

func newSvc(t *testing.T) (*Service, *memory.SCMConnectorStore) {
	t.Helper()
	store := memory.NewSCMConnectorStore()
	svc, err := NewService(store, &seqIDs{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func TestCreateStoresAndReturnsMetadataOnly(t *testing.T) {
	svc, store := newSvc(t)
	meta, err := svc.Create(tctx(), CreateInput{
		TenantID: "t1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: "github.com", Token: "ghp_x",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if meta.Host != "github.com" || meta.Username != "x-access-token" {
		t.Fatalf("meta = %+v", meta)
	}
	// The token resolves from the store (sealed there), proving Create persisted it.
	cred, ok, _ := store.ResolveGitCredential(tctx(), "github.com")
	if !ok || string(cred.Token) != "ghp_x" {
		t.Fatalf("stored credential = %+v ok=%v", cred, ok)
	}
}

func TestCreateAPIBaseNeedsTheOperatorAllowlist(t *testing.T) {
	hosts, err := selfhosted.ParseHostAllowlist([]string{"ghe.corp.example", "gitlab.corp.example:8443"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		rules    selfhosted.Rules
		provider scmconnector.Provider
		host     string
		apiBase  string
		ok       bool
	}{
		{"allowlisted GHES", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3", true},
		{"allowlisted GitLab on port", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitLab, "gitlab.corp.example:8443", "https://gitlab.corp.example:8443/api/v4", true},
		{"no API base needs no allowlist", selfhosted.Rules{}, scmconnector.ProviderGitHub, "github.com", "", true},
		{"empty allowlist", selfhosted.Rules{}, scmconnector.ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3", false},
		{"host not allowlisted", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitHub, "ghe.other.example", "https://ghe.other.example/api/v3", false},
		{"http", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitHub, "ghe.corp.example", "http://ghe.corp.example/api/v3", false},
		{"userinfo", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitHub, "ghe.corp.example", "https://u:p@ghe.corp.example/api/v3", false},
		{"query", selfhosted.Rules{Hosts: hosts}, scmconnector.ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3?a=b", false},
		{"private IP without the operator switch", selfhosted.Rules{Hosts: mustHosts(t, "10.0.0.5")}, scmconnector.ProviderGitLab, "10.0.0.5", "https://10.0.0.5/api/v4", false},
		{"Bitbucket Data Center", selfhosted.Rules{Hosts: mustHosts(t, "bb.corp.example")}, scmconnector.ProviderBitbucket, "bb.corp.example", "https://bb.corp.example/rest/api/1.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, store := newSvc(t)
			svc.SetSelfHostedRules(tc.rules)
			meta, err := svc.Create(tctx(), CreateInput{TenantID: "t1", Name: "forge", Provider: tc.provider, Host: tc.host, Username: "bot", Token: "tok", APIBase: tc.apiBase})
			if !tc.ok {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("err = %v, want validation", err)
				}
				if metas, _ := store.List(tctx()); len(metas) != 0 {
					t.Fatalf("a refused connector was stored: %+v", metas)
				}
				return
			}
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if meta.APIBase != tc.apiBase {
				t.Fatalf("api base = %q, want %q", meta.APIBase, tc.apiBase)
			}
		})
	}
}

func mustHosts(t *testing.T, values ...string) selfhosted.HostAllowlist {
	t.Helper()
	hosts, err := selfhosted.ParseHostAllowlist(values)
	if err != nil {
		t.Fatal(err)
	}
	return hosts
}

func TestCreateRequiresAToken(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Create(tctx(), CreateInput{TenantID: "t1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: "github.com"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing token must be ErrValidation, got %v", err)
	}
}

func TestCreateRejectsAnInvalidConnector(t *testing.T) {
	svc, _ := newSvc(t)
	// A bare-label host is refused by the domain.
	if _, err := svc.Create(tctx(), CreateInput{TenantID: "t1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: "localhost", Token: "x"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid host must be ErrValidation, got %v", err)
	}
}

func TestListAndDelete(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Create(tctx(), CreateInput{TenantID: "t1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: "github.com", Token: "x"}); err != nil {
		t.Fatal(err)
	}
	metas, err := svc.List(tctx())
	if err != nil || len(metas) != 1 {
		t.Fatalf("list = %+v err=%v", metas, err)
	}
	if err := svc.Delete(tctx(), metas[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if metas, _ := svc.List(tctx()); len(metas) != 0 {
		t.Fatalf("connector not deleted: %+v", metas)
	}
}

func TestCreateRejectsAnInternalHost(t *testing.T) {
	svc, _ := newSvc(t)
	// A loopback/metadata IP host is refused so a credential is never aimed at an internal address.
	for _, host := range []string{"127.0.0.1", "169.254.169.254"} {
		if _, err := svc.Create(tctx(), CreateInput{TenantID: "t1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: host, Token: "x"}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("internal host %q must be rejected, got %v", host, err)
		}
	}
}
