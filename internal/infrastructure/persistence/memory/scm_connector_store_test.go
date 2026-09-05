package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func tctx(tenant string) context.Context {
	return shared.WithTenant(context.Background(), shared.ID(tenant))
}

func conn(id, tenant, host string) scmconnector.Connector {
	c, err := scmconnector.NewConnector(shared.ID(id), shared.ID(tenant), "prod", scmconnector.ProviderGitHub, host, "", scmconnector.AuthPAT, time.Unix(0, 0))
	if err != nil {
		panic(err)
	}
	return *c
}

func TestSCMConnectorStoreResolvesByHostAndKeepsTokenSecret(t *testing.T) {
	s := NewSCMConnectorStore()
	if err := s.Put(tctx("t1"), conn("c1", "t1", "github.com"), []byte("tok-1")); err != nil {
		t.Fatalf("put: %v", err)
	}
	// List/Get expose no token.
	metas, err := s.List(tctx("t1"))
	if err != nil || len(metas) != 1 || metas[0].Host != "github.com" || metas[0].Username != "x-access-token" {
		t.Fatalf("list = %+v err=%v", metas, err)
	}
	// Resolve by host returns the credential.
	cred, ok, err := s.ResolveGitCredential(tctx("t1"), "github.com")
	if err != nil || !ok || cred.Username != "x-access-token" || string(cred.Token) != "tok-1" {
		t.Fatalf("resolve = %+v ok=%v err=%v", cred, ok, err)
	}
	// A host with no connector resolves to ok=false.
	if _, ok, _ := s.ResolveGitCredential(tctx("t1"), "gitlab.com"); ok {
		t.Fatal("unmatched host must resolve ok=false")
	}
}

func TestSCMConnectorStoreTenantIsolation(t *testing.T) {
	s := NewSCMConnectorStore()
	if err := s.Put(tctx("t1"), conn("c1", "t1", "github.com"), []byte("tok-1")); err != nil {
		t.Fatal(err)
	}
	// Another tenant sees nothing and cannot resolve t1's connector.
	if metas, _ := s.List(tctx("t2")); len(metas) != 0 {
		t.Fatalf("tenant t2 must not see t1's connectors: %+v", metas)
	}
	if _, ok, _ := s.ResolveGitCredential(tctx("t2"), "github.com"); ok {
		t.Fatal("tenant t2 must not resolve t1's credential")
	}
	if _, err := s.Get(tctx("t2"), "c1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant Get must be NotFound, got %v", err)
	}
}

func TestSCMConnectorStoreRequiresTokenAndUniqueHost(t *testing.T) {
	s := NewSCMConnectorStore()
	// A Put without a token is refused.
	if err := s.Put(tctx("t1"), conn("c1", "t1", "github.com"), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty token must be rejected, got %v", err)
	}
	if err := s.Put(tctx("t1"), conn("c1", "t1", "github.com"), []byte("tok-1")); err != nil {
		t.Fatal(err)
	}
	// A second connector (different id) for the same host under the tenant is a conflict, mirroring
	// the Postgres UNIQUE(tenant_id, host), so ResolveGitCredential can never be ambiguous.
	if err := s.Put(tctx("t1"), conn("c2", "t1", "github.com"), []byte("tok-2")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a duplicate host must conflict, got %v", err)
	}
	// Re-putting the SAME id updates it in place (not a conflict).
	if err := s.Put(tctx("t1"), conn("c1", "t1", "github.com"), []byte("tok-3")); err != nil {
		t.Fatalf("same-id upsert must be allowed: %v", err)
	}
	cred, ok, _ := s.ResolveGitCredential(tctx("t1"), "github.com")
	if !ok || string(cred.Token) != "tok-3" {
		t.Fatalf("upsert must replace the token: %+v", cred)
	}
}

func TestSCMConnectorStoreDelete(t *testing.T) {
	s := NewSCMConnectorStore()
	_ = s.Put(tctx("t1"), conn("c1", "t1", "github.com"), []byte("tok-1"))
	if err := s.Delete(tctx("t1"), "c1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := s.ResolveGitCredential(tctx("t1"), "github.com"); ok {
		t.Fatal("deleted connector must not resolve")
	}
	if err := s.Delete(tctx("t1"), "c1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleting an absent connector must be NotFound, got %v", err)
	}
}
