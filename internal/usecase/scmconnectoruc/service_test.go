package scmconnectoruc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
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
