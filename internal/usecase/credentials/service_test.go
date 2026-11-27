package credentials

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func newSvc(t *testing.T) (*Service, *vault.MemoryVault, *fakeAudit) {
	t.Helper()
	c, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mv := vault.NewMemoryVault(c, func() time.Time { return time.Unix(0, 0).UTC() })
	audit := &fakeAudit{}
	svc, err := NewService(mv, audit, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, mv, audit
}

func TestSetStoresAndAuditsWithoutValue(t *testing.T) {
	svc, mv, audit := newSvc(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	if err := svc.Set(ctx, "alice", "eng1", "github_pat", []byte("ghp_TOPSECRET")); err != nil {
		t.Fatal(err)
	}
	// The vault holds the secret (resolvable).
	if got, _ := mv.Resolve(ctx, "eng1", "github_pat"); string(got) != "ghp_TOPSECRET" {
		t.Errorf("vault did not store the secret, got %q", got)
	}
	// The audit recorded the name but NEVER the value.
	if len(audit.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Action != "credential.set" || e.Actor != "alice" || e.Metadata["name"] != "github_pat" {
		t.Errorf("audit attribution mismatch: %+v", e)
	}
	for k, v := range e.Metadata {
		if strings.Contains(v, "ghp_TOPSECRET") {
			t.Errorf("the secret value leaked into the audit metadata at %q", k)
		}
	}
}

func TestSetValidation(t *testing.T) {
	svc, _, audit := newSvc(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	if err := svc.Set(ctx, "alice", "eng1", "name", nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty secret must be ErrValidation, got %v", err)
	}
	if err := svc.Set(ctx, "  ", "eng1", "name", []byte("x")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("blank actor must be ErrValidation, got %v", err)
	}
	if err := svc.Set(ctx, "alice", "eng1", "bad name", []byte("x")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid name must be ErrValidation, got %v", err)
	}
	if len(audit.entries) != 0 {
		t.Error("a rejected Set must not audit")
	}
}

func TestListAndDelete(t *testing.T) {
	svc, _, audit := newSvc(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	_ = svc.Set(ctx, "alice", "eng1", "tok_a", []byte("a"))
	_ = svc.Set(ctx, "alice", "eng1", "tok_b", []byte("b"))
	metas, err := svc.List(ctx, "eng1")
	if err != nil || len(metas) != 2 {
		t.Fatalf("list = %v (err %v)", metas, err)
	}
	if err := svc.Delete(ctx, "alice", "eng1", "tok_a"); err != nil {
		t.Fatal(err)
	}
	if metas, _ := svc.List(ctx, "eng1"); len(metas) != 1 || metas[0].Name != "tok_b" {
		t.Errorf("after delete, expected only tok_b: %+v", metas)
	}
	if err := svc.Delete(ctx, "alice", "eng1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("deleting a missing credential must be ErrNotFound, got %v", err)
	}
	// set x2 + delete x1 (the failed delete does not audit).
	if len(audit.entries) != 3 {
		t.Errorf("expected 3 audit entries (2 set + 1 delete), got %d", len(audit.entries))
	}
}
