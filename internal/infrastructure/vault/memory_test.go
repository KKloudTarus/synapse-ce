package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func newMemVault(t *testing.T) *MemoryVault {
	t.Helper()
	c, err := NewCipher(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewMemoryVault(c, nil)
}

func TestMemoryVaultPutResolve(t *testing.T) {
	v := newMemVault(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	if err := v.Put(ctx, "eng1", "github_pat", []byte("ghp_secret")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Resolve(ctx, "eng1", "github_pat")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("ghp_secret")) {
		t.Fatalf("resolve = %q", got)
	}
	// Scoped per engagement: another engagement cannot read it.
	if _, err := v.Resolve(ctx, "eng2", "github_pat"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-engagement resolve must be ErrNotFound, got %v", err)
	}
}

func TestMemoryVaultUpsertReplacesSecret(t *testing.T) {
	v := newMemVault(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	_ = v.Put(ctx, "eng1", "tok", []byte("old"))
	metas, _ := v.List(ctx, "eng1")
	created := metas[0].CreatedAt
	_ = v.Put(ctx, "eng1", "tok", []byte("new"))
	got, _ := v.Resolve(ctx, "eng1", "tok")
	if !bytes.Equal(got, []byte("new")) {
		t.Errorf("upsert must replace the secret, got %q", got)
	}
	metas, _ = v.List(ctx, "eng1")
	if !metas[0].CreatedAt.Equal(created) {
		t.Error("upsert must preserve the original CreatedAt")
	}
}

func TestMemoryVaultListNamesOnly(t *testing.T) {
	v := newMemVault(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	_ = v.Put(ctx, "eng1", "b_tok", []byte("x"))
	_ = v.Put(ctx, "eng1", "a_tok", []byte("y"))
	_ = v.Put(ctx, "eng2", "other", []byte("z"))
	metas, err := v.List(ctx, "eng1")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 || metas[0].Name != "a_tok" || metas[1].Name != "b_tok" {
		t.Fatalf("list should be the 2 eng1 names, sorted: %+v", metas)
	}
}

func TestMemoryVaultDelete(t *testing.T) {
	v := newMemVault(t)
	ctx := shared.WithTenant(context.Background(), "t1")
	_ = v.Put(ctx, "eng1", "tok", []byte("x"))
	if err := v.Delete(ctx, "eng1", "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(ctx, "eng1", "tok"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("resolve after delete must be ErrNotFound, got %v", err)
	}
	if err := v.Delete(ctx, "eng1", "tok"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("deleting a missing credential must be ErrNotFound, got %v", err)
	}
}

func TestMemoryVaultRejectsBadName(t *testing.T) {
	v := newMemVault(t)
	for _, bad := range []string{"", "has space", "semi;colon", "$(inject)", "a/b"} {
		if err := v.Put(shared.WithTenant(context.Background(), "t1"), "eng1", bad, []byte("x")); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("name %q must be rejected, got %v", bad, err)
		}
	}
}

// TestMemoryVaultIsTenantBound keeps the test twin honest: a context without a tenant is refused and
// another tenant naming the same engagement reads nothing, as with the Postgres vault (#1687).
func TestMemoryVaultIsTenantBound(t *testing.T) {
	v := newMemVault(t)
	a := shared.WithTenant(context.Background(), "ta")
	b := shared.WithTenant(context.Background(), "tb")
	if err := v.Put(a, "eng1", "token", []byte("a-secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(context.Background(), "eng1", "token"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unscoped resolve: %v, want a validation refusal", err)
	}
	if _, err := v.Resolve(b, "eng1", "token"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant resolved the secret: %v", err)
	}
	if list, err := v.List(b, "eng1"); err != nil || len(list) != 0 {
		t.Fatalf("another tenant listed %d secrets (%v)", len(list), err)
	}
	if err := v.Delete(b, "eng1", "token"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant deleted the secret: %v", err)
	}
	if got, err := v.Resolve(a, "eng1", "token"); err != nil || string(got) != "a-secret" {
		t.Fatalf("own resolve = %q, %v", got, err)
	}
}
