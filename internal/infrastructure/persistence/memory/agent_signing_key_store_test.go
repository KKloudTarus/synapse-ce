package memory

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mkSK(t *testing.T, agent shared.ID, nb, na time.Time) fleetagent.AgentSigningKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	k, err := fleetagent.NewSigningKey(agent, fleetagent.PurposeDetectionBatch, pub, nb, na)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	return k
}

func TestSigningKeyStoreRegisterResolve(t *testing.T) {
	s := NewAgentSigningKeyStore()
	k := mkSK(t, "agent:1", time.Unix(1000, 0), time.Unix(2000, 0))
	if err := s.Register(ctxT("t1"), k); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, err := s.ResolveSigningKey(ctxT("t1"), "agent:1", k.KeyID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.KeyID != k.KeyID || !got.PublicKey.Equal(k.PublicKey) {
		t.Errorf("resolved key does not match the registered one")
	}
	// Unknown key + cross-tenant both fail closed with ErrNotFound.
	if _, err := s.ResolveSigningKey(ctxT("t1"), "agent:1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown key must be ErrNotFound, got %v", err)
	}
	if _, err := s.ResolveSigningKey(ctxT("t2"), "agent:1", k.KeyID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant resolve must be ErrNotFound, got %v", err)
	}
}

func TestSigningKeyStoreFailsClosedWithoutTenant(t *testing.T) {
	s := NewAgentSigningKeyStore()
	k := mkSK(t, "agent:1", time.Unix(1000, 0), time.Unix(2000, 0))
	// A tenant-less context must be refused, not silently bucketed under a default tenant — this store
	// is a security registry and mirrors the fail-closed Postgres behavior.
	if err := s.Register(context.Background(), k); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Register without a tenant must fail closed, got %v", err)
	}
	if _, err := s.ResolveSigningKey(context.Background(), "agent:1", k.KeyID); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Resolve without a tenant must fail closed, got %v", err)
	}
	if _, err := s.ListByAgent(context.Background(), "agent:1"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("ListByAgent without a tenant must fail closed, got %v", err)
	}
	if err := s.Revoke(context.Background(), "agent:1", k.KeyID, time.Unix(1500, 0)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Revoke without a tenant must fail closed, got %v", err)
	}
}

func TestSigningKeyStoreRegisterIdempotentAndConflict(t *testing.T) {
	s := NewAgentSigningKeyStore()
	k := mkSK(t, "agent:1", time.Unix(1000, 0), time.Unix(2000, 0))
	if err := s.Register(ctxT("t1"), k); err != nil {
		t.Fatal(err)
	}
	// Identical re-registration is a no-op (at-least-once safe).
	if err := s.Register(ctxT("t1"), k); err != nil {
		t.Errorf("identical re-register must be a no-op, got %v", err)
	}
	if keys, _ := s.ListByAgent(ctxT("t1"), "agent:1"); len(keys) != 1 {
		t.Fatalf("a duplicate register must not create a second row, got %d", len(keys))
	}
	// A DIFFERENT registration under the same KeyID (same public key, different window) is refused —
	// a KeyID can never be re-pointed (anti-rollback).
	rebind := k
	rebind.NotAfter = time.Unix(9999, 0)
	if err := s.Register(ctxT("t1"), rebind); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("re-pointing a KeyID must conflict, got %v", err)
	}
}

func TestSigningKeyStoreListAndRevoke(t *testing.T) {
	s := NewAgentSigningKeyStore()
	older := mkSK(t, "agent:1", time.Unix(1000, 0), time.Unix(2000, 0))
	newer := mkSK(t, "agent:1", time.Unix(1500, 0), time.Unix(2500, 0))
	other := mkSK(t, "agent:2", time.Unix(1000, 0), time.Unix(2000, 0))
	for _, k := range []fleetagent.AgentSigningKey{older, newer, other} {
		if err := s.Register(ctxT("t1"), k); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.ListByAgent(ctxT("t1"), "agent:1")
	if len(list) != 2 || list[0].KeyID != newer.KeyID {
		t.Fatalf("ListByAgent must return this agent's keys newest-first, got %+v", list)
	}

	// Revoke is monotonic: a second revoke at a later time keeps the first RevokedAt.
	if err := s.Revoke(ctxT("t1"), "agent:1", older.KeyID, time.Unix(1800, 0)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.Revoke(ctxT("t1"), "agent:1", older.KeyID, time.Unix(1900, 0)); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	got, _ := s.ResolveSigningKey(ctxT("t1"), "agent:1", older.KeyID)
	if !got.RevokedAt.Equal(time.Unix(1800, 0).UTC()) {
		t.Errorf("revocation must be monotonic (kept first time), got %v", got.RevokedAt)
	}
	// Revoking an unknown key is ErrNotFound.
	if err := s.Revoke(ctxT("t1"), "agent:1", "nope", time.Unix(1800, 0)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("revoking an unknown key must be ErrNotFound, got %v", err)
	}
}
