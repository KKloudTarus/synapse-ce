package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

func identityMemoryStore(t *testing.T) (*IdentityStore, context.Context, time.Time) {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	users := NewUserRepository()
	u, err := user.New("user", "tenant-a", "User", user.RoleMember, "key-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	store, err := NewIdentityStore(users)
	if err != nil {
		t.Fatal(err)
	}
	return store, shared.WithTenant(context.Background(), "tenant-a"), now
}

func TestIdentityStoreUniquenessAndTenantLinkage(t *testing.T) {
	store, ctx, now := identityMemoryStore(t)
	external, _ := identity.NewExternalIdentity("identity", "tenant-a", "user", "https://issuer", "subject", now)
	if err := store.CreateExternalIdentity(ctx, external); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateExternalIdentity(ctx, external); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate issuer/subject must conflict, got %v", err)
	}
	wrongTenant, _ := identity.NewExternalIdentity("wrong", "tenant-b", "user", "https://issuer-b", "subject", now)
	if err := store.CreateExternalIdentity(ctx, wrongTenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant user link must be forbidden, got %v", err)
	}
}

func TestIdentityStoreTransactionReplayAndExpiry(t *testing.T) {
	store, ctx, now := identityMemoryStore(t)
	transaction, _ := identity.NewAuthorizationTransaction("tx", "tenant-a", "state", "nonce", "ciphertext", now.Add(time.Minute), now)
	if err := store.CreateAuthorizationTransaction(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ConsumeAuthorizationTransaction(ctx, "tenant-a", "state", now); err != nil || got.ID != transaction.ID {
		t.Fatalf("first consume: got=%+v err=%v", got, err)
	}
	if _, err := store.ConsumeAuthorizationTransaction(ctx, "tenant-a", "state", now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("replay must fail, got %v", err)
	}
	expired, _ := identity.NewAuthorizationTransaction("expired", "tenant-a", "expired-state", "nonce", "ciphertext", now.Add(time.Second), now)
	if err := store.CreateAuthorizationTransaction(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationTransaction(ctx, "tenant-a", "expired-state", now.Add(time.Second)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expired transaction must fail closed, got %v", err)
	}
}

func TestIdentityStoreConsumesTransactionOnceUnderRace(t *testing.T) {
	store, ctx, now := identityMemoryStore(t)
	transaction, _ := identity.NewAuthorizationTransaction("tx", "tenant-a", "state", "nonce", "ciphertext", now.Add(time.Minute), now)
	if err := store.CreateAuthorizationTransaction(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeAuthorizationTransaction(ctx, "tenant-a", "state", now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("exactly one transaction consumer must win, got %d", successes)
	}
}

func TestIdentityStoreSessionRevocationAndTenantLinkage(t *testing.T) {
	store, ctx, now := identityMemoryStore(t)
	session, _ := identity.NewSession("session", "tenant-a", "user", "token", "csrf", nil, now.Add(time.Hour), now)
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	replacement, _ := identity.NewSession("replacement", "tenant-a", "user", "replacement-token", "replacement-csrf", nil, now.Add(time.Hour), now)
	if err := store.RotateSession(ctx, session.ID, replacement, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if old, err := store.GetSessionByTokenHash(ctx, "token"); err != nil || old.Active(now.Add(time.Second)) {
		t.Fatalf("old token remained active: got=%+v err=%v", old, err)
	}
	if err := store.RevokeSession(ctx, "tenant-b", replacement.ID, now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("wrong tenant must not find session, got %v", err)
	}
	if err := store.RevokeSession(ctx, "tenant-a", replacement.ID, now); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSessionByTokenHash(ctx, "replacement-token")
	if err != nil || got.RevokedAt == nil || got.Active(now) {
		t.Fatalf("revoked session must remain persisted but inactive: got=%+v err=%v", got, err)
	}
}
