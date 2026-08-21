package postgres

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

func TestPostgresIdentityStore(t *testing.T) {
	dsn := testDSN(t)
	base := context.Background()
	if err := Migrate(base, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(base, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := shared.WithTenant(base, shared.DefaultTenant)
	if _, err := pool.Exec(base, `TRUNCATE oidc_sessions, oidc_authorization_transactions, oidc_external_identities CASCADE`); err != nil {
		t.Fatalf("truncate identity tables: %v", err)
	}
	if _, err := pool.Exec(base, `INSERT INTO tenants(id,name) VALUES ('default', 'default tenant') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	users := NewUserRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	u, err := user.New(shared.ID("oidc-user-"+randHex(t)), "default", "OIDC User", user.RoleMember, "key-"+randHex(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(base, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	store, err := NewIdentityStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	external, _ := identity.NewExternalIdentity("identity-"+shared.ID(randHex(t)), "default", u.ID, "https://issuer", "subject", now)
	if err := store.CreateExternalIdentity(ctx, external); err != nil {
		t.Fatalf("link external identity: %v", err)
	}
	if err := store.CreateExternalIdentity(ctx, external); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate issuer/subject must conflict: %v", err)
	}
	if got, err := store.GetExternalIdentity(ctx, external.Issuer, external.Subject); err != nil || got.UserID != u.ID {
		t.Fatalf("identity lookup: got=%+v err=%v", got, err)
	}

	transaction, _ := identity.NewAuthorizationTransaction("tx-"+shared.ID(randHex(t)), "default", "state-"+randHex(t), "nonce-hash", "ciphertext", now.Add(time.Minute), now)
	if err := store.CreateAuthorizationTransaction(ctx, transaction); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeAuthorizationTransaction(ctx, "default", transaction.StateHash, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("only one replica may consume a transaction, got %d", successes)
	}
	expired, _ := identity.NewAuthorizationTransaction("expired-"+shared.ID(randHex(t)), "default", "expired-"+randHex(t), "nonce", "ciphertext", now.Add(time.Second), now)
	if err := store.CreateAuthorizationTransaction(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationTransaction(ctx, "default", expired.StateHash, now.Add(time.Second)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expired transaction must not be consumable: %v", err)
	}

	session, _ := identity.NewSession("session-"+shared.ID(randHex(t)), "default", u.ID, "token-"+randHex(t), "csrf-hash", map[string]string{"ip": "127.0.0.1"}, now.Add(time.Hour), now)
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}
	replacement, _ := identity.NewSession("replacement-"+shared.ID(randHex(t)), "default", u.ID, "replacement-token-"+randHex(t), "replacement-csrf", nil, now.Add(time.Hour), now)
	if err := store.RotateSession(ctx, session.ID, replacement, now.Add(time.Second)); err != nil {
		t.Fatalf("rotate session: %v", err)
	}
	oldSession, err := store.GetSessionByTokenHash(ctx, session.TokenHash)
	if err != nil || oldSession.RevokedAt == nil || oldSession.Active(now.Add(time.Second)) {
		t.Fatalf("rotated session must revoke old token: got=%+v err=%v", oldSession, err)
	}
	if got, err := store.GetSessionByTokenHash(ctx, replacement.TokenHash); err != nil || !got.Active(now.Add(time.Second)) {
		t.Fatalf("replacement session must be active: got=%+v err=%v", got, err)
	}
	second, _ := identity.NewSession("second-"+shared.ID(randHex(t)), "default", u.ID, "second-token-"+randHex(t), "second-csrf", nil, now.Add(time.Hour), now)
	if err := store.RotateSession(ctx, session.ID, second, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rotating a revoked session must fail atomically: %v", err)
	}
	if _, err := store.GetSessionByTokenHash(ctx, second.TokenHash); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("failed rotation must not persist replacement: %v", err)
	}
	if err := store.RevokeSession(ctx, replacement.TenantID, replacement.ID, now); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if err := store.RevokeSession(ctx, replacement.TenantID, replacement.ID, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second revoke must conflict: %v", err)
	}
	gotSession, err := store.GetSessionByTokenHash(ctx, replacement.TokenHash)
	if err != nil || gotSession.RevokedAt == nil || gotSession.Active(now) {
		t.Fatalf("revoked session must be retained but inactive: got=%+v err=%v", gotSession, err)
	}
}
