package identityuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type identityTestClock struct{ now time.Time }

func (c identityTestClock) Now() time.Time { return c.now }

type identityTestIDs struct{ n int }

func (g *identityTestIDs) NewID() shared.ID { g.n++; return shared.ID("id-" + string(rune('0'+g.n))) }

type identityTestProtector struct{}

func (identityTestProtector) Seal(_ context.Context, plaintext, aad []byte) (string, error) {
	return string(aad) + "|" + string(plaintext), nil
}
func (identityTestProtector) Open(_ context.Context, ciphertext string, aad []byte) ([]byte, error) {
	prefix := string(aad) + "|"
	if len(ciphertext) < len(prefix) || ciphertext[:len(prefix)] != prefix {
		return nil, errors.New("bad aad")
	}
	return []byte(ciphertext[len(prefix):]), nil
}

type identityTestStore struct {
	transaction identity.AuthorizationTransaction
	session     identity.Session
	consumed    bool
}

func (s *identityTestStore) CreateExternalIdentity(context.Context, identity.ExternalIdentity) error {
	return nil
}
func (s *identityTestStore) GetExternalIdentity(context.Context, string, string) (identity.ExternalIdentity, error) {
	return identity.ExternalIdentity{}, shared.ErrNotFound
}
func (s *identityTestStore) CreateAuthorizationTransaction(_ context.Context, tx identity.AuthorizationTransaction) error {
	s.transaction = tx
	return nil
}
func (s *identityTestStore) ConsumeAuthorizationTransaction(_ context.Context, tenantID shared.ID, hash string, now time.Time) (identity.AuthorizationTransaction, error) {
	if s.consumed || s.transaction.TenantID != tenantID || s.transaction.StateHash != hash || !s.transaction.Usable(now) {
		return identity.AuthorizationTransaction{}, shared.ErrNotFound
	}
	s.consumed = true
	return s.transaction, nil
}
func (s *identityTestStore) CreateSession(_ context.Context, session identity.Session) error {
	s.session = session
	return nil
}
func (s *identityTestStore) RotateSession(_ context.Context, _ shared.ID, replacement identity.Session, _ time.Time) error {
	s.session = replacement
	return nil
}
func (s *identityTestStore) GetSessionByTokenHash(_ context.Context, hash string) (identity.Session, error) {
	if s.session.TokenHash != hash {
		return identity.Session{}, shared.ErrNotFound
	}
	return s.session, nil
}
func (s *identityTestStore) RevokeSession(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}

var _ ports.IdentityStore = (*identityTestStore)(nil)

func TestAuthorizationTransactionPersistsHashesAndCiphertextThenBurnsState(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	store, ids := &identityTestStore{}, &identityTestIDs{}
	svc, err := NewService(store, identityTestProtector{}, identityTestClock{now}, ids)
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.BeginAuthorization(context.Background(), "tenant", "pkce-verifier", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if store.transaction.StateHash == started.State || store.transaction.NonceHash == started.Nonce || store.transaction.PKCEVerifierCiphertext == "pkce-verifier" {
		t.Fatalf("store must not receive raw transaction secrets: %+v", store.transaction)
	}
	consumed, err := svc.ConsumeAuthorization(context.Background(), "tenant", started.State)
	if err != nil || consumed.PKCEVerifier != "pkce-verifier" || consumed.NonceHash != stateHash(started.Nonce) || consumed.TenantID != "tenant" {
		t.Fatalf("consume transaction: %+v err=%v", consumed, err)
	}
	if _, err := svc.ConsumeAuthorization(context.Background(), "tenant", started.State); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("replay must fail: %v", err)
	}
}

func TestCreateSessionPersistsOnlyTokenHashes(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	store, ids := &identityTestStore{}, &identityTestIDs{}
	svc, _ := NewService(store, identityTestProtector{}, identityTestClock{now}, ids)
	created, err := svc.CreateSession(context.Background(), "tenant", "user", map[string]string{"ip": "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if store.session.TokenHash == created.Token || store.session.CSRFTokenHash == created.CSRFToken {
		t.Fatal("session store must receive hashes rather than raw tokens")
	}
	if _, err := svc.AuthenticateSession(context.Background(), "tenant", created.Token); err != nil {
		t.Fatalf("authenticate fresh session: %v", err)
	}
}

// TestRotateSessionEnforcesAbsoluteMaxAge locks in the absolute-lifetime cap (review LOW-1): a rotation
// refreshes the sliding TTL and carries the immutable origin forward, but a session lineage past
// identity.MaxSessionAge is refused so the browser is forced back through OIDC.
func TestRotateSessionEnforcesAbsoluteMaxAge(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	store, ids := &identityTestStore{}, &identityTestIDs{}
	svc, _ := NewService(store, identityTestProtector{}, identityTestClock{now}, ids)

	// Within the cap: rotation succeeds and the replacement inherits the original origin (not reset).
	fresh, err := identity.NewSession("s1", "tenant", "user", stateHash("tok"), stateHash("csrf"), nil, now.Add(time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.RotateSession(context.Background(), fresh, nil, time.Hour)
	if err != nil {
		t.Fatalf("within-cap rotation must succeed: %v", err)
	}
	if !rotated.Session.OriginAt.Equal(fresh.OriginAt) {
		t.Fatalf("rotation must carry the immutable origin: got %s want %s", rotated.Session.OriginAt, fresh.OriginAt)
	}

	// Past the cap: refused with ErrForbidden even though the sliding expiry is still in the future.
	old, err := identity.NewSession("s2", "tenant", "user", stateHash("tok2"), stateHash("csrf2"), nil, now.Add(time.Hour), now.Add(-(identity.MaxSessionAge + time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateSession(context.Background(), old, nil, time.Hour); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("past-cap rotation must be forbidden, got %v", err)
	}
}
