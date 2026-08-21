package identitybff

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	identityuc "github.com/KKloudTarus/synapse-ce/internal/usecase/identityuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type bffClock struct{ now time.Time }

func (c bffClock) Now() time.Time { return c.now }

type bffIDs struct{ n int }

func (g *bffIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("id-%d", g.n)) }

type bffProtector struct{}

func (bffProtector) Seal(_ context.Context, plain, _ []byte) (string, error) {
	return string(plain), nil
}
func (bffProtector) Open(_ context.Context, ciphertext string, _ []byte) ([]byte, error) {
	return []byte(ciphertext), nil
}

type bffProvider struct{ expectedNonce string }

func (p *bffProvider) GenerateVerifier() string { return "test-pkce-verifier-value-0123456789" }
func (p *bffProvider) AuthorizationURL(state, nonce, _ string) (string, error) {
	p.expectedNonce = nonce
	return "https://issuer.example/auth?state=" + state, nil
}
func (p *bffProvider) ExchangeAndVerify(_ context.Context, _, _, nonce string) (ports.OIDCIdentity, error) {
	if nonce != p.expectedNonce {
		return ports.OIDCIdentity{}, fmt.Errorf("nonce mismatch")
	}
	return ports.OIDCIdentity{Issuer: "https://issuer.example", Subject: "subject", Role: user.RoleAdmin}, nil
}

type bffStore struct {
	transaction  identity.AuthorizationTransaction
	identity     identity.ExternalIdentity
	tamperTenant bool
}

func (s *bffStore) CreateExternalIdentity(_ context.Context, external identity.ExternalIdentity) error {
	s.identity = external
	return nil
}
func (s *bffStore) GetExternalIdentity(_ context.Context, _, _ string) (identity.ExternalIdentity, error) {
	if s.identity.ID.IsZero() {
		return identity.ExternalIdentity{}, shared.ErrNotFound
	}
	return s.identity, nil
}
func (s *bffStore) CreateAuthorizationTransaction(_ context.Context, transaction identity.AuthorizationTransaction) error {
	s.transaction = transaction
	return nil
}
func (s *bffStore) ConsumeAuthorizationTransaction(_ context.Context, _ shared.ID, _ string, _ time.Time) (identity.AuthorizationTransaction, error) {
	transaction := s.transaction
	s.transaction = identity.AuthorizationTransaction{}
	if transaction.ID.IsZero() {
		return identity.AuthorizationTransaction{}, shared.ErrNotFound
	}
	if s.tamperTenant {
		transaction.TenantID = "other"
	}
	return transaction, nil
}
func (s *bffStore) CreateSession(context.Context, identity.Session) error { return nil }
func (s *bffStore) RotateSession(context.Context, shared.ID, identity.Session, time.Time) error {
	return nil
}
func (s *bffStore) GetSessionByTokenHash(context.Context, string) (identity.Session, error) {
	return identity.Session{}, shared.ErrNotFound
}
func (s *bffStore) RevokeSession(context.Context, shared.ID, shared.ID, time.Time) error { return nil }

type bffUsers struct {
	user    *user.User
	created []*user.User
	upserts []*user.User
}

func (s *bffUsers) Create(_ context.Context, u *user.User) error {
	s.created = append(s.created, u)
	if s.user == nil {
		s.user = u
	}
	return nil
}
func (s *bffUsers) Bootstrap(context.Context, *user.User, ports.AuditEntry) error { return nil }
func (s *bffUsers) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if s.user != nil && s.user.ID == id {
		return s.user, nil
	}
	for _, u := range s.created {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (s *bffUsers) GetByAPIKeyHash(context.Context, string) (*user.User, error) {
	return nil, shared.ErrNotFound
}
func (s *bffUsers) List(context.Context) ([]*user.User, error) { return nil, nil }
func (s *bffUsers) Upsert(_ context.Context, u *user.User) error {
	s.upserts = append(s.upserts, u)
	return nil
}

func newBFFTestService(t *testing.T, store *bffStore) (*Service, *bffProvider) {
	service, provider, _ := newBFFTestServiceWithUsers(t, store, true)
	return service, provider
}

// newBFFTestServiceWithUsers builds the BFF. When linked is false the store starts with no
// external identity, exercising first-login provisioning.
func newBFFTestServiceWithUsers(t *testing.T, store *bffStore, linked bool) (*Service, *bffProvider, *bffUsers) {
	t.Helper()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	ids := &bffIDs{}
	clock := bffClock{now: now}
	identityService, err := identityuc.NewService(store, bffProtector{}, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	users := &bffUsers{}
	if linked {
		u, err := user.New("user-1", "tenant", "OIDC Admin", user.RoleAdmin, "hash", now)
		if err != nil {
			t.Fatal(err)
		}
		external, err := identity.NewExternalIdentity("external-1", "tenant", u.ID, "https://issuer.example", "subject", now)
		if err != nil {
			t.Fatal(err)
		}
		store.identity = external
		users.user = u
	}
	provider := &bffProvider{}
	service, err := NewService(provider, identityService, store, users, clock, &bffIDs{n: 100}, Config{TenantID: "tenant", TransactionTTL: time.Minute, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return service, provider, users
}

// A first-time subject must be provisioned and linked; before this the callback failed with
// ErrNotFound and no OIDC login could ever succeed.
func TestCompleteProvisionsAndLinksFirstTimeSubject(t *testing.T) {
	store := &bffStore{}
	service, provider, users := newBFFTestServiceWithUsers(t, store, false)
	start, err := service.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Complete(context.Background(), extractState(start.URL), "code", provider.expectedNonce)
	if err != nil {
		t.Fatalf("first login must provision the subject: %v", err)
	}
	if len(users.created) != 1 {
		t.Fatalf("created users = %d, want 1", len(users.created))
	}
	created := users.created[0]
	if created.Role != user.RoleAdmin || created.TenantID != "tenant" {
		t.Fatalf("provisioned user has wrong identity: %+v", created)
	}
	if store.identity.Subject != "subject" || store.identity.UserID != created.ID {
		t.Fatalf("external identity was not linked: %+v", store.identity)
	}
	if session.Principal.Role != string(user.RoleAdmin) || session.Token == "" || session.CSRFToken == "" {
		t.Fatalf("unexpected session: %+v", session)
	}
	if created.APIKeyHash == "" || created.APIKeyHash == "hash" {
		t.Fatalf("provisioned user must carry an unusable random API key hash")
	}
}

// The operator-configured group mapping is authoritative, so a changed provider group updates
// the stored role instead of rejecting the login.
func TestCompleteAppliesMappedRoleToLinkedUser(t *testing.T) {
	store := &bffStore{}
	service, provider, users := newBFFTestServiceWithUsers(t, store, true)
	users.user.Role = user.RoleReadOnly
	start, err := service.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Complete(context.Background(), extractState(start.URL), "code", provider.expectedNonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(users.upserts) != 1 || users.upserts[0].Role != user.RoleAdmin {
		t.Fatalf("mapped role was not applied: %+v", users.upserts)
	}
	if session.Principal.Role != string(user.RoleAdmin) {
		t.Fatalf("session role = %q", session.Principal.Role)
	}
}

func TestCompleteRejectsStateReplay(t *testing.T) {
	store := &bffStore{}
	service, provider := newBFFTestService(t, store)
	start, err := service.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), extractState(start.URL), "code", provider.expectedNonce); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := service.Complete(context.Background(), extractState(start.URL), "code", provider.expectedNonce); err == nil {
		t.Fatal("replayed state must be rejected")
	}
}

func TestCompleteRejectsAuthorizationTenantTamper(t *testing.T) {
	store := &bffStore{tamperTenant: true}
	service, provider := newBFFTestService(t, store)
	start, err := service.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), extractState(start.URL), "code", provider.expectedNonce); err == nil {
		t.Fatal("tampered authorization tenant must be rejected")
	}
}

func extractState(url string) string { return url[len("https://issuer.example/auth?state="):] }
