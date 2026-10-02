package identitybff

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	identityuc "github.com/KKloudTarus/synapse-ce/internal/usecase/identityuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

const (
	testIssuer = "https://issuer.example"
	testTenant = shared.ID("tenant")
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = t }

type testIDs struct {
	mu sync.Mutex
	n  int
}

func (g *testIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID(fmt.Sprintf("id-%d", g.n))
}

type testProtector struct{}

func (testProtector) Seal(_ context.Context, plain, _ []byte) (string, error) {
	return string(plain), nil
}
func (testProtector) Open(_ context.Context, ciphertext string, _ []byte) ([]byte, error) {
	return []byte(ciphertext), nil
}

type nopAudit struct{}

func (nopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

// fakeProvider is a deterministic OpenID Provider: it returns exactly the identity it is given
// once the nonce round-trips. Signature, issuer, and audience validation belong to the real
// adapter and are not simulated here.
type fakeProvider struct {
	nonce    string
	identity ports.OIDCIdentity
}

func (p *fakeProvider) GenerateVerifier() string { return "test-pkce-verifier-value-0123456789" }
func (p *fakeProvider) AuthorizationURL(state, nonce, _ string) (string, error) {
	p.nonce = nonce
	return "https://issuer.example/auth?state=" + url.QueryEscape(state), nil
}
func (p *fakeProvider) ExchangeAndVerify(_ context.Context, _, _, nonce string) (ports.OIDCIdentity, error) {
	if nonce != p.nonce {
		return ports.OIDCIdentity{}, errors.New("nonce mismatch")
	}
	return p.identity, nil
}

// countingStore wraps the in-memory identity store to count writes and inject dependency failures.
type countingStore struct {
	*memory.IdentityStore
	mu                   sync.Mutex
	sessions             int
	links                int
	tamperTenant         bool
	getIdentityErr       error
	getSessionErr        error
	beforeSessionWrite   chan struct{}
	continueSessionWrite chan struct{}
}

func (s *countingStore) CreateSession(ctx context.Context, session identity.Session) error {
	s.pauseBeforeSessionWrite()
	if err := s.IdentityStore.CreateSession(ctx, session); err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) pauseBeforeSessionWrite() {
	s.mu.Lock()
	before, resume := s.beforeSessionWrite, s.continueSessionWrite
	s.beforeSessionWrite = nil
	s.continueSessionWrite = nil
	s.mu.Unlock()
	if before != nil {
		close(before)
		<-resume
	}
}
func (s *countingStore) CreateExternalIdentity(ctx context.Context, external identity.ExternalIdentity) error {
	if err := s.IdentityStore.CreateExternalIdentity(ctx, external); err != nil {
		return err
	}
	s.mu.Lock()
	s.links++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) CreateSessionForExternalIdentity(ctx context.Context, issuer, subject string, approvedUserUpdatedAt time.Time, session identity.Session) error {
	s.pauseBeforeSessionWrite()
	if err := s.IdentityStore.CreateSessionForExternalIdentity(ctx, issuer, subject, approvedUserUpdatedAt, session); err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) GetExternalIdentity(ctx context.Context, issuer, subject string) (identity.ExternalIdentity, error) {
	if s.getIdentityErr != nil {
		return identity.ExternalIdentity{}, s.getIdentityErr
	}
	return s.IdentityStore.GetExternalIdentity(ctx, issuer, subject)
}
func (s *countingStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (identity.Session, error) {
	if s.getSessionErr != nil {
		return identity.Session{}, s.getSessionErr
	}
	return s.IdentityStore.GetSessionByTokenHash(ctx, tokenHash)
}
func (s *countingStore) ConsumeAuthorizationTransaction(ctx context.Context, tenantID shared.ID, stateHash string, now time.Time) (identity.AuthorizationTransaction, error) {
	tx, err := s.IdentityStore.ConsumeAuthorizationTransaction(ctx, tenantID, stateHash, now)
	if err == nil && s.tamperTenant {
		tx.TenantID = "other-tenant"
	}
	return tx, err
}
func (s *countingStore) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions, s.links
}

// watchedUsers wraps the in-memory users repository to observe role writes and inject a lookup
// failure.
type watchedUsers struct {
	*memory.UserRepository
	mu     sync.Mutex
	writes int
	getErr error
}

func (u *watchedUsers) GetByID(ctx context.Context, tenantID, id shared.ID) (*user.User, error) {
	if u.getErr != nil {
		return nil, u.getErr
	}
	return u.UserRepository.GetByID(ctx, tenantID, id)
}
func (u *watchedUsers) Update(ctx context.Context, tenantID shared.ID, v *user.User) error {
	u.mu.Lock()
	u.writes++
	u.mu.Unlock()
	return u.UserRepository.Update(ctx, tenantID, v)
}
func (u *watchedUsers) Upsert(ctx context.Context, v *user.User) error {
	u.mu.Lock()
	u.writes++
	u.mu.Unlock()
	return u.UserRepository.Upsert(ctx, v)
}
func (u *watchedUsers) writeCount() int { u.mu.Lock(); defer u.mu.Unlock(); return u.writes }

type bffRig struct {
	svc      *Service
	users    *usersuc.Service
	repo     *watchedUsers
	store    *countingStore
	provider *fakeProvider
	clock    *testClock
	admin    usersuc.Actor
	tenant   shared.ID
}

var loginTime = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func newBFFRig(t *testing.T, tenant shared.ID) *bffRig {
	t.Helper()
	clock := &testClock{now: loginTime}
	ids := &testIDs{}
	repo := &watchedUsers{UserRepository: memory.NewUserRepository()}
	raw, err := memory.NewIdentityStore(repo)
	if err != nil {
		t.Fatal(err)
	}
	store := &countingStore{IdentityStore: raw}
	users, err := usersuc.NewService(repo, nopAudit{}, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	users.SetTransactionRunner(memory.NewTenantTransactionRunner())
	users.SetIdentityStore(store)
	if err := users.SetOIDCLinking(testIssuer, tenant); err != nil {
		t.Fatal(err)
	}
	admin, _, err := users.CreateUser(context.Background(), usersuc.Actor{ID: usersuc.BootstrapID}, tenant.String(), "Admin", user.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identityuc.NewService(store, testProtector{}, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	// A 24h sliding TTL keeps expiry out of the way so the 12h lineage cap is what is measured.
	svc, err := NewService(provider, identities, store, repo, clock, ids, Config{TenantID: tenant, TransactionTTL: time.Minute, SessionTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return &bffRig{svc: svc, users: users, repo: repo, store: store, provider: provider, clock: clock, admin: usersuc.Actor{ID: admin.ID.String(), TenantID: tenant.String()}, tenant: tenant}
}

func (r *bffRig) login(t *testing.T, id ports.OIDCIdentity) (Session, error) {
	t.Helper()
	r.provider.identity = id
	start, err := r.svc.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	return r.svc.Complete(context.Background(), parsed.Query().Get("state"), "code", r.provider.nonce)
}

type loginResult struct {
	value Session
	err   error
}

type pausedLogin struct {
	result <-chan loginResult
	resume chan struct{}
}

func (r *bffRig) pauseLoginBeforeSessionWrite(t *testing.T, id ports.OIDCIdentity) pausedLogin {
	t.Helper()
	paused, resume := make(chan struct{}), make(chan struct{})
	r.store.mu.Lock()
	r.store.beforeSessionWrite, r.store.continueSessionWrite = paused, resume
	r.store.mu.Unlock()
	result := make(chan loginResult, 1)
	go func() {
		value, err := r.login(t, id)
		result <- loginResult{value: value, err: err}
	}()
	<-paused
	return pausedLogin{result: result, resume: resume}
}

func (r *bffRig) member(t *testing.T, name string, role user.Role) *user.User {
	t.Helper()
	u, _, err := r.users.CreateUser(context.Background(), r.admin, "", name, role)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// preexistingLink writes a link the way earlier releases did, outside the link command.
func (r *bffRig) preexistingLink(t *testing.T, userID shared.ID, subject string) {
	t.Helper()
	link, err := identity.NewExternalIdentity(shared.ID("legacy-"+subject), r.tenant, userID, testIssuer, subject, loginTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.store.IdentityStore.CreateExternalIdentity(shared.WithTenant(context.Background(), r.tenant), link); err != nil {
		t.Fatal(err)
	}
}

func subject(sub string) ports.OIDCIdentity {
	return ports.OIDCIdentity{Issuer: testIssuer, Subject: sub}
}

func TestPreexistingApprovedLinkSignsIn(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	alice := rig.member(t, "Alice", user.RoleReviewer)
	rig.preexistingLink(t, alice.ID, "sub-alice")
	session, err := rig.login(t, subject("sub-alice"))
	if err != nil {
		t.Fatalf("preexisting link must keep working: %v", err)
	}
	if session.Token == "" || session.Principal.ID != alice.ID.String() || session.Principal.Role != string(user.RoleReviewer) || session.Principal.TenantID != testTenant.String() {
		t.Fatalf("session = %+v", session.Principal)
	}
	p, err := rig.svc.Authenticate(context.Background(), session.Token, "", false)
	if err != nil || p.ID != alice.ID.String() || p.SessionID == "" || !p.AuthenticatedAt.Equal(loginTime) {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}
}

func TestUnknownSubjectIsDeniedWithNoRowsCreated(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	before, _ := rig.repo.List(context.Background(), testTenant)
	sessions, links := rig.store.counts()
	_, err := rig.login(t, ports.OIDCIdentity{Issuer: testIssuer, Subject: "stranger", Email: "admin@example.com", EmailVerified: true, Name: "Admin"})
	if !errors.Is(err, ErrAccessDenied) || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unknown subject must be access denied: %v", err)
	}
	after, _ := rig.repo.List(context.Background(), testTenant)
	gotSessions, gotLinks := rig.store.counts()
	if len(after) != len(before) || gotSessions != sessions || gotLinks != links || rig.repo.writeCount() != 0 {
		t.Fatalf("unknown subject created rows: users %d->%d sessions %d->%d links %d->%d writes=%d", len(before), len(after), sessions, gotSessions, links, gotLinks, rig.repo.writeCount())
	}
}

func TestOperatorApprovedLinkThenCallbackSucceeds(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	bob := rig.member(t, "Bob", user.RoleConsultant)
	if _, err := rig.login(t, subject("sub-bob")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("before approval: %v", err)
	}
	if _, err := rig.users.LinkOIDCIdentity(context.Background(), rig.admin, bob.ID, testIssuer, "sub-bob"); err != nil {
		t.Fatalf("approve link: %v", err)
	}
	session, err := rig.login(t, subject("sub-bob"))
	if err != nil || session.Principal.ID != bob.ID.String() {
		t.Fatalf("approved subject must sign in: %+v %v", session.Principal, err)
	}
}

// The provider no longer delivers a role, so nothing about the IdP identity (groups, name, email)
// can change a Synapse role, integration_admin included, and the callback never writes the user.
func TestIdentityProviderChangesNeverTouchTheRole(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	for _, role := range []user.Role{user.RoleIntegrationAdmin, user.RoleReadOnly, user.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			u := rig.member(t, "User "+string(role), role)
			rig.preexistingLink(t, u.ID, "sub-"+string(role))
			for _, variant := range []ports.OIDCIdentity{
				{Issuer: testIssuer, Subject: "sub-" + string(role), Name: "Renamed"},
				{Issuer: testIssuer, Subject: "sub-" + string(role), Email: "boss@example.com", EmailVerified: true},
			} {
				session, err := rig.login(t, variant)
				if err != nil || session.Principal.Role != string(role) {
					t.Fatalf("login = %+v %v, want role %q", session.Principal, err, role)
				}
			}
			stored, err := rig.repo.GetByID(context.Background(), testTenant, u.ID)
			if err != nil || stored.Role != role {
				t.Fatalf("stored role = %v %v, want %q", stored, err, role)
			}
		})
	}
	if rig.repo.writeCount() != 0 {
		t.Fatalf("callbacks wrote users rows %d times", rig.repo.writeCount())
	}
}

func TestDisableThenReenableKeepsOldSessionDead(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	carol := rig.member(t, "Carol", user.RoleConsultant)
	rig.preexistingLink(t, carol.ID, "sub-carol")
	session, err := rig.login(t, subject("sub-carol"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.users.SetDisabled(context.Background(), rig.admin, carol.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "", false); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("session of a disabled user: %v", err)
	}
	if _, err := rig.login(t, subject("sub-carol")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("a disabled user must not sign in: %v", err)
	}
	if _, err := rig.users.SetDisabled(context.Background(), rig.admin, carol.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "", false); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("re-enable restored an old session: %v", err)
	}
	if _, err := rig.svc.Discover(context.Background(), session.Token); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("re-enable let an old session rotate: %v", err)
	}
	if _, err := rig.login(t, subject("sub-carol")); err != nil {
		t.Fatalf("a re-enabled user signs in again with a new session: %v", err)
	}
}

func TestSessionLineageCapOnEveryAuthentication(t *testing.T) {
	cases := []struct {
		name  string
		after time.Duration
		allow bool
	}{
		{"before the cap", identity.MaxSessionAge - time.Second, true},
		{"at the cap", identity.MaxSessionAge, false},
		{"after the cap", identity.MaxSessionAge + time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newBFFRig(t, testTenant)
			dave := rig.member(t, "Dave", user.RoleReadOnly)
			rig.preexistingLink(t, dave.ID, "sub-dave")
			session, err := rig.login(t, subject("sub-dave"))
			if err != nil {
				t.Fatal(err)
			}
			rig.clock.set(loginTime.Add(tc.after))
			_, authErr := rig.svc.Authenticate(context.Background(), session.Token, "", false)
			_, discoverErr := rig.svc.Discover(context.Background(), session.Token)
			for name, err := range map[string]error{"Authenticate": authErr, "Discover": discoverErr} {
				if tc.allow && err != nil {
					t.Errorf("%s within the cap: %v", name, err)
				}
				if !tc.allow && !errors.Is(err, authz.ErrCredentialInvalid) {
					t.Errorf("%s at or past the cap = %v, want invalid credential", name, err)
				}
			}
		})
	}
}

func TestDependencyOutageIsUnavailableNeverInvalid(t *testing.T) {
	outage := errors.New("database connection refused")
	rig := newBFFRig(t, testTenant)
	erin := rig.member(t, "Erin", user.RoleReadOnly)
	rig.preexistingLink(t, erin.ID, "sub-erin")
	session, err := rig.login(t, subject("sub-erin"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, authz.ErrAuthenticationUnavailable) || errors.Is(err, authz.ErrCredentialInvalid) {
			t.Errorf("%s during an outage = %v, want unavailable only", name, err)
		}
	}
	rig.store.getSessionErr = outage
	_, err = rig.svc.Authenticate(context.Background(), session.Token, "", false)
	check("session lookup", err)
	_, err = rig.svc.Discover(context.Background(), session.Token)
	check("session discovery", err)
	check("logout", rig.svc.Logout(context.Background(), session.Token))
	rig.store.getSessionErr = nil

	rig.repo.getErr = outage
	_, err = rig.svc.Authenticate(context.Background(), session.Token, "", false)
	check("session user lookup", err)
	rig.repo.getErr = nil

	rig.store.getIdentityErr = outage
	_, err = rig.login(t, subject("sub-erin"))
	check("callback link lookup", err)
	rig.store.getIdentityErr = nil

	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "", false); err != nil {
		t.Fatalf("the session must still be valid after the outage: %v", err)
	}
}

func TestAuthenticateCSRFAndLogout(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	fay := rig.member(t, "Fay", user.RoleConsultant)
	rig.preexistingLink(t, fay.ID, "sub-fay")
	session, err := rig.login(t, subject("sub-fay"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "wrong", true); !errors.Is(err, authz.ErrCSRFInvalid) {
		t.Fatalf("CSRF mismatch: %v", err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, session.CSRFToken, true); err != nil {
		t.Fatalf("matching CSRF: %v", err)
	}
	if err := rig.svc.Logout(context.Background(), session.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "", false); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("session after logout: %v", err)
	}
	if err := rig.svc.Logout(context.Background(), session.Token); err != nil {
		t.Fatalf("logout of an already invalid session is a no-op: %v", err)
	}
}

func TestCompleteRejectsStateReplayAndTenantTamper(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	gus := rig.member(t, "Gus", user.RoleReadOnly)
	rig.preexistingLink(t, gus.ID, "sub-gus")
	rig.provider.identity = subject("sub-gus")
	start, err := rig.svc.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(start.URL)
	state := parsed.Query().Get("state")
	if _, err := rig.svc.Complete(context.Background(), state, "code", rig.provider.nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.Complete(context.Background(), state, "code", rig.provider.nonce); err == nil {
		t.Fatal("state replay must fail")
	}
	rig.store.tamperTenant = true
	if _, err := rig.login(t, subject("sub-gus")); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("authorization tenant tamper: %v", err)
	}
}

// A link to the bootstrap operator (which the link command refuses, but an old row could carry) is
// still denied: the bootstrap principal's only credential is SYNAPSE_API_TOKEN.
func TestCompleteRefusesTheBootstrapOperator(t *testing.T) {
	rig := newBFFRig(t, shared.DefaultTenant)
	if err := rig.users.EnsureBootstrapAdmin(context.Background(), "bootstrap-token"); err != nil {
		t.Fatal(err)
	}
	rig.preexistingLink(t, usersuc.BootstrapID, "sub-operator")
	sessions, _ := rig.store.counts()
	if _, err := rig.login(t, subject("sub-operator")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("bootstrap link must be denied: %v", err)
	}
	if got, _ := rig.store.counts(); got != sessions || rig.repo.writeCount() != 0 {
		t.Fatalf("bootstrap login wrote state: sessions %d->%d writes=%d", sessions, got, rig.repo.writeCount())
	}
}

type recordedContacts struct {
	user    shared.ID
	issuer  string
	imports int
	revokes int
	fail    error
}

func (r *recordedContacts) ImportOIDCEmail(_ context.Context, _, user shared.ID, issuer, _ string) error {
	r.imports++
	r.user, r.issuer = user, issuer
	return r.fail
}
func (r *recordedContacts) RevokeOIDCEmail(_ context.Context, _, user shared.ID, issuer string) error {
	r.revokes++
	r.user, r.issuer = user, issuer
	return r.fail
}

// Email is imported only for the subject already resolved by (issuer, subject); it never selects the
// account, and a failed contact sync creates no session.
func TestCompleteSynchronizesVerifiedEmailForTheResolvedSubjectOnly(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	hal := rig.member(t, "Hal", user.RoleReadOnly)
	rig.preexistingLink(t, hal.ID, "sub-hal")
	contacts := &recordedContacts{}
	rig.svc.SetVerifiedEmailImporter(contacts)

	if _, err := rig.login(t, ports.OIDCIdentity{Issuer: testIssuer, Subject: "sub-hal", Email: "hal@example.com", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	if contacts.imports != 1 || contacts.user != hal.ID || contacts.issuer != testIssuer {
		t.Fatalf("verified email import = %+v", contacts)
	}
	if _, err := rig.login(t, subject("sub-hal")); err != nil || contacts.revokes != 1 {
		t.Fatalf("unverified email must revoke: %+v %v", contacts, err)
	}
	if _, err := rig.login(t, ports.OIDCIdentity{Issuer: testIssuer, Subject: "unknown", Email: "hal@example.com", EmailVerified: true}); !errors.Is(err, ErrAccessDenied) || contacts.imports != 1 {
		t.Fatalf("an email must not resolve an unknown subject: %+v %v", contacts, err)
	}
	contacts.fail = errors.New("contact store unavailable")
	sessions, _ := rig.store.counts()
	if _, err := rig.login(t, subject("sub-hal")); err == nil {
		t.Fatal("a failed contact sync must fail the login")
	}
	if got, _ := rig.store.counts(); got != sessions {
		t.Fatalf("failed contact sync created a session: %d -> %d", sessions, got)
	}
}

// After an approved link is removed, the subject's live session is dead and its next callback is
// denied exactly like a subject that was never approved.
func TestUnlinkedSubjectIsDeniedAndItsSessionIsDead(t *testing.T) {
	rig := newBFFRig(t, "tenant-a")
	dana := rig.member(t, "Dana", user.RoleConsultant)
	link, err := rig.users.LinkOIDCIdentity(context.Background(), rig.admin, dana.ID, testIssuer, "sub-dana")
	if err != nil {
		t.Fatalf("approve link: %v", err)
	}
	session, err := rig.login(t, subject("sub-dana"))
	if err != nil {
		t.Fatalf("approved subject must sign in: %v", err)
	}
	if _, err := rig.users.UnlinkOIDCIdentity(context.Background(), rig.admin, dana.ID, link.ID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := rig.svc.Authenticate(context.Background(), session.Token, "", false); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("the session minted through the removed link must be dead: %v", err)
	}
	if _, err := rig.login(t, subject("sub-dana")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("a callback for the unlinked subject must be access_denied: %v", err)
	}
}

func TestApprovedCallbackPausedBeforeIssuanceCannotSurviveUnlink(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	dana := rig.member(t, "Dana", user.RoleConsultant)
	link, err := rig.users.LinkOIDCIdentity(context.Background(), rig.admin, dana.ID, testIssuer, "sub-dana-race")
	if err != nil {
		t.Fatal(err)
	}

	login := rig.pauseLoginBeforeSessionWrite(t, subject("sub-dana-race"))
	if _, err := rig.users.UnlinkOIDCIdentity(context.Background(), rig.admin, dana.ID, link.ID); err != nil {
		t.Fatalf("unlink while callback is paused: %v", err)
	}
	close(login.resume)

	completed := <-login.result
	if !errors.Is(completed.err, ErrAccessDenied) {
		t.Fatalf("paused callback after unlink = %v, want access denied", completed.err)
	}
	if completed.value.Token != "" {
		t.Fatal("callback returned a token after its approval was revoked")
	}
}

func TestApprovedCallbackPausedBeforeIssuanceCannotSurviveDisableAndReenable(t *testing.T) {
	rig := newBFFRig(t, testTenant)
	dana := rig.member(t, "Dana", user.RoleConsultant)
	if _, err := rig.users.LinkOIDCIdentity(context.Background(), rig.admin, dana.ID, testIssuer, "sub-dana-state-race"); err != nil {
		t.Fatal(err)
	}

	rig.clock.set(loginTime.Add(time.Second))
	login := rig.pauseLoginBeforeSessionWrite(t, subject("sub-dana-state-race"))
	rig.clock.set(loginTime.Add(2 * time.Second))
	if _, err := rig.users.SetDisabled(context.Background(), rig.admin, dana.ID, true); err != nil {
		t.Fatalf("disable while callback is paused: %v", err)
	}
	if _, err := rig.users.SetDisabled(context.Background(), rig.admin, dana.ID, false); err != nil {
		t.Fatalf("re-enable while callback is paused: %v", err)
	}
	close(login.resume)

	completed := <-login.result
	if !errors.Is(completed.err, ErrAccessDenied) {
		t.Fatalf("paused callback after disable/re-enable = %v, want access denied", completed.err)
	}
	if completed.value.Token != "" {
		t.Fatal("callback returned a token after the user's credentials were revoked")
	}
}
