//go:build keycloak_integration

package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestKeycloakEnterpriseConformance proves the production protocol adapter against a pinned
// Keycloak release and a runtime-role PostgreSQL authority store. Both hostname layouts exercise
// discovery, S256, real code exchange, fresh auth_time, test-before-activate and admission.
func TestKeycloakEnterpriseConformance(t *testing.T) {
	for _, relativePath := range []string{"", "/auth"} {
		t.Run("base"+stringsForPath(relativePath), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
			defer cancel()
			keycloak := newKeycloakFixture(t, relativePath)
			fixture := newKeycloakPostgresFixture(t)
			tenant := shared.ID("kc-" + keycloakRandom(t, 6))
			fixture.tenant(t, tenant)
			fixture.declare(t, tenant)
			browser, connections, admission, proof, bootstrapToken := keycloakBrowser(t, fixture, keycloak, tenant)

			draft, err := connections.SaveDraft(ctx, proof.Principal, bootstrapToken, identityenterprise.ConnectionDraftInput{ID: "workforce", DisplayName: "Keycloak", Issuer: keycloak.issuer, ClientID: keycloak.clientID, ClientSecret: keycloak.clientSecret})
			if err != nil {
				t.Fatal("save real provider draft")
			}
			started, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: draft.ID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "connection-test", AdminProof: &proof})
			if err != nil {
				t.Fatal("begin provider test")
			}
			code, state := keycloak.authorize(ctx, started.AuthorizationURL, "recipient@example.test")
			result, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: state, Code: code, CallerNonce: "connection-test"})
			if err != nil || !result.TestOnly {
				t.Fatal("real provider test callback was not accepted")
			}
			active, err := connections.Activate(ctx, proof.Principal, bootstrapToken, draft.ID, draft.DraftRevision, draft.Version)
			if err != nil {
				t.Fatal("activate tested real provider")
			}

			unknownProvider := keycloak.provider()
			unknownVerifier := unknownProvider.GenerateVerifier()
			unknownURL, err := unknownProvider.AuthorizationURLWithMaxAge(ctx, "unknown-positive", "unknown-positive", unknownVerifier, 15*time.Minute)
			if err != nil {
				t.Fatal("start unapproved provider identity control")
			}
			controlCode, _ := keycloak.authorize(ctx, unknownURL, "unknown@example.test")
			unknownIdentity, err := unknownProvider.ExchangeAndVerifyWithMaxAge(ctx, controlCode, unknownVerifier, "unknown-positive", 15*time.Minute)
			if err != nil || unknownIdentity.Subject == "" || unknownIdentity.Issuer != keycloak.issuer {
				t.Fatal("unapproved Keycloak identity did not pass real protocol verification")
			}

			before := fixture.authorityCounts(t, tenant)
			unknown, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "unknown-login"})
			if err != nil {
				t.Fatal("begin unknown login")
			}
			unknownCode, unknownState := keycloak.authorize(ctx, unknown.AuthorizationURL, "unknown@example.test")
			if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: unknownState, Code: unknownCode, CallerNonce: "unknown-login"}); !errors.Is(err, shared.ErrForbidden) {
				t.Fatal("unapproved real provider identity was admitted")
			}
			if after := fixture.authorityCounts(t, tenant); after != before {
				t.Fatalf("unknown provider identity changed authority: before=%v after=%v", before, after)
			}

			// Prove realm B issues a valid, independently verified response before routing its
			// code and token response through A's transaction. This exercises the verifier at
			// the signed issuer boundary rather than treating any callback error as a pass.
			providerB := keycloak.providerB()
			verifierB := providerB.GenerateVerifier()
			urlB, err := providerB.AuthorizationURLWithMaxAge(ctx, "realm-b-positive", "realm-b-positive", verifierB, 15*time.Minute)
			if err != nil {
				t.Fatal("start realm B verification")
			}
			codeB, _ := keycloak.authorize(ctx, urlB, "recipient@example.test")
			identityB, err := providerB.ExchangeAndVerifyWithMaxAge(ctx, codeB, verifierB, "realm-b-positive", 15*time.Minute)
			if err != nil || identityB.Issuer == keycloak.issuer {
				t.Fatal("realm B signed identity was not independently verified")
			}
			before = fixture.authorityCounts(t, tenant)
			wrongRealm, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "wrong-realm"})
			if err != nil {
				t.Fatal("begin wrong realm login")
			}
			keycloak.substituteNextAFlowWithB()
			wrongCode, wrongState := keycloak.authorize(ctx, wrongRealm.AuthorizationURL, "recipient@example.test")
			if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: wrongState, Code: wrongCode, CallerNonce: "wrong-realm"}); err == nil || !strings.Contains(err.Error(), "failed to verify signature") {
				t.Fatal("realm B signed response was not rejected by A's real verifier")
			}
			if after := fixture.authorityCounts(t, tenant); after != before {
				t.Fatalf("wrong realm response changed authority: before=%v after=%v", before, after)
			}
			// The browser path above proves the ordinary A JWKS trust boundary. This separate
			// control supplies B's public JWKS only to a fresh A verifier, keeping discovery and
			// all production trust rules unchanged while proving the verifier's issuer check.
			issuerControl := keycloak.provider()
			issuerVerifier := issuerControl.GenerateVerifier()
			issuerURL, err := issuerControl.AuthorizationURLWithMaxAge(ctx, "realm-b-issuer", "realm-b-issuer", issuerVerifier, 15*time.Minute)
			if err != nil {
				t.Fatal("start issuer boundary control")
			}
			keycloak.substituteNextAFlowAndCertsWithB()
			issuerCode, _ := keycloak.authorize(ctx, issuerURL, "recipient@example.test")
			if _, err = issuerControl.ExchangeAndVerifyWithMaxAge(ctx, issuerCode, issuerVerifier, "realm-b-issuer", 15*time.Minute); err == nil || !strings.Contains(err.Error(), "id token issued by a different provider") {
				t.Fatal("trusted realm B public key did not reach A issuer mismatch check")
			}

			invitation, err := admission.CreateInvitation(ctx, tenant, "recipient@example.test", user.RoleAdmin, proof)
			if err != nil {
				t.Fatal("create invitation")
			}
			enroll, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationInvitation, InvitationCode: invitation.Code, CallerNonce: "enroll"})
			if err != nil {
				t.Fatal("begin invitation enrollment")
			}
			enrollCode, enrollState := keycloak.authorize(ctx, enroll.AuthorizationURL, "recipient@example.test")
			accepted, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: enrollState, Code: enrollCode, CallerNonce: "enroll"})
			if err != nil || accepted.Principal.Role != user.RoleAdmin || accepted.Principal.PersonID == "" {
				t.Fatal("invitation enrollment did not create administrator")
			}

			ordinary, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "ordinary-login"})
			if err != nil {
				t.Fatal("begin ordinary approved login")
			}
			ordinaryCode, ordinaryState := keycloak.authorize(ctx, ordinary.AuthorizationURL, "recipient@example.test")
			loggedIn, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: ordinaryState, Code: ordinaryCode, CallerNonce: "ordinary-login"})
			if err != nil || loggedIn.Principal.PersonID != accepted.Principal.PersonID || loggedIn.Principal.TenantID != tenant.String() || loggedIn.Principal.Role != user.RoleAdmin {
				t.Fatal("ordinary approved login changed authority")
			}
			if _, err := browser.Authenticate(ctx, loggedIn.Session.Token, "", false); err != nil {
				t.Fatal("issued browser session did not authenticate")
			}

			// Keycloak rotates the confidential-client credential with its native administrator API.
			// Keep the existing local session as a control while the old credential is rejected,
			// then test and activate the sealed replacement through the production factory.
			beforeRotation := fixture.authorityCounts(t, tenant)
			newSecret := keycloak.rotateClientSecret(ctx)
			oldSecretLogin, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "old-client-secret"})
			if err != nil {
				t.Fatal("begin cached old client secret negative control")
			}
			oldCode, oldState := keycloak.authorize(ctx, oldSecretLogin.AuthorizationURL, "recipient@example.test")
			if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: oldState, Code: oldCode, CallerNonce: "old-client-secret"}); !keycloakClientCredentialDenied(err) {
				t.Fatal("old Keycloak client secret was not rejected as a client credential denial")
			}
			if after := fixture.authorityCounts(t, tenant); after != beforeRotation {
				t.Fatalf("old client secret control changed authority: before=%v after=%v", beforeRotation, after)
			}
			if _, err := browser.Authenticate(ctx, loggedIn.Session.Token, "", false); err != nil {
				t.Fatal("existing local session did not survive client secret rotation")
			}

			rotationProof, err := connections.AdminProof(ctx, loggedIn.Principal, "")
			if err != nil || rotationProof.Principal.PersonID != loggedIn.Principal.PersonID {
				t.Fatal("fresh enrolled administrator proof was unavailable for client secret rotation")
			}
			rotatedDraft, err := connections.SaveDraft(ctx, loggedIn.Principal, "", identityenterprise.ConnectionDraftInput{ID: active.ID, DisplayName: "Keycloak", Issuer: keycloak.issuer, ClientID: keycloak.clientID, ClientSecret: newSecret, ExpectedVersion: active.Version})
			if err != nil {
				t.Fatal("save rotated Keycloak client secret draft")
			}
			if rotatedDraft.ID != active.ID || rotatedDraft.Issuer != active.Issuer || rotatedDraft.Settings.ClientID != active.Settings.ClientID || rotatedDraft.DraftRevision <= active.DraftRevision {
				t.Fatal("rotated Keycloak draft did not preserve the connection trust boundary")
			}
			rotationTest, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: rotatedDraft.ID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "rotated-connection-test", AdminProof: &rotationProof})
			if err != nil {
				t.Fatal("begin rotated Keycloak provider test")
			}
			rotationCode, rotationState := keycloak.authorize(ctx, rotationTest.AuthorizationURL, "recipient@example.test")
			rotationResult, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: rotationState, Code: rotationCode, CallerNonce: "rotated-connection-test"})
			if err != nil || !rotationResult.TestOnly {
				t.Fatal("rotated Keycloak provider test callback was not accepted")
			}
			rotatedActive, err := connections.Activate(ctx, loggedIn.Principal, "", rotatedDraft.ID, rotatedDraft.DraftRevision, rotatedDraft.Version)
			if err != nil {
				t.Fatal("activate tested rotated Keycloak client secret")
			}
			if rotatedActive.ID != active.ID || rotatedActive.Revision != rotatedDraft.DraftRevision || !rotatedActive.Enabled {
				t.Fatal("rotated Keycloak client secret did not activate the tested revision")
			}
			rotatedLogin, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: rotatedActive.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "rotated-ordinary-login"})
			if err != nil {
				t.Fatal("begin ordinary login with rotated Keycloak client secret")
			}
			rotatedCode, rotatedState := keycloak.authorize(ctx, rotatedLogin.AuthorizationURL, "recipient@example.test")
			rotatedLoggedIn, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: rotatedState, Code: rotatedCode, CallerNonce: "rotated-ordinary-login"})
			if err != nil || rotatedLoggedIn.Principal.PersonID != accepted.Principal.PersonID || rotatedLoggedIn.Principal.MembershipID != accepted.Principal.MembershipID || rotatedLoggedIn.Principal.TenantID != tenant.String() || rotatedLoggedIn.Principal.Role != user.RoleAdmin {
				t.Fatal("ordinary login with rotated Keycloak client secret changed authority")
			}
			rotatedPrincipal, err := browser.Authenticate(ctx, rotatedLoggedIn.Session.Token, "", false)
			if err != nil || rotatedPrincipal.PersonID != accepted.Principal.PersonID || rotatedPrincipal.MembershipID != accepted.Principal.MembershipID || rotatedPrincipal.TenantID != tenant.String() || rotatedPrincipal.Role != user.RoleAdmin {
				t.Fatal("rotated Keycloak browser session did not authenticate the expected principal")
			}
			afterRotation := fixture.authorityCounts(t, tenant)
			if afterRotation[0] != beforeRotation[0] || afterRotation[1] != beforeRotation[1] || afterRotation[2] != beforeRotation[2] || afterRotation[3] <= beforeRotation[3] {
				t.Fatalf("rotated Keycloak login changed authority unexpectedly: before=%v after=%v", beforeRotation, afterRotation)
			}

			// This disposable organization remains Optional. The live Required canary uses
			// an independent administrator connection to recover after disabling Keycloak.
			disabled, err := connections.Disable(ctx, rotatedLoggedIn.Principal, "", rotatedActive.ID, rotatedActive.Version)
			if err != nil || disabled.Enabled || disabled.ID != rotatedActive.ID || disabled.Epoch <= rotatedActive.Epoch {
				t.Fatal("disable Keycloak connection did not fence its prior session epoch")
			}
			if _, err = browser.Authenticate(ctx, rotatedLoggedIn.Session.Token, "", false); !errors.Is(err, authz.ErrCredentialInvalid) {
				t.Fatal("disabled Keycloak connection still authenticated its existing session")
			}
			if _, err = browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: disabled.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "disabled-login"}); !errors.Is(err, shared.ErrForbidden) {
				t.Fatal("disabled Keycloak connection still began a new login")
			}
			if after := fixture.authorityCounts(t, tenant); after != afterRotation {
				t.Fatalf("disabled Keycloak connection changed identity records: before=%v after=%v", afterRotation, after)
			}
		})
	}
}

type keycloakClock struct{}

func (keycloakClock) Now() time.Time { return time.Now().UTC() }

type keycloakIDs struct {
	prefix string
	n      atomic.Uint64
}

func (g *keycloakIDs) NewID() shared.ID {
	return shared.ID(fmt.Sprintf("keycloak-%s-%d", g.prefix, g.n.Add(1)))
}

// keycloakFactory preserves the production ConnectionFactory's sealed secret, revision and cache
// behavior. The wrapper substitutes the fixture's TLS client before a Provider is returned, so the
// production constructor never performs I/O with a private fixture address.
type keycloakFactory struct {
	factory *ConnectionFactory
	client  *http.Client
	mu      sync.Mutex
	bound   map[*Provider]struct{}
}

func (f *keycloakFactory) ProviderForConnection(ctx context.Context, c ports.IdentityConnection) (ports.OIDCProvider, error) {
	provider, err := f.factory.ProviderForConnection(ctx, c)
	if err != nil {
		return nil, err
	}
	p, ok := provider.(*Provider)
	if !ok {
		return nil, fmt.Errorf("unexpected OIDC provider type")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bound == nil {
		f.bound = make(map[*Provider]struct{})
	}
	if _, alreadyBound := f.bound[p]; !alreadyBound {
		p.client = f.client
		f.bound[p] = struct{}{}
	}
	return p, nil
}

func keycloakClientCredentialDenied(err error) bool {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) || retrieve.Response == nil {
		return false
	}
	switch retrieve.Response.StatusCode {
	case http.StatusBadRequest:
		return retrieve.ErrorCode == "invalid_client"
	case http.StatusUnauthorized:
		return retrieve.ErrorCode == "invalid_client" || retrieve.ErrorCode == "unauthorized_client"
	default:
		return false
	}
}

func TestKeycloakClientCredentialDenied(t *testing.T) {
	retrieve := func(status int, code string, response bool) error {
		err := &oauth2.RetrieveError{ErrorCode: code}
		if response {
			err.Response = &http.Response{StatusCode: status}
		}
		return err
	}
	wrapped := func(err error) error { return fmt.Errorf("wrapped provider response: %w", err) }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "wrapped 400 invalid client", err: wrapped(retrieve(http.StatusBadRequest, "invalid_client", true)), want: true},
		{name: "wrapped 401 invalid client", err: wrapped(retrieve(http.StatusUnauthorized, "invalid_client", true)), want: true},
		{name: "wrapped 401 Keycloak unauthorized client", err: wrapped(retrieve(http.StatusUnauthorized, "unauthorized_client", true)), want: true},
		{name: "nil error", err: nil},
		{name: "nil response", err: retrieve(http.StatusUnauthorized, "unauthorized_client", false)},
		{name: "400 invalid grant", err: retrieve(http.StatusBadRequest, "invalid_grant", true)},
		{name: "401 arbitrary code", err: retrieve(http.StatusUnauthorized, "access_denied", true)},
		{name: "500 invalid client", err: retrieve(http.StatusInternalServerError, "invalid_client", true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keycloakClientCredentialDenied(tc.err); got != tc.want {
				t.Fatalf("keycloakClientCredentialDenied() = %t, want %t", got, tc.want)
			}
		})
	}
}

type keycloakMailer struct{}

func (keycloakMailer) SendContactVerification(context.Context, string, string, shared.ID) ports.NotificationSendResult {
	return ports.NotificationSendResult{}
}

func keycloakBrowser(t *testing.T, f *keycloakPostgresFixture, kc *keycloakFixture, tenant shared.ID) (*identityenterprise.Browser, *identityenterprise.Connections, *identityenterprise.AdmissionService, ports.IdentityAdminProof, string) {
	t.Helper()
	clock, ids := keycloakClock{}, &keycloakIDs{prefix: keycloakRandom(t, 8)}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("generate test vault key")
	}
	defer clear(key)
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal("create test secret protector")
	}
	protector := NewSecretProtector(cipher)
	connections, err := identityenterprise.NewConnections(f.store, protector, clock, ids, kc.callbackURL)
	if err != nil {
		t.Fatal("create connection administration")
	}
	bootstrap := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: tenant.String(), Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
	token, err := connections.BeginBootstrap(t.Context(), bootstrap)
	if err != nil {
		t.Fatal("create bootstrap eligibility")
	}
	proof, err := connections.AdminProof(t.Context(), bootstrap, token)
	if err != nil {
		t.Fatal("read bootstrap eligibility")
	}
	realFactory, err := NewConnectionFactory(protector, kc.callbackURL)
	if err != nil {
		t.Fatal("create production connection factory")
	}
	protocol, err := identityenterprise.NewService(f.store, f.store, &keycloakFactory{factory: realFactory, client: kc.proxy.Client()}, protector, clock, ids)
	if err != nil {
		t.Fatal("create enterprise protocol")
	}
	if err := protocol.SetBootstrapCredentialID(bootstrap.Credential.ID); err != nil {
		t.Fatal("bind bootstrap credential")
	}
	admission, err := identityenterprise.NewAdmissionService(f.store, keycloakMailer{}, ids, clock)
	if err != nil {
		t.Fatal("create admission service")
	}
	browser, err := identityenterprise.NewBrowser(f.store, protocol, admission, protector, clock, ids, identityenterprise.BrowserConfig{TenantID: tenant, ReadEnabled: func(string) bool { return true }, MutationEnabled: func(string) bool { return true }, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal("create enterprise browser")
	}
	return browser, connections, admission, proof, token
}

type keycloakPostgresFixture struct {
	admin, runtime, owner *pgxpool.Pool
	store                 *postgres.IdentityFoundationStore
}

func newKeycloakPostgresFixture(t *testing.T) *keycloakPostgresFixture {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Fatal("keycloak integration requires SYNAPSE_TEST_DB_DSN")
	}
	ctx := t.Context()
	super, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect disposable PostgreSQL")
	}
	name := "keycloak_" + keycloakRandom(t, 8)
	owner, runtime, password := name+"_owner", name+"_runtime", keycloakRandom(t, 16)
	quote := func(value string) string { return pgx.Identifier{value}.Sanitize() }
	f := &keycloakPostgresFixture{}
	t.Cleanup(func() {
		if f.runtime != nil {
			f.runtime.Close()
		}
		if f.owner != nil {
			f.owner.Close()
		}
		if f.admin != nil {
			f.admin.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := super.Exec(cleanup, "DROP DATABASE IF EXISTS "+quote(name)+" WITH (FORCE)"); err != nil {
			t.Error("clean isolated PostgreSQL database")
		}
		for _, role := range []string{runtime, owner} {
			if _, err := super.Exec(cleanup, "DROP ROLE IF EXISTS "+quote(role)); err != nil {
				t.Error("clean isolated PostgreSQL role")
			}
		}
		if err := super.Close(cleanup); err != nil {
			t.Error("close isolated PostgreSQL administrator connection")
		}
	})
	for _, role := range []string{owner, runtime} {
		if _, err := super.Exec(ctx, "CREATE ROLE "+quote(role)+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"); err != nil {
			t.Fatal("create isolated PostgreSQL role")
		}
	}
	if _, err := super.Exec(ctx, "CREATE DATABASE "+quote(name)+" OWNER "+quote(owner)); err != nil {
		t.Fatal("create isolated PostgreSQL database")
	}
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("parse disposable PostgreSQL DSN")
	}
	base.Path, base.RawPath = "/"+name, ""
	adminDSN := base.String()
	ownerURL, runtimeURL := *base, *base
	ownerURL.User = url.UserPassword(owner, password)
	runtimeURL.User = url.UserPassword(runtime, password)
	if err := postgres.Migrate(ctx, ownerURL.String()); err != nil {
		t.Fatal("migrate isolated PostgreSQL database")
	}
	if err := postgres.GrantRuntimePrivileges(ctx, adminDSN, runtimeURL.String()); err != nil {
		t.Fatal("grant isolated runtime role")
	}
	if f.admin, err = pgxpool.New(ctx, adminDSN); err != nil {
		t.Fatal("open isolated PostgreSQL admin pool")
	}
	if f.runtime, err = pgxpool.New(ctx, runtimeURL.String()); err != nil {
		t.Fatal("open isolated PostgreSQL runtime pool")
	}
	if err = postgres.CheckRLSRuntimeRole(ctx, f.runtime); err != nil {
		t.Fatal("validate isolated runtime RLS role")
	}
	if f.store, err = postgres.NewIdentityFoundationStore(f.runtime); err != nil {
		t.Fatal("open identity authority store")
	}
	if f.owner, err = pgxpool.New(ctx, ownerURL.String()); err != nil {
		t.Fatal("open isolated PostgreSQL owner pool")
	}
	return f
}

func (f *keycloakPostgresFixture) tenant(t *testing.T, id shared.ID) {
	t.Helper()
	if _, err := f.admin.Exec(t.Context(), "INSERT INTO tenants(id,name) VALUES($1,$2)", id, "Keycloak"); err != nil {
		t.Fatal("seed isolated tenant")
	}
}
func (f *keycloakPostgresFixture) declare(t *testing.T, id shared.ID) {
	t.Helper()
	if err := postgres.WithTenant(t.Context(), f.runtime, id.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), "INSERT INTO identity_policies(tenant_id,id,cutover_phase) VALUES($1,'policy','shadow')", id); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), "INSERT INTO identity_cutover_ledger(tenant_id,action,actor,policy_version,created_at) VALUES($1,'declared','keycloak-test',1,now())", id); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), "UPDATE identity_policies SET cutover_phase='declared' WHERE tenant_id=$1", id)
		return err
	}); err != nil {
		t.Fatal("declare isolated identity authority")
	}
}
func (f *keycloakPostgresFixture) authorityCounts(t *testing.T, tenant shared.ID) [4]int {
	t.Helper()
	var out [4]int
	tables := []string{"identity_persons", "identity_memberships", "identity_authenticators", "identity_sessions"}
	for i, table := range tables {
		query := "SELECT count(*) FROM " + table
		args := []any{}
		if table != "identity_persons" {
			query += " WHERE tenant_id=$1"
			args = append(args, tenant)
		}
		if err := f.admin.QueryRow(t.Context(), query, args...).Scan(&out[i]); err != nil {
			t.Fatal("count authority rows")
		}
	}
	return out
}

func stringsForPath(path string) string {
	if path == "" {
		return "Root"
	}
	return "Auth"
}
