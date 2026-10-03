package postgres

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/oidc"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type browserClock struct{ at time.Time }

func (c browserClock) Now() time.Time { return c.at }

type browserIDs struct{ n int }

func (g *browserIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("browser-conformance-%d", g.n))
}

type browserProvider struct {
	clock  browserClock
	issuer string
}

func (p browserProvider) GenerateVerifier() string                        { return "deterministic-verifier" }
func (p browserProvider) AuthorizationURL(_, _, _ string) (string, error) { return "", nil }
func (p browserProvider) AuthorizationURLWithMaxAge(_ context.Context, state, _, _ string, _ time.Duration) (string, error) {
	return p.issuer + "/authorize?state=" + state, nil
}
func (p browserProvider) ExchangeAndVerify(context.Context, string, string, string) (ports.OIDCIdentity, error) {
	return ports.OIDCIdentity{}, fmt.Errorf("authenticated flow required")
}
func (p browserProvider) ExchangeAndVerifyWithMaxAge(_ context.Context, code, verifier, nonce string, _ time.Duration) (ports.OIDCIdentity, error) {
	if verifier != "deterministic-verifier" || nonce == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("invalid protocol binding")
	}
	return ports.OIDCIdentity{Issuer: p.issuer, Subject: code, Email: code + "@example.test", EmailVerified: true, Name: code, AuthenticatedAt: p.clock.Now()}, nil
}

type browserFactory struct{ provider browserProvider }

func (f browserFactory) ProviderForConnection(_ context.Context, connection ports.IdentityConnection) (ports.OIDCProvider, error) {
	p := f.provider
	p.issuer = connection.Issuer
	return p, nil
}

type browserMailer struct{}

func (browserMailer) SendContactVerification(context.Context, string, string, shared.ID) ports.NotificationSendResult {
	return ports.NotificationSendResult{}
}

// This exercises the production browser protocol against the runtime-role PostgreSQL store. The
// protocol provider is deliberately neutral; signed-provider interoperability is covered elsewhere.
func TestIdentityBrowserPostgresConformance(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	tenant := shared.ID("browser-conformance")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	clock := browserClock{at: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	ids := &browserIDs{}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	protector := oidc.NewSecretProtector(cipher)
	connections, err := identityenterprise.NewConnections(f.store, protector, clock, ids, "https://app.example/api/auth/enterprise/callback")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: tenant.String(), Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
	eligibility, err := connections.BeginBootstrap(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := connections.SaveDraft(ctx, bootstrap, eligibility, identityenterprise.ConnectionDraftInput{ID: "workforce", DisplayName: "Workforce", Issuer: "https://issuer.example", ClientID: "client", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := connections.AdminProof(ctx, bootstrap, eligibility)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := identityenterprise.NewService(f.store, f.store, browserFactory{browserProvider{clock: clock}}, protector, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := identityenterprise.NewAdmissionService(f.store, browserMailer{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := identityenterprise.NewBrowser(f.store, protocol, admission, protector, clock, ids, identityenterprise.BrowserConfig{TenantID: tenant, ReadEnabled: func(string) bool { return true }, MutationEnabled: func(string) bool { return true }, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	// A draft may be tested without creating membership or browser session state.
	testStart, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: draft.ID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "test-caller", AdminProof: &proof})
	if err != nil {
		t.Fatal(err)
	}
	state := conformanceState(t, testStart.AuthorizationURL)
	testResult, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: state, Code: "tester", CallerNonce: "test-caller"})
	if err != nil || !testResult.TestOnly {
		t.Fatalf("draft test result=%+v err=%v", testResult, err)
	}
	if got := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant); got != 0 {
		t.Fatalf("test created %d memberships", got)
	}
	active, err := connections.Activate(ctx, bootstrap, eligibility, draft.ID, draft.DraftRevision, draft.Version)
	if err != nil {
		t.Fatal(err)
	}

	// First admission remains invitation-only after an active connection exists.
	login, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, login.AuthorizationURL), Code: "unknown", CallerNonce: "unknown"}); err == nil {
		t.Fatal("unknown subject was admitted")
	}
	created, err := admission.CreateInvitation(ctx, tenant, "recipient@example.test", user.RoleAdmin, proof)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationInvitation, InvitationCode: created.Code, CallerNonce: "invite"})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, invite.AuthorizationURL), Code: "recipient", CallerNonce: "invite"})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Principal.Role != user.RoleAdmin || accepted.Session.Token == "" {
		t.Fatalf("invitation admission=%+v", accepted)
	}
	recipients, err := f.store.IdentityRecoveryAlertRecipients(ctx, tenant, accepted.Session.Session.MembershipID)
	if err != nil || len(recipients) != 1 || recipients[0] != "recipient@example.test" {
		t.Fatalf("first administrator verified recovery contact=%v err=%v", recipients, err)
	}
	ordinary, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "ordinary"})
	if err != nil {
		t.Fatal(err)
	}
	ordinaryResult, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, ordinary.AuthorizationURL), Code: "recipient", CallerNonce: "ordinary"})
	if err != nil || ordinaryResult.Principal.PersonID != accepted.Principal.PersonID {
		t.Fatalf("ordinary approved login=%+v err=%v", ordinaryResult, err)
	}
	link, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLink, CallerNonce: "link", SourceToken: ordinaryResult.Session.Token, CSRFToken: ordinaryResult.Session.CSRFToken})
	if err != nil {
		t.Fatal(err)
	}
	linked, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, link.AuthorizationURL), Code: "recipient-linked", CallerNonce: "link", SourceToken: ordinaryResult.Session.Token})
	if err != nil || linked.Session.Token == ordinaryResult.Session.Token {
		t.Fatalf("additive link=%+v err=%v", linked, err)
	}

	// A signed-in person can accept an explicit invitation for another declared organization;
	// admission keeps the person while rotating the initiating organization session.
	tenantB := shared.ID("browser-conformance-b")
	f.tenants(t, tenantB.String())
	f.declare(t, tenantB.String())
	bootstrapB := bootstrap
	bootstrapB.TenantID = tenantB.String()
	eligibilityB, err := connections.BeginBootstrap(ctx, bootstrapB)
	if err != nil {
		t.Fatal(err)
	}
	draftB, err := connections.SaveDraft(ctx, bootstrapB, eligibilityB, identityenterprise.ConnectionDraftInput{ID: "workforce-b", DisplayName: "Workforce B", Issuer: "https://issuer-b.example", ClientID: "client-b", ClientSecret: "secret-b"})
	if err != nil {
		t.Fatal(err)
	}
	proofB, err := connections.AdminProof(ctx, bootstrapB, eligibilityB)
	if err != nil {
		t.Fatal(err)
	}
	testB, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenantB, ConnectionID: draftB.ID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "test-b", AdminProof: &proofB})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenantB, State: conformanceState(t, testB.AuthorizationURL), Code: "tester-b", CallerNonce: "test-b"}); err != nil {
		t.Fatal(err)
	}
	activeB, err := connections.Activate(ctx, bootstrapB, eligibilityB, draftB.ID, draftB.DraftRevision, draftB.Version)
	if err != nil {
		t.Fatal(err)
	}
	invitationB, err := admission.CreateInvitation(ctx, tenantB, "recipient@example.test", user.RoleReadOnly, proofB)
	if err != nil {
		t.Fatal(err)
	}
	beginB, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: activeB.ID, Purpose: ports.IdentityAuthorizationInvitation, InvitationCode: invitationB.Code, CallerNonce: "invite-b", SourceToken: linked.Session.Token, CSRFToken: linked.Session.CSRFToken})
	if err != nil {
		t.Fatal(err)
	}
	acceptedB, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenantB, State: conformanceState(t, beginB.AuthorizationURL), Code: "recipient", CallerNonce: "invite-b", SourceToken: linked.Session.Token})
	if err != nil || acceptedB.Principal.PersonID != accepted.Principal.PersonID || acceptedB.Principal.Role != user.RoleReadOnly {
		t.Fatalf("second organization invitation=%+v err=%v", acceptedB, err)
	}
	if got := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE person_id=$1 AND state='active'`, accepted.Principal.PersonID); got != 2 {
		t.Fatalf("active memberships for invited person=%d", got)
	}
	if _, err = browser.Authenticate(ctx, linked.Session.Token, "", false); err == nil {
		t.Fatal("source organization session remained valid after signed-in invitation")
	}

	// B's recovery readiness and usable administrator are explicitly provisioned before
	// required enforcement. The first person's B role remains readonly throughout.
	adminInvite, err := admission.CreateInvitation(ctx, tenantB, "badmin@example.test", user.RoleAdmin, proofB)
	if err != nil {
		t.Fatal(err)
	}
	adminStart, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: activeB.ID, Purpose: ports.IdentityAuthorizationInvitation, InvitationCode: adminInvite.Code, CallerNonce: "badmin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenantB, State: conformanceState(t, adminStart.AuthorizationURL), Code: "badmin", CallerNonce: "badmin"}); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RehearseIdentityRecovery(ctx, tenantB, proofB, clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RecordIdentityRecoveryAlertTest(ctx, tenantB, proofB, clock.Now()); err != nil {
		t.Fatal(err)
	}
	policyB, err := f.store.GetIdentityRecoveryPolicy(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	policyB.Organization.Requirement = authz.SSORequired
	policyB.ExpectedVersion = policyB.Version
	policyB.UpdatedAt = clock.Now()
	if _, err = f.store.SaveIdentityRecoveryPolicy(ctx, policyB, proofB); err != nil {
		t.Fatal(err)
	}
	backToA, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "return-a"})
	if err != nil {
		t.Fatal(err)
	}
	sourceA, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, backToA.AuthorizationURL), Code: "recipient", CallerNonce: "return-a"})
	if err != nil {
		t.Fatal(err)
	}
	switchInput := identityenterprise.BrowserSwitchInput{SourceToken: sourceA.Session.Token, CSRFToken: sourceA.Session.CSRFToken, TenantID: tenantB, MembershipID: acceptedB.Session.Session.MembershipID, RetryKey: "destination-switch-retry", CallerNonce: "destination-switch"}
	decision, err := browser.Switch(ctx, switchInput)
	if err != nil || !decision.ReauthenticationRequired || decision.Session != nil {
		t.Fatalf("required decision=%+v err=%v", decision, err)
	}
	switchInput.ConnectionID = activeB.ID
	wrongStart, err := browser.Switch(ctx, switchInput)
	if err != nil || wrongStart.Authorization == nil {
		t.Fatalf("start destination proof=%+v err=%v", wrongStart, err)
	}
	if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenantB, State: conformanceState(t, wrongStart.Authorization.AuthorizationURL), Code: "badmin", CallerNonce: switchInput.CallerNonce, SourceToken: sourceA.Session.Token}); err == nil {
		t.Fatal("other person's destination subject switched membership")
	}
	if _, err = browser.Authenticate(ctx, sourceA.Session.Token, "", false); err != nil {
		t.Fatalf("wrong-person proof revoked source: %v", err)
	}
	startSwitch, err := browser.Switch(ctx, switchInput)
	if err != nil || startSwitch.Authorization == nil {
		t.Fatalf("start same-person proof=%+v err=%v", startSwitch, err)
	}
	switched, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenantB, State: conformanceState(t, startSwitch.Authorization.AuthorizationURL), Code: "recipient", CallerNonce: switchInput.CallerNonce, SourceToken: sourceA.Session.Token})
	if err != nil || switched.Principal.TenantID != tenantB.String() || switched.Principal.Role != user.RoleReadOnly || switched.Principal.PersonID != sourceA.Principal.PersonID {
		t.Fatalf("destination completion=%+v err=%v", switched, err)
	}
	if authz.Decide(switched.Principal, authz.Action{Permission: user.PermAdminister}).Allowed {
		t.Fatal("readonly destination gained administration")
	}
	if _, err = browser.Authenticate(ctx, sourceA.Session.Token, "", false); err == nil {
		t.Fatal("successful switch kept source token active")
	}
	retry, err := browser.Switch(ctx, switchInput)
	if err != nil || retry.Session == nil || retry.Session.Token != switched.Session.Token {
		t.Fatalf("exact response-loss retry=%+v err=%v", retry, err)
	}
	if err = browser.Logout(ctx, switched.Session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Switch(ctx, switchInput); err == nil {
		t.Fatal("logout allowed retained switch replay")
	}
}

func TestIdentityBrowserStepUpRefreshesAgedSessionButLinkRequiresRecentAuthentication(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	tenant := shared.ID("browser-step-up-age")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	clock := browserClock{at: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	ids := &browserIDs{}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	protector := oidc.NewSecretProtector(cipher)
	connections, err := identityenterprise.NewConnections(f.store, protector, clock, ids, "https://app.example/api/auth/enterprise/callback")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: tenant.String(), Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
	eligibility, err := connections.BeginBootstrap(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := connections.SaveDraft(ctx, bootstrap, eligibility, identityenterprise.ConnectionDraftInput{ID: "workforce", DisplayName: "Workforce", Issuer: "https://issuer.example", ClientID: "client", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := connections.AdminProof(ctx, bootstrap, eligibility)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := identityenterprise.NewService(f.store, f.store, browserFactory{browserProvider{clock: clock}}, protector, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := identityenterprise.NewAdmissionService(f.store, browserMailer{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := identityenterprise.NewBrowser(f.store, protocol, admission, protector, clock, ids, identityenterprise.BrowserConfig{TenantID: tenant, ReadEnabled: func(string) bool { return true }, MutationEnabled: func(string) bool { return true }, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	testStart, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: draft.ID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "test", AdminProof: &proof})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, testStart.AuthorizationURL), Code: "tester", CallerNonce: "test"}); err != nil {
		t.Fatal(err)
	}
	active, err := connections.Activate(ctx, bootstrap, eligibility, draft.ID, draft.DraftRevision, draft.Version)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := admission.CreateInvitation(ctx, tenant, "recipient@example.test", user.RoleAdmin, proof)
	if err != nil {
		t.Fatal(err)
	}
	start, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationInvitation, InvitationCode: invitation.Code, CallerNonce: "invite"})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, start.AuthorizationURL), Code: "recipient", CallerNonce: "invite"})
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Session.Session.ExpiresAt.After(clock.Now()) || accepted.Session.Session.OriginAt.Before(clock.Now().Add(-12*time.Hour)) {
		t.Fatalf("invitation session is not current: %+v", accepted.Session.Session)
	}
	agedAuthenticatedAt := clock.Now().Add(-16 * time.Minute)
	if err := f.runtimeExec(tenant.String(), `UPDATE identity_sessions SET authenticated_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant.String(), accepted.Session.Session.ID.String(), agedAuthenticatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationLink, CallerNonce: "link", SourceToken: accepted.Session.Token, CSRFToken: accepted.Session.CSRFToken}); err == nil {
		t.Fatal("aged source began a link without step-up")
	}
	stepUp, err := browser.Begin(ctx, identityenterprise.BrowserAuthorization{TenantID: tenant, ConnectionID: active.ID, Purpose: ports.IdentityAuthorizationStepUp, CallerNonce: "step-up", SourceToken: accepted.Session.Token, CSRFToken: accepted.Session.CSRFToken})
	if err != nil {
		t.Fatalf("aged valid source did not begin step-up: %v", err)
	}
	stepped, err := browser.Complete(ctx, identityenterprise.BrowserCallback{TenantID: tenant, State: conformanceState(t, stepUp.AuthorizationURL), Code: "recipient", CallerNonce: "step-up", SourceToken: accepted.Session.Token})
	if err != nil {
		t.Fatal(err)
	}
	if stepped.Principal.PersonID != accepted.Principal.PersonID || stepped.Session.Token == accepted.Session.Token || !stepped.Session.Session.OriginAt.Equal(accepted.Session.Session.OriginAt) || !stepped.Session.Session.AuthenticatedAt.Equal(clock.Now()) {
		t.Fatalf("step-up result=%+v prior=%+v", stepped, accepted)
	}
}

func conformanceState(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("missing protocol state")
	}
	return state
}
