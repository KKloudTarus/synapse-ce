package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityfoundation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func initialProvisioningPrincipal(source, credential string) authz.Principal {
	return authz.Principal{ActorID: authz.BootstrapActorID, TenantID: source, Role: user.RoleAdmin, Credential: authz.Credential{Kind: authz.KindBootstrap, ID: credential}}
}

func initialProvisioningBegin(target string, p authz.Principal, recipient string, at time.Time) ports.IdentityProvisioningBegin {
	return ports.IdentityProvisioningBegin{TenantID: shared.ID(target), ID: "provisioning", ConnectionID: "connection", InvitationID: "invitation", Principal: p, Recipient: recipient, At: at}
}

func initialProvisioningProof(state ports.IdentityInitialProvisioning, p authz.Principal, at time.Time) ports.IdentityProvisioningProof {
	return ports.IdentityProvisioningProof{TenantID: state.TenantID, ID: state.ID, ConnectionID: state.ConnectionID, InvitationID: state.InvitationID, Principal: p, Recipient: state.Recipient, IssuedAt: at, ExpiresAt: at.Add(10 * time.Minute), At: at}
}

func declaredInitialTenant(t *testing.T) (*identityFixture, authz.Principal, ports.IdentityInitialProvisioning, time.Time) {
	t.Helper()
	f := newIdentityFixture(t)
	const target = "initial-provisioning-target"
	f.tenants(t, target)
	f.declare(t, target)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	p := initialProvisioningPrincipal("source-tenant", "bootstrap-generation-a")
	state, err := f.store.BeginIdentityProvisioning(context.Background(), initialProvisioningBegin(target, p, "admin@example.com", at))
	if err != nil {
		t.Fatal(err)
	}
	return f, p, state, at
}

func TestIdentityInitialProvisioningBeginConvergesAndFencesBinding(t *testing.T) {
	f := newIdentityFixture(t)
	const target = "initial-provisioning-concurrent"
	f.tenants(t, target)
	f.declare(t, target)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	p := initialProvisioningPrincipal("source-tenant", "bootstrap-generation-a")
	first := initialProvisioningBegin(target, p, "admin@example.com", at)
	second := first
	second.ID, second.ConnectionID, second.InvitationID = "other-provisioning", "other-connection", "other-invitation"
	var results [2]ports.IdentityInitialProvisioning
	var errs [2]error
	var wg sync.WaitGroup
	for i, begin := range []ports.IdentityProvisioningBegin{first, second} {
		wg.Add(1)
		go func(i int, begin ports.IdentityProvisioningBegin) {
			defer wg.Done()
			results[i], errs[i] = f.store.BeginIdentityProvisioning(context.Background(), begin)
		}(i, begin)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].ID != results[1].ID || results[0].ConnectionID != results[1].ConnectionID || results[0].InvitationID != results[1].InvitationID {
		t.Fatalf("converged begins=%+v/%+v errors=%v/%v", results[0], results[1], errs[0], errs[1])
	}
	conflict := initialProvisioningBegin(target, p, "other@example.com", at)
	if _, err := f.store.BeginIdentityProvisioning(context.Background(), conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting recipient=%v, want ErrConflict", err)
	}
}

func TestIdentityInitialProvisioningCredentialRebindResumesExistingReservation(t *testing.T) {
	f, originalPrincipal, original, at := declaredInitialTenant(t)
	ctx := context.Background()
	rotatedPrincipal := originalPrincipal
	rotatedPrincipal.Credential.ID = "bootstrap-generation-b"
	begin := initialProvisioningBegin(original.TenantID.String(), rotatedPrincipal, original.Recipient, at.Add(time.Minute))
	// The use case allocates new candidate IDs on each Begin, including retries.
	begin.ID, begin.ConnectionID, begin.InvitationID = "retry-provisioning", "retry-connection", "retry-invitation"
	rebound, err := f.store.BeginIdentityProvisioning(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.ID != original.ID || rebound.ConnectionID != original.ConnectionID || rebound.InvitationID != original.InvitationID || rebound.CredentialID != rotatedPrincipal.Credential.ID || rebound.Version != original.Version+1 {
		t.Fatalf("reservation was not rebound in place: original=%+v rebound=%+v", original, rebound)
	}
	if _, err := f.store.ReadIdentityProvisioning(ctx, initialProvisioningProof(original, originalPrincipal, begin.At)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("old credential proof=%v, want ErrForbidden", err)
	}
	proof := initialProvisioningProof(rebound, rotatedPrincipal, begin.At)
	if _, err := f.store.ReadIdentityProvisioning(ctx, proof); err != nil {
		t.Fatalf("new credential status: %v", err)
	}
	draft := ports.IdentityConnectionDraft{TenantID: original.TenantID, ID: original.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	if _, err := f.store.SaveIdentityProvisioningDraft(ctx, draft, proof); err != nil {
		t.Fatalf("continue draft after credential rotation: %v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.initial_provisioning_credential_rebound' AND target=$2`, original.TenantID.String(), original.ID.String()); n != 1 {
		t.Fatalf("rebind audits for retained reservation=%d, want one", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_initial_provisioning WHERE tenant_id=$1`, original.TenantID.String()); n != 1 {
		t.Fatalf("reservations=%d, want one", n)
	}
	if _, err := f.store.BeginIdentityProvisioning(ctx, begin); err != nil {
		t.Fatalf("repeat Begin with current credential: %v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.initial_provisioning_credential_rebound'`, original.TenantID.String()); n != 1 {
		t.Fatalf("repeated Begin emitted %d rebind audits, want one", n)
	}
}

func TestIdentityInitialProvisioningProofFencesCredentialAndExpiry(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	proof := initialProvisioningProof(state, p, at)
	if _, err := f.store.ReadIdentityProvisioning(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	wrongCredential := proof
	wrongCredential.Principal.Credential.ID = "bootstrap-generation-b"
	if _, err := f.store.ReadIdentityProvisioning(context.Background(), wrongCredential); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong credential proof=%v, want ErrForbidden", err)
	}
	expired := proof
	expired.At = expired.ExpiresAt
	if _, err := f.store.ReadIdentityProvisioning(context.Background(), expired); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expired proof=%v, want ErrForbidden", err)
	}
	wrongIDs := proof
	wrongIDs.ConnectionID = "other"
	if _, err := f.store.ReadIdentityProvisioning(context.Background(), wrongIDs); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong connection proof=%v, want ErrForbidden", err)
	}
}

func TestIdentityInitialProvisioningRequiresTestAndReplaysOneInvitation(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	proof := initialProvisioningProof(state, p, at)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	proof = initialProvisioningProof(state, p, at)
	// The callback burns a Test transaction before this store records the successful provider
	// exchange. The consumed, pinned transaction is the only intermediate authorization row
	// permitted while provisioning remains open.
	callbackState, callerNonce := identityDigest("initial-callback-state"), identityDigest("initial-callback-nonce")
	if err = f.store.CreateIdentityAuthorization(context.Background(), ports.IdentityAuthorizationTransaction{ID: "initial-test-transaction", TenantID: state.TenantID, Purpose: ports.IdentityAuthorizationTest, ConnectionID: state.ConnectionID, ConnectionRevision: 1, StateDigest: callbackState, NonceDigest: identityDigest("initial-callback-provider-nonce"), CallerNonceDigest: callerNonce, PKCEVerifierSealed: "sealed-verifier", ContextSealed: "sealed-provisioning-context", ExpiresAt: at.Add(time.Minute), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ConsumeIdentityAuthorization(context.Background(), state.TenantID, callbackState, callerNonce, at); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, 1, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("untested activation=%v, want ErrConflict", err)
	}
	if err = f.store.RecordIdentityProvisioningTest(context.Background(), ports.IdentityConnectionTest{ID: "too-long-provisioning-test", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour + time.Nanosecond)}, proof); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over-one-hour provisioning test lifetime=%v, want ErrValidation", err)
	}
	test := ports.IdentityConnectionTest{ID: "real-callback-test", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}
	if err = f.store.RecordIdentityProvisioningTest(context.Background(), test, proof); err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ReadIdentityProvisioning(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || state.Connection.SettingsRevision != 1 || !state.Connection.TestPassed {
		t.Fatalf("passed original draft status=%+v", state.Connection)
	}
	proof = initialProvisioningProof(state, p, at)
	state, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, 1, proof)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, 1, initialProvisioningProof(state, p, at))
	if err != nil || retry.State != "active" || retry.Connection == nil || !retry.Connection.Enabled {
		t.Fatalf("already active provisioning retry=%+v err=%v", retry, err)
	}
	proof = initialProvisioningProof(state, p, at)
	invitation := ports.IdentityInvitationCreate{Invitation: ports.IdentityInvitation{ID: state.InvitationID, TenantID: state.TenantID, Recipient: state.Recipient, Role: user.RoleAdmin, CreatedAt: at, ExpiresAt: at.Add(time.Hour)}, CodeDigest: identityDigest("one-admin-code"), Actor: p.ActorID}
	first, err := f.store.IssueIdentityProvisioningInvitation(context.Background(), invitation, "sealed-retry-code", proof)
	if err != nil {
		t.Fatal(err)
	}
	secondInvitation := invitation
	secondInvitation.CodeDigest = identityDigest("different-candidate-must-not-replace")
	second, err := f.store.IssueIdentityProvisioningInvitation(context.Background(), secondInvitation, "different-sealed-candidate", initialProvisioningProof(first, p, at))
	if err != nil {
		t.Fatal(err)
	}
	if first.InvitationCodeSealed != "sealed-retry-code" || second.InvitationCodeSealed != first.InvitationCodeSealed || second.Invitation == nil || first.Invitation == nil || second.Invitation.ID != first.Invitation.ID {
		t.Fatalf("invitation retry first=%+v second=%+v", first, second)
	}
	if n := f.runtimeCount(t, state.TenantID.String(), `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1`, state.TenantID.String()); n != 1 {
		t.Fatalf("invitations=%d, want one", n)
	}
}

func TestIdentityInitialProvisioningLegacyTestLifetimeDoesNotExtendActivationAuthority(t *testing.T) {
	f, p, state, _ := declaredInitialTenant(t)
	var now time.Time
	if err := f.admin.QueryRow(context.Background(), `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	proof := initialProvisioningProof(state, p, now)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestedAt := now.Add(-59 * time.Minute)
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'legacy-long-provisioning-test',$2,1,'passed',$3,$4)`, state.TenantID.String(), state.ConnectionID.String(), legacyTestedAt, now.Add(24*time.Hour))
	f.exec(t, `UPDATE identity_initial_provisioning SET state='tested',version=version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, state.TenantID.String(), state.ID.String(), now)
	state, err = f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, now))
	if err != nil || state.Connection == nil || !state.Connection.TestPassed {
		t.Fatalf("legacy provisioning test just before one hour state=%+v err=%v", state, err)
	}
	boundary := legacyTestedAt.Add(time.Hour)
	boundaryState, err := f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, boundary))
	if err != nil || boundaryState.Connection == nil || boundaryState.Connection.TestPassed {
		t.Fatalf("legacy provisioning test at one-hour boundary remained ready: %+v err=%v", boundaryState, err)
	}
	if _, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, boundaryState.Connection.Version, initialProvisioningProof(boundaryState, p, boundary)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("legacy provisioning test at one-hour boundary activated: %v", err)
	}
	// An explicit expiry earlier than the lifetime remains a hard upper bound for the
	// provisioning status returned to the same scoped operation.
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'short-provisioning-expiry',$2,1,'passed',$3,$4)`, state.TenantID.String(), state.ConnectionID.String(), now.Add(-58*time.Minute), now.Add(-time.Minute))
	state, err = f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, now))
	if err != nil || state.Connection == nil || state.Connection.TestPassed {
		t.Fatalf("short provisioning expiry was ignored: %+v err=%v", state, err)
	}
}

func TestIdentityInitialProvisioningPermitsAbandonedPinnedTest(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	proof := initialProvisioningProof(state, p, at)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.CreateIdentityAuthorization(context.Background(), ports.IdentityAuthorizationTransaction{ID: "abandoned-pinned-test", TenantID: state.TenantID, Purpose: ports.IdentityAuthorizationTest, ConnectionID: state.ConnectionID, ConnectionRevision: 1, StateDigest: identityDigest("abandoned-test-state"), NonceDigest: identityDigest("abandoned-test-nonce"), CallerNonceDigest: identityDigest("abandoned-test-caller-nonce"), PKCEVerifierSealed: "sealed-verifier", ContextSealed: "sealed-provisioning-context", ExpiresAt: at.Add(time.Minute), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	proof = initialProvisioningProof(state, p, at)
	if _, err = f.store.ReadIdentityProvisioning(context.Background(), proof); err != nil {
		t.Fatalf("status after abandoned pinned test: %v", err)
	}
	resumed, err := f.store.BeginIdentityProvisioning(context.Background(), initialProvisioningBegin(state.TenantID.String(), p, state.Recipient, at))
	if err != nil || resumed.ID != state.ID || resumed.State != "draft" {
		t.Fatalf("resume after abandoned pinned test=%+v err=%v", resumed, err)
	}
}

func TestIdentityInitialProvisioningAcceptsEmptyNativeCutoverProvenance(t *testing.T) {
	f := newIdentityFixture(t)
	const target = "initial-provisioning-zero-cutover"
	f.tenants(t, target)
	ctx := context.Background()
	prepared, err := f.store.PrepareCutover(ctx, target, 0, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	service := f.service(t)
	if _, err = service.Backfill(ctx, target, identityfoundation.BackfillOptions{Actor: "operator", BatchSize: 10, Lease: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err = service.Rollback(ctx, target, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Backfill(ctx, target, identityfoundation.BackfillOptions{Actor: "operator", BatchSize: 10, Lease: time.Minute}); err != nil {
		t.Fatal(err)
	}
	canary, err := f.store.CanaryCutover(ctx, target)
	if err != nil || !canary.Ready || !canary.RollbackPrepared || canary.LegacyUsers != 0 || canary.Memberships != 0 {
		t.Fatalf("zero-user canary=%+v err=%v", canary, err)
	}
	declareAt := time.Now().UTC()
	if err = f.store.RecordCutoverWriterHeartbeat(ctx, target, "native-writer", "api-a", declareAt); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DeclareCutover(ctx, target, prepared.PolicyVersion, ports.IdentityCutoverEvidence{ShadowReportID: canary.ID, OldWriterGeneration: "native-writer", MigrationVersion: identityMigrationCeiling(t)}, "operator", declareAt); err != nil {
		t.Fatal(err)
	}
	p := initialProvisioningPrincipal("source-tenant", "bootstrap-generation-a")
	state, err := f.store.BeginIdentityProvisioning(ctx, initialProvisioningBegin(target, p, "admin@example.com", declareAt))
	if err != nil || state.State != "open" {
		t.Fatalf("begin after clean native cutover=%+v err=%v", state, err)
	}
}

func TestIdentityInitialProvisioningMembershipClosureIsTerminal(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	person := shared.ID("initial-provisioning-person")
	if _, err := f.platform.ApplyPersonCommand(context.Background(), person, ports.IdentityPersonCreated, "platform", "initial provisioning closure"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AddMembership(context.Background(), state.TenantID, person, "First admin", user.RoleAdmin, p.ActorID, at); err != nil {
		t.Fatal(err)
	}
	proof := initialProvisioningProof(state, p, at)
	closed, err := f.store.ReadIdentityProvisioning(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != "closed" || closed.InvitationCodeSealed != "" || closed.ClosedAt == nil {
		t.Fatalf("closed provisioning=%+v", closed)
	}
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "No longer allowed", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	if _, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("post-membership draft=%v, want ErrForbidden", err)
	}
	resumed, err := f.store.BeginIdentityProvisioning(context.Background(), initialProvisioningBegin(state.TenantID.String(), p, "", at.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ID != state.ID || resumed.State != "closed" {
		t.Fatalf("closed begin resume=%+v", resumed)
	}
}

func TestIdentityInitialProvisioningReplacesOnlySecretBeforeActivation(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	proof := initialProvisioningProof(state, p, at)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "wrong-secret"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	proof = initialProvisioningProof(state, p, at)
	zeroVersionReplacement := draft
	zeroVersionReplacement.Settings.SealedClientSecret = "zero-version-replacement"
	replayed, err := f.store.SaveIdentityProvisioningDraft(context.Background(), zeroVersionReplacement, proof)
	if err != nil {
		t.Fatalf("zero-version retry: %v", err)
	}
	if replayed.Version != state.Version || replayed.State != state.State || replayed.Connection == nil || replayed.Connection.Version != state.Connection.Version || replayed.Connection.DraftRevision != state.Connection.DraftRevision || replayed.Connection.Settings.SealedClientSecret != draft.Settings.SealedClientSecret {
		t.Fatalf("zero-version retry replaced pinned draft: replay=%+v connection=%+v", replayed, replayed.Connection)
	}
	if err := f.store.RecordIdentityProvisioningTest(context.Background(), ports.IdentityConnectionTest{ID: "test-wrong-secret", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}, proof); err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ReadIdentityProvisioning(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || state.Connection.SettingsRevision != 1 || !state.Connection.TestPassed {
		t.Fatalf("passed original revision before replacement=%+v", state.Connection)
	}
	proof = initialProvisioningProof(state, p, at)
	callbackState, callbackNonce := identityDigest("wrong-secret-state"), identityDigest("wrong-secret-nonce")
	if err := f.store.CreateIdentityAuthorization(context.Background(), ports.IdentityAuthorizationTransaction{ID: "wrong-secret-callback", TenantID: state.TenantID, Purpose: ports.IdentityAuthorizationTest, ConnectionID: state.ConnectionID, ConnectionRevision: 1, StateDigest: callbackState, NonceDigest: identityDigest("wrong-secret-provider-nonce"), CallerNonceDigest: callbackNonce, PKCEVerifierSealed: "sealed-verifier", ContextSealed: "sealed-context", ExpiresAt: at.Add(time.Hour), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}

	replacement := draft
	replacement.ExpectedVersion = state.Connection.Version
	replacement.Settings.SealedClientSecret = "replacement-secret"
	state, err = f.store.SaveIdentityProvisioningDraft(context.Background(), replacement, proof)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != "draft" || state.Connection == nil || state.Connection.DraftRevision != 2 || state.Connection.Version != replacement.ExpectedVersion+1 || state.Connection.Settings.SealedClientSecret != "replacement-secret" || state.Connection.TestPassed {
		t.Fatalf("replacement state=%+v connection=%+v", state, state.Connection)
	}
	trustChange := replacement
	trustChange.ExpectedVersion = state.Connection.Version
	trustChange.Settings.ClientID = "other-client"
	if _, err = f.store.SaveIdentityProvisioningDraft(context.Background(), trustChange, initialProvisioningProof(state, p, at)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("trust change=%v, want ErrConflict", err)
	}
	if _, err = f.store.ConsumeIdentityAuthorization(context.Background(), state.TenantID, callbackState, callbackNonce, at); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("old callback after replacement=%v, want ErrNotFound", err)
	}
	if _, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, replacement.ExpectedVersion, initialProvisioningProof(state, p, at)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("old test activates replacement=%v, want ErrConflict", err)
	}
	if err = f.store.RecordIdentityProvisioningTest(context.Background(), ports.IdentityConnectionTest{ID: "test-replacement-secret", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 2, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}, initialProvisioningProof(state, p, at)); err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || !state.Connection.TestPassed {
		t.Fatalf("replacement successful test not projected: %+v", state.Connection)
	}
	if _, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 2, state.Connection.Version, initialProvisioningProof(state, p, at)); err != nil {
		t.Fatalf("fresh test activates replacement: %v", err)
	}

}

func TestIdentityInitialProvisioningTestStatusUsesCurrentDraftRevision(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "first-secret"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	replacement := draft
	replacement.ExpectedVersion = state.Connection.Version
	replacement.Settings.SealedClientSecret = "second-secret"
	state, err = f.store.SaveIdentityProvisioningDraft(context.Background(), replacement, initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || state.Connection.DraftRevision != 2 || state.Connection.TestPassed {
		t.Fatalf("untested replacement status=%+v", state.Connection)
	}
	if err = f.store.RecordIdentityProvisioningTest(context.Background(), ports.IdentityConnectionTest{ID: "current-draft-test", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 2, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}, initialProvisioningProof(state, p, at)); err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || state.Connection.SettingsRevision != 2 || !state.Connection.TestPassed {
		t.Fatalf("current draft test status=%+v", state.Connection)
	}
	refreshedAt := at.Add(time.Hour)
	state, err = f.store.BeginIdentityProvisioning(context.Background(), initialProvisioningBegin(state.TenantID.String(), p, "", refreshedAt))
	if err != nil {
		t.Fatal(err)
	}
	expiredProof := initialProvisioningProof(state, p, refreshedAt)
	state, err = f.store.ReadIdentityProvisioning(context.Background(), expiredProof)
	if err != nil {
		t.Fatal(err)
	}
	if state.Connection == nil || state.Connection.TestPassed {
		t.Fatalf("expired current draft test status=%+v", state.Connection)
	}
}

func TestIdentityInitialProvisioningMembershipRaceClosesBeforeFurtherMutation(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	person := shared.ID("initial-provisioning-race-person")
	if _, err := f.platform.ApplyPersonCommand(context.Background(), person, ports.IdentityPersonCreated, "platform", "membership race"); err != nil {
		t.Fatal(err)
	}
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	start := make(chan struct{})
	memberErr := make(chan error, 1)
	draftErr := make(chan error, 1)
	go func() {
		<-start
		_, err := f.store.AddMembership(context.Background(), state.TenantID, person, "First admin", user.RoleAdmin, p.ActorID, at)
		memberErr <- err
	}()
	go func() {
		<-start
		_, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, initialProvisioningProof(state, p, at))
		draftErr <- err
	}()
	close(start)
	if err := <-memberErr; err != nil {
		t.Fatalf("first membership: %v", err)
	}
	if err := <-draftErr; err != nil && !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("racing draft: %v", err)
	}
	closed, err := f.store.ReadIdentityProvisioning(context.Background(), initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != "closed" {
		t.Fatalf("race provisioning state=%q, want closed", closed.State)
	}
	if _, err = f.store.SaveIdentityProvisioningDraft(context.Background(), draft, initialProvisioningProof(closed, p, at)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("mutation after membership closure=%v, want ErrForbidden", err)
	}
}

func TestIdentityInitialProvisioningExpiredInvitationDoesNotRenewOnRetry(t *testing.T) {
	f, p, state, at := declaredInitialTenant(t)
	proof := initialProvisioningProof(state, p, at)
	draft := ports.IdentityConnectionDraft{TenantID: state.TenantID, ID: state.ConnectionID, DisplayName: "Sandbox Auth0", Issuer: "https://issuer.example/", Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://127.0.0.1:8446/api/auth/enterprise/callback", SealedClientSecret: "sealed"}}
	state, err := f.store.SaveIdentityProvisioningDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	proof = initialProvisioningProof(state, p, at)
	if err = f.store.RecordIdentityProvisioningTest(context.Background(), ports.IdentityConnectionTest{ID: "expiry-test", TenantID: state.TenantID, ConnectionID: state.ConnectionID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}, proof); err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ReadIdentityProvisioning(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	state, err = f.store.ActivateIdentityProvisioningConnection(context.Background(), 1, state.Connection.Version, initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	invitation := ports.IdentityInvitationCreate{Invitation: ports.IdentityInvitation{ID: state.InvitationID, TenantID: state.TenantID, Recipient: state.Recipient, Role: user.RoleAdmin, CreatedAt: at, ExpiresAt: at.Add(7 * 24 * time.Hour)}, CodeDigest: identityDigest("fixed-lifetime-code"), Actor: p.ActorID}
	issued, err := f.store.IssueIdentityProvisioningInvitation(context.Background(), invitation, "sealed-fixed-lifetime-code", initialProvisioningProof(state, p, at))
	if err != nil {
		t.Fatal(err)
	}
	var digestBefore string
	var expiryBefore time.Time
	if err := WithTenant(context.Background(), f.runtime, state.TenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT code_digest,expires_at FROM identity_invitations WHERE tenant_id=$1 AND id=$2`, state.TenantID.String(), state.InvitationID.String()).Scan(&digestBefore, &expiryBefore)
	}); err != nil {
		t.Fatal(err)
	}
	expiredAt := invitation.Invitation.ExpiresAt.Add(time.Second)
	retry := invitation
	retry.CodeDigest = identityDigest("must-not-renew-expired-code")
	if _, err = f.store.IssueIdentityProvisioningInvitation(context.Background(), retry, "sealed-must-not-renew", initialProvisioningProof(issued, p, expiredAt)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expired invitation retry=%v, want ErrConflict", err)
	}
	var digestAfter string
	var expiryAfter time.Time
	if err := WithTenant(context.Background(), f.runtime, state.TenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT code_digest,expires_at FROM identity_invitations WHERE tenant_id=$1 AND id=$2`, state.TenantID.String(), state.InvitationID.String()).Scan(&digestAfter, &expiryAfter)
	}); err != nil {
		t.Fatal(err)
	}
	if digestAfter != digestBefore || !expiryAfter.Equal(expiryBefore) {
		t.Fatalf("expired retry changed invitation digest=%q/%q expiry=%s/%s", digestBefore, digestAfter, expiryBefore, expiryAfter)
	}
	if got := f.runtimeCount(t, state.TenantID.String(), `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, state.TenantID.String()); got != 0 {
		t.Fatalf("expired retry memberships=%d, want zero", got)
	}
}

func TestMigration0265InitialProvisioningDownRefusesProvenanceUnderForceRLS(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 265, 265)
	const tenant = "migration-0265-provenance"
	if _, err := isolate.db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$2)`, tenant, "Migration 0265"); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, isolate.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_initial_provisioning(
			tenant_id,id,connection_id,invitation_id,actor_id,source_tenant_id,credential_id,recipient,state,created_at,updated_at)
			VALUES($1,'provisioning','connection','invitation','bootstrap','source','credential','admin@example.com','open',clock_timestamp(),clock_timestamp())`, tenant); err != nil {
			t.Fatalf("seed provisioning provenance: %v", err)
		}
	})

	if err := goose.DownTo(isolate.db, ".", 264); err == nil || !strings.Contains(err.Error(), "requires a forward fix") {
		t.Fatalf("rollback populated provisioning provenance err=%v", err)
	}
	requireMigrationRLS(t, isolate.db, "identity_initial_provisioning")
	var functionDefinition string
	if err := isolate.db.QueryRow(`SELECT pg_get_functiondef('public.synapse_identity_close_initial_provisioning()'::regprocedure)`).Scan(&functionDefinition); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(functionDefinition, "IF NOT EXISTS") {
		t.Fatalf("failed rollback restored legacy closure: %s", functionDefinition)
	}
}

func TestIdentityInitialProvisioningClosureSkipsLegacyProjectionWithoutDeadlock(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "initial-provisioning-legacy-projection"
	f.tenants(t, tenant)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if err := WithTenant(context.Background(), f.runtime, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO identity_policies(tenant_id,id) VALUES($1,'policy')`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.enableProjection(t, tenant, at)

	// 0264 upgraded each transaction's compatibility FOR SHARE lock to FOR UPDATE in its
	// membership trigger. Force both shares before either projects a membership to make the old
	// deadlock reproducible on this disposable database.
	installInitialProvisioningClosure(t, f, false)
	oldErrs := concurrentLegacyProjectionCreates(t, f, tenant, at, "legacy-old-one", "legacy-old-two")
	var oldDeadlock bool
	for _, err := range oldErrs {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
			oldDeadlock = true
		}
	}
	if !oldDeadlock {
		t.Fatalf("0264 closure did not reproduce policy lock-upgrade deadlock: %v", oldErrs)
	}

	installInitialProvisioningClosure(t, f, true)
	for _, err := range concurrentLegacyProjectionCreates(t, f, tenant, at, "legacy-repaired-one", "legacy-repaired-two") {
		if err != nil {
			t.Fatalf("repaired legacy projection create: %v", err)
		}
	}
	if got := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1 AND legacy_user_id IN ('legacy-repaired-one','legacy-repaired-two')`, tenant); got != 2 {
		t.Fatalf("repaired legacy memberships=%d, want 2", got)
	}
}

func concurrentLegacyProjectionCreates(t *testing.T, f *identityFixture, tenant string, at time.Time, ids ...string) []error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{}, len(ids))
	release := make(chan struct{})
	errs := make(chan error, len(ids))
	for _, id := range ids {
		id := id
		go func() {
			digest := identityDigest("legacy-projection-" + id)
			u, err := user.New(shared.ID(id), tenant, "User "+id, user.RoleMember, digest, at)
			if err == nil {
				err = f.tx.Run(ctx, shared.ID(tenant), func(txCtx context.Context) error {
					tx, bound, txErr := contextTenantTx(txCtx, shared.ID(tenant))
					if txErr != nil {
						return txErr
					}
					if !bound {
						return errors.New("legacy projection transaction is not tenant-bound")
					}
					if _, txErr = tx.Exec(txCtx, `SELECT 1 FROM identity_policies WHERE tenant_id=$1 FOR SHARE`, tenant); txErr != nil {
						return txErr
					}
					ready <- struct{}{}
					select {
					case <-release:
					case <-txCtx.Done():
						return txCtx.Err()
					}
					return f.users.Create(txCtx, u)
				})
			}
			errs <- err
		}()
	}
	for range ids {
		select {
		case <-ready:
		case <-ctx.Done():
			close(release)
			results := make([]error, 0, len(ids))
			for range ids {
				results = append(results, <-errs)
			}
			return results
		}
	}
	close(release)
	results := make([]error, 0, len(ids))
	for range ids {
		results = append(results, <-errs)
	}
	return results
}

func installInitialProvisioningClosure(t *testing.T, f *identityFixture, repaired bool) {
	t.Helper()
	body := `
DECLARE
    close_at TIMESTAMPTZ := GREATEST(NEW.created_at, clock_timestamp());
BEGIN
    PERFORM 1 FROM public.identity_policies WHERE tenant_id = NEW.tenant_id FOR UPDATE;
    UPDATE public.identity_initial_provisioning
       SET state = 'closed', invitation_code_sealed = NULL,
           closed_at = GREATEST(close_at, updated_at),
           updated_at = GREATEST(close_at, updated_at), version = version + 1
     WHERE tenant_id = NEW.tenant_id AND state <> 'closed';
    RETURN NULL;
END;`
	if repaired {
		body = `
DECLARE
    close_at TIMESTAMPTZ := GREATEST(NEW.created_at, clock_timestamp());
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.identity_initial_provisioning
         WHERE tenant_id = NEW.tenant_id AND state <> 'closed'
    ) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM public.identity_policies WHERE tenant_id = NEW.tenant_id FOR UPDATE;
    UPDATE public.identity_initial_provisioning
       SET state = 'closed', invitation_code_sealed = NULL,
           closed_at = GREATEST(close_at, updated_at),
           updated_at = GREATEST(close_at, updated_at), version = version + 1
     WHERE tenant_id = NEW.tenant_id AND state <> 'closed';
    RETURN NULL;
END;`
	}
	statement := `CREATE OR REPLACE FUNCTION synapse_identity_close_initial_provisioning()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $close_initial_provisioning$` + body + `
$close_initial_provisioning$;`
	if _, err := f.admin.Exec(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
	if repaired {
		return
	}
	t.Cleanup(func() { installInitialProvisioningClosure(t, f, true) })
}
