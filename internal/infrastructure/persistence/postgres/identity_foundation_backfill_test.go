package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityfoundation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const testIssuer = "https://idp.example.test"

func (f *identityFixture) service(t *testing.T) *identityfoundation.Service {
	t.Helper()
	svc, err := identityfoundation.NewService(f.store, f.store, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (f *identityFixture) backfill(t *testing.T, tenant string, batch int) identityfoundation.BackfillResult {
	t.Helper()
	res, err := f.service(t).Backfill(context.Background(), shared.ID(tenant), identityfoundation.BackfillOptions{
		Actor: "backfill-test", Issuer: testIssuer, BatchSize: batch, Lease: time.Minute,
	})
	if err != nil {
		t.Fatalf("backfill %s: %v", tenant, err)
	}
	return res
}

// seedIssued seeds a users row plus the create audit that proves its key was issued.
func (f *identityFixture) seedIssued(t *testing.T, tenant, id string, role user.Role, disabled bool) string {
	t.Helper()
	digest := identityDigest("seed-" + tenant + "-" + id)
	f.seedUser(t, tenant, id, role, digest, disabled)
	f.seedAudit(t, tenant, "user.created", id, map[string]string{"name": id})
	return digest
}

func (f *identityFixture) item(t *testing.T, tenant, id string) (string, string) {
	t.Helper()
	var class, credential string
	if err := f.admin.QueryRow(context.Background(), `SELECT classification, credential_class FROM identity_backfill_items WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&class, &credential); err != nil {
		t.Fatalf("backfill item %s/%s: %v", tenant, id, err)
	}
	return class, credential
}

func (f *identityFixture) auditFingerprint(t *testing.T) string {
	t.Helper()
	var out string
	if err := f.admin.QueryRow(context.Background(), `SELECT COALESCE(string_agg(id::text||':'||actor||':'||COALESCE(hash,''), ',' ORDER BY id), '') FROM audit_log WHERE action NOT LIKE 'identity.%'`).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIdentityBackfillClassificationOnPopulatedDB(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a", "org-b")
	// The users source carries a global unique hash index; drop it here to model a corrupted source.
	f.exec(t, `DROP INDEX idx_users_api_key_hash`)
	f.seedUser(t, "", "operator", user.RoleAdmin, identityDigest("bootstrap-token"), false)
	realKey := f.seedIssued(t, "org-a", "real", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "rotated", user.RoleConsultant, false)
	f.seedAudit(t, "org-a", "user.api_key_rotated", "rotated", nil)
	// Disabled by the current binary: the disable replaced the key.
	f.seedIssued(t, "org-a", "disabled", user.RoleMember, true)
	f.seedAudit(t, "org-a", "user.disabled", "disabled", map[string]string{"api_key_revoked": "true"})
	// OIDC-provisioned placeholder: random digest, approved link, no issuance evidence.
	f.seedUser(t, "org-a", "oidc-user", user.RoleMember, identityDigest("placeholder"), false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-1','org-a','oidc-user',$1,'subject-1')`, testIssuer)
	// Operator-approved link records its approver.
	f.seedIssued(t, "org-a", "linked", user.RoleReviewer, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-2','org-a','linked',$1,'subject-2')`, testIssuer)
	f.seedAudit(t, "org-a", "user.oidc_identity_linked", "linked", map[string]string{"link_id": "link-2"})
	f.seedUser(t, "org-a", "unproven", user.RoleMember, identityDigest("unproven"), false)
	f.seedUser(t, "org-a", "corrupt", user.RoleMember, "not-a-digest", false)
	f.seedUser(t, "org-a", "dup-1", user.RoleMember, identityDigest("shared"), false)
	f.seedUser(t, "org-a", "dup-2", user.RoleMember, identityDigest("shared"), false)
	f.seedIssued(t, "org-a", "foreign", user.RoleMember, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-3','org-a','foreign','https://other.test','subject-3')`)
	// Cross-tenant duplicate: org-b shares a digest with org-a users.
	f.seedUser(t, "org-b", "copycat", user.RoleMember, identityDigest("shared"), false)
	before := f.auditFingerprint(t)

	res := f.backfill(t, "org-a", 3)
	f.backfill(t, "default", 3)
	resB := f.backfill(t, "org-b", 3)

	want := map[string][2]string{
		"real":      {"migrated", "real"},
		"rotated":   {"migrated", "real"},
		"disabled":  {"suspended", "disabled"},
		"oidc-user": {"migrated", "placeholder"},
		"linked":    {"migrated", "real"},
		"unproven":  {"ambiguous_unproven_key", "ambiguous"},
		"corrupt":   {"ambiguous_corrupt", "ambiguous"},
		"dup-1":     {"ambiguous_duplicate", "ambiguous"},
		"dup-2":     {"ambiguous_duplicate", "ambiguous"},
		"foreign":   {"ambiguous_foreign_link", "real"},
	}
	for id, w := range want {
		if class, credential := f.item(t, "org-a", id); class != w[0] || credential != w[1] {
			t.Errorf("%s classified %s/%s, want %s/%s", id, class, credential, w[0], w[1])
		}
	}
	if class, _ := f.item(t, "default", "operator"); class != "bootstrap_skipped" {
		t.Fatalf("bootstrap classified %s", class)
	}
	if class, _ := f.item(t, "org-b", "copycat"); class != "ambiguous_duplicate" {
		t.Fatalf("cross-tenant duplicate classified %s", class)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE legacy_user_id IN ('operator','corrupt','dup-1','dup-2','copycat')`); n != 0 {
		t.Fatalf("bootstrap or ambiguous-hash users projected: %d", n)
	}
	// Credentials: only issued keys; disabled keeps none; placeholder gets none.
	if r, err := f.store.RouteCredentialDigest(ctx, realKey); err != nil || r.TenantID != "org-a" {
		t.Fatalf("real key route: %v", err)
	}
	for _, digest := range []string{identityDigest("placeholder"), identityDigest("unproven"), identityDigest("shared"), identityDigest("seed-org-a-disabled"), identityDigest("bootstrap-token")} {
		if _, err := f.store.RouteCredentialDigest(ctx, digest); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("unissued digest routes: %v", err)
		}
	}
	if m := f.membershipOf(t, "org-a", "disabled"); m.State != ports.IdentityMembershipSuspended || m.SuspensionSource != ports.IdentityTransitionManual {
		t.Fatalf("disabled user membership = %+v", m)
	}
	// Approved links import under the configured issuer only, with approval provenance.
	var approvedBy string
	if err := f.admin.QueryRow(ctx, `SELECT approved_by FROM identity_authenticators WHERE tenant_id='org-a' AND protocol_subject='subject-2'`).Scan(&approvedBy); err != nil || approvedBy != "admin" {
		t.Fatalf("operator-approved link provenance = %q, %v", approvedBy, err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id='org-a'`); n != 2 {
		t.Fatalf("imported authenticators = %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_connections WHERE tenant_id='org-a' AND trust_namespace=$1 AND NOT enabled`, testIssuer); n != 1 {
		t.Fatalf("pinned issuer connection = %d", n)
	}
	// Ambiguous rows block readiness; nothing drifts.
	if res.Report.Ready || res.Report.Ambiguous != 5 || res.Report.DriftTotal != 0 || res.Report.Placeholders != 1 {
		t.Fatalf("org-a report = %+v", res.Report)
	}
	if resB.Report.Ready || resB.Report.Ambiguous != 1 {
		t.Fatalf("org-b report = %+v", resB.Report)
	}
	// No actor string or audit hash was rewritten.
	if after := f.auditFingerprint(t); after != before {
		t.Fatal("backfill rewrote existing audit records")
	}
	if n := f.adminCount(t, `SELECT count(*) FROM users WHERE id='corrupt' AND api_key_hash='not-a-digest'`); n != 1 {
		t.Fatal("backfill repaired the legacy source")
	}
}

func TestIdentityBackfillCrashRetryAndFence(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a")
	for i := 0; i < 25; i++ {
		f.seedIssued(t, "org-a", fmt.Sprintf("user-%02d", i), user.RoleMember, false)
	}
	run, err := f.store.StartRun(ctx, "org-a", "run-1", "test", 10, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	// A second run cannot take a live fence.
	if _, err := f.store.StartRun(ctx, "org-a", "run-x", "test", 10, time.Minute, now); !errors.Is(err, ports.ErrIdentityFenceLost) {
		t.Fatalf("concurrent start: %v", err)
	}
	classify := identityfoundation.NewClassifier(testIssuer)
	if _, err := f.store.ApplyBatch(ctx, &run, testIssuer, classify, now); err != nil {
		t.Fatal(err)
	}
	// Crash mid-batch: cancel after four users of the second batch.
	crashCtx, cancel := context.WithCancel(ctx)
	seen := 0
	crashing := func(u ports.IdentityLegacyUser) ports.IdentityBackfillDecision {
		seen++
		if seen == 4 {
			cancel()
		}
		return classify(u)
	}
	if _, err := f.store.ApplyBatch(crashCtx, &run, testIssuer, crashing, now); err == nil {
		t.Fatal("cancelled batch committed")
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_backfill_items WHERE tenant_id='org-a'`); n != 10 {
		t.Fatalf("partial batch committed %d items", n)
	}
	if run.CheckpointUserID != "user-09" {
		t.Fatalf("checkpoint = %s", run.CheckpointUserID)
	}
	// The crashed run holds its lease; after expiry a new run takes the fence and resumes.
	later := now.Add(2 * time.Minute)
	resumed, err := f.store.StartRun(ctx, "org-a", "run-2", "test", 10, time.Minute, later)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.CheckpointUserID != "user-09" || resumed.FenceToken != run.FenceToken+1 {
		t.Fatalf("resumed run = %+v", resumed)
	}
	// The superseded run is fenced out and writes nothing.
	if _, err := f.store.ApplyBatch(ctx, &run, testIssuer, classify, later); !errors.Is(err, ports.ErrIdentityFenceLost) {
		t.Fatalf("stale fence batch: %v", err)
	}
	for {
		batch, err := f.store.ApplyBatch(ctx, &resumed, testIssuer, classify, later)
		if err != nil {
			t.Fatal(err)
		}
		if batch.Done {
			break
		}
	}
	if err := f.store.FinishRun(ctx, resumed, nil, later); err != nil {
		t.Fatal(err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id='org-a'`); n != 25 {
		t.Fatalf("memberships after resume = %d", n)
	}
	// Idempotent rerun: same rows, a clean shadow report.
	res := f.backfill(t, "org-a", 7)
	if !res.Report.Ready || res.Report.Memberships != 25 || res.Report.CredentialsMatched != 25 {
		t.Fatalf("rerun report = %+v", res.Report)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_credentials WHERE tenant_id='org-a'`); n != 25 {
		t.Fatalf("credentials after rerun = %d", n)
	}
	var states string
	_ = f.admin.QueryRow(ctx, `SELECT string_agg(id||'='||state, ',' ORDER BY id) FROM identity_backfill_runs WHERE tenant_id='org-a'`).Scan(&states)
	if states == "" {
		t.Fatal("no run records")
	}
}

func TestIdentityBackfillConcurrentOldWritesAndRotation(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a")
	for i := 0; i < 60; i++ {
		f.seedIssued(t, "org-a", fmt.Sprintf("user-%02d", i), user.RoleMember, false)
	}
	f.seedIssued(t, "org-a", "admin-a", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "admin-b", user.RoleAdmin, false)
	var wg sync.WaitGroup
	var writeErr error
	var mu sync.Mutex
	latest := map[string]string{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := 0; round < 3; round++ {
			for i := 0; i < 60; i += 7 {
				id := fmt.Sprintf("user-%02d", i)
				digest := identityDigest(fmt.Sprintf("rotation-%d-%s", round, id))
				err := f.updateUser(t, "org-a", id, "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = digest })
				mu.Lock()
				if err != nil && writeErr == nil {
					writeErr = err
				}
				latest[id] = digest
				mu.Unlock()
			}
		}
		// An old-path create and a disable during the backfill.
		f.createUser(t, "org-a", "user-zz", user.RoleMember, time.Now().UTC())
		if err := f.updateUser(t, "org-a", "user-01", "user.disabled", func(u *user.User) {
			u.Disabled, u.APIKeyHash = true, identityDigest("disabled-user-01")
		}); err != nil {
			mu.Lock()
			writeErr = err
			mu.Unlock()
		}
	}()
	res := f.backfill(t, "org-a", 5)
	wg.Wait()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	// Whatever interleaving occurred, a fresh parity report shows no drift.
	report, err := f.service(t).Shadow(ctx, "org-a", ports.IdentityShadowThresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if report.DriftTotal != 0 || report.Ambiguous != 0 || !report.Ready {
		t.Fatalf("post-concurrency report = %+v (backfill report %+v)", report, res.Report)
	}
	for id, digest := range latest {
		if r, err := f.store.RouteCredentialDigest(ctx, digest); err != nil || r.TenantID != "org-a" {
			t.Fatalf("latest rotated digest of %s does not route: %v", id, err)
		}
	}
	for _, digest := range []string{identityDigest("seed-org-a-user-01"), identityDigest("disabled-user-01")} {
		if _, err := f.store.RouteCredentialDigest(ctx, digest); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("disabled user digest routes: %v", err)
		}
	}
	if class, _ := f.item(t, "org-a", "user-zz"); class != "migrated" {
		t.Fatalf("old-path create classified %s", class)
	}
}

func TestIdentityBackfillReconcilesAuthoritativeApprovedLinks(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a")
	f.seedIssued(t, "org-a", "alice", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "bob", user.RoleMember, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-a','org-a','alice',$1,'shared-subject')`, testIssuer)
	first := f.backfill(t, "org-a", 10)
	if !first.Report.Ready || first.Report.AuthenticatorsExpected != 1 || first.Report.AuthenticatorsMatched != 1 || first.Report.AuthenticatorMismatches != 0 {
		t.Fatalf("initial authenticator parity = %+v", first.Report)
	}
	alice := f.membershipOf(t, "org-a", "alice")
	bob := f.membershipOf(t, "org-a", "bob")
	var membership, person string
	if err := f.admin.QueryRow(ctx, `SELECT membership_id,person_id FROM identity_authenticators WHERE tenant_id='org-a' AND protocol_subject='shared-subject'`).Scan(&membership, &person); err != nil {
		t.Fatal(err)
	}
	if membership != alice.ID.String() || person != alice.PersonID.String() {
		t.Fatalf("initial owner = %s/%s, want alice", membership, person)
	}

	// Direct authoritative deletion is reconciled, including an extra stale derived row.
	f.exec(t, `DELETE FROM oidc_external_identities WHERE id='link-a'`)
	f.exec(t, `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		SELECT 'org-a','stale-auth',id,'stale-subject',$1,$2,'legacy','legacy_link' FROM identity_connections WHERE tenant_id='org-a' AND trust_namespace=$3`, alice.ID.String(), alice.PersonID.String(), testIssuer)
	unlinked := f.backfill(t, "org-a", 10)
	if !unlinked.Report.Ready || unlinked.Report.AuthenticatorsExpected != 0 || unlinked.Report.AuthenticatorsMatched != 0 || unlinked.Report.AuthenticatorMismatches != 0 {
		t.Fatalf("unlink authenticator parity = %+v", unlinked.Report)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id='org-a'`); n != 0 {
		t.Fatalf("stale authenticators after unlink = %d", n)
	}

	// Reapproval to another user replaces the immutable legacy binding transactionally.
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-b','org-a','bob',$1,'shared-subject')`, testIssuer)
	rebound := f.backfill(t, "org-a", 10)
	if !rebound.Report.Ready || rebound.Report.AuthenticatorsExpected != 1 || rebound.Report.AuthenticatorsMatched != 1 || rebound.Report.AuthenticatorMismatches != 0 {
		t.Fatalf("rebound authenticator parity = %+v", rebound.Report)
	}
	if err := f.admin.QueryRow(ctx, `SELECT membership_id,person_id FROM identity_authenticators WHERE tenant_id='org-a' AND protocol_subject='shared-subject'`).Scan(&membership, &person); err != nil {
		t.Fatal(err)
	}
	if membership != bob.ID.String() || person != bob.PersonID.String() {
		t.Fatalf("rebound owner = %s/%s, want bob", membership, person)
	}

	// Shadow reports direct authoritative drift without repairing it.
	f.exec(t, `UPDATE oidc_external_identities SET user_id='alice' WHERE id='link-b'`)
	drift, err := f.service(t).Shadow(ctx, "org-a", ports.IdentityShadowThresholds{MaxDrift: 0})
	if err != nil {
		t.Fatal(err)
	}
	if drift.AuthenticatorsExpected != 1 || drift.AuthenticatorsMatched != 0 || drift.AuthenticatorMismatches != 2 || drift.DriftTotal < 2 || drift.Ready || !drift.Aborted {
		t.Fatalf("direct rebind drift = %+v", drift)
	}
	var currentUser string
	if err := f.admin.QueryRow(ctx, `SELECT user_id FROM oidc_external_identities WHERE id='link-b'`).Scan(&currentUser); err != nil || currentUser != "alice" {
		t.Fatalf("shadow changed authoritative link = %q, %v", currentUser, err)
	}
	if repaired := f.backfill(t, "org-a", 10); !repaired.Report.Ready || repaired.Report.AuthenticatorMismatches != 0 {
		t.Fatalf("direct rebind reconciliation = %+v", repaired.Report)
	}
}

func TestIdentityBackfillFailsClosedOnNativeAuthenticatorConflict(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "org-a")
	f.seedIssued(t, "org-a", "alice", user.RoleAdmin, false)
	f.backfill(t, "org-a", 10)
	f.declare(t, "org-a")
	alice := f.membershipOf(t, "org-a", "alice")
	f.exec(t, `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		SELECT 'org-a','native-auth',id,'native-subject',$1,$2,'admin','native' FROM identity_connections WHERE tenant_id='org-a' AND trust_namespace=$3`, alice.ID.String(), alice.PersonID.String(), testIssuer)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-native','org-a','alice',$1,'native-subject')`, testIssuer)
	_, err := f.service(t).Backfill(context.Background(), "org-a", identityfoundation.BackfillOptions{
		Actor: "backfill-test", Issuer: testIssuer, BatchSize: 10, Lease: time.Minute,
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("native conflict error = %v, want conflict", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id='org-a' AND id='native-auth' AND source='native'`); n != 1 {
		t.Fatalf("native conflict changed native row: %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id='org-a' AND protocol_subject='native-subject' AND source='legacy_link'`); n != 0 {
		t.Fatalf("native conflict inserted legacy row: %d", n)
	}
}

func TestIdentityBackfillSerializesConcurrentLinkChange(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a")
	f.seedIssued(t, "org-a", "alice", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "bob", user.RoleMember, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-race','org-a','alice',$1,'race-subject')`, testIssuer)
	f.backfill(t, "org-a", 10)

	locked := make(chan struct{})
	release := make(chan struct{})
	changeDone := make(chan error, 1)
	go func() {
		err := WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE oidc_external_identities SET user_id='bob' WHERE id='link-race'`); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
		changeDone <- err
	}()
	<-locked
	backfillDone := make(chan identityfoundation.BackfillResult, 1)
	backfillErr := make(chan error, 1)
	go func() {
		res, err := f.service(t).Backfill(context.Background(), "org-a", identityfoundation.BackfillOptions{
			Actor: "backfill-test", Issuer: testIssuer, BatchSize: 10, Lease: time.Minute,
		})
		backfillDone <- res
		backfillErr <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(release)
	if err := <-changeDone; err != nil {
		t.Fatal(err)
	}
	res := <-backfillDone
	if err := <-backfillErr; err != nil {
		t.Fatal(err)
	}
	if !res.Report.Ready || res.Report.AuthenticatorMismatches != 0 {
		t.Fatalf("concurrent link reconciliation = %+v", res.Report)
	}
	bob := f.membershipOf(t, "org-a", "bob")
	if n := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id='org-a' AND protocol_subject='race-subject' AND membership_id=$1 AND person_id=$2`, bob.ID.String(), bob.PersonID.String()); n != 1 {
		t.Fatalf("concurrent link owner not reconciled: %d", n)
	}
}

func TestIdentityShadowDriftReportNeverRepairs(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a")
	f.seedIssued(t, "org-a", "alice", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "bob", user.RoleMember, false)
	f.seedIssued(t, "org-a", "carol", user.RoleMember, false)
	if res := f.backfill(t, "org-a", 10); !res.Report.Ready {
		t.Fatalf("initial report not ready: %+v", res.Report)
	}
	// An older binary writes users directly, bypassing projection.
	f.exec(t, `UPDATE users SET role='readonly' WHERE id='bob'`)
	f.exec(t, `UPDATE users SET api_key_hash=$1 WHERE id='carol'`, identityDigest("carol-direct"))
	f.exec(t, `UPDATE users SET disabled=true WHERE id='alice'`)
	svc := f.service(t)
	strict, err := svc.Shadow(ctx, "org-a", ports.IdentityShadowThresholds{MaxDrift: 0})
	if err != nil {
		t.Fatal(err)
	}
	if strict.RoleDrift != 1 || strict.StateDrift != 1 || strict.DigestMismatches != 2 || strict.RoutingMismatches == 0 || strict.Ready || !strict.Aborted || !strict.RollbackPrepared {
		t.Fatalf("strict drift report = %+v", strict)
	}
	if len(strict.DriftedUserIDs) != 3 {
		t.Fatalf("drifted users = %v", strict.DriftedUserIDs)
	}
	lenient, err := svc.Shadow(ctx, "org-a", ports.IdentityShadowThresholds{MaxDrift: 100})
	if err != nil || lenient.Aborted || lenient.Ready {
		t.Fatalf("lenient drift report = %+v, %v", lenient, err)
	}
	// The report never repairs the source.
	if n := f.adminCount(t, `SELECT count(*) FROM users WHERE (id='bob' AND role='readonly') OR (id='carol' AND api_key_hash=$1) OR (id='alice' AND disabled)`, identityDigest("carol-direct")); n != 3 {
		t.Fatal("shadow report changed users")
	}
	var details []byte
	if err := f.admin.QueryRow(ctx, `SELECT details FROM identity_shadow_reports WHERE id=$1`, strict.ID.String()).Scan(&details); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(details, &decoded); err != nil || decoded["cutover_phase"] != "legacy" {
		t.Fatalf("report details = %s, %v", details, err)
	}
	err = f.runtimeExec("org-a", `UPDATE identity_shadow_reports SET ready=true WHERE id=$1`, strict.ID.String())
	requireSQLState(t, err, "SYN02")
	// A rerun reconciles the derived rows from the authoritative source.
	if res := f.backfill(t, "org-a", 10); !res.Report.Ready {
		t.Fatalf("reconciled report = %+v", res.Report)
	}
}

// consumerStatements inserts one row into every table that references a users row, for user u of
// tenant t. Setup statements are tenant-owned prerequisites; each consumer statement is checked
// separately so an FK failure names its table.
func consumerSetup(tenant string) []string {
	p := tenant + "-"
	return []string{
		`INSERT INTO engagements(id,tenant_id,name) VALUES('` + p + `eng','` + tenant + `','E')`,
		`INSERT INTO ownership_teams(tenant_id,id,slug,name,revision,created_at,updated_at) VALUES('` + tenant + `','team','team','Team',1,now(),now())`,
		`INSERT INTO ownership_policies(tenant_id,engagement_id,id) VALUES('` + tenant + `','` + p + `eng','policy')`,
		`INSERT INTO ownership_policy_versions(tenant_id,engagement_id,policy_id,version,content_hash,payload,created_at) VALUES('` + tenant + `','` + p + `eng','policy',1,repeat('a',64),'{}',now())`,
		`INSERT INTO ownership_runs(tenant_id,engagement_id,id,policy_id,policy_version,mode,state,revision,policy_revision,policy_hash,cutoff,total,filter,created_at)
		 VALUES('` + tenant + `','` + p + `eng','run','policy',1,'preview','queued',1,1,repeat('a',64),now(),0,'{}',now())`,
		`INSERT INTO findings(id,tenant_id,engagement_id,title,severity,status,dedup_key,created_at,updated_at) VALUES('` + p + `finding','` + tenant + `','` + p + `eng','F','high','open','` + p + `dedup',now(),now())`,
		`INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES('` + tenant + `','event','scan.completed','scan_job','scan-1',1,now(),'{}')`,
	}
}

func consumerStatements(tenant, u string) map[string]string {
	p := tenant + "-"
	return map[string]string{
		"ownership_memberships":              `INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES('` + tenant + `','team','` + u + `',now())`,
		"ownership_mappings":                 `INSERT INTO ownership_mappings(tenant_id,engagement_id,repository,owner_token,team_id,suggested_user_id,revision) VALUES('` + tenant + `','` + p + `eng','repo','` + u + `','team','` + u + `',1)`,
		"ownership_assignments":              `INSERT INTO ownership_assignments(tenant_id,engagement_id,finding_id,team_id,assignee_id,legacy_assignee,mode,revision,resolution,reason,updated_at) VALUES('` + tenant + `','` + p + `eng','` + p + `finding','team','` + u + `','` + u + `','manual',1,'resolved','test',now())`,
		"ownership_bulk_requests":            `INSERT INTO ownership_bulk_requests(tenant_id,actor_id,request_key,request_hash,created_at) VALUES('` + tenant + `','` + u + `','key',repeat('b',64),now())`,
		"ownership_run_requests":             `INSERT INTO ownership_run_requests(tenant_id,actor_id,request_key,request_hash,run_id) VALUES('` + tenant + `','` + u + `','key',repeat('c',64),'run')`,
		"user_contacts":                      `INSERT INTO user_contacts(tenant_id,id,user_id,kind,value) VALUES('` + tenant + `','` + u + `-contact','` + u + `','email','person@example.test')`,
		"user_contact_verification_requests": `INSERT INTO user_contact_verification_requests(tenant_id,id,user_id) VALUES('` + tenant + `','` + u + `-vr','` + u + `')`,
		"findings.assignee_user_id":          `UPDATE findings SET assignee_user_id='` + u + `' WHERE tenant_id='` + tenant + `' AND id='` + p + `finding'`,
		"user_notifications":                 `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at) VALUES('` + tenant + `','` + u + `','n-` + u + `','event','scan.completed','T','S','/findings',now())`,
		"user_notification_preferences":      `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES('` + tenant + `','` + u + `','scan.completed','in_app','enabled',1,now())`,
		"oidc_external_identities":           `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-` + p + u + `','` + tenant + `','` + u + `','` + testIssuer + `','sub-` + p + u + `')`,
		"oidc_sessions":                      `INSERT INTO oidc_sessions(id,tenant_id,user_id,token_hash,csrf_token_hash,origin_at,expires_at) VALUES('sess-` + p + u + `','` + tenant + `','` + u + `','tok-` + p + u + `','csrf',now(),now()+interval '1 hour')`,
	}
}

func TestIdentityTenantBMemberUsesExistingUserForeignKeys(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b")
	aliceKey := f.seedIssued(t, "org-a", "alice", user.RoleConsultant, false)
	f.seedIssued(t, "org-a", "admin-a", user.RoleAdmin, false)
	f.exec(t, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,value,source,source_key,verified_at) VALUES('org-a','oidc-contact','alice','email','alice@example.test','oidc','issuer|subject',now())`)
	var contactBefore string
	contactRow := `SELECT row_to_json(c)::text FROM user_contacts c WHERE tenant_id='org-a' AND id='oidc-contact'`
	if err := f.admin.QueryRow(ctx, contactRow).Scan(&contactBefore); err != nil {
		t.Fatal(err)
	}
	f.backfill(t, "org-a", 10)
	alice := f.membershipOf(t, "org-a", "alice")
	f.declare(t, "org-b")
	inB, err := f.store.AddMembership(ctx, "org-b", alice.PersonID, "Alice", user.RoleConsultant, "platform-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	member := inB.LegacyUserID.String()
	// No duplicate global users.id: the B member is a distinct tenant-local users row.
	if member == "alice" || f.adminCount(t, `SELECT count(*) FROM users WHERE id='alice'`) != 1 ||
		f.adminCount(t, `SELECT count(*) FROM users WHERE id=$1 AND tenant_id='org-b' AND NOT disabled`, member) != 1 {
		t.Fatalf("B member projection is not a single tenant-local row: %s", member)
	}
	// The projected users row never carries a usable bearer key.
	var bHash string
	_ = f.admin.QueryRow(ctx, `SELECT api_key_hash FROM users WHERE id=$1`, member).Scan(&bHash)
	if _, err := f.store.RouteCredentialDigest(ctx, bHash); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("projected B users hash routes: %v", err)
	}
	for _, tenant := range []string{"org-a", "org-b"} {
		for _, stmt := range consumerSetup(tenant) {
			if err := f.runtimeExec(tenant, stmt); err != nil {
				t.Fatalf("%s setup %q: %v", tenant, stmt, err)
			}
		}
	}
	// Every users consumer accepts the A actor in A and the projected member in B, under RLS.
	for tenant, u := range map[string]string{"org-a": "alice", "org-b": member} {
		for table, stmt := range consumerStatements(tenant, u) {
			if err := f.runtimeExec(tenant, stmt); err != nil {
				t.Errorf("%s %s rejected %s: %v", tenant, table, u, err)
			}
		}
	}
	// ... and rejects the other tenant's actor.
	f.exec(t, `DELETE FROM oidc_sessions`)
	for tenant, u := range map[string]string{"org-a": member, "org-b": "alice"} {
		for table, stmt := range consumerStatements(tenant, u) {
			if table == "ownership_bulk_requests" || table == "ownership_run_requests" {
				stmt = replaceOnce(stmt, "'key'", "'key-cross'")
			}
			err := f.runtimeExec(tenant, stmt)
			if err == nil {
				t.Errorf("%s %s accepted cross-tenant actor %s", tenant, table, u)
			}
		}
	}
	// The finding assignee bridge resolves the B member by its tenant-local id.
	if err := f.runtimeExec("org-b", `UPDATE findings SET assignee=$1 WHERE tenant_id='org-b' AND id='org-b-finding'`, member); err != nil {
		t.Fatal(err)
	}
	if n := f.runtimeCount(t, "org-b", `SELECT count(*) FROM findings WHERE id='org-b-finding' AND assignee_user_id=$1`, member); n != 1 {
		t.Fatal("assignee bridge did not resolve the B member")
	}
	// Inbox routing resolves the B member as assignee in B.
	data, _ := json.Marshal(notification.OwnershipChanged{DecisionID: "d", FindingID: "org-b-finding", EngagementID: "org-b-eng", NewAssigneeID: shared.ID(member), NewTeamID: "team"})
	recipients, err := NewNotificationRepository(f.runtime).ResolvePersonalRecipients(ctx, "org-b", notification.Event{
		TenantID: "org-b", ID: "event-owned", Type: notification.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: "d",
		EngagementID: "org-b-eng", SchemaVersion: 1, OccurredAt: now, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recipients {
		if r.UserID.String() == member {
			found = true
		}
		if r.UserID == "alice" {
			t.Fatal("A actor resolved as a B recipient")
		}
	}
	if !found {
		t.Fatalf("B member not resolved as recipient: %+v", recipients)
	}
	// Contact source provenance is untouched by backfill.
	var contactAfter string
	if err := f.admin.QueryRow(ctx, contactRow).Scan(&contactAfter); err != nil || contactAfter != contactBefore {
		t.Fatalf("contact provenance changed:\n%s\n%s", contactBefore, contactAfter)
	}
	// A still authenticates on the legacy path with its unchanged key.
	if u, err := f.users.GetByAPIKeyHash(ctx, aliceKey); err != nil || u.ID != "alice" {
		t.Fatalf("legacy authentication: %v", err)
	}
}

func replaceOnce(s, old, repl string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + repl + s[i+len(old):]
		}
	}
	return s
}

func TestIdentityRollbackDrillKeepsLegacyAuthoritative(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a", "org-b")
	aliceKey := f.seedIssued(t, "org-a", "alice", user.RoleAdmin, false)
	f.seedIssued(t, "org-a", "bob", user.RoleMember, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject) VALUES('link-b','org-a','bob',$1,'subject-b')`, testIssuer)
	for _, stmt := range append(consumerSetup("org-a"), valuesOf(consumerStatements("org-a", "alice"))...) {
		if err := f.runtimeExec("org-a", stmt); err != nil {
			t.Fatalf("seed consumer %q: %v", stmt, err)
		}
	}
	res := f.backfill(t, "org-a", 10)
	if !res.Report.RollbackPrepared {
		t.Fatalf("rollback not prepared: %+v", res.Report)
	}
	consumers := f.adminCount(t, `SELECT (SELECT count(*) FROM ownership_memberships)+(SELECT count(*) FROM user_contacts)+(SELECT count(*) FROM user_notifications)+(SELECT count(*) FROM oidc_external_identities)`)
	usersBefore := f.adminCount(t, `SELECT count(*) FROM users`)
	auditBefore := f.auditFingerprint(t)
	if err := f.service(t).Rollback(ctx, "org-a", "operator-drill"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_memberships", "identity_credentials", "identity_authenticators", "identity_backfill_items"} {
		if n := f.runtimeCount(t, "org-a", `SELECT count(*) FROM `+table); n != 0 {
			t.Fatalf("%s kept %d rows after rollback", table, n)
		}
	}
	if _, err := f.store.RouteCredentialDigest(ctx, aliceKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rolled-back digest routes: %v", err)
	}
	// users and every consumer stay exactly as they were; legacy auth and writes keep working.
	if f.adminCount(t, `SELECT count(*) FROM users`) != usersBefore ||
		f.adminCount(t, `SELECT (SELECT count(*) FROM ownership_memberships)+(SELECT count(*) FROM user_contacts)+(SELECT count(*) FROM user_notifications)+(SELECT count(*) FROM oidc_external_identities)`) != consumers {
		t.Fatal("rollback touched legacy rows")
	}
	if u, err := f.users.GetByAPIKeyHash(ctx, aliceKey); err != nil || u.ID != "alice" {
		t.Fatalf("legacy auth after rollback: %v", err)
	}
	fresh := identityDigest("after-rollback")
	if err := f.updateUser(t, "org-a", "alice", "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = fresh }); err != nil {
		t.Fatalf("legacy write after rollback: %v", err)
	}
	if n := f.runtimeCount(t, "org-a", `SELECT count(*) FROM identity_credentials`); n != 0 {
		t.Fatal("projection kept writing after rollback")
	}
	if after := f.auditFingerprint(t); len(after) < len(auditBefore) || after[:len(auditBefore)] != auditBefore {
		t.Fatal("rollback rewrote audit history")
	}
	// Re-running the backfill converges again.
	if res := f.backfill(t, "org-a", 10); !res.Report.Ready || res.Report.Memberships != 2 {
		t.Fatalf("re-backfill report = %+v", res.Report)
	}
	// A declared tenant cannot be rolled back.
	f.declare(t, "org-b")
	if err := f.service(t).Rollback(ctx, "org-b", "operator-drill"); !errors.Is(err, ports.ErrIdentityLifecycle) {
		t.Fatalf("declared rollback: %v", err)
	}
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// TestIdentityBackfillBatchedEvidence loads the evidence of one whole batch with the set-based
// reads and checks each user classifies exactly as the newest decisive record dictates.
func TestIdentityBackfillBatchedEvidence(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.tenants(t, "org-a", "org-b")
	f.exec(t, `DROP INDEX idx_users_api_key_hash`)
	approve := func(target, linkID, actor string) {
		t.Helper()
		if err := WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
			return appendTenantAudit(ctx, tx, "org-a", ports.AuditEntry{Actor: actor, Action: "user.oidc_identity_linked", Target: target,
				Metadata: map[string]string{"link_id": linkID}, At: time.Now().UTC()})
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.seedIssued(t, "org-a", "issued", user.RoleMember, false)
	f.seedIssued(t, "org-a", "revoked", user.RoleMember, true)
	f.seedAudit(t, "org-a", "user.disabled", "revoked", map[string]string{"api_key_revoked": "true"})
	// A disable without the flag is skipped: the earlier create stays decisive.
	f.seedIssued(t, "org-a", "old-disable", user.RoleMember, false)
	f.seedAudit(t, "org-a", "user.disabled", "old-disable", nil)
	// A rotation after a revoking disable is newer, so the key is issued again.
	f.seedIssued(t, "org-a", "reissued", user.RoleMember, false)
	f.seedAudit(t, "org-a", "user.disabled", "reissued", map[string]string{"api_key_revoked": "true"})
	f.seedAudit(t, "org-a", "user.api_key_rotated", "reissued", nil)
	// Only a non-decisive disable: no evidence.
	f.seedUser(t, "org-a", "disable-only", user.RoleMember, identityDigest("disable-only"), false)
	f.seedAudit(t, "org-a", "user.disabled", "disable-only", nil)
	f.seedUser(t, "org-a", "none", user.RoleMember, identityDigest("none"), false)
	// Evidence in another tenant never counts.
	f.seedUser(t, "org-a", "foreign-evidence", user.RoleMember, identityDigest("foreign-evidence"), false)
	f.seedAudit(t, "org-b", "user.created", "foreign-evidence", nil)
	f.seedUser(t, "org-a", "dup-1", user.RoleMember, identityDigest("shared"), false)
	f.seedUser(t, "org-a", "dup-2", user.RoleMember, identityDigest("shared"), false)
	f.seedIssued(t, "org-a", "linked", user.RoleMember, false)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject,created_at) VALUES('link-a','org-a','linked',$1,'subject-a',now()-interval '1 hour')`, testIssuer)
	f.exec(t, `INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject,created_at) VALUES('link-b','org-a','linked',$1,'subject-b',now())`, testIssuer)
	approve("linked", "link-a", "first-approver")
	approve("linked", "link-a", "latest-approver")
	approve("linked", "link-other", "unrelated-approver")

	load := func() map[string]ports.IdentityLegacyUser {
		t.Helper()
		out := map[string]ports.IdentityLegacyUser{}
		if err := WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
			batch, err := lockLegacyBatch(ctx, tx, "org-a", "", identityBackfillMaxBatch)
			if err != nil {
				return err
			}
			if err := loadLegacyEvidence(ctx, tx, batch); err != nil {
				return err
			}
			for _, u := range batch {
				out[u.ID.String()] = u
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := load()
	for id, want := range map[string]ports.IdentityKeyEvidence{
		"issued": ports.IdentityKeyIssued, "revoked": ports.IdentityKeyRevokedByDisable, "old-disable": ports.IdentityKeyIssued,
		"reissued": ports.IdentityKeyIssued, "disable-only": ports.IdentityKeyNoEvidence, "none": ports.IdentityKeyNoEvidence,
		"foreign-evidence": ports.IdentityKeyNoEvidence, "dup-1": ports.IdentityKeyNoEvidence, "linked": ports.IdentityKeyIssued,
	} {
		if got[id].KeyEvidence != want {
			t.Errorf("%s key evidence = %s, want %s", id, got[id].KeyEvidence, want)
		}
	}
	for id, u := range got {
		if want := id == "dup-1" || id == "dup-2"; u.DuplicateHash != want {
			t.Errorf("%s duplicate hash = %v, want %v", id, u.DuplicateHash, want)
		}
	}
	links := got["linked"].Links
	if len(links) != 2 || links[0].Subject != "subject-a" || links[0].ApprovedBy != "latest-approver" ||
		links[1].Subject != "subject-b" || links[1].ApprovedBy != "" {
		t.Fatalf("linked links = %+v", links)
	}
	if len(got["issued"].Links) != 0 {
		t.Fatalf("unlinked user carries links: %+v", got["issued"].Links)
	}

	// After a backfill each issued digest routes to the user's own derived credential, which is
	// not a duplicate. A digest copied onto another user is.
	f.backfill(t, "org-a", 4)
	got = load()
	if got["issued"].DuplicateHash || got["reissued"].DuplicateHash || got["linked"].DuplicateHash {
		t.Fatalf("own derived credential counted as duplicate: issued=%v reissued=%v linked=%v",
			got["issued"].DuplicateHash, got["reissued"].DuplicateHash, got["linked"].DuplicateHash)
	}
	f.exec(t, `UPDATE users SET api_key_hash=$1 WHERE id='none'`, identityDigest("seed-org-a-issued"))
	if got = load(); !got["none"].DuplicateHash || !got["issued"].DuplicateHash {
		t.Fatal("digest held by two users and routed to one of them not flagged on both")
	}
	// A cross-tenant route of the same digest is a duplicate too.
	f.seedIssued(t, "org-b", "copy", user.RoleMember, false)
	f.backfill(t, "org-b", 4)
	f.exec(t, `UPDATE users SET api_key_hash=$1 WHERE id='disable-only'`, identityDigest("seed-org-b-copy"))
	if got = load(); !got["disable-only"].DuplicateHash {
		t.Fatal("digest routed to another tenant not flagged")
	}
}
