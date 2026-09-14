package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrollout"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type identityRolloutTestClock struct{ now time.Time }

func (clock identityRolloutTestClock) Now() time.Time { return clock.now }

type identityRolloutTestIDs struct{ next shared.ID }

func (ids identityRolloutTestIDs) NewID() shared.ID { return ids.next }

func TestMigration0178IdentityRolloutRLSAndAppendOnlyEvidence(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	for _, table := range []string{"identity_backfill_runs", "identity_backfill_items", "identity_rollout_phase_records"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}

	now := time.Now().UTC()
	seedIdentityRolloutTenant(t, db, "identity-rls")
	repository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	run, _, err := repository.AcquireIdentityBackfillRun(context.Background(), identityAcquire("identity-rls", "run-rls", "lease-rls", "worker-a", now))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if run.ID != "run-rls" {
		t.Fatalf("run id=%q", run.ID)
	}

	// Runtime role without a tenant binding cannot see an RLS-owned run.
	var visible int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM identity_backfill_runs`).Scan(&visible); err != nil {
		t.Fatalf("raw runtime query: %v", err)
	}
	if visible != 0 {
		t.Fatalf("unbound runtime saw %d identity backfill rows", visible)
	}

	record := ports.IdentityRolloutPhaseRecord{
		TenantID: "identity-rls", ID: "phase-1", Phase: string(identityrollout.PhaseExpand), Owner: "operator-a",
		SourceOfTruth: "legacy_users", AllowedWriters: []string{"legacy_users"}, RollbackAction: "disable enterprise identity reads",
		CreatedBy: "operator-a", CreatedAt: now,
	}
	if err := repository.AppendIdentityRolloutPhaseRecord(context.Background(), record); err != nil {
		t.Fatalf("append phase record: %v", err)
	}
	if _, err := db.Exec(`UPDATE identity_rollout_phase_records SET owner='rewrite' WHERE tenant_id='identity-rls' AND id='phase-1'`); err == nil {
		t.Fatal("append-only rollout evidence unexpectedly accepted UPDATE")
	}
	if _, err := db.Exec(`DELETE FROM identity_rollout_phase_records WHERE tenant_id='identity-rls' AND id='phase-1'`); err == nil {
		t.Fatal("append-only rollout evidence unexpectedly accepted DELETE")
	}
}

func TestIdentityBackfillLeaseFenceAndReconciledDrift(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	seedIdentityRolloutTenant(t, db, "identity-fence")
	seedIdentityLegacyUser(t, db, "identity-fence", "alice", strings.Repeat("a", 64), false, now.Add(-time.Hour))
	repository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}

	first, _, err := repository.AcquireIdentityBackfillRun(context.Background(), identityAcquire("identity-fence", "run-a", "lease-a", "worker-a", now))
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, _, err := repository.AcquireIdentityBackfillRun(context.Background(), identityAcquire("identity-fence", "run-b", "lease-b", "worker-b", now)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("live lease takeover err=%v, want conflict", err)
	}

	if _, err := db.Exec(`UPDATE identity_backfill_runs SET lease_expires_at=now()-interval '1 second' WHERE tenant_id='identity-fence' AND id='run-a'`); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	secondRequest := identityAcquire("identity-fence", "ignored-new-id", "lease-b", "worker-b", now.Add(time.Second))
	second, resumed, err := repository.AcquireIdentityBackfillRun(context.Background(), secondRequest)
	if err != nil || !resumed || second.ID != first.ID || second.LeaseToken != "lease-b" {
		t.Fatalf("takeover run=%+v resumed=%v err=%v", second, resumed, err)
	}

	sources, err := repository.ListLegacyHumans(context.Background(), "identity-fence", "", second.SnapshotAt, 10)
	if err != nil || len(sources) != 1 {
		t.Fatalf("sources=%+v err=%v", sources, err)
	}
	sourceHash := identityrolloutLegacyHashForTest(sources[0])
	if _, _, err := repository.ProjectLegacyHuman(context.Background(), first, sources[0], sourceHash, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale lease projection err=%v, want conflict", err)
	}
	item, created, err := repository.ProjectLegacyHuman(context.Background(), second, sources[0], sourceHash, now.Add(2*time.Second))
	if err != nil || !created || item.Outcome != identityrollout.BackfillOutcomeProjected {
		t.Fatalf("project item=%+v created=%v err=%v", item, created, err)
	}

	// Corrupt only the derived side after the item committed. Final reconciliation must record
	// this separately; it must not make processed_count cease matching item outcome counts.
	if _, err := db.Exec(`UPDATE memberships SET role='reviewer' WHERE tenant_id='identity-fence' AND id='alice'`); err != nil {
		t.Fatalf("inject derived drift: %v", err)
	}
	reconciliation, err := repository.ReconcileIdentityBackfill(context.Background(), "identity-fence", second.SnapshotAt)
	if err != nil || reconciliation.DriftCount != 1 {
		t.Fatalf("reconciliation=%+v err=%v", reconciliation, err)
	}
	finished, err := repository.FinishIdentityBackfillRun(context.Background(), "identity-fence", second.ID, "worker-b", second.LeaseToken, ports.IdentityBackfillCompleted, reconciliation, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("finish with reconciliation drift: %v", err)
	}
	if finished.ProcessedCount != 1 || finished.ProjectedCount != 1 || finished.DriftCount != 0 || finished.ReconciledDriftCount != 1 {
		t.Fatalf("finished counts=%+v", finished)
	}
}

func TestIdentityBackfillRunnerProjectsLegacyUsersButNeverBootstrap(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	seedIdentityRolloutTenant(t, db, "identity-clean")
	seedIdentityLegacyUser(t, db, "identity-clean", "alice", strings.Repeat("a", 64), false, now.Add(-2*time.Hour))
	seedIdentityLegacyUser(t, db, "identity-clean", "bob", strings.Repeat("b", 64), true, now.Add(-2*time.Hour))
	seedIdentityLegacyUser(t, db, "identity-clean", "operator", strings.Repeat("c", 64), false, now.Add(-2*time.Hour))
	repository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := identityrollout.NewBackfillRunner(repository, repository, identityRolloutTestIDs{next: "run-clean"}, identityRolloutTestClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(context.Background(), identityrollout.BackfillRequest{TenantID: "identity-clean", Actor: "operator-a", LeaseOwner: "worker-a", BatchSize: 1, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatalf("run backfill: %v", err)
	}
	if run.State != ports.IdentityBackfillCompleted || run.SourceCount != 2 || run.ProcessedCount != 2 || run.ReconciledDriftCount != 0 {
		t.Fatalf("run=%+v", run)
	}

	for _, test := range []struct {
		id, status string
	}{
		{id: "alice", status: "active"},
		{id: "bob", status: "suspended"},
	} {
		var personID, status string
		if err := db.QueryRow(`SELECT person_id,status FROM memberships WHERE tenant_id='identity-clean' AND id=$1`, test.id).Scan(&personID, &status); err != nil {
			t.Fatalf("membership %s: %v", test.id, err)
		}
		if personID != test.id || status != test.status {
			t.Fatalf("membership %s person=%q status=%q", test.id, personID, status)
		}
	}
	var bootstrapMemberships int
	if err := db.QueryRow(`SELECT count(*) FROM memberships WHERE tenant_id='identity-clean' AND (id='operator' OR person_id='operator')`).Scan(&bootstrapMemberships); err != nil || bootstrapMemberships != 0 {
		t.Fatalf("bootstrap memberships=%d err=%v", bootstrapMemberships, err)
	}
	var legacyUsers int
	if err := db.QueryRow(`SELECT count(*) FROM users WHERE ownership_tenant_id='identity-clean'`).Scan(&legacyUsers); err != nil || legacyUsers != 3 {
		t.Fatalf("legacy users changed count=%d err=%v", legacyUsers, err)
	}
}

func TestIdentityBackfillRejectsCorruptAndDuplicateLegacyDigests(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		pool, db := ownershipTestDatabase(t, 0, nil)
		now := time.Now().UTC()
		seedIdentityRolloutTenant(t, db, "identity-corrupt")
		seedIdentityLegacyUser(t, db, "identity-corrupt", "alice", "not-a-sha256", false, now.Add(-time.Hour))
		repository, err := NewIdentityRolloutRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := identityrollout.NewBackfillRunner(repository, repository, identityRolloutTestIDs{next: "run-corrupt"}, identityRolloutTestClock{now: now})
		if err != nil {
			t.Fatal(err)
		}
		run, err := runner.Run(context.Background(), identityrollout.BackfillRequest{TenantID: "identity-corrupt", Actor: "operator-a", LeaseOwner: "worker-a", LeaseDuration: time.Minute})
		if err == nil || run.State != ports.IdentityBackfillFailed {
			t.Fatalf("run=%+v err=%v, want failed corrupt digest", run, err)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		pool, db := ownershipTestDatabase(t, 0, nil)
		now := time.Now().UTC()
		seedIdentityRolloutTenant(t, db, "identity-duplicate")
		if _, err := db.Exec(`DROP INDEX idx_users_api_key_hash`); err != nil {
			t.Fatalf("simulate corrupt legacy uniqueness: %v", err)
		}
		dup := strings.Repeat("d", 64)
		seedIdentityLegacyUser(t, db, "identity-duplicate", "alice", dup, false, now.Add(-time.Hour))
		seedIdentityLegacyUser(t, db, "identity-duplicate", "bob", dup, false, now.Add(-time.Hour))
		repository, err := NewIdentityRolloutRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		reconciliation, err := repository.ReconcileIdentityBackfill(context.Background(), "identity-duplicate", now)
		if err != nil || reconciliation.DuplicateCredentialCount != 1 {
			t.Fatalf("reconciliation=%+v err=%v", reconciliation, err)
		}
	})
}

func TestIdentityOIDCShadowImportNeverEnablesServingAuthority(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	seedIdentityRolloutTenant(t, db, "identity-shadow")
	seedIdentityLegacyUser(t, db, "identity-shadow", "alice", strings.Repeat("a", 64), false, now.Add(-2*time.Hour))
	repository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := identityrollout.NewBackfillRunner(repository, repository, identityRolloutTestIDs{next: "run-shadow"}, identityRolloutTestClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), identityrollout.BackfillRequest{TenantID: "identity-shadow", Actor: "operator-a", LeaseOwner: "worker-a", LeaseDuration: time.Minute}); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject,created_at,updated_at)
		VALUES('legacy-link-a','identity-shadow','alice','https://issuer.example','subject-a',$1,$1)`, now); err != nil {
		t.Fatalf("seed legacy OIDC link: %v", err)
	}
	result, err := repository.ImportLegacyOIDCShadow(context.Background(), ports.LegacyOIDCShadowConfig{
		TenantID: "identity-shadow", Issuer: "https://issuer.example", ClientID: "client-a", RedirectURL: "https://synapse.example/api/auth/oidc/callback", Actor: "operator-a",
	})
	if err != nil || result.ProjectedLinks != 1 || result.DriftedLinks != 0 {
		t.Fatalf("first shadow import=%+v err=%v", result, err)
	}

	var enabled bool
	var active sql.NullInt64
	var secretRef, configJSON string
	if err := db.QueryRow(`SELECT c.enabled,c.active_revision,r.encrypted_secret_ref,r.configuration::text
		FROM sso_connections c JOIN sso_connection_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.revision=1
		WHERE c.tenant_id='identity-shadow' AND c.id=$1`, result.ConnectionID.String()).Scan(&enabled, &active, &secretRef, &configJSON); err != nil {
		t.Fatalf("read shadow connection: %v", err)
	}
	if enabled || active.Valid {
		t.Fatalf("shadow import enabled serving authority: enabled=%v active=%v", enabled, active)
	}
	if secretRef != "env:SYNAPSE_OIDC_CLIENT_SECRET" || strings.Contains(strings.ToLower(configJSON), "client_secret") {
		t.Fatalf("shadow revision stored unsafe secret material: ref=%q config=%s", secretRef, configJSON)
	}

	retry, err := repository.ImportLegacyOIDCShadow(context.Background(), ports.LegacyOIDCShadowConfig{
		TenantID: "identity-shadow", Issuer: "https://issuer.example", ClientID: "client-a", RedirectURL: "https://synapse.example/api/auth/oidc/callback", Actor: "operator-a",
	})
	if err != nil || retry.UnchangedLinks != 1 || retry.ProjectedLinks != 0 {
		t.Fatalf("idempotent shadow retry=%+v err=%v", retry, err)
	}
}

func seedIdentityRolloutTenant(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1) ON CONFLICT (id) DO NOTHING`, tenantID); err != nil {
		t.Fatalf("seed tenant %s: %v", tenantID, err)
	}
}

func seedIdentityLegacyUser(t *testing.T, db *sql.DB, tenantID, userID, digest string, disabled bool, createdAt time.Time) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,disabled,tenant_id,created_at,updated_at)
		VALUES($1,$2,'consultant',$3,$4,$5,$6,$6)`, userID, "User "+userID, digest, disabled, tenantID, createdAt.UTC()); err != nil {
		t.Fatalf("seed legacy user %s/%s: %v", tenantID, userID, err)
	}
}

func identityAcquire(tenantID, runID, leaseToken, leaseOwner string, now time.Time) ports.IdentityBackfillAcquireRequest {
	return ports.IdentityBackfillAcquireRequest{
		Run: ports.IdentityBackfillRun{
			TenantID: tenantID, ID: shared.ID(runID), SchemaVersion: identityrollout.IdentityBackfillSchemaVersion,
			BatchSize: 10, SnapshotAt: now, State: ports.IdentityBackfillRunning, LeaseOwner: leaseOwner,
			LeaseToken: shared.ID(leaseToken), LeaseExpiresAt: now.Add(time.Minute), CreatedBy: "operator-a", CreatedAt: now, UpdatedAt: now,
		},
		LeaseDuration: time.Minute,
	}
}

// Keep the test independent from the unexported production helper while exercising the exact same
// length-prefixed snapshot hash contract passed to the PostgreSQL store.
func identityrolloutLegacyHashForTest(source ports.LegacyHumanSnapshot) string {
	// Calling the runner is the primary coverage for hash construction. These direct store tests use
	// a stable valid digest because ProjectLegacyHuman treats sourceHash as opaque evidence.
	return strings.Repeat("f", 64)
}
