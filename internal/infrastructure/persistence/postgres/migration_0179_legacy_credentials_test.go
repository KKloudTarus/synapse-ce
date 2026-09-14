package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrollout"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

type d5Clock struct{ now time.Time }

func (clock d5Clock) Now() time.Time { return clock.now }

type d5IDs struct{ id shared.ID }

func (ids d5IDs) NewID() shared.ID { return ids.id }

type d5FailingAudit struct{ err error }

func (audit d5FailingAudit) Record(context.Context, ports.AuditEntry) error { return audit.err }

func TestMigration0179LegacyCredentialRLSAndClassification(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	for _, table := range []string{"legacy_human_credentials", "legacy_credential_resolutions"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}

	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-classify")
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "issued", strings.Repeat("a", 64), false, now.Add(-time.Hour))
	seedIdentityLegacyUser(t, db, tenantID.String(), "placeholder", strings.Repeat("b", 64), false, now.Add(-time.Hour))
	seedIdentityLegacyUser(t, db, tenantID.String(), "ambiguous", strings.Repeat("c", 64), true, now.Add(-time.Hour))
	projectD4Tenant(t, pool, tenantID, now)

	audit := NewAuditLog(pool)
	if err := audit.Record(shared.WithTenant(context.Background(), tenantID), ports.AuditEntry{
		Actor: "admin", Action: "user.created", Target: "issued", At: now,
	}); err != nil {
		t.Fatalf("seed issuance audit: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject,created_at,updated_at)
		VALUES('d5-placeholder-link',$1,'placeholder','https://issuer.example','subject-placeholder',$2,$2)`, tenantID.String(), now); err != nil {
		t.Fatalf("seed placeholder OIDC link: %v", err)
	}

	repository, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := repository.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "issued", now.Add(time.Second))
	if err != nil {
		t.Fatalf("classify issued: %v", err)
	}
	placeholder, err := repository.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "placeholder", now.Add(time.Second))
	if err != nil {
		t.Fatalf("classify placeholder: %v", err)
	}
	ambiguous, err := repository.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "ambiguous", now.Add(time.Second))
	if err != nil {
		t.Fatalf("classify ambiguous: %v", err)
	}

	if issued.Classification != ports.LegacyCredentialIssued || issued.Digest != strings.Repeat("a", 64) || issued.Status != ports.LegacyCredentialActive {
		t.Fatalf("issued projection=%+v", issued)
	}
	if placeholder.Classification != ports.LegacyCredentialPlaceholder || placeholder.Digest != "" || placeholder.Status != ports.LegacyCredentialUnavailable {
		t.Fatalf("placeholder projection=%+v", placeholder)
	}
	if ambiguous.Classification != ports.LegacyCredentialAmbiguous || ambiguous.Digest != "" || ambiguous.Status != ports.LegacyCredentialUnavailable {
		t.Fatalf("ambiguous projection=%+v", ambiguous)
	}

	var indexed int
	if err := db.QueryRow(`SELECT count(*) FROM credential_index WHERE organization_id=$1 AND credential_kind='legacy_api_key'`, tenantID.String()).Scan(&indexed); err != nil {
		t.Fatalf("count locators: %v", err)
	}
	if indexed != 1 {
		t.Fatalf("credential locators=%d, want only issued credential", indexed)
	}
	var unbound int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM legacy_human_credentials`).Scan(&unbound); err != nil {
		t.Fatalf("unbound projection read: %v", err)
	}
	if unbound != 0 {
		t.Fatalf("unbound runtime saw %d legacy credential rows", unbound)
	}

	reconciliation, err := repository.ReconcileLegacyCredentials(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("reconcile credentials: %v", err)
	}
	if reconciliation.SourceCount != 3 || reconciliation.ProjectedCount != 3 || reconciliation.IssuedCount != 1 || reconciliation.PlaceholderCount != 1 || reconciliation.AmbiguousCount != 1 || reconciliation.MissingCount != 0 || reconciliation.DriftCount != 0 || reconciliation.IndexDriftCount != 0 {
		t.Fatalf("reconciliation=%+v", reconciliation)
	}

	resolved, err := repository.ResolveLegacyCredentialClassification(context.Background(), ports.LegacyCredentialResolutionRequest{
		TenantID: tenantID, ResolutionID: "resolution-1", UserID: "ambiguous", Resolution: ports.LegacyCredentialIssued,
		ExpectedVersion: ambiguous.Version, Reason: "operator verified historical issuance", Actor: "admin", At: now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("resolve ambiguous: %v", err)
	}
	if resolved.Classification != ports.LegacyCredentialIssued || resolved.Digest != strings.Repeat("c", 64) || resolved.Status != ports.LegacyCredentialDisabled {
		t.Fatalf("resolved projection=%+v", resolved)
	}
	if _, err := db.Exec(`UPDATE legacy_credential_resolutions SET actor='rewrite' WHERE tenant_id=$1 AND id='resolution-1'`, tenantID.String()); err == nil {
		t.Fatal("append-only credential resolution unexpectedly accepted UPDATE")
	}
}

func TestD5RotationAuditFailureRollsBackSourceProjectionAndLocator(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-audit-rollback")
	oldDigest := strings.Repeat("d", 64)
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "alice", oldDigest, false, now.Add(-time.Hour))
	projectD4Tenant(t, pool, tenantID, now)

	realAudit := NewAuditLog(pool)
	if err := realAudit.Record(shared.WithTenant(context.Background(), tenantID), ports.AuditEntry{Actor: "admin", Action: "user.created", Target: "alice", At: now}); err != nil {
		t.Fatalf("seed issuance evidence: %v", err)
	}
	credentialRepo, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := credentialRepo.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "alice", now.Add(time.Second))
	if err != nil || projection.Digest != oldDigest {
		t.Fatalf("initial projection=%+v err=%v", projection, err)
	}

	userRepo := NewUserRepository(pool)
	boom := errors.New("audit sink unavailable")
	service, err := usersuc.NewService(userRepo, d5FailingAudit{err: boom}, d5Clock{now: now.Add(2 * time.Second)}, d5IDs{id: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(NewTenantTransactionRunner(pool))
	if err := service.SetLegacyCredentialProjectionStore(credentialRepo); err != nil {
		t.Fatal(err)
	}
	_, plaintext, err := service.RotateAPIKey(context.Background(), usersuc.Actor{ID: "admin", TenantID: tenantID.String()}, "alice")
	if !errors.Is(err, boom) {
		t.Fatalf("rotate err=%v, want audit failure", err)
	}
	if plaintext != "" {
		t.Fatal("failed rotation leaked a plaintext credential")
	}

	var sourceDigest string
	if err := db.QueryRow(`SELECT api_key_hash FROM users WHERE ownership_tenant_id=$1 AND id='alice'`, tenantID.String()).Scan(&sourceDigest); err != nil {
		t.Fatalf("read rolled back user: %v", err)
	}
	if sourceDigest != oldDigest {
		t.Fatalf("source digest committed across audit failure: %s", sourceDigest)
	}
	got, err := credentialRepo.GetLegacyCredentialProjection(context.Background(), tenantID, "alice")
	if err != nil || got.Digest != oldDigest || got.Version != projection.Version {
		t.Fatalf("projection after rollback=%+v err=%v", got, err)
	}
	var locatorDigest string
	if err := db.QueryRow(`SELECT digest FROM credential_index WHERE organization_id=$1 AND credential_kind='legacy_api_key' AND credential_id='alice'`, tenantID.String()).Scan(&locatorDigest); err != nil {
		t.Fatalf("read locator after rollback: %v", err)
	}
	if locatorDigest != oldDigest {
		t.Fatalf("locator committed across audit failure: %s", locatorDigest)
	}
}

func TestD5RotationBeforeCredentialBackfillConvergesOnNewIssuedDigest(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-rotation-race")
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "alice", strings.Repeat("e", 64), false, now.Add(-time.Hour))

	userRepo := NewUserRepository(pool)
	audit := NewAuditLog(pool)
	credentialRepo, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := usersuc.NewService(userRepo, audit, d5Clock{now: now}, d5IDs{id: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(NewTenantTransactionRunner(pool))
	if err := service.SetLegacyCredentialProjectionStore(credentialRepo); err != nil {
		t.Fatal(err)
	}

	rotated, plaintext, err := service.RotateAPIKey(context.Background(), usersuc.Actor{ID: "admin", TenantID: tenantID.String()}, "alice")
	if err != nil {
		t.Fatalf("rotate before backfill: %v", err)
	}
	newDigest := usersuc.HashToken(plaintext)
	if plaintext == "" || rotated.APIKeyHash != newDigest || newDigest == strings.Repeat("e", 64) {
		t.Fatalf("rotation result user=%+v plaintext=%q", rotated, plaintext)
	}
	if _, err := credentialRepo.GetLegacyCredentialProjection(context.Background(), tenantID, "alice"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rotation manufactured unclassified projection: %v", err)
	}

	projectD4Tenant(t, pool, tenantID, now.Add(time.Second))
	projection, err := credentialRepo.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "alice", now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("classify after rotation/backfill: %v", err)
	}
	if projection.Classification != ports.LegacyCredentialIssued || projection.Digest != newDigest {
		t.Fatalf("post-race projection=%+v want issued digest %s", projection, newDigest)
	}
	var locatorTarget string
	if err := db.QueryRow(`SELECT credential_id FROM credential_index WHERE digest=$1 AND organization_id=$2 AND credential_kind='legacy_api_key'`, newDigest, tenantID.String()).Scan(&locatorTarget); err != nil {
		t.Fatalf("read new locator: %v", err)
	}
	if locatorTarget != "alice" {
		t.Fatalf("new locator target=%q", locatorTarget)
	}
}

func TestD5DisableEnableProjectsClassifiedIssuedCredential(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-disable-enable")
	digest := strings.Repeat("e", 64)
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "alice", digest, false, now.Add(-time.Hour))
	projectD4Tenant(t, pool, tenantID, now)

	audit := NewAuditLog(pool)
	if err := audit.Record(shared.WithTenant(context.Background(), tenantID), ports.AuditEntry{
		Actor: "admin", Action: "user.created", Target: "alice", At: now,
	}); err != nil {
		t.Fatalf("seed issuance evidence: %v", err)
	}
	credentials, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := credentials.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "alice", now.Add(time.Second))
	if err != nil || initial.Classification != ports.LegacyCredentialIssued || initial.Status != ports.LegacyCredentialActive {
		t.Fatalf("initial issued projection=%+v err=%v", initial, err)
	}

	service, err := usersuc.NewService(NewUserRepository(pool), audit, d5Clock{now: now.Add(2 * time.Second)}, d5IDs{id: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(NewTenantTransactionRunner(pool))
	if err := service.SetLegacyCredentialProjectionStore(credentials); err != nil {
		t.Fatal(err)
	}
	actor := usersuc.Actor{ID: "admin", TenantID: tenantID.String()}
	disabled, err := service.SetDisabled(context.Background(), actor, "alice", true)
	if err != nil || !disabled.Disabled || disabled.APIKeyHash != digest {
		t.Fatalf("disable result=%+v err=%v", disabled, err)
	}
	afterDisable, err := credentials.GetLegacyCredentialProjection(context.Background(), tenantID, "alice")
	if err != nil || afterDisable.Digest != digest || afterDisable.Status != ports.LegacyCredentialDisabled || afterDisable.Version != initial.Version+1 {
		t.Fatalf("disabled projection=%+v err=%v", afterDisable, err)
	}

	enabled, err := service.SetDisabled(context.Background(), actor, "alice", false)
	if err != nil || enabled.Disabled || enabled.APIKeyHash != digest {
		t.Fatalf("enable result=%+v err=%v", enabled, err)
	}
	afterEnable, err := credentials.GetLegacyCredentialProjection(context.Background(), tenantID, "alice")
	if err != nil || afterEnable.Digest != digest || afterEnable.Status != ports.LegacyCredentialActive || afterEnable.Version != afterDisable.Version+1 {
		t.Fatalf("enabled projection=%+v err=%v", afterEnable, err)
	}
	var locatorCount int
	if err := db.QueryRow(`SELECT count(*) FROM credential_index WHERE digest=$1 AND organization_id=$2 AND credential_kind='legacy_api_key'`, digest, tenantID.String()).Scan(&locatorCount); err != nil || locatorCount != 1 {
		t.Fatalf("exact-hash locator count=%d err=%v", locatorCount, err)
	}
}

func TestD5CredentialRunnerPersistsReconciliationEvidenceInImmutableLedger(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-runner-ledger")
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "issued", strings.Repeat("a", 64), false, now.Add(-time.Hour))
	seedIdentityLegacyUser(t, db, tenantID.String(), "placeholder", strings.Repeat("b", 64), false, now.Add(-time.Hour))
	seedIdentityLegacyUser(t, db, tenantID.String(), "ambiguous", strings.Repeat("c", 64), true, now.Add(-time.Hour))
	projectD4Tenant(t, pool, tenantID, now)

	audit := NewAuditLog(pool)
	if err := audit.Record(shared.WithTenant(context.Background(), tenantID), ports.AuditEntry{
		Actor: "admin", Action: "user.created", Target: "issued", At: now,
	}); err != nil {
		t.Fatalf("seed issuance evidence: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO oidc_external_identities(id,tenant_id,user_id,issuer,subject,created_at,updated_at)
		VALUES('d5-runner-placeholder-link',$1,'placeholder','https://issuer.example','subject-placeholder',$2,$2)`, tenantID.String(), now); err != nil {
		t.Fatalf("seed placeholder OIDC link: %v", err)
	}

	identityRepository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := identityrollout.NewCredentialProjectionRunner(identityRepository, credentials, d5Clock{now: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := runner.Run(context.Background(), identityrollout.CredentialProjectionRequest{TenantID: tenantID, BatchSize: 1})
	if err != nil {
		t.Fatalf("run D5 credential projection: %v", err)
	}
	if reconciliation.SourceCount != 3 || reconciliation.ProjectedCount != 3 || reconciliation.IssuedCount != 1 || reconciliation.PlaceholderCount != 1 || reconciliation.AmbiguousCount != 1 || reconciliation.MissingCount != 0 || reconciliation.DriftCount != 0 || reconciliation.IndexDriftCount != 0 {
		t.Fatalf("runner reconciliation=%+v", reconciliation)
	}

	record := ports.IdentityRolloutPhaseRecord{
		TenantID: tenantID, ID: "d5-evidence", Phase: string(identityrollout.PhaseLegacyAuthoritativeBackfill), Owner: "identity-operator",
		SourceOfTruth: "legacy_users", AllowedWriters: []string{"legacy_users"}, SourceCount: reconciliation.SourceCount, ProjectedCount: reconciliation.SourceCount,
		CredentialProjectionComplete: true, CredentialProjectedCount: reconciliation.ProjectedCount, IssuedCredentialCount: reconciliation.IssuedCount,
		PlaceholderCredentialCount: reconciliation.PlaceholderCount, AmbiguousCredentialCount: reconciliation.AmbiguousCount, MissingCredentialCount: reconciliation.MissingCount,
		CredentialDriftCount: reconciliation.DriftCount, CredentialIndexDriftCount: reconciliation.IndexDriftCount,
		RollbackAction: "disable enterprise identity reads", MetricsRecorded: true, ApprovalRecorded: true, CreatedBy: "identity-operator", CreatedAt: now.Add(2 * time.Second),
	}
	if err := identityRepository.AppendIdentityCredentialRolloutPhaseRecord(context.Background(), record); err != nil {
		t.Fatalf("append D5 reconciliation evidence: %v", err)
	}
	var complete bool
	var projected, issued, placeholder, ambiguous, missing, drift, indexDrift int
	if err := db.QueryRow(`SELECT credential_projection_complete,credential_projected_count,issued_credential_count,placeholder_credential_count,
		ambiguous_credential_count,missing_credential_count,credential_drift_count,credential_index_drift_count
		FROM identity_rollout_phase_records WHERE tenant_id=$1 AND id='d5-evidence'`, tenantID.String()).
		Scan(&complete, &projected, &issued, &placeholder, &ambiguous, &missing, &drift, &indexDrift); err != nil {
		t.Fatalf("read D5 reconciliation evidence: %v", err)
	}
	if !complete || projected != 3 || issued != 1 || placeholder != 1 || ambiguous != 1 || missing != 0 || drift != 0 || indexDrift != 0 {
		t.Fatalf("persisted D5 evidence complete=%v counts=%d/%d/%d/%d/%d/%d/%d", complete, projected, issued, placeholder, ambiguous, missing, drift, indexDrift)
	}
	if _, err := db.Exec(`UPDATE identity_rollout_phase_records SET credential_projection_complete=false WHERE tenant_id=$1 AND id='d5-evidence'`, tenantID.String()); err == nil {
		t.Fatal("immutable D5 reconciliation evidence unexpectedly accepted UPDATE")
	}
}

func TestD5BootstrapNeverProjectsAsOrdinaryCredential(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	now := time.Now().UTC()
	tenantID := shared.ID("identity-d5-bootstrap")
	seedIdentityRolloutTenant(t, db, tenantID.String())
	seedIdentityLegacyUser(t, db, tenantID.String(), "operator", strings.Repeat("f", 64), false, now.Add(-time.Hour))
	repository, err := NewLegacyCredentialRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClassifyAndProjectLegacyCredential(context.Background(), tenantID, "operator", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bootstrap projection err=%v, want validation refusal", err)
	}
	var projected, indexed int
	if err := db.QueryRow(`SELECT count(*) FROM legacy_human_credentials WHERE tenant_id=$1 AND user_id='operator'`, tenantID.String()).Scan(&projected); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM credential_index WHERE organization_id=$1 AND credential_kind='legacy_api_key' AND credential_id='operator'`, tenantID.String()).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if projected != 0 || indexed != 0 {
		t.Fatalf("bootstrap leaked into D5 projection: projected=%d indexed=%d", projected, indexed)
	}
}

func projectD4Tenant(t *testing.T, pool *pgxpool.Pool, tenantID shared.ID, now time.Time) {
	t.Helper()
	repository, err := NewIdentityRolloutRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := identityrollout.NewBackfillRunner(repository, repository, d5IDs{id: shared.ID("d4-" + tenantID.String())}, d5Clock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), identityrollout.BackfillRequest{
		TenantID: tenantID, Actor: "admin", LeaseOwner: "d5-test", BatchSize: 50, LeaseDuration: time.Minute,
	}); err != nil {
		t.Fatalf("D4 prerequisite backfill: %v", err)
	}
}
