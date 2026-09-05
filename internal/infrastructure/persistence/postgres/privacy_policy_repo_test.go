package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type privacyPolicyPostgresFixture struct {
	pool                *pgxpool.Pool
	dsn                 string
	tenant, otherTenant shared.ID
	at                  time.Time
}

func newPrivacyPolicyPostgresFixture(t *testing.T) privacyPolicyPostgresFixture {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	requireDetectionProvenanceTestAdmin(t, dsn)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	id := randHex(t)
	fixture := privacyPolicyPostgresFixture{
		pool:        pool,
		dsn:         dsn,
		tenant:      shared.ID("privacy-" + id),
		otherTenant: shared.ID("privacy-other-" + id),
		at:          time.Date(2026, 8, 27, 14, 0, 0, 0, time.UTC),
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pool.Acquire(cleanupCtx)
		if err != nil {
			t.Errorf("acquire privacy policy cleanup connection: %v", err)
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = replica`); err != nil {
			t.Errorf("disable privacy policy cleanup triggers: %v", err)
			return
		}
		defer func() {
			if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = origin`); err != nil {
				t.Errorf("restore privacy policy cleanup triggers: %v", err)
			}
		}()
		for _, tenantID := range []shared.ID{fixture.tenant, fixture.otherTenant} {
			if _, err := conn.Exec(cleanupCtx, `DELETE FROM privacy_policy_activations WHERE tenant_id=$1`, tenantID.String()); err != nil {
				t.Errorf("delete privacy policy activation history for %q: %v", tenantID, err)
			}
			if _, err := conn.Exec(cleanupCtx, `DELETE FROM privacy_active_policies WHERE tenant_id=$1`, tenantID.String()); err != nil {
				t.Errorf("delete active privacy policy for %q: %v", tenantID, err)
			}
			if _, err := conn.Exec(cleanupCtx, `DELETE FROM privacy_policies WHERE tenant_id=$1`, tenantID.String()); err != nil {
				t.Errorf("delete privacy policy history for %q: %v", tenantID, err)
			}
			if _, err := conn.Exec(cleanupCtx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()); err != nil {
				t.Errorf("delete privacy policy tenant %q: %v", tenantID, err)
			}
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, fixture.tenant.String(), fixture.otherTenant.String()); err != nil {
		t.Fatalf("seed privacy policy tenants: %v", err)
	}
	return fixture
}

func (f privacyPolicyPostgresFixture) assignment(t *testing.T, version string, at time.Time) privacy.Assignment {
	t.Helper()
	policy := privacy.DefaultPolicy()
	policy.Version = version
	if version != "tenant:v1" {
		policy.MaxArgLen = 1024
	}
	assignment, err := privacy.NewAssignment(f.tenant, policy, "integration-admin", at)
	if err != nil {
		t.Fatalf("new privacy assignment: %v", err)
	}
	return assignment
}

func newPrivacyPolicyRLSRole(t *testing.T, fixture privacyPolicyPostgresFixture) string {
	t.Helper()
	role := "privacy_policy_runtime_" + randHex(t)
	if _, err := fixture.pool.Exec(context.Background(), `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create privacy policy RLS role: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := fixture.pool.Exec(ctx, `DROP OWNED BY `+role); err != nil {
			t.Errorf("drop privacy policy RLS role ownership: %v", err)
		}
		if _, err := fixture.pool.Exec(ctx, `DROP ROLE IF EXISTS `+role); err != nil {
			t.Errorf("drop privacy policy RLS role: %v", err)
		}
	})
	if _, err := fixture.pool.Exec(context.Background(), `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatalf("grant privacy policy schema usage: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `GRANT SELECT ON privacy_policies,privacy_active_policies,privacy_policy_activations TO `+role); err != nil {
		t.Fatalf("grant privacy policy reads: %v", err)
	}
	return role
}

func TestPrivacyPolicyRepositoryHistoryActivationAndRestart(t *testing.T) {
	fixture := newPrivacyPolicyPostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewPrivacyPolicyRepository(t, fixture.pool)
	v1 := fixture.assignment(t, "tenant:v1", fixture.at)
	created, err := repo.PutPrivacyPolicy(ctx, v1)
	if err != nil || !created {
		t.Fatalf("PutPrivacyPolicy(v1)=%t/%v, want created", created, err)
	}
	if _, err := repo.ActivePrivacyPolicy(ctx, fixture.tenant); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("admission changed active pointer: %v", err)
	}

	retry := v1
	retry.CreatedAt = retry.CreatedAt.Add(time.Hour)
	created, err = repo.PutPrivacyPolicy(ctx, retry)
	if err != nil || created {
		t.Fatalf("later-clock retry=%t/%v, want idempotent", created, err)
	}
	storedV1, err := repo.PrivacyPolicyByDigest(ctx, fixture.tenant, v1.Digest)
	if err != nil || !storedV1.CreatedAt.Equal(v1.CreatedAt) {
		t.Fatalf("retry replaced first admission=%#v/%v", storedV1, err)
	}

	v2 := fixture.assignment(t, "tenant:v2", fixture.at.Add(2*time.Hour))
	created, err = repo.PutPrivacyPolicy(ctx, v2)
	if err != nil || !created {
		t.Fatalf("PutPrivacyPolicy(v2)=%t/%v, want created", created, err)
	}
	activate := func(operationID shared.ID, assignment privacy.Assignment, at time.Time) privacy.Activation {
		t.Helper()
		activation, err := repo.ActivatePrivacyPolicy(ctx, privacy.Activation{
			TenantID: fixture.tenant, OperationID: operationID, PolicyDigest: assignment.Digest,
			PolicyVersion: assignment.Policy.Version, ActivatedBy: "integration-admin", ActivatedAt: at,
		})
		if err != nil {
			t.Fatalf("activate %s: %v", operationID, err)
		}
		return activation
	}
	first := activate("activate-v1", v1, fixture.at.Add(3*time.Hour))
	if first.Revision != 1 {
		t.Fatalf("first activation revision=%d, want 1", first.Revision)
	}
	exactRetry := activate("activate-v1", v1, fixture.at.Add(24*time.Hour))
	if exactRetry != first {
		t.Fatalf("exact activation retry=%#v, want original %#v", exactRetry, first)
	}
	second := activate("activate-v2", v2, fixture.at.Add(4*time.Hour))
	third := activate("reactivate-v1", v1, fixture.at.Add(5*time.Hour))
	if second.Revision != 2 || third.Revision != 3 {
		t.Fatalf("A -> B -> A revisions=%d/%d/%d, want 1/2/3", first.Revision, second.Revision, third.Revision)
	}
	active, err := repo.ActivePrivacyPolicy(ctx, fixture.tenant)
	if err != nil || active.Digest != v1.Digest {
		t.Fatalf("active policy=%#v/%v, want v1", active, err)
	}
	history, err := repo.PrivacyPolicyHistory(ctx, fixture.tenant)
	if err != nil || len(history) != 2 || history[0].Digest != v2.Digest || history[1].Digest != v1.Digest {
		t.Fatalf("policy history=%#v/%v", history, err)
	}
	activations, err := repo.PrivacyPolicyActivationHistory(ctx, fixture.tenant)
	if err != nil || len(activations) != 3 || activations[0] != first || activations[1] != second || activations[2] != third {
		t.Fatalf("activation history=%#v/%v", activations, err)
	}

	reconnected, err := Connect(context.Background(), fixture.dsn)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	t.Cleanup(reconnected.Close)
	restarted := mustNewPrivacyPolicyRepository(t, reconnected)
	reloaded, err := restarted.ActivePrivacyPolicy(ctx, fixture.tenant)
	if err != nil || reloaded.Digest != v1.Digest {
		t.Fatalf("active policy after restart=%#v/%v", reloaded, err)
	}
	reloadedHistory, err := restarted.PrivacyPolicyActivationHistory(ctx, fixture.tenant)
	if err != nil || len(reloadedHistory) != 3 || reloadedHistory[2] != third {
		t.Fatalf("activation history after restart=%#v/%v", reloadedHistory, err)
	}

	contradictoryOperation := privacy.Activation{
		TenantID: fixture.tenant, OperationID: "activate-v1", PolicyDigest: v2.Digest,
		PolicyVersion: v2.Policy.Version, ActivatedBy: "other-admin", ActivatedAt: fixture.at.Add(6 * time.Hour),
	}
	if _, err := repo.ActivatePrivacyPolicy(ctx, contradictoryOperation); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory operation error=%v, want conflict", err)
	}
	contradictory := v1
	contradictory.CreatedBy = "other-admin"
	if _, err := repo.PutPrivacyPolicy(ctx, contradictory); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory version error=%v, want conflict", err)
	}
	aliased := v1
	aliased.Policy.Version = "tenant:alias"
	if _, err := repo.PutPrivacyPolicy(ctx, aliased); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same digest under another version error=%v, want conflict", err)
	}
	if _, err := repo.ActivePrivacyPolicy(shared.WithTenant(context.Background(), fixture.otherTenant), fixture.tenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant active lookup error=%v, want forbidden", err)
	}
	if _, err := repo.PrivacyPolicyByDigest(shared.WithTenant(context.Background(), fixture.otherTenant), fixture.otherTenant, v1.Digest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other-tenant digest lookup error=%v, want not found", err)
	}
	if _, err := repo.PrivacyPolicyActivationHistory(shared.WithTenant(context.Background(), fixture.otherTenant), fixture.tenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant activation history error=%v, want forbidden", err)
	}
}

func TestPrivacyPolicyRepositoryConcurrentInsertAndDatabaseGuards(t *testing.T) {
	fixture := newPrivacyPolicyPostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewPrivacyPolicyRepository(t, fixture.pool)
	assignment := fixture.assignment(t, "tenant:v1", fixture.at)

	const callers = 12
	start := make(chan struct{})
	results := make(chan struct {
		created bool
		err     error
	}, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			created, err := repo.PutPrivacyPolicy(ctx, assignment)
			results <- struct {
				created bool
				err     error
			}{created, err}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	createdCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent identical policy insert: %v", result.err)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent created count=%d, want 1", createdCount)
	}

	activationStart := make(chan struct{})
	activations := make(chan privacy.Activation, callers)
	activationErrors := make(chan error, callers)
	for i := range callers {
		operationID := shared.ID(fmt.Sprintf("activate-concurrent-%d", i))
		wg.Go(func() {
			<-activationStart
			activation, err := repo.ActivatePrivacyPolicy(ctx, privacy.Activation{
				TenantID: fixture.tenant, OperationID: operationID, PolicyDigest: assignment.Digest,
				PolicyVersion: assignment.Policy.Version, ActivatedBy: "integration-admin",
				ActivatedAt: fixture.at.Add(time.Duration(i+1) * time.Minute),
			})
			if err != nil {
				activationErrors <- err
				return
			}
			activations <- activation
		})
	}
	close(activationStart)
	wg.Wait()
	close(activations)
	close(activationErrors)
	for err := range activationErrors {
		t.Fatalf("concurrent activation: %v", err)
	}
	seenRevisions := make(map[uint64]bool, callers)
	for activation := range activations {
		if activation.Revision == 0 || activation.Revision > callers || seenRevisions[activation.Revision] {
			t.Fatalf("concurrent activation revision=%d, seen=%v", activation.Revision, seenRevisions)
		}
		seenRevisions[activation.Revision] = true
	}
	if len(seenRevisions) != callers {
		t.Fatalf("concurrent activation revisions=%v, want 1..%d", seenRevisions, callers)
	}

	for _, mutation := range []struct {
		operation string
		query     string
		args      []any
	}{
		{"policy UPDATE", `UPDATE privacy_policies SET created_by='tampered' WHERE tenant_id=$1`, []any{fixture.tenant.String()}},
		{"policy DELETE", `DELETE FROM privacy_policies WHERE tenant_id=$1`, []any{fixture.tenant.String()}},
		{"activation UPDATE", `UPDATE privacy_policy_activations SET activated_by='tampered' WHERE tenant_id=$1`, []any{fixture.tenant.String()}},
		{"activation DELETE", `DELETE FROM privacy_policy_activations WHERE tenant_id=$1`, []any{fixture.tenant.String()}},
		{"activation TRUNCATE", `TRUNCATE privacy_policy_activations`, nil},
		// Truncate the whole referencing set together: naming fewer tables is refused by the
		// foreign key before the trigger runs, which would leave the append-only guard itself
		// unproven. This is the only TRUNCATE shape PostgreSQL would otherwise allow.
		{"policy TRUNCATE", `TRUNCATE privacy_active_policies,privacy_policy_activations,privacy_policies`, nil},
	} {
		_, err := fixture.pool.Exec(context.Background(), mutation.query, mutation.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("%s immutable privacy policy error=%v, want SQLSTATE P0001", mutation.operation, err)
		}
	}

	role := newPrivacyPolicyRLSRole(t, fixture)
	count := func(tenantID shared.ID, table string) int {
		t.Helper()
		var visible int
		err := WithTenant(context.Background(), fixture.pool, tenantID.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `SET LOCAL ROLE `+role); err != nil {
				return fmt.Errorf("set privacy policy RLS role: %w", err)
			}
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE policy_version=$1`, assignment.Policy.Version).Scan(&visible)
		})
		if err != nil {
			t.Fatalf("privacy policy RLS count for %s: %v", table, err)
		}
		return visible
	}
	for _, table := range []string{"privacy_policies", "privacy_policy_activations"} {
		if count(fixture.tenant, table) == 0 || count(fixture.otherTenant, table) != 0 || count("", table) != 0 {
			t.Fatalf("%s RLS did not isolate known policy identity", table)
		}
	}
	for _, table := range []string{"privacy_policies", "privacy_active_policies", "privacy_policy_activations"} {
		var rls, forced bool
		if err := fixture.pool.QueryRow(context.Background(), `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&rls, &forced); err != nil || !rls || !forced {
			t.Fatalf("%s RLS/forced=%t/%t err=%v", table, rls, forced, err)
		}
	}
	assertPrivacyPolicyGUCReset(t, fixture, role, assignment.Policy.Version)
}

func assertPrivacyPolicyGUCReset(t *testing.T, fixture privacyPolicyPostgresFixture, role, version string) {
	t.Helper()
	ctx := context.Background()
	pool, err := ConnectPool(ctx, fixture.dsn, PoolConfig{MaxConns: 1})
	if err != nil {
		t.Fatalf("connect privacy policy reset pool: %v", err)
	}
	t.Cleanup(pool.Close)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire privacy policy reset connection: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin privacy policy tenant transaction: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, fixture.tenant.String()); err != nil {
		t.Fatalf("set privacy policy tenant GUC: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatalf("set privacy policy RLS role: %v", err)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM privacy_policies WHERE policy_version=$1`, version).Scan(&visible); err != nil || visible != 1 {
		t.Fatalf("tenant transaction visible policies=%d err=%v", visible, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit privacy policy tenant transaction: %v", err)
	}
	var reset string
	if err := conn.QueryRow(ctx, `SELECT current_setting('app.current_tenant',true)`).Scan(&reset); err != nil || reset != "" {
		t.Fatalf("privacy policy tenant GUC after commit=%q err=%v", reset, err)
	}
	reused, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reused privacy policy connection: %v", err)
	}
	defer func() {
		if err := reused.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback reused privacy policy transaction: %v", err)
		}
	}()
	if _, err := reused.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatalf("set role on reused privacy policy connection: %v", err)
	}
	if err := reused.QueryRow(ctx, `SELECT count(*) FROM privacy_policies WHERE policy_version=$1`, version).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("reused reset connection visible policies=%d err=%v", visible, err)
	}
}
