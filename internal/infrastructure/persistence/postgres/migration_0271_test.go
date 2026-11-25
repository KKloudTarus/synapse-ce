package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// bindingFixture stands up one tenant, one engagement, one finding and one observation, which is the
// minimum the composite foreign keys need before a binding can exist at all.
type bindingFixture struct {
	pool        *pgxpool.Pool
	tenant      string
	engagement  string
	findingA    string
	findingB    string
	observation string
}

func setupBindingFixture(t *testing.T, tenant string) *bindingFixture {
	t.Helper()
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	fixture := &bindingFixture{
		pool: pool, tenant: tenant, engagement: tenant + "-eng",
		findingA: tenant + "-fa", findingB: tenant + "-fb", observation: tenant + "-obs",
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		clean := context.Background()
		_ = WithTenant(clean, pool, tenant, func(tx pgx.Tx) error {
			_, _ = tx.Exec(clean, `DELETE FROM observation_finding_bindings WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(clean, `DELETE FROM imported_findings WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(clean, `DELETE FROM findings WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(clean, `DELETE FROM engagements WHERE tenant_id=$1`, tenant)
			return nil
		})
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	err = WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name, status, created_at, updated_at)
			VALUES ($1,$2,'binding fixture','draft',$3,$3) ON CONFLICT (id) DO NOTHING`, fixture.engagement, tenant, now); err != nil {
			return err
		}
		for _, id := range []string{fixture.findingA, fixture.findingB} {
			if _, err := tx.Exec(ctx, `INSERT INTO findings (id, tenant_id, engagement_id, title, severity, status, created_at, updated_at)
				VALUES ($1,$2,$3,'canonical','high','open',$4,$4) ON CONFLICT (id) DO NOTHING`, id, tenant, fixture.engagement, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed engagement and findings: %v", err)
	}

	observations := NewImportedFindingRepository(pool)
	if _, _, err := observations.Save(ctx, shared.ID(tenant), []importedfinding.ImportedFinding{{
		ID: shared.ID(fixture.observation), TenantID: shared.ID(tenant), EngagementID: shared.ID(fixture.engagement),
		Severity: shared.SeverityHigh, Title: "external result", Message: "m",
		Location:    importedfinding.Location{Path: "src/app.go", StartLine: 42},
		Fingerprint: "abc",
		Provenance: importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.a",
			SourceDigest: "sha256:" + tenant, IngestedBy: "human:test", IngestedAt: now,
		},
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}}); err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	return fixture
}

func (f *bindingFixture) binding(id, findingID string, version int, at time.Time) observationbinding.Binding {
	return observationbinding.Binding{
		ID: shared.ID(id), TenantID: shared.ID(f.tenant), EngagementID: shared.ID(f.engagement),
		Scope: "semgrep", ExternalIdentity: "fingerprint:abc",
		FindingID: shared.ID(findingID), ObservationID: shared.ID(f.observation), Version: version,
		DecidedBy: "human:test", Reason: "same issue, confirmed by hand", DecidedAt: at,
	}
}

func TestMigration0271ObservationBindingsApplies(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-apply")
	ctx := context.Background()
	var forced, hasPolicy bool
	if err := fixture.pool.QueryRow(ctx, `SELECT relforcerowsecurity,
		EXISTS(SELECT 1 FROM pg_policies WHERE tablename='observation_finding_bindings')
		FROM pg_class WHERE relname='observation_finding_bindings'`).Scan(&forced, &hasPolicy); err != nil {
		t.Fatalf("inspect table: %v", err)
	}
	// A tenant table without FORCE is isolated only for non-owners, which is not the guarantee the rest
	// of the schema makes.
	if !forced || !hasPolicy {
		t.Fatalf("observation_finding_bindings: forced=%v policy=%v, want both", forced, hasPolicy)
	}
}

func TestObservationBindingConcurrentAdoptionResolvesToOne(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-race")
	repo := NewObservationBindingRepository(fixture.pool)
	at := time.Now().UTC().Truncate(time.Millisecond)

	// Every racer adopts a DIFFERENT finding on the same scoped identity, so at most one can win. This is
	// the acceptance criterion the partial unique index exists for: two people adopting at the same
	// moment must not end with two workflows each believing it owns the remediation.
	const racers = 8
	results := make([]error, racers)
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(index int) {
			defer wg.Done()
			findingID := fixture.findingA
			if index%2 == 1 {
				findingID = fixture.findingB
			}
			binding := fixture.binding("race-"+string(rune('a'+index)), findingID, 1, at)
			_, results[index] = repo.Adopt(context.Background(), shared.ID(fixture.tenant), binding)
		}(i)
	}
	wg.Wait()

	won := 0
	for index, err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, shared.ErrConflict):
		default:
			t.Fatalf("racer %d: %v", index, err)
		}
	}
	// Half the racers name the same finding as the winner, and adoption is idempotent for that, so more
	// than one may return without error. What must hold is that exactly one ROW exists.
	if won == 0 {
		t.Fatal("every racer lost; one adoption must succeed")
	}
	all, err := repo.ListByEngagement(context.Background(), shared.ID(fixture.tenant), shared.ID(fixture.engagement))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d bindings after %d concurrent adoptions, want exactly 1: %+v", len(all), racers, all)
	}
}

func TestObservationBindingRefusesACrossTenantFinding(t *testing.T) {
	home := setupBindingFixture(t, "t-bind-home")
	foreign := setupBindingFixture(t, "t-bind-foreign")
	repo := NewObservationBindingRepository(home.pool)

	// The composite foreign key carries the tenant and the engagement into the reference, so supplying a
	// real finding id from another tenant is refused by the database rather than accepted.
	binding := home.binding("cross-1", foreign.findingA, 1, time.Now().UTC().Truncate(time.Millisecond))
	_, err := repo.Adopt(context.Background(), shared.ID(home.tenant), binding)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("binding another tenant's finding = %v, want a refusal", err)
	}
}

func TestObservationBindingSupersedeKeepsTheReplacedVersion(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-super")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("sup-1", fixture.findingA, 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	later := at.Add(time.Hour)
	if _, err := repo.Supersede(ctx, shared.ID(fixture.tenant), 1, fixture.binding("sup-2", fixture.findingB, 2, later)); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	current, err := repo.Current(ctx, shared.ID(fixture.tenant), shared.ID(fixture.engagement),
		observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"})
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if current.ID != "sup-2" || current.Version != 2 {
		t.Fatalf("binding in force = %+v, want version 2", current)
	}
	all, err := repo.ListByEngagement(ctx, shared.ID(fixture.tenant), shared.ID(fixture.engagement))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("%d versions, want the replaced one kept", len(all))
	}

	// Superseding a version that is no longer in force is refused, so a decision made against a stale
	// view cannot overwrite the one made in between.
	if _, err := repo.Supersede(ctx, shared.ID(fixture.tenant), 1, fixture.binding("sup-3", fixture.findingA, 2, later.Add(time.Hour))); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("superseding a stale version = %v, want a conflict", err)
	}
}

func TestObservationBindingDecisionsAreImmutable(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-immut")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("imm-1", fixture.findingA, 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// The reason and the actor ARE the audit record. A guard trigger refuses to rewrite them, so a
	// decision cannot be re-attributed after the fact.
	err := WithTenant(ctx, fixture.pool, fixture.tenant, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `UPDATE observation_finding_bindings SET reason='rewritten' WHERE id='imm-1'`)
		return execErr
	})
	if err == nil {
		t.Fatal("rewriting a decision's reason was accepted")
	}

	// Retiring a version twice is refused too, which is what keeps a superseded row from being reused.
	err = WithTenant(ctx, fixture.pool, fixture.tenant, func(tx pgx.Tx) error {
		if _, execErr := tx.Exec(ctx, `UPDATE observation_finding_bindings SET superseded_at=now() WHERE id='imm-1'`); execErr != nil {
			return execErr
		}
		_, execErr := tx.Exec(ctx, `UPDATE observation_finding_bindings SET superseded_at=now() WHERE id='imm-1'`)
		return execErr
	})
	if err == nil {
		t.Fatal("retiring an already superseded version was accepted")
	}
}

// TestObservationBindingIndexRefusesASecondCurrentRow exercises the partial unique index directly.
//
// The repository's own FOR UPDATE read serializes adopters that arrive after a row exists, which is why
// the goroutine race above passes even with the index downgraded to a plain one: by the time the second
// adopter looks, the first has committed. Two transactions that BOTH pass that read before either commits
// are the case only the index can decide, and this drives exactly that, with no timing left to chance.
func TestObservationBindingIndexRefusesASecondCurrentRow(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-index")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	insert := func(ctx context.Context, tx pgx.Tx, id, findingID string) error {
		_, err := tx.Exec(ctx, `INSERT INTO observation_finding_bindings
			(id, tenant_id, engagement_id, scope, external_identity, finding_id, observation_id, version,
			 decided_by, reason, decided_at)
			VALUES ($1, current_setting('app.current_tenant'), $2,'semgrep','fingerprint:abc',$3,$4,1,'human:test','same issue',$5)`,
			id, fixture.engagement, findingID, fixture.observation, at)
		return err
	}

	first, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin first: %v", err)
	}
	defer func() { _ = first.Rollback(context.Background()) }()
	if _, err := first.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, fixture.tenant); err != nil {
		t.Fatalf("bind first tenant: %v", err)
	}
	if err := insert(ctx, first, "idx-1", fixture.findingA); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// The second transaction starts while the first is still open, so it cannot see the uncommitted row.
	second, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second: %v", err)
	}
	defer func() { _ = second.Rollback(context.Background()) }()
	if _, err := second.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, fixture.tenant); err != nil {
		t.Fatalf("bind second tenant: %v", err)
	}

	// The second insert blocks on the index until the first resolves, so it runs in its own goroutine.
	blocked := make(chan error, 1)
	go func() { blocked <- insert(context.Background(), second, "idx-2", fixture.findingB) }()

	if err := first.Commit(ctx); err != nil {
		t.Fatalf("commit first: %v", err)
	}
	secondErr := <-blocked
	if secondErr == nil {
		t.Fatal("two current bindings for one scoped identity were accepted; the partial unique index is not enforcing")
	}

	var rows int
	if err := WithTenant(context.Background(), fixture.pool, fixture.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM observation_finding_bindings
			WHERE engagement_id=$1 AND superseded_at IS NULL`, fixture.engagement).Scan(&rows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("%d bindings in force, want 1", rows)
	}
}

// TestObservationBindingLosingASupersedeRaceIsAConflictNotAMissingBinding pins what a second reviewer
// gets when their decision arrives after someone else's. The winner leaves a new version in force, so
// the loser's FOR UPDATE finds it and reports the version mismatch. The narrower state, where every
// version is retired and none is in force, is covered separately below: a mutation that removes the
// conflict branch does not fail THIS test, because this one resolves through the version comparison.
func TestObservationBindingLosingASupersedeRaceIsAConflictNotAMissingBinding(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-race2")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("r2-1", fixture.findingA, 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// A holds the current row and replaces it, without committing.
	first, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = first.Rollback(context.Background()) }()
	if _, err := first.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, fixture.tenant); err != nil {
		t.Fatalf("bind tenant: %v", err)
	}
	later := at.Add(time.Hour)
	if _, err := first.Exec(ctx, `UPDATE observation_finding_bindings SET superseded_at=$1 WHERE id='r2-1'`, later); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := first.Exec(ctx, `INSERT INTO observation_finding_bindings
		(id, tenant_id, engagement_id, scope, external_identity, finding_id, observation_id, version, decided_by, reason, decided_at)
		VALUES ('r2-2', current_setting('app.current_tenant'), $1,'semgrep','fingerprint:abc',$2,$3,2,'human:a','first mover',$4)`,
		fixture.engagement, fixture.findingB, fixture.observation, later); err != nil {
		t.Fatalf("insert replacement: %v", err)
	}

	// B decides against version 1, the view it could see, and blocks on A's lock.
	type outcome struct{ err error }
	done := make(chan outcome, 1)
	go func() {
		_, err := repo.Supersede(context.Background(), shared.ID(fixture.tenant), 1, fixture.binding("r2-3", fixture.findingA, 2, later.Add(time.Minute)))
		done <- outcome{err: err}
	}()

	if err := first.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got := <-done
	if !errors.Is(got.err, shared.ErrConflict) {
		t.Fatalf("losing the race = %v, want a conflict naming the version that won", got.err)
	}
	if errors.Is(got.err, shared.ErrNotFound) {
		t.Fatal("a lost race must not report the binding as missing")
	}
}

// TestObservationBindingSupersedeSurvivesABackwardClock keeps a skewed replica from turning a valid
// decision into a 500. The table refuses a row retired before it was decided, so the retirement time is
// clamped instead of passed straight through.
func TestObservationBindingSupersedeSurvivesABackwardClock(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-clock")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("clk-1", fixture.findingA, 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// A second replica two seconds behind records the replacement.
	behind := at.Add(-2 * time.Second)
	if _, err := repo.Supersede(ctx, shared.ID(fixture.tenant), 1, fixture.binding("clk-2", fixture.findingB, 2, behind)); err != nil {
		t.Fatalf("supersede from a slow replica: %v", err)
	}
	current, err := repo.Current(ctx, shared.ID(fixture.tenant), shared.ID(fixture.engagement),
		observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"})
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if current.ID != "clk-2" {
		t.Fatalf("binding in force = %s, want the replacement", current.ID)
	}
}

// TestObservationBindingSurvivesItsObservationBeingDeleted is why the observation foreign key restricts.
// The identity was chosen to outlive the row; a cascade there would take the decision with it and let the
// next adopt start again at version 1 with nothing to show one was ever made.
func TestObservationBindingSurvivesItsObservationBeingDeleted(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-del")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("del-1", fixture.findingA, 1, time.Now().UTC().Truncate(time.Millisecond))); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	err := WithTenant(ctx, fixture.pool, fixture.tenant, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `DELETE FROM imported_findings WHERE tenant_id=$1 AND id=$2`, fixture.tenant, fixture.observation)
		return execErr
	})
	if err == nil {
		t.Fatal("deleting an observation that carries a human decision was accepted")
	}
	all, listErr := repo.ListByEngagement(ctx, shared.ID(fixture.tenant), shared.ID(fixture.engagement))
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	if len(all) != 1 {
		t.Fatalf("%d bindings after the refused delete, want the decision intact", len(all))
	}
}

// TestSupersedingWhenEveryVersionIsRetiredIsAConflictNotAMissingBinding covers the state the race test
// above cannot reach through the repository's own API: Supersede always inserts a replacement, so it
// never leaves an identity with no version in force. A direct retire does, and from that state the
// honest answer is still a conflict. Reporting not found would tell a caller that a decision it can read
// in the lineage was never made.
func TestSupersedingWhenEveryVersionIsRetiredIsAConflictNotAMissingBinding(t *testing.T) {
	fixture := setupBindingFixture(t, "t-bind-retired")
	repo := NewObservationBindingRepository(fixture.pool)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := repo.Adopt(ctx, shared.ID(fixture.tenant), fixture.binding("ret-1", fixture.findingA, 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if err := WithTenant(ctx, fixture.pool, fixture.tenant, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `UPDATE observation_finding_bindings SET superseded_at=$1 WHERE id='ret-1'`, at.Add(time.Minute))
		return execErr
	}); err != nil {
		t.Fatalf("retire: %v", err)
	}

	_, err := repo.Supersede(ctx, shared.ID(fixture.tenant), 1, fixture.binding("ret-2", fixture.findingB, 2, at.Add(time.Hour)))
	if errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("superseding a retired identity = %v, want a conflict: version 1 is on record", err)
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("superseding a retired identity = %v, want a conflict", err)
	}

	// An identity nothing was ever adopted for is genuinely missing, and must stay distinguishable.
	absent := fixture.binding("ret-3", fixture.findingA, 2, at.Add(time.Hour))
	absent.ExternalIdentity = "fingerprint:never-adopted"
	if _, err := repo.Supersede(ctx, shared.ID(fixture.tenant), 1, absent); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("superseding an identity with no history = %v, want not found", err)
	}
}
