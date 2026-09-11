package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ownershipTestIDs struct{ next atomic.Int64 }

func (i *ownershipTestIDs) NewID() shared.ID {
	return shared.ID(fmt.Sprintf("ownership-job-%d", i.next.Add(1)))
}

type ownershipFixture struct {
	pool     *pgxpool.Pool
	ddl      *sql.DB
	repo     *OwnershipRepository
	ctx      context.Context
	at       time.Time
	policy   ownership.PolicyVersion
	snapshot ownership.Snapshot
	queue    *JobQueue
}

func newOwnershipFixture(t *testing.T) *ownershipFixture {
	t.Helper()
	pool, ddl := ownershipTestDatabase(t, 163, nil)
	ctx := shared.WithTenant(context.Background(), "own-a")
	at := time.Now().UTC().Truncate(time.Microsecond)
	repo, err := NewOwnershipRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	f := &ownershipFixture{pool: pool, ddl: ddl, repo: repo, ctx: ctx, at: at, queue: NewJobQueue(pool, &ownershipTestIDs{})}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('own-a','A'),('own-b','B'); INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('alice','Alice','admin','own-alice','own-a'),('bob','Bob','consultant','own-bob','own-a'),('viewer','Viewer','readonly','own-viewer','own-a'),('outsider','Other tenant','admin','own-out','own-b')`); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []shared.ID{"own-a", "own-b"} {
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Ownership test')`, tenant.String()+"-eng", tenant); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title,assignee) VALUES($1,$2,$3,'Ownership finding',''),($4,$2,$3,'Legacy finding','Old owner')`, tenant.String()+"-finding", tenant, tenant.String()+"-eng", tenant.String()+"-legacy")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []shared.ID{"pay", "ops"} {
		if _, err := repo.CreateTeam(ctx, ownership.Team{TenantID: "own-a", ID: id, Slug: id.String(), Name: id.String(), Revision: 1, CreatedAt: at, UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []shared.ID{"alice", "bob", "viewer"} {
		if err := repo.AddMember(ctx, "pay", id, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.AddMember(ctx, "ops", "bob", at); err != nil {
		t.Fatal(err)
	}
	f.snapshot = ownership.Snapshot{TenantID: "own-a", ID: "snapshot", EngagementID: "own-a-eng", Repository: "repo", Revision: "git:1111111111111111111111111111111111111111", FilePath: "CODEOWNERS", Content: "* @org/pay", ParserVersion: ownership.ParserVersion, Trust: "base_ref", ApprovedBy: "alice", CreatedAt: at}
	f.snapshot.Hash = ownership.ContentHash(f.snapshot.Content)
	if err := repo.CreateSnapshot(ctx, f.snapshot); err != nil {
		t.Fatal(err)
	}
	f.policy = ownership.PolicyVersion{TenantID: "own-a", PolicyID: "policy", EngagementID: "own-a-eng", Repository: "repo", Version: 1, SnapshotID: "snapshot", Mappings: []ownership.Mapping{{Repository: "repo", Owner: "@org/pay", TeamID: "pay"}}, CreatedBy: "alice", CreatedAt: at}
	if err := repo.CreatePolicyVersion(ctx, f.policy); err != nil {
		t.Fatal(err)
	}
	if err := repo.ActivatePolicy(ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 1, ExpectedRevision: 1, ExpectedHash: f.policy.Hash()}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *ownershipFixture) mutation(t *testing.T, kind string) ports.OwnershipMutation {
	t.Helper()
	cur, err := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-finding")
	if err != nil {
		t.Fatal(err)
	}
	return ports.OwnershipMutation{EngagementID: "own-a-eng", FindingID: "own-a-finding", DecisionID: shared.ID("decision-" + kind), Key: "request-" + kind, Actor: "alice", Kind: kind, ExpectedFindingVersion: cur.FindingVersion, ExpectedRevision: cur.Assignment.Revision, ExpectedManualGeneration: cur.Assignment.ManualGeneration, At: f.at, Notify: true}
}
func (f *ownershipFixture) route(t *testing.T) ports.OwnershipMutation {
	t.Helper()
	m := f.mutation(t, "route")
	r, err := ownership.NewResolver(f.policy, &f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Resolve(ownership.Input{TenantID: "own-a", EngagementID: "own-a-eng", FindingID: "own-a-finding", Repository: "repo", Paths: []string{"src/main.go"}, SourceRevision: "git:2222222222222222222222222222222222222222", SourceBound: true, Supported: true, Current: ownership.Assignment{Mode: "auto"}, ActiveTeams: []shared.ID{"pay"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.queue.Enqueue(f.ctx, "ownership.route", []byte(`{"finding_id":"own-a-finding"}`))
	if err != nil {
		t.Fatal(err)
	}
	job, err := f.queue.Claim(f.ctx, time.Minute, "ownership.route")
	if err != nil || job == nil {
		t.Fatalf("claim job=%v %v", job, err)
	}
	m.JobID = job.ID
	m.Fence = job.Fence
	m.PolicyID = f.policy.PolicyID
	m.Repository = "repo"
	m.PolicyVersion = 1
	m.ExpectedPolicyRevision = 2
	m.Result = result
	m.TeamID = "pay"
	m.Actor = "ownership-worker"
	return m
}

func TestOwnershipPostgresRoutingClaimAndReplay(t *testing.T) {
	f := newOwnershipFixture(t)
	route := f.route(t)
	d, err := f.repo.ApplyAssignment(f.ctx, route)
	if err != nil || d.After.TeamID != "pay" || d.After.Mode != "auto" {
		t.Fatalf("route=%+v %v", d, err)
	}
	replay := route
	replay.DecisionID = "different-id"
	replay.At = replay.At.Add(time.Hour)
	d2, err := f.repo.ApplyAssignment(f.ctx, replay)
	if err != nil || d2.ID != d.ID {
		t.Fatalf("replay=%+v %v", d2, err)
	}
	changed := route
	changed.TeamID = "ops"
	changed.Result.TeamID = "ops"
	if _, err := f.repo.ApplyAssignment(f.ctx, changed); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same key different content=%v", err)
	}
	claim := f.mutation(t, "claim")
	claim.TeamID = "pay"
	claim.AssigneeID = "alice"
	claim.LegacyAssignee = "alice"
	claimed, err := f.repo.ApplyAssignment(f.ctx, claim)
	if err != nil || claimed.After.Mode != "manual" || claimed.After.ManualGeneration != 1 {
		t.Fatalf("claim=%+v %v", claimed, err)
	}
	cur, _ := f.repo.GetAssignment(f.ctx, claim.EngagementID, claim.FindingID)
	if cur.FindingAssignee != "alice" || cur.Assignment.AssigneeID != "alice" || cur.FindingVersion != 3 {
		t.Fatalf("mirror=%+v", cur)
	}
	history, err := f.repo.ListDecisions(f.ctx, claim.EngagementID, claim.FindingID, ports.OwnershipHistoryCursor{Limit: 1})
	if err != nil || len(history) != 1 {
		t.Fatal(err)
	}
	page, err := f.repo.ListDecisions(f.ctx, claim.EngagementID, claim.FindingID, ports.OwnershipHistoryCursor{Limit: 1, Before: history[0].CreatedAt, BeforeID: history[0].ID})
	if err != nil || len(page) != 1 || history[0].ID == page[0].ID {
		t.Fatalf("history page=%+v %v", page, err)
	}
	intents, err := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if err != nil || len(intents) != 2 {
		t.Fatalf("intents=%+v %v", intents, err)
	}
	if err := f.repo.CompleteIntent(f.ctx, intents[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.CompleteIntent(f.ctx, intents[0].ID); err != nil {
		t.Fatal(err)
	}
	entries, err := NewAuditLog(f.pool).List(f.ctx, 100)
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit=%d %v", len(entries), err)
	}
	report, err := NewAuditLog(f.pool).Verify(f.ctx)
	if err != nil || !report.Intact {
		t.Fatalf("audit chain=%+v %v", report, err)
	}
}

func TestOwnershipPostgresManualProtectionAndEligibility(t *testing.T) {
	f := newOwnershipFixture(t)
	route := f.route(t)
	legacy := route
	legacy.FindingID = "own-a-legacy"
	legacy.Key = "legacy-key"
	legacy.DecisionID = "legacy-decision"
	if _, err := f.repo.ApplyAssignment(f.ctx, legacy); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("legacy assignment overwritten: %v", err)
	}
	if _, err := f.repo.ApplyAssignment(f.ctx, route); err != nil {
		t.Fatal(err)
	}
	readonly := f.mutation(t, "claim")
	readonly.Actor = "viewer"
	readonly.TeamID = "pay"
	readonly.AssigneeID = "viewer"
	readonly.LegacyAssignee = "viewer"
	if _, err := f.repo.ApplyAssignment(f.ctx, readonly); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("readonly claim=%v", err)
	}
	clear := f.mutation(t, "clear")
	if _, err := f.repo.ApplyAssignment(f.ctx, clear); err != nil {
		t.Fatal(err)
	}
	stale := f.route(t)
	stale.Key = "after-clear"
	stale.DecisionID = "after-clear"
	if _, err := f.repo.ApplyAssignment(f.ctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("clear silently released protection=%v", err)
	}
	release := f.mutation(t, "release")
	release.Notify = false
	if _, err := f.repo.ApplyAssignment(f.ctx, release); err != nil {
		t.Fatal(err)
	}
	routes, err := f.repo.ListPendingIntents(f.ctx, "route", 100)
	if err != nil || len(routes) != 1 {
		t.Fatalf("release intent=%+v %v", routes, err)
	}
	assign := f.mutation(t, "assign")
	assign.TeamID = "ops"
	assign.AssigneeID = "alice"
	assign.LegacyAssignee = "alice"
	if _, err := f.repo.ApplyAssignment(f.ctx, assign); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nonmember assignment=%v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET disabled=true WHERE id='bob'`); err != nil {
		t.Fatal(err)
	}
	assign.AssigneeID = "bob"
	assign.LegacyAssignee = "bob"
	if _, err := f.repo.ApplyAssignment(f.ctx, assign); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("disabled assignment=%v", err)
	}
	team, _ := f.repo.GetTeam(f.ctx, "ops")
	team.Archived = true
	team.Revision++
	if _, err := f.repo.UpdateTeam(f.ctx, team, 1); err != nil {
		t.Fatal(err)
	}
	assign.AssigneeID = ""
	assign.LegacyAssignee = ""
	if _, err := f.repo.ApplyAssignment(f.ctx, assign); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("archived assignment=%v", err)
	}
}

func TestOwnershipPostgresIsolationAndMappingRevisions(t *testing.T) {
	f := newOwnershipFixture(t)
	other := shared.WithTenant(context.Background(), "own-b")
	if _, err := f.repo.GetTeam(other, "pay"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.repo.GetSnapshot(other, "snapshot"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.repo.GetAssignment(other, "own-a-eng", "own-a-finding"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.repo.GetTeam(context.Background(), "pay"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant=%v", err)
	}
	if err := f.repo.AddMember(f.ctx, "pay", "outsider", f.at); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross user membership=%v", err)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM ownership_teams`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unbound RLS count=%d %v", count, err)
	}
	err := WithTenant(other, f.pool, "own-b", func(tx pgx.Tx) error {
		_, err := tx.Exec(other, `INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES('own-b','pay','outsider',now())`)
		return err
	})
	if err == nil {
		t.Fatal("composite FK admitted cross-tenant team")
	}
	err = WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE ownership_snapshots SET content='tampered' WHERE id='snapshot'`)
		return err
	})
	if err == nil {
		t.Fatal("snapshot update accepted")
	}
	m := ports.OwnershipMapping{Mapping: ownership.Mapping{Repository: "repo", Owner: "@org/pay", TeamID: "pay", SuggestedUserID: "alice"}, Revision: 1}
	if err := f.repo.SaveMapping(f.ctx, "own-a-eng", m); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.SaveMapping(f.ctx, "own-a-eng", m); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate mapping=%v", err)
	}
	m.Revision = 2
	m.Mapping.TeamID = "ops"
	m.Mapping.SuggestedUserID = "bob"
	if err := f.repo.SaveMapping(f.ctx, "own-a-eng", m); err != nil {
		t.Fatal(err)
	}
	p, err := f.repo.GetPolicyVersion(f.ctx, "policy", 1)
	if err != nil || p.Mappings[0].TeamID != "pay" {
		t.Fatalf("mapping edit changed frozen policy: %+v %v", p, err)
	}
	if err := f.repo.DeleteMapping(f.ctx, "own-a-eng", "repo", "@org/pay", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale delete=%v", err)
	}
	if err := f.repo.DeleteMapping(f.ctx, "own-a-eng", "repo", "@org/pay", 2); err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipPostgresAtomicRollback(t *testing.T) {
	f := newOwnershipFixture(t)
	for _, table := range []string{"ownership_intents", "audit_log"} {
		t.Run(table, func(t *testing.T) {
			// Failure injection at each downstream write must undo the assignment and decision.
			if _, err := f.ddl.Exec(`CREATE FUNCTION ownership_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ownership failure'; END; $$; CREATE TRIGGER ownership_test_failure BEFORE INSERT ON ` + pgx.Identifier{table}.Sanitize() + ` FOR EACH ROW EXECUTE FUNCTION ownership_test_fail()`); err != nil {
				t.Fatal(err)
			}
			m := f.mutation(t, "assign")
			m.TeamID = "pay"
			m.AssigneeID = "alice"
			m.LegacyAssignee = "alice"
			if _, err := f.repo.ApplyAssignment(f.ctx, m); err == nil {
				t.Fatal("injected failure ignored")
			}
			cur, _ := f.repo.GetAssignment(f.ctx, m.EngagementID, m.FindingID)
			if cur.FindingVersion != 1 || cur.Assignment.Revision != 0 || cur.FindingAssignee != "" {
				t.Fatalf("partial assignment=%+v", cur)
			}
			for _, name := range []string{"ownership_decisions", "ownership_intents", "audit_log"} {
				err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
					var count int
					if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM `+pgx.Identifier{name}.Sanitize()).Scan(&count); err != nil {
						return err
					}
					if count != 0 {
						return fmt.Errorf("partial %s rows=%d", name, count)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.ddl.Exec(`DROP TRIGGER ownership_test_failure ON ` + pgx.Identifier{table}.Sanitize() + `; DROP FUNCTION ownership_test_fail()`); err != nil {
				t.Fatal(err)
			}
		})
	}
	m := f.mutation(t, "assign")
	m.TeamID = "pay"
	m.Notify = false
	rollback := errors.New("outer rollback")
	err := NewTenantTransactionRunner(f.pool).Run(f.ctx, "own-a", func(ctx context.Context) error {
		if _, err := f.repo.ApplyAssignment(ctx, m); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, err := f.repo.ApplyAssignment(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	intents, _ := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if len(intents) != 0 {
		t.Fatal("notifications-disabled transition queued delivery")
	}
	if err := f.repo.CompleteIntent(f.ctx, "notification:decision-assign"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("suppressed intent resumed: %v", err)
	}
}

func TestOwnershipPostgresConcurrentClaimsAndStaleWorkers(t *testing.T) {
	f := newOwnershipFixture(t)
	route := f.route(t)
	if _, err := f.repo.ApplyAssignment(f.ctx, route); err != nil {
		t.Fatal(err)
	}
	claim := f.mutation(t, "claim")
	claim.TeamID = "pay"
	claim.AssigneeID = "alice"
	claim.LegacyAssignee = "alice"
	other := claim
	other.Actor = "bob"
	other.AssigneeID = "bob"
	other.LegacyAssignee = "bob"
	other.Key = "bob-claim"
	other.DecisionID = "bob-claim"
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, m := range []ports.OwnershipMutation{claim, other} {
		wg.Add(1)
		go func(m ports.OwnershipMutation) {
			defer wg.Done()
			<-start
			_, err := f.repo.ApplyAssignment(f.ctx, m)
			results <- err
		}(m)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, shared.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("claims=%d conflicts=%d", success, conflicts)
	}
	stale := f.route(t)
	stale.Key = "stale-after-human"
	stale.DecisionID = "stale-after-human"
	if _, err := f.repo.ApplyAssignment(f.ctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("worker overwrote claim=%v", err)
	}
	if err := f.queue.Fail(f.ctx, stale.JobID, stale.Fence, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.queue.Claim(f.ctx, time.Minute, "ownership.route"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.ApplyAssignment(f.ctx, stale); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale job=%v", err)
	}
	history, _ := f.repo.ListDecisions(f.ctx, "own-a-eng", "own-a-finding", ports.OwnershipHistoryCursor{Limit: 100})
	if len(history) != 2 {
		t.Fatalf("stale worker wrote history=%d", len(history))
	}
}

func TestOwnershipPostgresPreviewAndPolicyCAS(t *testing.T) {
	f := newOwnershipFixture(t)
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 1, ExpectedRevision: 1, ExpectedHash: f.policy.Hash()}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale activation=%v", err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 1, ExpectedRevision: 2, ExpectedHash: "wrong-hash"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("wrong preview hash=%v", err)
	}
	run := ports.OwnershipRun{ID: "preview", EngagementID: "own-a-eng", PolicyID: "policy", PolicyVersion: 1, PolicyRevision: 2, PolicyHash: f.policy.Hash(), Mode: "preview", State: "queued", Revision: 1, Cutoff: f.at, Total: 1, Filter: json.RawMessage(`{}`), CreatedAt: f.at}
	if err := f.repo.CreateRun(f.ctx, run); err != nil {
		t.Fatal(err)
	}
	item := ports.OwnershipRunItem{RunID: "preview", EngagementID: "own-a-eng", FindingID: "own-a-finding", FindingVersion: 1, Result: ownership.Result{Resolution: ownership.Resolved, Reason: "codeowners", TeamID: "pay", PolicyHash: f.policy.Hash()}}
	if err := f.repo.SetRunState(f.ctx, "preview", 1, "completed"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("premature completion=%v", err)
	}
	if err := f.repo.SaveRunItems(f.ctx, "preview", 1, []ports.OwnershipRunItem{item}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.SaveRunItems(f.ctx, "preview", 2, []ports.OwnershipRunItem{item}); err != nil {
		t.Fatal(err)
	}
	items, err := f.repo.ListRunItems(f.ctx, "preview", "", 100)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%v %v", items, err)
	}
	if err := f.repo.SetRunState(f.ctx, "preview", 2, "completed"); err != nil {
		t.Fatal(err)
	}
	saved, _ := f.repo.GetRun(f.ctx, "preview")
	if saved.Processed != 1 || saved.State != "completed" || saved.Revision != 3 {
		t.Fatalf("run=%+v", saved)
	}
	cur, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-finding")
	if cur.Assignment.Revision != 0 || cur.FindingVersion != 1 {
		t.Fatal("preview changed assignment")
	}
	intents, _ := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if len(intents) != 0 {
		t.Fatal("preview emitted notifications")
	}
	newVersion := f.policy
	newVersion.Version = 2
	newVersion.Mappings = []ownership.Mapping{{Repository: "repo", Owner: "@org/pay", TeamID: "ops"}}
	if err := f.repo.CreatePolicyVersion(f.ctx, newVersion); err != nil {
		t.Fatal(err)
	}
	route := f.route(t)
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 2, ExpectedRevision: 2, ExpectedHash: newVersion.Hash()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.ApplyAssignment(f.ctx, route); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("old policy worker=%v", err)
	}
	active, err := f.repo.GetActivePolicy(f.ctx, "own-a-eng", "repo")
	if err != nil || active.Version.Version != 2 {
		t.Fatalf("active=%+v %v", active, err)
	}
}

func TestOwnershipPostgresPolicyScopeNoOpAndImmutableHistory(t *testing.T) {
	f := newOwnershipFixture(t)
	fallback := f.policy
	fallback.PolicyID = "fallback"
	fallback.Repository = ""
	fallback.SnapshotID = ""
	fallback.Mappings = nil
	fallback.Rules = []ownership.Rule{{ID: "fallback-rule", Priority: 1, TeamID: "ops"}}
	if err := f.repo.CreatePolicyVersion(f.ctx, fallback); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "fallback", Version: 1, ExpectedRevision: 1, ExpectedHash: fallback.Hash()}); err != nil {
		t.Fatal(err)
	}
	active, err := f.repo.GetActivePolicy(f.ctx, "own-a-eng", "repo")
	if err != nil || active.Version.PolicyID != "policy" {
		t.Fatalf("specific policy precedence=%+v %v", active, err)
	}
	active, err = f.repo.GetActivePolicy(f.ctx, "own-a-eng", "other-repo")
	if err != nil || active.Version.PolicyID != "fallback" {
		t.Fatalf("fallback=%+v %v", active, err)
	}
	route := f.route(t)
	wrong := route
	wrong.PolicyID = "fallback"
	wrong.Result.PolicyHash = fallback.Hash()
	wrong.TeamID = "ops"
	wrong.Result.TeamID = "ops"
	if _, err := f.repo.ApplyAssignment(f.ctx, wrong); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("superseded fallback committed=%v", err)
	}
	d, err := f.repo.ApplyAssignment(f.ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-finding")
	noop := route
	noop.Key = "reevaluation"
	noop.DecisionID = "reevaluation"
	noop.ExpectedFindingVersion = cur.FindingVersion
	noop.ExpectedRevision = cur.Assignment.Revision
	noop.Result.InputHash = ownership.ContentHash("new source input")
	decision, err := f.repo.ApplyAssignment(f.ctx, noop)
	if err != nil || decision.After.Revision != d.After.Revision {
		t.Fatalf("no-op=%+v %v", decision, err)
	}
	next, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-finding")
	if next.FindingVersion != cur.FindingVersion {
		t.Fatal("reevaluation changed finding version")
	}
	intents, _ := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if len(intents) != 1 {
		t.Fatalf("reevaluation notifications=%d", len(intents))
	}
	for _, query := range []string{`DELETE FROM ownership_decisions`, `UPDATE ownership_policy_versions SET payload='{}'`, `DELETE FROM ownership_snapshots`} {
		if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, query); return err }); err == nil {
			t.Fatalf("mutable evidence accepted: %s", query)
		}
	}
	s := f.snapshot
	s.ID = "untrusted"
	s.Trust = "untrusted"
	if err := f.repo.CreateSnapshot(f.ctx, s); err != nil {
		t.Fatal(err)
	}
	p := f.policy
	p.Version = 2
	p.SnapshotID = s.ID
	if err := f.repo.CreatePolicyVersion(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 2, ExpectedRevision: 2, ExpectedHash: p.Hash()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("untrusted policy activated=%v", err)
	}
}
