package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type ownershipWallClock struct{}

func (ownershipWallClock) Now() time.Time { return time.Now().UTC() }

func ownershipRuntime(t *testing.T, f *ownershipFixture, mode string) (*OwnershipExecution, *ownershipuc.Worker) {
	t.Helper()
	store, err := NewOwnershipExecution(f.repo, f.queue.ids, ownershipWallClock{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := ownershipuc.NewWorker(store, f.repo, mode, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return store, w
}

func TestOwnershipExecutionAuditRollbackAndDeadLetterReplay(t *testing.T) {
	f := newOwnershipFixture(t)
	store, worker := ownershipRuntime(t, f, "enforce")
	ownershipCapturedFinding(t, f, "payment-retry", true)
	header, err := f.repo.GetOwnershipPolicy(f.ctx, "policy")
	if err != nil {
		t.Fatal(err)
	}
	filter, _ := json.Marshal(ports.OwnershipInboxFilter{EngagementID: "own-a-eng"})
	req := ports.OwnershipRunRequest{Policy: header, Version: f.policy, Actor: "alice", Key: "before-fault", Mode: "preview", Filter: filter}
	preview, err := worker.StartOwnershipRun(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	req.Mode, req.Key, req.PreviewID = "reroute", "fault-run", preview.ID
	run, err := worker.StartOwnershipRun(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	job, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := f.ddl.Exec(`CREATE FUNCTION ownership_worker_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END; $$; CREATE TRIGGER ownership_worker_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION ownership_worker_audit_fail()`); err != nil {
		t.Fatal(err)
	}
	if err := worker.Handle(f.ctx, *job); err == nil {
		t.Fatal("worker ignored audit failure")
	}
	run, err = f.repo.GetRun(f.ctx, run.ID)
	if err != nil || run.Processed != 0 {
		t.Fatalf("progress escaped rollback: %+v %v", run, err)
	}
	cur, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "payment-retry")
	if cur.Assignment.Revision != 0 {
		t.Fatal("assignment escaped audit rollback")
	}
	intents, _ := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if len(intents) != 0 {
		t.Fatal("event escaped audit rollback")
	}
	if err := worker.OnDeadLetter(f.ctx, *job, errors.New("storage failure")); err != nil {
		t.Fatal(err)
	}
	if err := f.queue.Deadletter(f.ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	run, _ = f.repo.GetRun(f.ctx, run.ID)
	if run.State != "failed" {
		t.Fatalf("dead letter hidden: %+v", run)
	}
	if _, err := f.ddl.Exec(`DROP TRIGGER ownership_worker_audit_failure ON audit_log; DROP FUNCTION ownership_worker_audit_fail()`); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplayOwnershipRun(shared.WithTenant(context.Background(), "own-b"), "outsider", run.ID, run.Revision); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign replay: %v", err)
	}
	if err := store.ReplayOwnershipRun(f.ctx, "viewer", run.ID, run.Revision); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("viewer replay: %v", err)
	}
	if err := store.ReplayOwnershipRun(f.ctx, "alice", run.ID, run.Revision); err != nil {
		t.Fatal(err)
	}
	if err := worker.Handle(f.ctx, *job); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("dead worker resumed: %v", err)
	}
	ownershipDrain(t, f, worker)
	run, _ = f.repo.GetRun(f.ctx, run.ID)
	if run.State != "completed" || run.Processed != 1 {
		t.Fatalf("replay progress: %+v", run)
	}
	history, _ := f.repo.ListDecisions(f.ctx, "own-a-eng", "payment-retry", ports.OwnershipHistoryCursor{Limit: 100})
	if len(history) != 1 {
		t.Fatalf("replay transitions=%d", len(history))
	}
}

func TestOwnershipExecutionBindingAndTrustedBaseFences(t *testing.T) {
	f := newOwnershipFixture(t)
	_, worker := ownershipRuntime(t, f, "enforce")
	source := ownershipCapturedFinding(t, f, "changed-source", true)
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	job, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	// Binding can change independently of finding.version. Use the actual
	// producer binding helper to mimic an overlapping source publication.
	newSource := source
	newSource.ID = "new-source"
	newSource.Revision = "git:2222222222222222222222222222222222222222"
	newSource.BaseRequired = true
	if err := f.repo.SaveOwnershipSource(f.ctx, newSource); err != nil {
		t.Fatal(err)
	}
	bind := func(source ports.OwnershipSourceRecord) {
		t.Helper()
		if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
			return ownershipBindFinding(f.ctx, tx, "own-a", finding.Finding{ID: "changed-source", EngagementID: "own-a-eng", DedupKey: "changed-source"}, ports.OwnershipSourceBatch{Source: source, Findings: map[string]ports.OwnershipFindingSource{"changed-source": {Paths: []string{"src/pay.go"}}}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	bind(newSource)
	if err := f.repo.MarkOwnershipSourceReady(f.ctx, newSource.EngagementID, newSource.ID); err != nil {
		t.Fatal(err)
	}
	if err := worker.Handle(f.ctx, *job); err != nil {
		t.Fatal(err)
	}
	if err := f.queue.Complete(f.ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	cur, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "changed-source")
	if cur.Assignment.Revision != 0 {
		t.Fatal("stale source assigned")
	}
	// Late completion of the earlier scan cannot overwrite the newer binding.
	bind(source)
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cur, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "changed-source")
	if cur.Reason != "missing_trusted_base_snapshot" || !cur.Assignment.TeamID.IsZero() {
		t.Fatalf("PR head bypassed required base: %+v", cur)
	}
	resolver, err := ownership.NewResolver(f.policy, &f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(ownership.Input{TenantID: "own-a", EngagementID: "own-a-eng", FindingID: "test", Repository: "repo", Kind: "sast", Severity: shared.SeverityHigh, Paths: []string{"src/a.go"}, SourceRevision: source.Revision, SourceBound: true, BaseRequired: true, BaseRevision: newSource.Revision, Supported: true, Current: ownership.Assignment{Mode: "auto"}, ActiveTeams: []shared.ID{"pay"}})
	if err != nil || result.Reason != "missing_trusted_base_snapshot" {
		t.Fatalf("wrong base revision accepted: %+v %v", result, err)
	}
}

func ownershipCapturedFinding(t *testing.T, f *ownershipFixture, id string, ready bool) ports.OwnershipSourceRecord {
	t.Helper()
	source := ports.OwnershipSourceRecord{ID: shared.ID("source-" + id), EngagementID: "own-a-eng", Repository: "repo", Revision: f.snapshot.Revision, CreatedBy: "alice", CreatedAt: time.Now().UTC()}
	if err := f.repo.SaveOwnershipSource(f.ctx, source); err != nil {
		t.Fatal(err)
	}
	item := finding.Finding{ID: shared.ID(id), EngagementID: "own-a-eng", DedupKey: id, Title: "Payment vulnerability", Kind: finding.KindSAST, RuleKey: "synapse:ownership", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Audit: shared.Audit{CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}}
	ctx := ports.WithOwnershipSource(f.ctx, ports.OwnershipSourceBatch{Source: source, Findings: map[string]ports.OwnershipFindingSource{id: {Paths: []string{"services/payment/handler.go"}}}})
	if err := NewFindingRepository(f.pool).Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	if ready {
		if err := f.repo.MarkOwnershipSourceReady(f.ctx, source.EngagementID, source.ID); err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func ownershipDrain(t *testing.T, f *ownershipFixture, w *ownershipuc.Worker) {
	t.Helper()
	for i := 0; i < 100; i++ {
		job, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			return
		}
		ctx := shared.WithTenant(context.Background(), job.TenantID)
		if err := w.Handle(ctx, *job); err != nil {
			t.Fatal(err)
		}
		if err := f.queue.Complete(ctx, job.ID, job.Fence); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("ownership queue did not drain")
}

func TestOwnershipExecutionCaptureReadinessAndCrashRecovery(t *testing.T) {
	f := newOwnershipFixture(t)
	for _, table := range []string{"ownership_source_readiness", "ownership_run_requests", "ownership_work_items"} {
		requireMigrationRLS(t, f.ddl, table)
	}
	_, worker := ownershipRuntime(t, f, "enforce")
	source := ownershipCapturedFinding(t, f, "new-payment", false)
	if n, err := worker.Poll(f.ctx); err != nil || n != 0 {
		t.Fatalf("unfinished source dispatched: %d %v", n, err)
	}
	if err := f.repo.MarkOwnershipSourceReady(f.ctx, source.EngagementID, source.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := worker.Poll(f.ctx); err != nil || n != 1 {
		t.Fatalf("ready dispatch=%d %v", n, err)
	}
	job, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
	if err != nil || job == nil {
		t.Fatalf("claim: %v %v", job, err)
	}
	if err := worker.Handle(f.ctx, *job); err != nil {
		t.Fatal(err)
	}
	current, err := f.repo.GetAssignment(f.ctx, "own-a-eng", "new-payment")
	if err != nil || current.Assignment.TeamID != "pay" {
		t.Fatalf("current: %+v %v", current, err)
	}
	// Crash after committing all items but before completing the durable job.
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE jobs SET claimed_until=now()-interval '1 second' WHERE id=$1`, job.ID)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	retry, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
	if err != nil || retry == nil || retry.ID != job.ID {
		t.Fatalf("redelivery: %+v %v", retry, err)
	}
	if err := worker.Handle(f.ctx, *job); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("old fence accepted: %v", err)
	}
	if err := worker.Handle(f.ctx, *retry); err != nil {
		t.Fatal(err)
	}
	if err := f.queue.Complete(f.ctx, retry.ID, retry.Fence); err != nil {
		t.Fatal(err)
	}
	history, err := f.repo.ListDecisions(f.ctx, "own-a-eng", "new-payment", ports.OwnershipHistoryCursor{Limit: 100})
	if err != nil || len(history) != 1 {
		t.Fatalf("duplicate transition: %d %v", len(history), err)
	}
	intents, err := f.repo.ListPendingIntents(f.ctx, "notification", 100)
	if err != nil || len(intents) != 1 {
		t.Fatalf("duplicate event: %d %v", len(intents), err)
	}
	legacy, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-legacy")
	if legacy.Assignment.Mode != "manual" || legacy.FindingAssignee != "Old owner" {
		t.Fatal("legacy owner overwritten")
	}
}

func TestOwnershipExecutionPreviewRerouteAndManualRace(t *testing.T) {
	f := newOwnershipFixture(t)
	store, worker := ownershipRuntime(t, f, "enforce")
	ownershipCapturedFinding(t, f, "payment-a", true)
	ownershipCapturedFinding(t, f, "payment-b", true)
	filter, _ := json.Marshal(ports.OwnershipInboxFilter{EngagementID: "own-a-eng"})
	header, err := f.repo.GetOwnershipPolicy(f.ctx, "policy")
	if err != nil {
		t.Fatal(err)
	}
	req := ports.OwnershipRunRequest{Policy: header, Version: f.policy, Actor: "alice", Key: "preview-key", Mode: "preview", Filter: filter}
	run, err := worker.StartOwnershipRun(f.ctx, req)
	if err != nil || run.Total != 2 {
		t.Fatalf("admission: %+v %v", run, err)
	}
	replay, err := worker.StartOwnershipRun(f.ctx, req)
	if err != nil || replay.ID != run.ID {
		t.Fatalf("admission replay: %+v %v", replay, err)
	}
	changed := req
	changed.Filter = json.RawMessage(`{"engagement_id":"own-a-eng","severity":"critical"}`)
	if _, err := worker.StartOwnershipRun(f.ctx, changed); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("key reuse: %v", err)
	}
	ownershipDrain(t, f, worker)
	run, err = f.repo.GetRun(f.ctx, run.ID)
	if err != nil || run.State != "completed" || run.Processed != 2 {
		t.Fatalf("preview completion: %+v %v", run, err)
	}
	current, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "payment-a")
	if current.Assignment.Revision != 0 {
		t.Fatal("preview changed assignment")
	}
	history, _ := f.repo.ListDecisions(f.ctx, "own-a-eng", "payment-a", ports.OwnershipHistoryCursor{Limit: 100})
	if len(history) != 0 {
		t.Fatal("preview wrote audit decision")
	}
	items, err := f.repo.ListRunItems(f.ctx, run.ID, "", 100)
	if err != nil || len(items) != 2 || items[0].Result.TeamID != "pay" {
		t.Fatalf("preview results: %+v %v", items, err)
	}
	req.Mode, req.Key, req.PreviewID = "reroute", "apply-preview", run.ID
	routing, err := worker.StartOwnershipRun(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// A new finding after preview must not be silently added to reroute.
	ownershipCapturedFinding(t, f, "payment-later", true)
	// A human races the frozen selection. Their clear remains protected.
	m := ports.OwnershipMutation{EngagementID: "own-a-eng", FindingID: "payment-a", DecisionID: "manual-race", Key: "manual-race", Actor: "alice", Kind: "clear", ExpectedFindingVersion: current.FindingVersion, ExpectedRevision: current.Assignment.Revision, ExpectedManualGeneration: current.Assignment.ManualGeneration, At: time.Now().UTC()}
	if _, err := f.repo.ApplyAssignment(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	routing, _ = f.repo.GetRun(f.ctx, routing.ID)
	if routing.Total != 2 || routing.Processed != 2 || routing.State != "completed" {
		t.Fatalf("reroute counters: %+v", routing)
	}
	items, _ = f.repo.ListRunItems(f.ctx, routing.ID, "", 100)
	if items[0].Outcome != "conflict" {
		t.Fatalf("manual race not visible: %+v", items)
	}
	current, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "payment-a")
	if current.Assignment.Mode != "manual" || !current.Assignment.TeamID.IsZero() {
		t.Fatalf("manual clear lost: %+v", current)
	}
	current, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "payment-b")
	if current.Assignment.TeamID != "pay" {
		t.Fatalf("uncontended route missing: %+v", current)
	}
	current, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "payment-later")
	if current.Assignment.Revision != 0 {
		t.Fatal("reroute widened frozen selection")
	}
	// Cancellation does not depend on an in-memory worker handle.
	req.Mode, req.Key, req.PreviewID = "preview", "cancel-preview", ""
	cancelled, err := store.StartOwnershipRun(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.SetRunState(f.ctx, cancelled.ID, cancelled.Revision, "cancelled"); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cancelled, _ = f.repo.GetRun(f.ctx, cancelled.ID)
	if cancelled.Processed != 0 || cancelled.State != "cancelled" {
		t.Fatalf("cancelled run executed: %+v", cancelled)
	}
}

func TestOwnershipExecutionObserveAndPolicyFence(t *testing.T) {
	f := newOwnershipFixture(t)
	_, observer := ownershipRuntime(t, f, "observe")
	ownershipCapturedFinding(t, f, "observed", true)
	if n, err := observer.Poll(f.ctx); err != nil || n != 1 {
		t.Fatalf("observe dispatch: %d %v", n, err)
	}
	ownershipDrain(t, f, observer)
	current, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "observed")
	if current.Assignment.Revision != 0 {
		t.Fatal("observe mode assigned owner")
	}
	// Reevaluate a new source after switching to enforce; paused enforce work
	// must remain retryable, and a later policy activation must reject old input.
	_, enforcer := ownershipRuntime(t, f, "enforce")
	ownershipCapturedFinding(t, f, "enforced", true)
	if n, err := enforcer.Poll(f.ctx); err != nil || n != 1 {
		t.Fatalf("enforce dispatch: %d %v", n, err)
	}
	job, err := f.queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	if err := observer.Handle(f.ctx, *job); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("pause acknowledged job: %v", err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "policy", Version: 0, ExpectedRevision: 2}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Handle(f.ctx, *job); err != nil {
		t.Fatal(err)
	}
	current, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "enforced")
	if current.Assignment.Revision != 0 {
		t.Fatal("stale policy assigned owner")
	}
}

func TestOwnershipExecutionAssetChangesAndRelease(t *testing.T) {
	f := newOwnershipFixture(t)
	_, worker := ownershipRuntime(t, f, "enforce")
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO fleet_business_services(tenant_id,id,key,name,owner) VALUES('own-a','payment-service','payment-service','Payments','Some free text'),('own-a','operations-service','operations-service','Operations','Some free text')`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	policy := ownership.PolicyVersion{TenantID: "own-a", PolicyID: "fallback", EngagementID: "own-a-eng", Version: 1, CreatedBy: "alice", CreatedAt: time.Now().UTC(), Assets: []ownership.AssetMapping{{AssetID: "payment-service", TeamID: "pay"}, {AssetID: "operations-service", TeamID: "ops"}}}
	if err := f.repo.CreatePolicyVersion(f.ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: "fallback", Version: 1, ExpectedRevision: 1, ExpectedHash: policy.Hash()}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO findings(tenant_id,engagement_id,id,title) VALUES('own-a','own-a-eng','asset-finding','Manual or network finding')`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cur, _ := f.repo.GetAssignment(f.ctx, "own-a-eng", "asset-finding")
	if !cur.Assignment.TeamID.IsZero() || cur.Reason != "no_matching_owner" {
		t.Fatalf("guessed business owner: %+v", cur)
	}
	setAsset := func(id string) {
		t.Helper()
		if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
			_, e := tx.Exec(f.ctx, `UPDATE engagements SET business_asset_id=$1 WHERE tenant_id='own-a' AND id='own-a-eng'`, id)
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	setAsset("payment-service")
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cur, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "asset-finding")
	if cur.Assignment.TeamID != "pay" || cur.Reason != "business_asset" {
		t.Fatalf("late asset binding lost: %+v", cur)
	}
	m := ports.OwnershipMutation{EngagementID: "own-a-eng", FindingID: "asset-finding", DecisionID: "clear-asset", Key: "clear-asset", Actor: "alice", Kind: "clear", ExpectedFindingVersion: cur.FindingVersion, ExpectedRevision: cur.Assignment.Revision, ExpectedManualGeneration: cur.Assignment.ManualGeneration, At: time.Now().UTC()}
	if _, err := f.repo.ApplyAssignment(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	setAsset("operations-service")
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cur, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "asset-finding")
	if !cur.Assignment.TeamID.IsZero() || cur.Assignment.Mode != "manual" {
		t.Fatal("asset change overwrote manual protection")
	}
	m.Kind, m.Key, m.DecisionID = "release", "release-asset", "release-asset"
	m.ExpectedFindingVersion, m.ExpectedRevision, m.ExpectedManualGeneration = cur.FindingVersion, cur.Assignment.Revision, cur.Assignment.ManualGeneration
	if _, err := f.repo.ApplyAssignment(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Poll(f.ctx); err != nil {
		t.Fatal(err)
	}
	ownershipDrain(t, f, worker)
	cur, _ = f.repo.GetAssignment(f.ctx, "own-a-eng", "asset-finding")
	if cur.Assignment.TeamID != "ops" || cur.Assignment.Mode != "auto" {
		t.Fatalf("release obligation lost: %+v", cur)
	}
}
