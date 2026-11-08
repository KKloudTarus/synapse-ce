package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestDASTDeadLetterRecoveryPostgres(t *testing.T) {
	f := newTenantRLSFixtureWithDSN(t, isolatedMigrationDSN(t, testDSN(t), "dast_recovery"))
	suffix := randHex(t)
	root := context.Background()
	tenant := shared.ID("recovery-t-" + suffix)
	other := shared.ID("recovery-other-" + suffix)
	eng := shared.ID("recovery-e-" + suffix)
	for _, id := range []shared.ID{tenant, other} {
		if _, err := f.owner.Exec(root, `INSERT INTO tenants(id,name) VALUES($1,$1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.owner.Exec(root, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'scan')`, eng, tenant); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(root, tenant)
	store := NewDASTRunStore(f.runtime)
	queue := NewJobQueue(f.runtime, nil)
	eventRepo := NewNotificationRepository(f.runtime)
	eventRepo.SetEventProjector(notificationuc.NewEventBuilders())
	if _, err := NewNotificationSource(f.runtime, eventRepo, time.Minute).Poll(ctx, time.Now().UTC(), 100); err != nil {
		t.Fatal(err)
	}
	execSQL := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	makeScan := func(name string, approval bool) (dastrun.Run, ports.DASTScanJob, ports.QueuedJob) {
		t.Helper()
		action := shared.ID(name + "-action-" + suffix)
		if approval {
			execSQL(`INSERT INTO agent_approvals (action_id,tenant_id,session_id,engagement_id,tool,action,argv,egress_preview,risk,proposed_at,decision_state,decided_by,decided_at) VALUES ($1,$2,'session',$3,'scan','scan','[]','[]','intrusive',now(),'approved','reviewer',now())`, action, tenant, eng)
		}
		run, err := dastrun.NewScanRun(shared.ID(name+"-run-"+suffix), tenant, eng, action, "operator", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		config := json.RawMessage(`{}`)
		job := ports.DASTScanJob{TenantID: tenant, RunID: run.ID, Config: config, ConfigSHA256: fmt.Sprintf("%x", sha256.Sum256(config)), HelperPath: "/opt/helper", HelperSHA256: strings.Repeat("a", 64)}
		payload, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnqueueDASTRun(ctx, run, "dast_scan", payload); err != nil {
			t.Fatal(err)
		}
		claim, err := queue.Claim(root, time.Hour, "dast_scan")
		if err != nil || claim == nil || claim.ID != run.ID.String()+"-job" {
			t.Fatalf("claim %s: %+v %v", name, claim, err)
		}
		return run, job, *claim
	}
	status := func(run dastrun.Run, want dastrun.RunStatus) {
		t.Helper()
		got, err := store.GetDASTRun(ctx, tenant, run.ID)
		if err != nil || got.Status != want {
			t.Fatalf("run %s: %+v %v", run.ID, got, err)
		}
	}
	countSources := func(run dastrun.Run) int {
		t.Helper()
		var n int
		if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='dast_run' AND source_id=$2`, tenant, run.ID).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	missing, payload, claim := makeScan("missing", false)
	execution := ports.DASTScanExecution{TenantID: tenant, RunID: missing.ID, JobID: claim.ID, Fence: claim.Fence}
	if won, err := store.StartDASTScan(ctx, execution, payload); won || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("missing approval start: %v %v", won, err)
	}
	if won, err := store.FailDeadLetteredDASTScan(ctx, claim, "queue_failed", time.Now()); err != nil || won {
		t.Fatalf("live job finalized: %v %v", won, err)
	}
	if err := queue.Deadletter(ctx, claim.ID, claim.Fence); err != nil {
		t.Fatal(err)
	}
	stale := claim
	stale.Fence++
	if won, err := store.FailDeadLetteredDASTScan(ctx, stale, "queue_failed", time.Now()); err != nil || won {
		t.Fatalf("stale fence: %v %v", won, err)
	}
	if _, err := store.FailDeadLetteredDASTScan(shared.WithTenant(root, other), claim, "queue_failed", time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("foreign tenant: %v", err)
	}
	forged := claim
	forged.TenantID = other
	if won, err := store.FailDeadLetteredDASTScan(shared.WithTenant(root, other), forged, "queue_failed", time.Now()); err != nil || won {
		t.Fatalf("foreign job identity: %v %v", won, err)
	}
	if won, err := store.FailDeadLetteredDASTScan(ctx, claim, "queue_failed", time.Now()); err != nil || !won {
		t.Fatalf("missing approval cleanup: %v %v", won, err)
	}
	if won, err := store.FailDeadLetteredDASTScan(ctx, claim, "queue_failed", time.Now()); err != nil || won {
		t.Fatalf("repeat cleanup: %v %v", won, err)
	}
	status(missing, dastrun.RunFailed)
	if n := countSources(missing); n != 1 {
		t.Fatalf("missing approval notifications: %d", n)
	}

	omitted, _, omittedClaim := makeScan("omitted", true)
	if err := queue.Deadletter(ctx, omittedClaim.ID, omittedClaim.Fence); err != nil {
		t.Fatal(err)
	}
	failed, failedPayload, failedClaim := makeScan("failed", true)
	failedExecution := ports.DASTScanExecution{TenantID: tenant, RunID: failed.ID, JobID: failedClaim.ID, Fence: failedClaim.Fence}
	if won, err := store.StartDASTScan(ctx, failedExecution, failedPayload); err != nil || !won {
		t.Fatalf("start approved scan: %v %v", won, err)
	}
	execSQL(`UPDATE agent_approvals SET decision_state='consumed',consumed_by_dast_run_id=$3 WHERE tenant_id=$1 AND action_id=$2`, tenant, failed.ActionID, failed.ID)
	execSQL(`UPDATE dast_runs SET egress_grant_issued_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, failed.ID)
	if err := queue.Deadletter(ctx, failedClaim.ID, failedClaim.Fence); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.FailDeadLetteredDASTScan(cancelled, failedClaim, "queue_failed", time.Now()); err == nil {
		t.Fatal("cancelled callback unexpectedly succeeded")
	}
	status(omitted, dastrun.RunQueued)
	status(failed, dastrun.RunRunning)
	if next, err := NewJobQueue(f.runtime, nil).Claim(root, time.Hour, "dast_scan"); err != nil || next != nil {
		t.Fatalf("failed jobs claimable: %+v %v", next, err)
	}

	for _, terminal := range []dastrun.RunStatus{dastrun.RunSucceeded, dastrun.RunIncomplete} {
		run, _, job := makeScan(string(terminal), true)
		execSQL(`UPDATE dast_runs SET status=$3,evidence_id='sealed',finished_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, run.ID, string(terminal))
		if err := queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
			t.Fatal(err)
		}
		if won, err := store.FailDeadLetteredDASTScan(ctx, job, "queue_failed", time.Now()); err != nil || won {
			t.Fatalf("terminal overwritten: %v %v", won, err)
		}
		defer status(run, terminal)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewDASTRunStore(f.runtime).RecoverDeadLetteredDASTScans(root, time.Now())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n, err := store.RecoverDeadLetteredDASTScans(root, time.Now()); err != nil || n != 0 {
		t.Fatalf("repeat sweep: %d %v", n, err)
	}
	if _, err := store.RecoverDeadLetteredDASTScans(ctx, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("bound global sweep: %v", err)
	}
	for _, run := range []dastrun.Run{omitted, failed} {
		status(run, dastrun.RunFailed)
		if n := countSources(run); n != 1 {
			t.Fatalf("notifications for %s: %d", run.ID, n)
		}
	}
	for _, run := range []dastrun.Run{missing, omitted, failed} {
		got, err := store.GetDASTRun(ctx, tenant, run.ID)
		if err != nil || got.EvidenceID != "" || got.ErrorCode != "queue_failed" {
			t.Fatalf("cleanup result for %s: %+v %v", run.ID, got, err)
		}
	}
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		var issued, consumed, evidenceCount int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM dast_runs WHERE tenant_id=$1 AND id=ANY($2) AND egress_grant_issued_at IS NOT NULL`, tenant, []string{missing.ID.String(), omitted.ID.String()}).Scan(&issued); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2 AND (consumed_by_dast_run_id IS NOT NULL OR decision_state<>'approved')`, tenant, omitted.ActionID).Scan(&consumed); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM evidence WHERE tenant_id=$1`, tenant).Scan(&evidenceCount); err != nil {
			return err
		}
		if evidenceCount != 0 {
			return fmt.Errorf("cleanup created %d evidence records", evidenceCount)
		}
		if issued != 0 || consumed != 0 {
			return fmt.Errorf("cleanup issued %d grants or consumed %d approvals", issued, consumed)
		}
		var preserved bool
		if err := tx.QueryRow(ctx, `SELECT r.scan_fence=$3 AND r.egress_grant_issued_at IS NOT NULL AND a.decision_state='consumed' AND a.consumed_by_dast_run_id=r.id FROM dast_runs r JOIN agent_approvals a ON a.tenant_id=r.tenant_id AND a.action_id=r.action_id WHERE r.tenant_id=$1 AND r.id=$2`, tenant, failed.ID, failedClaim.Fence).Scan(&preserved); err != nil {
			return err
		}
		if !preserved {
			return errors.New("cleanup changed previous scan authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
