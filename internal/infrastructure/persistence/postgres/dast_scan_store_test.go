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
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestDASTScanPostgresFenceAndGrant(t *testing.T) {
	f := newTenantRLSFixtureWithDSN(t, isolatedMigrationDSN(t, testDSN(t), "dast_scan"))
	suffix := randHex(t)
	tenant, eng, action := shared.ID("scan-t-"+suffix), shared.ID("scan-e-"+suffix), shared.ID("scan-a-"+suffix)
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'scan')`, eng, tenant); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), tenant)
	store := NewDASTRunStore(f.runtime)
	execSQL := func(q string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(`INSERT INTO agent_approvals (action_id,tenant_id,session_id,engagement_id,tool,action,argv,egress_preview,risk,proposed_at,decision_state,decided_by,decided_at) VALUES ($1,$2,'session',$3,'scan','scan','[]','[]','intrusive',now(),'approved','reviewer',now())`, action, tenant, eng)
	run, err := dastrun.NewScanRun(shared.ID("scan-r-"+suffix), tenant, eng, action, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := json.RawMessage(`{"target":"https://example.invalid"}`)
	job := ports.DASTScanJob{TenantID: tenant, RunID: run.ID, Config: config, ConfigSHA256: fmt.Sprintf("%x", sha256.Sum256(config)), HelperPath: "/opt/helper", HelperSHA256: strings.Repeat("a", 64)}
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnqueueDASTRun(ctx, run, "dast_run", payload); err == nil {
		t.Fatal("accepted verifier job for scan")
	}
	if err = store.EnqueueDASTRun(ctx, run, "dast_scan", payload); err != nil {
		t.Fatal(err)
	}
	execution := ports.DASTScanExecution{TenantID: tenant, RunID: run.ID, JobID: run.ID.String() + "-job", Fence: 1}
	execSQL(`UPDATE jobs SET status='claimed',claim_fence=1,claimed_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
	wrong := job
	wrong.HelperPath = "/wrong"
	if _, err = store.StartDASTScan(ctx, execution, wrong); err == nil {
		t.Fatal("accepted substituted payload")
	}
	stale := execution
	stale.Fence++
	if _, err = store.StartDASTScan(ctx, stale, job); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("wrong fence: %v", err)
	}
	if _, err = store.StartDASTScan(shared.WithTenant(context.Background(), shared.ID("foreign")), execution, job); err == nil {
		t.Fatal("accepted foreign tenant")
	}
	execSQL(`UPDATE jobs SET claimed_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
	if _, err = store.StartDASTScan(ctx, execution, job); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("expired claim: %v", err)
	}
	execSQL(`UPDATE jobs SET claimed_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
	if won, err := store.StartDASTScan(ctx, execution, job); err != nil || !won {
		t.Fatalf("start: %v %v", won, err)
	}
	execSQL(`UPDATE jobs SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID, []byte(`{}`))
	if err = store.WithDASTScanOwner(ctx, execution, func(context.Context) error { return nil }); err == nil {
		t.Fatal("accepted changed persisted payload")
	}
	execSQL(`UPDATE jobs SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID, payload)
	if _, err = store.GetDASTRunAuthorization(ctx, tenant, run.ID); err == nil {
		t.Fatal("scan accepted by verifier authority")
	}
	stored, err := store.GetDASTRun(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	substituted := stored
	substituted.Actor = "other"
	if err = substituted.CompleteScan("sealed", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = store.FinishDASTScan(ctx, execution, substituted); err == nil {
		t.Fatal("accepted substituted run identity")
	}
	// Expire the claim in the same transaction as a custody mutation; both must roll back.
	err = store.WithDASTScanOwner(ctx, execution, func(c context.Context) error {
		tx := c.Value(tenantTransactionKey{}).(tenantTransaction).tx
		if _, err := tx.Exec(c, `UPDATE agent_approvals SET decided_by='must-rollback' WHERE tenant_id=$1 AND action_id=$2`, tenant, action); err != nil {
			return err
		}
		_, err := tx.Exec(c, `UPDATE jobs SET claimed_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
		return err
	})
	if !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("expired callback: %v", err)
	}
	if err = WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		var actor string
		if err := tx.QueryRow(ctx, `SELECT decided_by FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2`, tenant, action).Scan(&actor); err != nil {
			return err
		}
		if actor != "reviewer" {
			return fmt.Errorf("custody mutation committed: %s", actor)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	execSQL(`UPDATE agent_approvals SET decision_state='consumed',consumed_by_dast_run_id=$3 WHERE tenant_id=$1 AND action_id=$2`, tenant, action, run.ID)
	admission := evidence.Evidence{ID: shared.ID("scan-admission-" + suffix), EngagementID: eng, Kind: "admission", Content: []byte(`{}`), CreatedAt: time.Now(), CreatedBy: "operator"}.Seal()
	content, _ := json.Marshal(ports.DASTApprovalConsumption{TenantID: tenant, EngagementID: eng, RunID: run.ID, ActionID: action, Actor: "operator", AdmissionID: admission.ID})
	consumption := evidence.Evidence{ID: ports.DASTConsumptionEvidenceID(run.ID), EngagementID: eng, Kind: "agent_approval_consumed", Content: content, CreatedAt: time.Now(), CreatedBy: "operator", PreviousHash: admission.Hash}.Seal()
	if err = NewEvidenceStore(f.runtime).Append(ctx, []evidence.Evidence{admission, consumption}); err != nil {
		t.Fatal(err)
	}
	authority, err := store.GetDASTScanAuthorization(ctx, execution)
	if err != nil {
		t.Fatal(err)
	}
	err = store.ClaimDASTScanGrant(ctx, authority, time.Now(), func(c context.Context) error {
		tx := c.Value(tenantTransactionKey{}).(tenantTransaction).tx
		if _, err := tx.Exec(c, `UPDATE agent_approvals SET decided_by='rollback-claim' WHERE tenant_id=$1 AND action_id=$2`, tenant, action); err != nil {
			return err
		}
		_, err := tx.Exec(c, `UPDATE jobs SET claimed_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
		return err
	})
	if !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("expired grant callback: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- store.ClaimDASTScanGrant(ctx, authority, time.Now(), func(context.Context) error { return nil })
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("grant wins: %d", wins)
	}
	if err = store.ClaimDASTScanGrant(ctx, authority, time.Now(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("grant replay succeeded")
	}
	// A later queue owner can only interrupt; it cannot adopt the original execution.
	execSQL(`UPDATE jobs SET claim_fence=2,claimed_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, execution.JobID)
	next := execution
	next.Fence = 2
	if err = store.WithDASTScanOwner(ctx, execution, func(context.Context) error { return nil }); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale owner: %v", err)
	}
	if won, err := store.InterruptDASTScan(ctx, next, time.Now()); err != nil || !won {
		t.Fatalf("interrupt: %v %v", won, err)
	}
	got, err := store.GetDASTRun(ctx, tenant, run.ID)
	if err != nil || got.Status != dastrun.RunFailed || got.ErrorCode != "interrupted" {
		t.Fatalf("interrupted run: %+v %v", got, err)
	}
	if won, err := store.InterruptDASTScan(ctx, next, time.Now()); err != nil || won {
		t.Fatalf("terminal changed: %v %v", won, err)
	}
}

func TestDASTScanApprovalSingleOwnerPostgres(t *testing.T) {
	f := newTenantRLSFixtureWithDSN(t, isolatedMigrationDSN(t, testDSN(t), "dast_scan"))
	suffix := randHex(t)
	tenant, eng, action := shared.ID("scan-owner-t-"+suffix), shared.ID("scan-owner-e-"+suffix), shared.ID("scan-owner-a-"+suffix)
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'scan')`, eng, tenant); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), tenant)
	execSQL := func(q string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(`INSERT INTO agent_approvals (action_id,tenant_id,session_id,engagement_id,tool,action,argv,egress_preview,risk,proposed_at,decision_state,decided_by,decided_at) VALUES ($1,$2,'session',$3,'scan','scan','[]','[]','intrusive',now(),'approved','reviewer',now())`, action, tenant, eng)
	store := NewDASTRunStore(f.runtime)
	approvals := NewApprovalStore(f.runtime)
	claims := make([]ports.DASTScanExecution, 2)
	for i := range claims {
		run, err := dastrun.NewScanRun(shared.ID(fmt.Sprintf("scan-owner-r-%s-%d", suffix, i)), tenant, eng, action, "operator", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		config := json.RawMessage(`{}`)
		job := ports.DASTScanJob{TenantID: tenant, RunID: run.ID, Config: config, ConfigSHA256: fmt.Sprintf("%x", sha256.Sum256(config)), HelperPath: "/opt/helper", HelperSHA256: strings.Repeat("a", 64)}
		payload, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.EnqueueDASTRun(ctx, run, "dast_scan", payload); err != nil {
			t.Fatal(err)
		}
		claims[i] = ports.DASTScanExecution{TenantID: tenant, RunID: run.ID, JobID: run.ID.String() + "-job", Fence: 1}
		execSQL(`UPDATE jobs SET status='claimed',claim_fence=1,claimed_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, claims[i].JobID)
		if won, err := store.StartDASTScan(ctx, claims[i], job); err != nil || !won {
			t.Fatalf("start: %v %v", won, err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, claim := range claims {
		wg.Add(1)
		go func(e ports.DASTScanExecution) {
			defer wg.Done()
			<-start
			results <- store.WithDASTScanOwner(ctx, e, func(c context.Context) error { return approvals.ConsumeForDASTRun(c, action, e.RunID) })
		}(claim)
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("consume: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("approval owners: %d", wins)
	}
	e := claims[0]
	stored, err := store.GetDASTRun(ctx, tenant, e.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err = stored.CompleteScan("sealed-result", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if won, err := store.FinishDASTScan(ctx, e, stored); err != nil || !won {
		t.Fatalf("incomplete completion: %v %v", won, err)
	}
	if _, err = store.FinishDASTScan(ctx, e, stored); err == nil {
		t.Fatal("terminal scan accepted second finish")
	}
	after, err := store.GetDASTRun(ctx, tenant, e.RunID)
	if err != nil || after.Status != dastrun.RunIncomplete || after.EvidenceID != "sealed-result" {
		t.Fatalf("incomplete not frozen: %+v %v", after, err)
	}
	queued, err := dastrun.NewScanRun(shared.ID("deadletter-"+suffix), tenant, eng, action, "operator", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	config := json.RawMessage(`{}`)
	job := ports.DASTScanJob{TenantID: tenant, RunID: queued.ID, Config: config, ConfigSHA256: fmt.Sprintf("%x", sha256.Sum256(config)), HelperPath: "/opt/helper", HelperSHA256: strings.Repeat("a", 64)}
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnqueueDASTRun(ctx, queued, "dast_scan", payload); err != nil {
		t.Fatal(err)
	}
	dead := ports.QueuedJob{TenantID: tenant, ID: queued.ID.String() + "-job", Kind: "dast_scan", Fence: 2, Payload: []byte(`not-json`)}
	execSQL(`UPDATE jobs SET status='failed',claim_fence=2,claimed_until=NULL,payload=$3 WHERE tenant_id=$1 AND id=$2`, tenant, dead.ID, dead.Payload)
	stale := dead
	stale.Fence = 1
	if won, err := store.FailDeadLetteredDASTScan(ctx, stale, "invalid_job", time.Now()); err != nil || won {
		t.Fatalf("stale deadletter: %v %v", won, err)
	}
	if won, err := store.FailDeadLetteredDASTScan(ctx, dead, "invalid_job", time.Now()); err != nil || !won {
		t.Fatalf("deadletter: %v %v", won, err)
	}
	if won, err := store.FailDeadLetteredDASTScan(ctx, dead, "other", time.Now()); err != nil || won {
		t.Fatalf("terminal deadletter: %v %v", won, err)
	}
	after, err = store.GetDASTRun(ctx, tenant, queued.ID)
	if err != nil || after.Status != dastrun.RunFailed || after.ErrorCode != "invalid_job" {
		t.Fatalf("deadletter result: %+v %v", after, err)
	}
}
