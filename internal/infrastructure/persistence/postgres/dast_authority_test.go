package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestDASTAuthorityPostgres(t *testing.T) {
	f := newRLS817Fixture(t)
	suffix := randHex(t)
	tenant := shared.ID("dast-authority-" + suffix)
	engagementID := shared.ID("dast-eng-" + suffix)
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'DAST')`, engagementID, tenant); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), tenant)
	runs := []shared.ID{shared.ID("authority-run-a-" + suffix), shared.ID("authority-run-b-" + suffix)}
	action := shared.ID("authority-action-" + suffix)
	store := NewDASTRunStore(f.runtime)
	approvals := NewApprovalStore(f.runtime)
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_approvals (action_id,tenant_id,session_id,engagement_id,tool,action,argv,egress_preview,risk,proposed_at,decision_state,decided_by,decided_at) VALUES ($1,$2,'session',$3,'run_dast_verifier','dast.safe_http_probe','[]','[]','intrusive',now(),'approved','reviewer',now())`, action, tenant, engagementID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range runs {
		run := dastrun.Run{ID: id, TenantID: tenant, EngagementID: engagementID, ActionID: action, Actor: "operator", Status: dastrun.RunQueued, StartedAt: time.Now()}
		payload, err := json.Marshal(ports.DASTRunJob{TenantID: tenant, RunID: id})
		if err != nil {
			t.Fatal(err)
		}
		if err = store.EnqueueDASTRun(ctx, run, "dast_run", payload); err != nil {
			t.Fatal(err)
		}
		run.Status = dastrun.RunRunning
		if won, err := store.StartRun(ctx, tenant, run); err != nil || !won {
			t.Fatalf("start: %v %v", won, err)
		}
	}
	// A failed custody transaction must not consume the approval.
	rollback := errors.New("rollback")
	err := NewTenantTransactionRunner(f.runtime).Run(ctx, tenant, func(txCtx context.Context) error {
		if err := approvals.ConsumeForDASTRun(txCtx, action, runs[0]); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("rollback: %v", err)
	}
	foreign := shared.WithTenant(context.Background(), rls817TenantB)
	if err := NewTenantTransactionRunner(f.runtime).Run(foreign, rls817TenantB, func(txCtx context.Context) error { return approvals.ConsumeForDASTRun(txCtx, action, runs[0]) }); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign consume: %v", err)
	}
	start := make(chan struct{})
	results := make(chan struct {
		id  shared.ID
		err error
	}, 2)
	var wg sync.WaitGroup
	for _, id := range runs {
		wg.Add(1)
		go func(id shared.ID) {
			defer wg.Done()
			<-start
			results <- struct {
				id  shared.ID
				err error
			}{id, NewTenantTransactionRunner(f.runtime).Run(ctx, tenant, func(txCtx context.Context) error { return approvals.ConsumeForDASTRun(txCtx, action, id) })}
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner shared.ID
	successes := 0
	for r := range results {
		if r.err == nil {
			winner = r.id
			successes++
		} else if !errors.Is(r.err, shared.ErrConflict) {
			t.Fatalf("competing consume: %v", r.err)
		}
	}
	if successes != 1 {
		t.Fatalf("consume successes: %d", successes)
	}
	admission := evidence.Evidence{ID: shared.ID("authority-admission-" + suffix), EngagementID: engagementID, Kind: "admission", Content: []byte(`{}`), CreatedAt: time.Now(), CreatedBy: "operator"}.Seal()
	content, _ := json.Marshal(ports.DASTApprovalConsumption{TenantID: tenant, EngagementID: engagementID, RunID: winner, ActionID: action, Actor: "operator", AdmissionID: admission.ID})
	consumption := evidence.Evidence{ID: ports.DASTConsumptionEvidenceID(winner), EngagementID: engagementID, Kind: "agent_approval_consumed", Content: content, CreatedAt: time.Now(), CreatedBy: "operator", PreviousHash: admission.Hash}.Seal()
	if err := NewEvidenceStore(f.runtime).Append(ctx, []evidence.Evidence{admission, consumption}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ctx   context.Context
		eng   shared.ID
		found bool
	}{{ctx, engagementID, true}, {foreign, engagementID, false}, {ctx, "different-engagement", false}} {
		got, found, err := NewEvidenceStore(f.runtime).LookupSealedByID(test.ctx, test.eng, consumption.ID)
		if err != nil || found != test.found || (found && (got.Hash != consumption.Hash || string(got.Content) != string(consumption.Content))) {
			t.Fatalf("indexed evidence lookup: found=%v want=%v err=%v", found, test.found, err)
		}
	}
	auth, err := store.GetDASTRunAuthorization(ctx, tenant, winner)
	if err != nil {
		t.Fatal(err)
	}
	if auth.ConsumedBy != winner || auth.GrantIssued {
		t.Fatal("wrong owner or grant marker")
	}
	if _, err := store.GetDASTRunAuthorization(foreign, tenant, winner); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("foreign read: %v", err)
	}
	// A legacy consumed approval without an owner and a terminal run cannot issue.
	mutate := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	mutate(`UPDATE agent_approvals SET consumed_by_dast_run_id=NULL WHERE tenant_id=$1 AND action_id=$2`, tenant, action)
	if err := store.ClaimDASTRunGrant(ctx, auth, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("legacy owner: %v", err)
	}
	mutate(`UPDATE agent_approvals SET consumed_by_dast_run_id=$3 WHERE tenant_id=$1 AND action_id=$2`, tenant, action, winner)
	mutate(`UPDATE dast_runs SET status='failed', finished_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, winner)
	if err := store.ClaimDASTRunGrant(ctx, auth, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("terminal run: %v", err)
	}
	mutate(`UPDATE dast_runs SET status='running', finished_at=NULL WHERE tenant_id=$1 AND id=$2`, tenant, winner)
	mutate(`UPDATE jobs SET kind='wrong' WHERE tenant_id=$1 AND id=$2`, tenant, winner.String()+"-job")
	if err := store.ClaimDASTRunGrant(ctx, auth, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("changed job: %v", err)
	}
	mutate(`UPDATE jobs SET kind='dast_run' WHERE tenant_id=$1 AND id=$2`, tenant, winner.String()+"-job")
	changed := auth
	changed.Run.Actor = "different"
	if err := store.ClaimDASTRunGrant(ctx, changed, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("changed authority: %v", err)
	}
	// Concurrent claims issue exactly once, even when the winner's caller
	// subsequently rolls back an unrelated ambient transaction.
	var claimErrors [2]error
	err = NewTenantTransactionRunner(f.runtime).Run(ctx, tenant, func(txCtx context.Context) error {
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, claimCtx := range []context.Context{txCtx, ctx} {
			wg.Add(1)
			go func(i int, claimCtx context.Context) {
				defer wg.Done()
				<-start
				claimErrors[i] = store.ClaimDASTRunGrant(claimCtx, auth, time.Now())
			}(i, claimCtx)
		}
		close(start)
		wg.Wait()
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("ambient rollback: %v", err)
	}
	claimSuccess := 0
	for _, claimErr := range claimErrors {
		if claimErr == nil {
			claimSuccess++
		} else if !errors.Is(claimErr, shared.ErrForbidden) {
			t.Fatalf("competing claim: %v", claimErr)
		}
	}
	if claimSuccess != 1 {
		t.Fatalf("grant claim successes: %d", claimSuccess)
	}
	if err := store.ClaimDASTRunGrant(ctx, auth, time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("grant replay: %v", err)
	}

	got, err := store.GetDASTRunAuthorization(ctx, tenant, winner)
	if err != nil || !got.GrantIssued {
		t.Fatalf("committed marker: %v", err)
	}
}
