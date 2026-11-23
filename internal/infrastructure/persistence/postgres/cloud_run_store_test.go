package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestCloudRunJobAuthorityPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("cloud-auth")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),('cloud-other','other')`, tenant); err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("cloud-auth-eng", "", "Cloud", "", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	if err = NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	run := cloudposture.Run{ID: "cloud-auth-run", TenantID: tenant, EngagementID: eng.ID, Actor: "operator", Status: cloudposture.RunQueued, StartedAt: time.Unix(1, 0)}
	job := ports.CloudRunJob{TenantID: tenant, RunID: run.ID, EngagementID: eng.ID, Actor: run.Actor, Scopes: []ports.CloudScope{{EngagementID: eng.ID, Provider: cloudposture.ProviderAzure, Root: "subscriptions/example", CredentialRef: "vault-reference"}}, ApprovedTargets: []string{"example"}}
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCloudRunStore(pool)
	if err = store.EnqueueCloudRun(ctx, run, "cspm", payload); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetCloudRunJob(ctx, "cloud-other", run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	got, err := store.GetCloudRunJob(ctx, tenant, run.ID)
	if err != nil || got.Scopes[0].CredentialRef != job.Scopes[0].CredentialRef {
		t.Fatalf("read job: %v", err)
	}
	projection, err := store.GetCloudRunAuthorization(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(projection)
	if strings.Contains(string(raw), "vault-reference") || !projection.Scopes[0].CredentialBound {
		t.Fatal("projection exposed reference or lost binding")
	}
	finished := time.Unix(2, 123456789)
	terminal := run
	terminal.Status, terminal.FinishedAt = cloudposture.RunCancelled, &finished
	running := run
	running.Status = cloudposture.RunRunning
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _ = store.SaveCloudRun(ctx, running) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if err := store.SaveCloudRun(ctx, terminal); err != nil {
			t.Errorf("cancel: %v", err)
		}
	}()
	close(start)
	wg.Wait()
	current, err := store.GetCloudRun(ctx, tenant, run.ID)
	if err != nil || current.Status != cloudposture.RunCancelled {
		t.Fatalf("terminal state lost: %v %v", current.Status, err)
	}
	if err := store.SaveCloudRun(ctx, running); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late save accepted: %v", err)
	}
	completed := terminal
	completed.Status, completed.Complete = cloudposture.RunSucceeded, true
	if err := store.SaveCloudRun(ctx, completed); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late completion accepted: %v", err)
	}
	if err := store.SaveCloudRun(ctx, terminal); err != nil {
		t.Fatalf("idempotent retry rejected: %v", err)
	}
	terminal.CoverageIssues = []cloudposture.CoverageIssue{}
	terminal.EvidenceRefs = []cloudposture.EvidenceReference{}
	if err := store.SaveCloudRun(ctx, terminal); err != nil {
		t.Fatalf("equivalent empty slices retry rejected: %v", err)
	}
	modified := terminal
	modified.Findings++
	if err := store.SaveCloudRun(ctx, modified); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("modified terminal accepted: %v", err)
	}

	competingRun := run
	competingRun.ID = "cloud-competing-run"
	competingJob := job
	competingJob.RunID = competingRun.ID
	competingPayload, err := json.Marshal(competingJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueCloudRun(ctx, competingRun, "cspm", competingPayload); err != nil {
		t.Fatal(err)
	}
	cancelled := competingRun
	cancelled.Status, cancelled.FinishedAt = cloudposture.RunCancelled, &finished
	succeeded := cancelled
	succeeded.Status, succeeded.Complete = cloudposture.RunSucceeded, true
	competingStart := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-competingStart; results <- store.SaveCloudRun(ctx, cancelled) }()
	go func() { <-competingStart; results <- store.SaveCloudRun(ctx, succeeded) }()
	close(competingStart)
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, shared.ErrForbidden)) || (b == nil && errors.Is(a, shared.ErrForbidden))) {
		t.Fatalf("competing outcomes: %v %v", a, b)
	}
	correctedRun := run
	correctedRun.ID = "cloud-corrected-run"
	correctedJob := job
	correctedJob.RunID = correctedRun.ID
	correctedPayload, err := json.Marshal(correctedJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueCloudRun(ctx, correctedRun, "cspm", correctedPayload); err != nil {
		t.Fatal(err)
	}
	correctedRun.Status, correctedRun.FinishedAt, correctedRun.ErrorCode = cloudposture.RunFailed, &finished, "failed"
	if err := store.SaveCloudRun(ctx, correctedRun); err != nil {
		t.Fatal(err)
	}
	correctedRun.Status, correctedRun.ErrorCode, correctedRun.Complete = cloudposture.RunSucceeded, "", true
	if err := store.SaveCloudRun(ctx, correctedRun); err != nil {
		t.Fatalf("correction rejected: %v", err)
	}
	gotCorrection, err := store.GetCloudRun(ctx, tenant, correctedRun.ID)
	if err != nil || gotCorrection.Status != cloudposture.RunSucceeded || !gotCorrection.Complete {
		t.Fatalf("correction missing: %v %v", gotCorrection.Status, err)
	}
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE jobs SET kind='other' WHERE tenant_id=$1 AND id=$2`, tenant, run.ID.String()+"-job")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetCloudRunAuthorization(ctx, tenant, run.ID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong kind accepted: %v", err)
	}
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, run.ID.String()+"-job")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetCloudRunJob(ctx, tenant, run.ID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("missing job accepted: %v", err)
	}
}
