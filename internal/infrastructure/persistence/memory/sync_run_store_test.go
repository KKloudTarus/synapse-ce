package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysync"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSyncRunReadMetadataDateAndTenantIsolation(t *testing.T) {
	clock := &movableClock{t: time.Date(2026, 8, 12, 23, 0, 0, 0, time.UTC)}
	queue := NewJobQueue(&seqIDs{}, clock.now)
	store := NewSyncRunStore(&seqIDs{}, clock.now, queue)
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	ctxB := shared.WithTenant(context.Background(), "tenant-b")

	start := func(ctx context.Context, source, actor string) vulnerabilitysync.Run {
		run, created, err := store.Start(ctx, ports.SyncRunStart{SourceID: shared.ID(source), AdapterType: "osv", Mode: vulnerabilitysync.ModeIncremental, Trigger: "manual", Actor: actor, JobKind: "vulnerability_sync", JobPayload: []byte(`{}`)})
		if err != nil || !created {
			t.Fatalf("start run=%+v created=%v err=%v", run, created, err)
		}
		return run
	}

	before := start(ctxA, "source-before", "analyst-a")
	clock.t = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	inRange := start(ctxA, "source-in-range", "analyst-a")
	_ = start(ctxB, "source-tenant-b", "analyst-b")

	claimed, err := queue.Claim(ctxA, time.Minute, "vulnerability_sync")
	if err != nil || claimed == nil || claimed.ID != before.DurableJobID {
		t.Fatalf("first claim=%+v err=%v", claimed, err)
	}
	if err := queue.Complete(ctxA, claimed.ID, claimed.Fence); err != nil {
		t.Fatal(err)
	}
	claimed, err = queue.Claim(ctxA, time.Minute, "vulnerability_sync")
	if err != nil || claimed == nil || claimed.ID != inRange.DurableJobID {
		t.Fatalf("second claim=%+v err=%v", claimed, err)
	}
	if err := queue.Fail(ctxA, claimed.ID, claimed.Fence, 0); err != nil {
		t.Fatal(err)
	}
	claimed, err = queue.Claim(ctxA, time.Minute, "vulnerability_sync")
	if err != nil || claimed == nil || claimed.Attempts != 2 {
		t.Fatalf("retry claim=%+v err=%v", claimed, err)
	}
	if err := queue.Deadletter(ctxA, claimed.ID, claimed.Fence); err != nil {
		t.Fatal(err)
	}

	page, err := store.ListVulnerabilitySyncRuns(ctxA, vulnerabilityintel.SyncRunQuery{
		TenantID: "tenant-a", CreatedAtFrom: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC), CreatedAtBefore: time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC), Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Run.ID != inRange.ID || page.Items[0].Run.Actor != "analyst-a" || page.Items[0].Attempts != 2 || !page.Items[0].DeadLettered {
		t.Fatalf("page=%+v", page)
	}
	if _, err := store.GetVulnerabilitySyncRun(ctxB, "tenant-b", inRange.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	if _, err := queue.JobStatus(ctxB, inRange.DurableJobID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant job status error=%v", err)
	}
}
