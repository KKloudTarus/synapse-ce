package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCIImportAdmissionDoesNotBlockConcurrentScans(t *testing.T) {
	ctx := context.Background()
	store := NewScanJobStore()
	now := time.Now().UTC()
	makeJob := func(id, kind string) ports.ScanJob {
		return ports.ScanJob{ID: id, EngagementID: "eng", Kind: kind, Status: ports.ScanRunning, Stage: "starting", StartedAt: now}
	}
	server := makeJob("server", "git")
	if err := store.CreateRunning(ctx, server); err != nil {
		t.Fatal(err)
	}
	// CI imports already ran outside the server; their transient running
	// status is only a fence for the notification capture trigger.
	for _, id := range []string{"ci-1", "ci-2"} {
		if err := store.CreateRunning(ctx, makeJob(id, "ci-import")); err != nil {
			t.Fatalf("concurrent CI import %s wrongly blocked: %v", id, err)
		}
	}
	if err := store.CreateRunning(ctx, makeJob("server-duplicate", "git")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent server scans must still conflict, got %v", err)
	}
	server.Status = ports.ScanSucceeded
	if err := store.Save(ctx, server); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRunning(ctx, makeJob("server-next", "git")); err != nil {
		t.Fatalf("transient CI imports must not block the next server scan: %v", err)
	}
	for _, id := range []string{"ci-1", "ci-2", "server-next"} {
		got, err := store.GetJob(ctx, id)
		if err != nil || got.Status != ports.ScanRunning {
			t.Fatalf("admitted job %s missing or terminal: %+v %v", id, got, err)
		}
	}
}
