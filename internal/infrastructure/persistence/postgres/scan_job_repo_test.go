package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanJobStorePersistsDebugEvents(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// t.Cleanup is LIFO. Close must be registered before fixture cleanup so a second suite run sees
	// the same database state as the first one did.
	t.Cleanup(pool.Close)

	store := NewScanJobStore(pool)
	job := ports.ScanJob{
		ID:           "scan-job-debug-" + randHex(t),
		EngagementID: "eng-debug",
		Target:       "local-target",
		Kind:         ports.TargetLocal,
		Status:       ports.ScanRunning,
		Stage:        "scanning vulnerabilities",
		Progress:     55,
		StartedAt:    time.Now().UTC(),
		DebugEvents: []ports.ScanDebugEvent{{
			Stage:     "scanning vulnerabilities",
			Step:      "osv",
			Status:    ports.ScanDebugSucceeded,
			Tool:      "osv",
			Counts:    map[string]int{"raw_findings": 2},
			StartedAt: time.Now().UTC(),
		}},
	}
	if err := store.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM scan_jobs WHERE id=$1", job.ID); err != nil {
			t.Errorf("cleanup scan job %s: %v", job.ID, err)
		}
	})

	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if len(got.DebugEvents) != 1 || got.DebugEvents[0].Step != "osv" || got.DebugEvents[0].Counts["raw_findings"] != 2 {
		t.Fatalf("debug events not round-tripped: %+v", got.DebugEvents)
	}
}
