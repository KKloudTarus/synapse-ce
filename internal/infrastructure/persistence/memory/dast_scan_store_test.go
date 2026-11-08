package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMemoryDASTStoreRefusesUnfencedScans(t *testing.T) {
	store := NewDASTRunStore()
	run, err := dastrun.NewScanRun("run", "tenant", "eng", "action", "actor", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDASTRun(context.Background(), run); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("save scan: %v", err)
	}
	if err := store.EnqueueDASTRun(context.Background(), run, "dast_scan", []byte(`{}`)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("enqueue scan: %v", err)
	}
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartRun(context.Background(), "tenant", run); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("start scan: %v", err)
	}
	if err := run.CompleteScan("evidence", true, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishRun(context.Background(), "tenant", run); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("finish scan: %v", err)
	}
}
