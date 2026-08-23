package telemetryingest

import (
	"errors"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestIngestRejectsConflictingReplayAtAcknowledgedSequence(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	beforeAudit := h.audit.count()
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "different-event")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same sequence with different signed batch must conflict, got %v", err)
	}
	if h.audit.count() <= beforeAudit {
		t.Fatal("sequence equivocation must be audited")
	}
	if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 1 {
		t.Fatalf("conflicting replay mutated stored membership: count=%d err=%v", n, err)
	}
}

func TestConcurrentTelemetrySequenceEquivocationHasSingleWinner(t *testing.T) {
	h := newHarness(t)
	requests := []IngestRequest{
		h.signedBatch(1, 1, 0, "event-a"),
		h.signedBatch(1, 1, 0, "event-b"),
	}
	start := make(chan struct{})
	errs := make([]error, len(requests))
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = h.svc.Ingest(h.ctx, "agent-1", requests[i])
		}(i)
	}
	close(start)
	wg.Wait()

	successes, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent ingest error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent equivocation results: successes=%d conflicts=%d errors=%v", successes, conflicts, errs)
	}
	if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 1 {
		t.Fatalf("equivocation stored %d events, err=%v; want exactly one winning batch", n, err)
	}
}
