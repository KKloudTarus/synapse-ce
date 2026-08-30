package telemetryingest

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

type fakeTimelineRecorder struct {
	calls int
	err   error
}

func (f *fakeTimelineRecorder) Record(_ context.Context, _ telemetry.TelemetryEnvelope) ([]endpoint.TimelineEntry, error) {
	f.calls++
	return nil, f.err
}

// TestIngestFansOutAcceptedEnvelopesToTimeline: a durably-accepted batch projects each envelope into the
// State Timeline (#594 B7).
func TestIngestFansOutAcceptedEnvelopesToTimeline(t *testing.T) {
	h := newHarness(t)
	rec := &fakeTimelineRecorder{}
	h.svc.SetEndpointTimeline(rec)
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1"))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Accepted {
		t.Fatal("batch must be accepted")
	}
	if rec.calls != 1 {
		t.Fatalf("the accepted envelope must be projected to the timeline once, got %d", rec.calls)
	}
}

// TestIngestTimelineProjectionFailureDoesNotFailIngest: the projection is best-effort — the batch is
// already durably stored, so a timeline failure must NOT fail the ingest.
func TestIngestTimelineProjectionFailureDoesNotFailIngest(t *testing.T) {
	h := newHarness(t)
	h.svc.SetEndpointTimeline(&fakeTimelineRecorder{err: errors.New("timeline store down")})
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1"))
	if err != nil {
		t.Fatalf("a timeline projection failure must not fail ingest: %v", err)
	}
	if !res.Accepted {
		t.Fatal("batch must still be accepted despite the projection failure")
	}
}
