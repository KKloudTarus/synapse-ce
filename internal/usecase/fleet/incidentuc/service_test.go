package incidentuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

const (
	tenant = shared.ID("tenant-i")
	asset  = shared.ID("asset-i")
	entity = shared.ID("pe-i")
)

var base = time.Unix(1_800_000_000, 0).UTC()

func newSvc(t *testing.T) (*Service, context.Context) {
	t.Helper()
	svc, err := NewService(memory.NewIncidentEventStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, shared.WithTenant(context.Background(), tenant)
}

// correlate produces a real correlator event stream for one session, so the C2→C7→C1 path is exercised.
func correlate(t *testing.T) []incident.IncidentEvent {
	t.Helper()
	events, err := correlation.Correlate(
		correlation.Config{Window: time.Minute, MaxPerIncident: 100},
		[]correlation.Signal{
			{ID: "d1", AssetID: asset, EntityID: entity, OccurredAt: base, Severity: shared.SeverityLow, Title: "exec"},
			{ID: "d2", AssetID: asset, EntityID: entity, OccurredAt: base.Add(time.Second), Severity: shared.SeverityHigh, Title: "exec"},
		})
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	return events
}

func TestNewServiceRequiresStore(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil store must be rejected, got %v", err)
	}
}

func TestRecordCorrelationCreatesAndIsIdempotent(t *testing.T) {
	svc, ctx := newSvc(t)
	events := correlate(t)
	created, err := svc.RecordCorrelation(ctx, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("one incident expected, got %d", len(created))
	}
	inc := created[0]
	if inc.State != incident.StateNew || len(inc.DetectionIDs) != 2 || inc.Severity != shared.SeverityHigh {
		t.Fatalf("recorded incident wrong: %+v", inc)
	}
	// Re-recording the same correlation is a no-op (batch idempotency).
	again, err := svc.RecordCorrelation(ctx, events)
	if err != nil || len(again) != 0 {
		t.Fatalf("re-record must create nothing: created=%d err=%v", len(again), err)
	}
	// Get reconstructs the same projection.
	got, err := svc.Get(ctx, inc.ID)
	if err != nil || got.Revision != inc.Revision || len(got.DetectionIDs) != 2 {
		t.Fatalf("get after record: %+v err=%v", got, err)
	}
}

func TestGetNotFound(t *testing.T) {
	svc, ctx := newSvc(t)
	if _, err := svc.Get(ctx, "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown incident must be ErrNotFound, got %v", err)
	}
}

func TestAppendOptimisticConcurrencyAndProjectValidation(t *testing.T) {
	svc, ctx := newSvc(t)
	created, err := svc.RecordCorrelation(ctx, correlate(t))
	if err != nil {
		t.Fatal(err)
	}
	inc := created[0]
	// A stale expectedRevision is rejected.
	_, err = svc.Append(ctx, inc.ID, inc.Revision-1, []incident.IncidentEvent{
		{IncidentID: inc.ID, Kind: incident.EventStatusChanged, At: base.Add(time.Hour), Actor: "a", To: incident.StateInvestigating},
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	// A legal append at the correct revision succeeds.
	updated, err := svc.Append(ctx, inc.ID, inc.Revision, []incident.IncidentEvent{
		{IncidentID: inc.ID, Kind: incident.EventStatusChanged, At: base.Add(time.Hour), Actor: "alice", To: incident.StateInvestigating},
	})
	if err != nil || updated.State != incident.StateInvestigating {
		t.Fatalf("legal append failed: %+v err=%v", updated, err)
	}
	// An append that would produce an INVALID incident (illegal transition) is rejected and NOT persisted.
	_, err = svc.Append(ctx, inc.ID, updated.Revision, []incident.IncidentEvent{
		{IncidentID: inc.ID, Kind: incident.EventStatusChanged, At: base.Add(2 * time.Hour), Actor: "alice", To: incident.StateNew},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("illegal transition append must be rejected, got %v", err)
	}
	after, _ := svc.Get(ctx, inc.ID)
	if after.Revision != updated.Revision {
		t.Fatalf("rejected append must not persist: rev %d != %d", after.Revision, updated.Revision)
	}
}

func TestListByAsset(t *testing.T) {
	svc, ctx := newSvc(t)
	if _, err := svc.RecordCorrelation(ctx, correlate(t)); err != nil {
		t.Fatal(err)
	}
	incs, err := svc.ListByAsset(ctx, asset, 0)
	if err != nil || len(incs) != 1 {
		t.Fatalf("list by asset: %d err=%v", len(incs), err)
	}
	// A different asset returns nothing.
	if other, _ := svc.ListByAsset(ctx, "asset-other", 0); len(other) != 0 {
		t.Fatalf("other asset must list nothing, got %d", len(other))
	}
}
