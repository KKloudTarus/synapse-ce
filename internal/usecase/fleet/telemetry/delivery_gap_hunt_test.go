package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDeliveryGapReader struct {
	gaps []ports.TelemetryGap
	err  error
	last ports.TelemetryGapQuery
}

func (f *fakeDeliveryGapReader) QueryDeliveryGaps(_ context.Context, q ports.TelemetryGapQuery) ([]ports.TelemetryGap, error) {
	f.last = q
	if f.err != nil {
		return nil, f.err
	}
	return append([]ports.TelemetryGap(nil), f.gaps...), nil
}

func newGapAwareTelemetryService(t *testing.T, gaps ports.TelemetryDeliveryGapReader) *Service {
	t.Helper()
	store := memory.NewTelemetryStore(7*24*time.Hour, 30*24*time.Hour)
	svc, err := NewServiceWithDeliveryGaps(store, gaps, &fakeAudit{}, fixedClock{t: time.Unix(1_000_000, 0)}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestHuntDeliveryGapOverlapForcesIncomplete(t *testing.T) {
	base := time.Unix(1_000_000, 0).UTC()
	reader := &fakeDeliveryGapReader{gaps: []ports.TelemetryGap{{
		AgentID: "host-1", AssetID: "asset-1", StreamID: "stream-p3", Priority: fleetagent.PriorityP3,
		Epoch: 1, FromSequence: 2, ToSequence: 3,
		FromAt: base.Add(-10 * time.Minute), ToAt: base.Add(10 * time.Minute), DetectedAt: base,
	}}}
	svc := newGapAwareTelemetryService(t, reader)
	if _, err := svc.Ingest(tctx(), batch(1, 1, procEventAt("ps", base))); err != nil {
		t.Fatal(err)
	}

	q := ports.HuntQuery{
		HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess,
		Since: base.Add(-time.Minute), Until: base.Add(time.Minute),
	}
	res, err := svc.Hunt(tctx(), q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("a hunt overlapping an A3 delivery gap must never report Complete=true")
	}
	if len(res.DeliveryGaps) != 1 || res.DeliveryGaps[0].FromSequence != 2 || res.DeliveryGaps[0].ToSequence != 3 {
		t.Fatalf("hunt delivery gaps = %+v; want persisted [2,3]", res.DeliveryGaps)
	}
	if reader.last.AgentID != "host-1" || reader.last.AssetID != "asset-1" {
		t.Fatalf("delivery-gap query identity = %+v; want canonical host/asset filters", reader.last)
	}
	if reader.last.Priority == nil || *reader.last.Priority != fleetagent.PriorityP3 {
		t.Fatalf("process hunt must query the P3 delivery lane, got %+v", reader.last.Priority)
	}
	if !reader.last.Since.Equal(q.Since) || !reader.last.Until.Equal(q.Until) {
		t.Fatalf("delivery-gap query window = %s..%s; want %s..%s", reader.last.Since, reader.last.Until, q.Since, q.Until)
	}
}

func TestRetroRunRuleCarriesDeliveryGapCompleteness(t *testing.T) {
	base := time.Unix(1_000_000, 0).UTC()
	reader := &fakeDeliveryGapReader{gaps: []ports.TelemetryGap{{
		AgentID: "host-1", AssetID: "asset-1", StreamID: "stream-p3", Priority: fleetagent.PriorityP3,
		Epoch: 1, FromSequence: 2, ToSequence: 2, FromAt: base.Add(-time.Minute), ToAt: base.Add(time.Minute), DetectedAt: base,
	}}}
	svc := newGapAwareTelemetryService(t, reader)
	if _, err := svc.Ingest(tctx(), batch(1, 1, procEventAt("ps", base))); err != nil {
		t.Fatal(err)
	}

	fired, res, err := svc.RetroRunRule(tctx(), ports.HuntQuery{
		HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess,
		Since: base.Add(-time.Minute), Until: base.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 {
		t.Fatalf("retro rule should still evaluate available telemetry, fired=%d", len(fired))
	}
	if res.Complete || len(res.DeliveryGaps) != 1 {
		t.Fatalf("retro rule must carry lossy coverage metadata, result=%+v", res)
	}
}

func TestHuntFailsClosedWhenDeliveryGapReaderFails(t *testing.T) {
	reader := &fakeDeliveryGapReader{err: errors.New("gap store unavailable")}
	svc := newGapAwareTelemetryService(t, reader)
	_, err := svc.Hunt(shared.WithTenant(context.Background(), "t1"), ports.HuntQuery{HostID: "host-1"})
	if err == nil {
		t.Fatal("configured delivery-gap read failure must fail the hunt instead of returning uncertain completeness")
	}
}
