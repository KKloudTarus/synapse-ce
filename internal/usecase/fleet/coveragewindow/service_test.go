package coveragewindow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type sourceFixture struct {
	states   []sensorstate.Observation
	batches  []ports.TelemetryBatchAccounting
	gaps     []ports.CoverageGapFact
	stateErr error
	batchErr error
	gapErr   error
}

func (s *sourceFixture) ListCoverageSensorStates(context.Context, ports.CoverageSensorStateQuery) ([]sensorstate.Observation, error) {
	return append([]sensorstate.Observation(nil), s.states...), s.stateErr
}

func (s *sourceFixture) QueryTelemetryBatchAccounting(context.Context, ports.TelemetryBatchAccountingQuery) ([]ports.TelemetryBatchAccounting, error) {
	return append([]ports.TelemetryBatchAccounting(nil), s.batches...), s.batchErr
}

func (s *sourceFixture) ListCoverageGapFacts(context.Context, ports.CoverageGapQuery) ([]ports.CoverageGapFact, error) {
	return append([]ports.CoverageGapFact(nil), s.gaps...), s.gapErr
}

type windowStore struct {
	windows []sensorstate.CoverageWindow
}

func (s *windowStore) AppendCoverageWindow(_ context.Context, window sensorstate.CoverageWindow) (sensorstate.CoverageWindow, error) {
	for _, current := range s.windows {
		if current.Revision == window.Revision {
			return current, nil
		}
	}
	s.windows = append(s.windows, window)
	return window, nil
}

func (s *windowStore) ListCoverageWindows(context.Context, ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error) {
	return append([]sensorstate.CoverageWindow(nil), s.windows...), nil
}

func coverageObservation(id shared.ID, at time.Time, state detection.ClassState, reason string) sensorstate.Observation {
	return sensorstate.Observation{
		ReportID: id, AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Kind: sensorstate.RecordSensorState, ObservedAt: at,
		PayloadDigest:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SignedContentDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		SchemaVersion:       1, RecordedAt: at.Add(time.Minute),
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: "host-1", AgentID: "agent-1",
			State: state, Reason: reason, Since: at,
		}},
	}
}

func accounting(id shared.ID, sequence uint64, at time.Time) ports.TelemetryBatchAccounting {
	return ports.TelemetryBatchAccounting{
		AgentID: "agent-1", AssetID: "asset-1", StreamID: "stream-1", BatchID: id,
		Priority: fleetagent.PriorityP1, Epoch: 1, Sequence: sequence,
		ObservedCount: 5, KeptCount: 3, SampledOutCount: 1, TruncatedCount: 1,
		DroppedCount: 1, SamplingPolicyDigest: "sampling-digest", FromAt: at, ToAt: at,
	}
}

func gapFact(source ports.CoverageGapSource, id shared.ID, at time.Time) ports.CoverageGapFact {
	return ports.CoverageGapFact{
		Source: source, FactID: id, AgentID: "agent-1", AssetID: "asset-1", StreamID: "stream-1",
		Priority: fleetagent.PriorityP1, Epoch: 1, KnownSequence: true,
		FromSequence: 7, ToSequence: 8, Count: 2, Reason: "quota_eviction",
		FromAt: at, ToAt: at.Add(time.Second), RecordedAt: at.Add(time.Minute),
	}
}

func newTestService(t *testing.T, sources *sourceFixture) (*Service, *windowStore) {
	t.Helper()
	store := &windowStore{}
	service, err := NewService(sources, sources, sources, store, fixedClock{now: time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, store
}

func TestComposePreservesMidWindowFailureAfterRecovery(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	sources := &sourceFixture{states: []sensorstate.Observation{
		coverageObservation("before", since.Add(-time.Minute), detection.StateActive, ""),
		coverageObservation("failed", since.Add(time.Minute), detection.StateFailed, "attach failed"),
		coverageObservation("recovered", since.Add(2*time.Minute), detection.StateActive, ""),
	}}
	service, _ := newTestService(t, sources)
	window, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if len(window.States) != 1 || window.States[0].State != detection.StateFailed || window.States[0].Reason != "attach failed" {
		t.Fatalf("States = %#v, want the worst in-window state", window.States)
	}
	if window.Vector.Process != 0 {
		t.Fatalf("process coverage = %d, want 0", window.Vector.Process)
	}
}

func TestComposeIsSourceOrderIndependentAndCommitsExactFacts(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stateA := coverageObservation("state-a", since.Add(-time.Minute), detection.StateActive, "")
	stateB := coverageObservation("state-b", since.Add(time.Minute), detection.StateDegraded, "buffer pressure")
	batchA := accounting("batch-a", 1, since.Add(2*time.Minute))
	batchB := accounting("batch-b", 2, since.Add(3*time.Minute))
	gapA := gapFact(ports.CoverageGapAgent, "gap-a", since.Add(4*time.Minute))
	gapB := gapFact(ports.CoverageGapInferred, "gap-b", since.Add(4*time.Minute))

	first, _ := newTestService(t, &sourceFixture{
		states: []sensorstate.Observation{stateA, stateB}, batches: []ports.TelemetryBatchAccounting{batchA, batchB}, gaps: []ports.CoverageGapFact{gapA, gapB},
	})
	second, _ := newTestService(t, &sourceFixture{
		states: []sensorstate.Observation{stateB, stateA}, batches: []ports.TelemetryBatchAccounting{batchB, batchA}, gaps: []ports.CoverageGapFact{gapB, gapA},
	})
	request := ComposeRequest{AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour)}
	left, err := first.Compose(context.Background(), request)
	if err != nil {
		t.Fatalf("first Compose() error = %v", err)
	}
	right, err := second.Compose(context.Background(), request)
	if err != nil {
		t.Fatalf("second Compose() error = %v", err)
	}
	if left.InputDigest != right.InputDigest || left.Revision != right.Revision {
		t.Fatalf("source order changed identity: %s/%s != %s/%s", left.InputDigest, left.Revision, right.InputDigest, right.Revision)
	}

	changed := gapB
	changed.FactID = "different-inferred-fact"
	third, _ := newTestService(t, &sourceFixture{
		states: []sensorstate.Observation{stateA, stateB}, batches: []ports.TelemetryBatchAccounting{batchA, batchB}, gaps: []ports.CoverageGapFact{gapA, changed},
	})
	different, err := third.Compose(context.Background(), request)
	if err != nil {
		t.Fatalf("third Compose() error = %v", err)
	}
	if different.GapCount != left.GapCount || different.SampledCount != left.SampledCount || different.InputDigest == left.InputDigest || different.Revision == left.Revision {
		t.Fatalf("different immutable facts did not produce a distinct identity: first=%#v different=%#v", left, different)
	}
}

func TestComposeCanonicalizesPostgresTimestampPrecision(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 123456789, time.FixedZone("offset", 7*60*60))
	observation := coverageObservation("state-a", since.Add(-time.Minute), detection.StateActive, "")
	observation.ObservedAt = observation.ObservedAt.Add(321 * time.Nanosecond)
	observation.RecordedAt = observation.RecordedAt.Add(654 * time.Nanosecond)
	observation.States[0].Since = observation.States[0].Since.Add(987 * time.Nanosecond)
	batch := accounting("batch-a", 1, since.Add(2*time.Minute))
	batch.FromAt = batch.FromAt.Add(111 * time.Nanosecond)
	batch.ToAt = batch.ToAt.Add(222 * time.Nanosecond)
	gap := gapFact(ports.CoverageGapAgent, "gap-a", since.Add(4*time.Minute))
	gap.FromAt = gap.FromAt.Add(333 * time.Nanosecond)
	gap.ToAt = gap.ToAt.Add(444 * time.Nanosecond)
	gap.RecordedAt = gap.RecordedAt.Add(555 * time.Nanosecond)

	service, _ := newTestService(t, &sourceFixture{
		states:  []sensorstate.Observation{observation},
		batches: []ports.TelemetryBatchAccounting{batch},
		gaps:    []ports.CoverageGapFact{gap},
	})
	window, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	for name, at := range map[string]time.Time{
		"Since": window.Since, "Until": window.Until, "state Since": window.States[0].Since,
	} {
		if at.Location() != time.UTC || at.Nanosecond()%int(time.Microsecond) != 0 {
			t.Fatalf("%s = %s, want UTC microsecond precision", name, at)
		}
	}

	postgresRoundTrip := window
	postgresRoundTrip.Since = postgresRoundTrip.Since.UTC().Truncate(time.Microsecond)
	postgresRoundTrip.Until = postgresRoundTrip.Until.UTC().Truncate(time.Microsecond)
	for i := range postgresRoundTrip.States {
		postgresRoundTrip.States[i].Since = postgresRoundTrip.States[i].Since.UTC().Truncate(time.Microsecond)
	}
	if got := sensorstate.RevisionFor(postgresRoundTrip); got != window.Revision {
		t.Fatalf("PostgreSQL precision changed revision: got %s, want %s", got, window.Revision)
	}
}

func TestComposeRejectsMultiplePreWindowStatesForClass(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	service, store := newTestService(t, &sourceFixture{states: []sensorstate.Observation{
		coverageObservation("older", since.Add(-2*time.Minute), detection.StateActive, ""),
		coverageObservation("latest", since.Add(-time.Minute), detection.StateDegraded, "sensor gap"),
	}})
	_, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: since, Until: since.Add(time.Hour),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Compose() error = %v, want validation error", err)
	}
	if len(store.windows) != 0 {
		t.Fatalf("persisted %d windows after invalid reader result", len(store.windows))
	}
}

func TestComposeRejectsDispositionCountOverflow(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	first := accounting("batch-a", 1, since.Add(time.Minute))
	second := accounting("batch-b", 2, since.Add(2*time.Minute))
	first.ObservedCount = int(^uint(0) >> 1)
	first.KeptCount = first.ObservedCount
	first.SampledOutCount = 0
	first.TruncatedCount = first.KeptCount
	second.ObservedCount = 1
	second.KeptCount = 1
	second.SampledOutCount = 0
	second.TruncatedCount = 1

	service, store := newTestService(t, &sourceFixture{batches: []ports.TelemetryBatchAccounting{first, second}})
	_, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: since, Until: since.Add(time.Hour),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Compose() error = %v, want validation error", err)
	}
	if len(store.windows) != 0 {
		t.Fatalf("persisted %d windows after count overflow", len(store.windows))
	}
}

func TestComposeDeduplicatesOnlyScoredCoordinateGap(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	agent := gapFact(ports.CoverageGapAgent, "gap-agent", since.Add(time.Minute))
	inferred := gapFact(ports.CoverageGapInferred, "gap-inferred", since.Add(time.Minute))
	sources := &sourceFixture{
		states: []sensorstate.Observation{coverageObservation("active", since.Add(-time.Minute), detection.StateActive, "")},
		gaps:   []ports.CoverageGapFact{agent, inferred},
	}
	service, _ := newTestService(t, sources)
	window, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if window.GapCount != 1 {
		t.Fatalf("GapCount = %d, want one scored coordinate defect", window.GapCount)
	}

	withoutInferred := &sourceFixture{states: sources.states, gaps: []ports.CoverageGapFact{agent}}
	oneSource, _ := newTestService(t, withoutInferred)
	one, err := oneSource.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("single-source Compose() error = %v", err)
	}
	if one.GapCount != window.GapCount || one.InputDigest == window.InputDigest {
		t.Fatalf("audit source was collapsed from input identity: one=%#v both=%#v", one, window)
	}
}

func TestComposeCountsUnknownCoordinateGapWithoutInventingDroppedEvents(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	unknown := gapFact(ports.CoverageGapAgent, "gap-unknown", since.Add(time.Minute))
	unknown.KnownSequence = false
	unknown.FromSequence = 0
	unknown.ToSequence = 0
	unknown.Count = 23
	sources := &sourceFixture{
		states: []sensorstate.Observation{coverageObservation("active", since.Add(-time.Minute), detection.StateActive, "")},
		gaps:   []ports.CoverageGapFact{unknown},
	}
	service, _ := newTestService(t, sources)
	window, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if window.GapCount != 1 || window.DroppedCount != 0 {
		t.Fatalf("gap/dropped counts = %d/%d, want 1/0", window.GapCount, window.DroppedCount)
	}
}

func TestComposePersistsServerOwnedCreatedAt(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	sources := &sourceFixture{states: []sensorstate.Observation{coverageObservation("active", since.Add(-time.Minute), detection.StateActive, "")}}
	service, store := newTestService(t, sources)
	window, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if !window.CreatedAt.Equal(time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC)) || len(store.windows) != 1 {
		t.Fatalf("stored window = %#v", window)
	}
	if err := window.Validate(); err != nil {
		t.Fatalf("composed window validation = %v", err)
	}
}

func TestComposeExcludesFactsAtUntil(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	until := since.Add(time.Hour)
	sources := &sourceFixture{
		states: []sensorstate.Observation{
			coverageObservation("active", since.Add(-time.Minute), detection.StateActive, ""),
			coverageObservation("at-until", until, detection.StateFailed, "must be excluded"),
		},
		batches: []ports.TelemetryBatchAccounting{accounting("at-until", 1, until)},
		gaps:    []ports.CoverageGapFact{gapFact(ports.CoverageGapAgent, "at-until", until)},
	}
	service, _ := newTestService(t, sources)
	_, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: until,
	})
	if err == nil {
		t.Fatal("Compose() accepted a source fact at the exclusive upper bound")
	}
}

func TestComposePropagatesSourceFailureWithoutPersisting(t *testing.T) {
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	sources := &sourceFixture{gapErr: context.Canceled}
	service, store := newTestService(t, sources)
	_, err := service.Compose(context.Background(), ComposeRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1", Since: since, Until: since.Add(time.Hour),
	})
	if err == nil || len(store.windows) != 0 {
		t.Fatalf("Compose() error/windows = %v/%d, want source failure and no persistence", err, len(store.windows))
	}
}

func TestReconcileCoverageUsesFixedWindowsAndDeterministicRetries(t *testing.T) {
	service, store := newTestService(t, &sourceFixture{})
	reconciler, err := NewReconciler(service, 5*time.Minute, 10)
	if err != nil {
		t.Fatalf("NewReconciler() error = %v", err)
	}
	since := time.Date(2026, 8, 27, 12, 3, 0, 0, time.UTC)
	request := ports.CoverageReconcileRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: since, Until: since.Add(9 * time.Minute),
	}
	if err := reconciler.ReconcileCoverage(t.Context(), request); err != nil {
		t.Fatalf("ReconcileCoverage() error = %v", err)
	}
	if len(store.windows) != 3 {
		t.Fatalf("fixed windows = %d, want 3", len(store.windows))
	}
	for i, wantStart := range []time.Time{
		time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 27, 12, 5, 0, 0, time.UTC),
		time.Date(2026, 8, 27, 12, 10, 0, 0, time.UTC),
	} {
		if store.windows[i].Since != wantStart || store.windows[i].Until != wantStart.Add(5*time.Minute) {
			t.Fatalf("window[%d] = [%s,%s), want [%s,%s)", i, store.windows[i].Since, store.windows[i].Until, wantStart, wantStart.Add(5*time.Minute))
		}
	}
	firstRevisions := make([]string, len(store.windows))
	for i := range store.windows {
		firstRevisions[i] = store.windows[i].Revision
	}
	if err := reconciler.ReconcileCoverage(t.Context(), request); err != nil {
		t.Fatalf("exact reconciliation retry: %v", err)
	}
	if len(store.windows) != 3 {
		t.Fatalf("exact retry appended duplicate revisions: %d windows", len(store.windows))
	}
	for i := range store.windows {
		if store.windows[i].Revision != firstRevisions[i] {
			t.Fatalf("window[%d] revision changed on exact retry", i)
		}
	}
}

func TestReconcileCoverageBoundsAffectedWindows(t *testing.T) {
	service, store := newTestService(t, &sourceFixture{})
	reconciler, err := NewReconciler(service, 5*time.Minute, 2)
	if err != nil {
		t.Fatalf("NewReconciler() error = %v", err)
	}
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	err = reconciler.ReconcileCoverage(t.Context(), ports.CoverageReconcileRequest{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: since, Until: since.Add(10 * time.Minute),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("affected-window overflow error = %v, want validation", err)
	}
	if len(store.windows) != 0 {
		t.Fatalf("bounded reconciler persisted %d windows, want preflight rejection before any append", len(store.windows))
	}
}
