package correlationuc

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDetections struct{ recs []detection.Record }

func (f fakeDetections) CorrelationHighWater(_ context.Context, _ shared.ID, completed correlation.SourcePosition, _ time.Time) (correlation.SourcePosition, bool, error) {
	var high correlation.SourcePosition
	for _, r := range f.recs {
		at := r.RecordedAt
		if at.IsZero() {
			at = r.Detection.Observed
		}
		p := correlation.SourcePosition{RecordedAt: at, ID: r.ID}
		if !completed.RecordedAt.IsZero() && !sourcePositionAfter(p, completed) {
			continue
		}
		if high.RecordedAt.IsZero() || sourcePositionAfter(p, high) {
			high = p
		}
	}
	return high, !high.RecordedAt.IsZero(), nil
}
func (f fakeDetections) ListCorrelationSourcePage(_ context.Context, _ shared.ID, after, through correlation.SourcePosition, _ time.Time, limit int) ([]detection.Record, bool, error) {
	var out []detection.Record
	for _, r := range f.recs {
		if r.RecordedAt.IsZero() {
			r.RecordedAt = r.Detection.Observed
		}
		if (after.RecordedAt.IsZero() || r.RecordedAt.After(after.RecordedAt) || (r.RecordedAt.Equal(after.RecordedAt) && r.ID > after.ID)) && (r.RecordedAt.Before(through.RecordedAt) || (r.RecordedAt.Equal(through.RecordedAt) && r.ID <= through.ID)) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RecordedAt.Equal(out[j].RecordedAt) {
			return out[i].RecordedAt.Before(out[j].RecordedAt)
		}
		return out[i].ID < out[j].ID
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

type fakeIncidents struct {
	seen   map[shared.ID]bool
	events []incident.IncidentEvent
}

func (f *fakeIncidents) RecordCorrelation(_ context.Context, events []incident.IncidentEvent) ([]incident.Incident, []incident.Incident, error) {
	if f.seen == nil {
		f.seen = map[shared.ID]bool{}
	}
	incidentIDs := map[shared.ID]struct{}{}
	f.events = append(f.events, events...)
	for _, event := range events {
		incidentIDs[event.IncidentID] = struct{}{}
	}
	var created, updated []incident.Incident
	for id := range incidentIDs {
		projection := incident.Incident{ID: id, State: incident.StateOpen}
		if f.seen[id] {
			updated = append(updated, projection)
		} else {
			f.seen[id] = true
			created = append(created, projection)
		}
	}
	return created, updated, nil
}

type fakeReassessor struct {
	calls int
	err   error
}

func (f *fakeReassessor) Reassess(_ context.Context, _ string, id shared.ID) (incident.Incident, error) {
	f.calls++
	if f.err != nil {
		return incident.Incident{}, f.err
	}
	return incident.Incident{ID: id, State: incident.StateOpen}, nil
}

type fakeAudit struct{ n int }

func (f *fakeAudit) Record(context.Context, ports.AuditEntry) error { f.n++; return nil }

func rec(id, host string, at time.Time) detection.Record {
	return detection.Record{ID: shared.ID(id), AssetID: "asset-1", Detection: detection.Detection{RuleID: "r1", RuleVersion: 1, Class: detection.ClassProcess, Severity: shared.SeverityHigh, HostID: shared.ID(host), Observed: at}}
}
func newSvc(t *testing.T, dets []detection.Record, reassessor RiskReassessor) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	service, err := NewService(fakeDetections{recs: dets}, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), &fakeIncidents{}, reassessor, correlation.Config{Window: time.Hour, AllowedLateness: time.Minute, MaxPerIncident: 50}, audit, func() time.Time { return time.Unix(1_700_000_100, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return service, audit
}
func testCtx() context.Context { return shared.WithTenant(context.Background(), "tenant-1") }
func correlateSnapshot(t *testing.T, svc *Service, ctx context.Context) Result {
	t.Helper()
	var total Result
	for range 32 {
		result, err := svc.CorrelateEngagement(ctx, "operator", "eng-1")
		if err != nil {
			t.Fatal(err)
		}
		total.Created = append(total.Created, result.Created...)
		total.Updated = append(total.Updated, result.Updated...)
		total.Reassessed += result.Reassessed
		total.ReassessFailed += result.ReassessFailed
		total.Evicted += result.Evicted
		state, err := svc.state.LoadCorrelationState(ctx, "eng-1", nil, 100)
		if err != nil {
			t.Fatal(err)
		}
		if state.Checkpoint.Phase == "" {
			return total
		}
	}
	t.Fatal("correlation snapshot did not finish")
	return Result{}
}

func TestCorrelateCreatesAndReassesses(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	reassessor := &fakeReassessor{}
	service, audit := newSvc(t, []detection.Record{rec("d1", "host-1", base), rec("d2", "host-1", base.Add(time.Minute))}, reassessor)
	result := correlateSnapshot(t, service, testCtx())
	if len(result.Created) != 1 || result.Reassessed != 1 || result.ReassessFailed != 0 || reassessor.calls != 1 || audit.n != 3 {
		t.Fatalf("unexpected result: %+v calls=%d audit=%d", result, reassessor.calls, audit.n)
	}
}
func TestReassessFailureIsCountedNotFatal(t *testing.T) {
	service, _ := newSvc(t, []detection.Record{rec("d1", "host-1", time.Unix(1_700_000_000, 0).UTC())}, &fakeReassessor{err: errors.New("scorer down")})
	result := correlateSnapshot(t, service, testCtx())
	if len(result.Created) != 1 || result.ReassessFailed != 1 {
		t.Fatalf("result=%+v", result)
	}
}
func TestIncrementalRerunIsNoOp(t *testing.T) {
	service, _ := newSvc(t, []detection.Record{rec("d1", "host-1", time.Unix(1_700_000_000, 0).UTC())}, nil)
	_ = correlateSnapshot(t, service, testCtx())
	result, err := service.CorrelateEngagement(testCtx(), "operator", "eng-1")
	if err != nil || len(result.Created) != 0 || len(result.Updated) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestCorrelationSnapshotIsIndependentOfSourceOrderAndPageSize(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	run := func(pageSize int, reverseRecorded bool) []incident.IncidentEvent {
		left := rec("d-a", "host-1", base)
		right := rec("d-c", "host-1", base.Add(2*time.Hour))
		// Source ordering is intentionally opposite event time, with an equal-time ID tie.
		left.RecordedAt, right.RecordedAt = base.Add(time.Second), base
		if reverseRecorded {
			left.RecordedAt, right.RecordedAt = right.RecordedAt, left.RecordedAt
		}
		source := &mutableDetections{recs: []detection.Record{right, left}}
		recorder := &fakeIncidents{}
		svc, err := NewService(source, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), recorder, nil, correlation.Config{Window: time.Hour, AllowedLateness: 3 * time.Hour, MaxPerIncident: 10, PageSize: pageSize}, &fakeAudit{}, func() time.Time { return base.Add(4 * time.Hour) })
		if err != nil {
			t.Fatal(err)
		}
		if result := correlateSnapshot(t, svc, testCtx()); len(result.Created) != 2 {
			t.Fatalf("initial sessions page size %d: %+v", pageSize, result)
		}
		bridge := rec("d-b", "host-1", base.Add(time.Hour))
		bridge.RecordedAt = base.Add(2 * time.Second) // newer source frontier, between the two event-time sessions.
		source.recs = append(source.recs, bridge)
		_ = correlateSnapshot(t, svc, testCtx())
		merged := false
		for _, event := range recorder.events {
			merged = merged || event.Kind == incident.EventMerged
		}
		if !merged {
			t.Fatalf("bridge did not merge prior sessions: %+v", recorder.events)
		}
		return recorder.events
	}
	forward := run(1, false)
	reverse := run(3, true)
	if len(forward) != len(reverse) {
		t.Fatalf("event count varies with page/order: %d != %d", len(forward), len(reverse))
	}
	for i := range forward {
		if forward[i] != reverse[i] {
			t.Fatalf("event %d varies with page/order: %+v != %+v", i, forward[i], reverse[i])
		}
	}
}

type mutableDetections struct{ recs []detection.Record }

func (f *mutableDetections) CorrelationHighWater(ctx context.Context, engagement shared.ID, completed correlation.SourcePosition, asOf time.Time) (correlation.SourcePosition, bool, error) {
	return fakeDetections{recs: f.recs}.CorrelationHighWater(ctx, engagement, completed, asOf)
}
func (f *mutableDetections) ListCorrelationSourcePage(ctx context.Context, engagement shared.ID, after, through correlation.SourcePosition, asOf time.Time, limit int) ([]detection.Record, bool, error) {
	return fakeDetections{recs: f.recs}.ListCorrelationSourcePage(ctx, engagement, after, through, asOf, limit)
}

func TestCorrelationSnapshotExcludesConcurrentDetectionUntilNextSnapshot(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	source := &mutableDetections{recs: []detection.Record{rec("d1", "host-1", base)}}
	source.recs[0].RecordedAt = base
	recorder := &fakeIncidents{}
	svc, err := NewService(source, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), recorder, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 10, PageSize: 1}, &fakeAudit{}, func() time.Time { return base.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	ctx := testCtx()
	if _, err := svc.CorrelateEngagement(ctx, "operator", "eng-1"); err != nil { // captures high water.
		t.Fatal(err)
	}
	source.recs = append(source.recs, rec("d2", "host-2", base.Add(time.Second)))
	source.recs[1].RecordedAt = base.Add(time.Second)
	_ = correlateSnapshot(t, svc, ctx)
	if len(recorder.events) != 1 || recorder.events[0].DetectionID != "d1" {
		t.Fatalf("first snapshot included post-high-water detection: %+v", recorder.events)
	}
	_ = correlateSnapshot(t, svc, ctx)
	seenD2 := false
	for _, event := range recorder.events {
		seenD2 = seenD2 || event.DetectionID == "d2"
	}
	if !seenD2 {
		t.Fatalf("next snapshot did not consume post-high-water detection: %+v", recorder.events)
	}
}

func TestCorrelationFanoutSaturationDoesNotAdvanceMaterialization(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	ctx := testCtx()
	provenance := memory.NewDetectionProvenanceStore()
	record := rec("d1", "host-1", base)
	record.AgentID, record.RecordedAt = "agent-1", base
	transition := detectionprovenance.Transition{TenantID: "tenant-1", EngagementID: "eng-1", DetectionID: record.ID, Sequence: 1, Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending, AgentID: record.AgentID, AssetID: record.AssetID, OccurredAt: base, TelemetryRefs: []fleetagent.TelemetryReference{{StreamID: "stream", Epoch: 1, Sequence: 1, EventID: "event-1", Digest: "a"}, {StreamID: "stream", Epoch: 1, Sequence: 2, EventID: "event-2", Digest: "b"}}}
	transition = detectionprovenance.SealTransition(transition, "")
	if err := provenance.AdmitPending(ctx, detectionprovenance.Current{TenantID: "tenant-1", EngagementID: "eng-1", DetectionID: record.ID, Status: detectionprovenance.StatusPending, PendingInput: []byte("x"), UpdatedAt: base}, transition); err != nil {
		t.Fatal(err)
	}
	state, recorder := memory.NewCorrelationStateStore(), &fakeIncidents{}
	svc, err := NewService(fakeDetections{recs: []detection.Record{record}}, provenance, memory.NewEndpointTimelineStore(), state, recorder, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 10, MaxTimelineRefsPerDetection: 1, MaxTimelineRefsPerPage: 1}, &fakeAudit{}, func() time.Time { return base.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CorrelateEngagement(ctx, "operator", "eng-1"); err != nil {
		t.Fatal(err)
	}
	before, err := state.LoadCorrelationState(ctx, "eng-1", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CorrelateEngagement(ctx, "operator", "eng-1"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("fanout saturation error=%v", err)
	}
	after, err := state.LoadCorrelationState(ctx, "eng-1", nil, 10)
	if err != nil || after.Checkpoint != before.Checkpoint || len(recorder.events) != 0 {
		t.Fatalf("fanout saturation mutated state=%+v before=%+v events=%+v err=%v", after.Checkpoint, before.Checkpoint, recorder.events, err)
	}
}

func TestCorrelationActiveSessionEvictionMakesTerminalForwardProgress(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	records := []detection.Record{rec("d1", "host-1", base), rec("d2", "host-2", base.Add(time.Second)), rec("d3", "host-3", base.Add(2*time.Second))}
	for i := range records {
		records[i].RecordedAt = base.Add(time.Duration(i) * time.Second)
	}
	recorder := &fakeIncidents{}
	state := memory.NewCorrelationStateStore()
	svc, err := NewService(fakeDetections{recs: records}, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), state, recorder, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 10, PageSize: 1, MaxActiveSessions: 1}, &fakeAudit{}, func() time.Time { return base.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	result := correlateSnapshot(t, svc, testCtx())
	if result.Evicted != 2 || len(result.Created) != 3 {
		t.Fatalf("correlation must assign all signals and evict overflow sessions: %+v", result)
	}
	stateAfter, err := state.LoadCorrelationState(testCtx(), "eng-1", nil, 1)
	if err != nil || stateAfter.Checkpoint.Phase != "" || len(stateAfter.ActiveSessions) != 1 {
		t.Fatalf("correlation did not complete with bounded active sessions: state=%+v err=%v", stateAfter, err)
	}
	comments := 0
	for _, event := range recorder.events {
		if event.Kind == incident.EventAnalystCommented && event.CorrelationKey != "" {
			comments++
		}
	}
	if comments != 2 {
		t.Fatalf("evictions must produce visible coverage comments: %+v", recorder.events)
	}
}

func TestSignalsLoadsOnlyCausalTimelineAndRejectsContradictions(t *testing.T) {
	ctx := testCtx()
	base := time.Unix(1_700_000_000, 0).UTC()
	records := []detection.Record{{ID: "d1", AgentID: "agent-1", AssetID: "asset-1", Detection: detection.Detection{HostID: "host-1", Observed: base, Severity: shared.SeverityHigh, RuleID: "r"}}}
	provenance := memory.NewDetectionProvenanceStore()
	timeline := memory.NewEndpointTimelineStore()
	transition := detectionprovenance.Transition{TenantID: "tenant-1", EngagementID: "eng-1", DetectionID: "d1", Sequence: 1, Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending, AgentID: "agent-1", AssetID: "asset-1", TelemetryRefs: []fleetagent.TelemetryReference{{StreamID: "stream", Epoch: 1, Sequence: 1, EventID: "event-causal", Digest: "digest"}}, OccurredAt: base}
	transition = detectionprovenance.SealTransition(transition, "")
	current := detectionprovenance.Current{TenantID: "tenant-1", EngagementID: "eng-1", DetectionID: "d1", Status: detectionprovenance.StatusPending, PendingInput: []byte("x"), UpdatedAt: base}
	if err := provenance.AdmitPending(ctx, current, transition); err != nil {
		t.Fatal(err)
	}
	entries := []endpoint.TimelineEntry{{TenantID: "tenant-1", AssetID: "asset-1", SourceAgentID: "agent-1", EntityID: "host-1", EventID: "event-causal", OccurredAt: base, Kind: endpoint.TimelineProcessExit, Summary: "causal exit"}, {TenantID: "tenant-1", AssetID: "asset-1", SourceAgentID: "agent-1", EntityID: "host-1", EventID: "event-unrelated", OccurredAt: base, Kind: endpoint.TimelineProcessExit, Summary: "unrelated"}}
	if err := timeline.AppendTimeline(ctx, entries); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(fakeDetections{recs: records}, provenance, timeline, memory.NewCorrelationStateStore(), &fakeIncidents{}, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 10}, &fakeAudit{}, func() time.Time { return base.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	result := correlateSnapshot(t, svc, ctx)
	if len(result.Created) != 1 {
		t.Fatalf("correlate result=%+v err=%v", result, err)
	}
	state, err := svc.state.LoadCorrelationState(ctx, "eng-1", []shared.ID{timelineSignalID("d1", "event-causal"), timelineSignalID("d1", "event-unrelated")}, 100)
	if err != nil || len(state.KnownSignalIDs) != 1 {
		t.Fatalf("causal timeline selection=%+v err=%v", state, err)
	}
	entries[0].SourceAgentID = "wrong-agent"
	timeline = memory.NewEndpointTimelineStore()
	if err := timeline.AppendTimeline(ctx, entries[:1]); err != nil {
		t.Fatal(err)
	}
	svc.timeline = timeline
	if _, err := svc.sourceSignals(ctx, "eng-1", records); err == nil {
		t.Fatal("wrong timeline agent must fail closed")
	}
}
