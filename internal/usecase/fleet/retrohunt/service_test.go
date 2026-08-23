package retrohunt

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var huntAt = time.Unix(1_800_200_000, 0).UTC()

type timelineStub struct {
	entries []endpoint.TimelineEntry
	err     error
	queries []ports.EndpointTimelineQuery
}

func (s *timelineStub) QueryTimeline(_ context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	s.queries = append(s.queries, q)
	if s.err != nil {
		return nil, s.err
	}
	var out []endpoint.TimelineEntry
	for _, entry := range s.entries {
		if entry.AssetID != q.AssetID || (!q.From.IsZero() && entry.OccurredAt.Before(q.From)) ||
			(!q.To.IsZero() && entry.OccurredAt.After(q.To)) || (!q.EntityID.IsZero() && entry.EntityID != q.EntityID) {
			continue
		}
		out = append(out, entry)
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

type telemetryStub struct {
	result  ports.HuntResult
	err     error
	queries []ports.HuntQuery
}

func (s *telemetryStub) Query(_ context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	s.queries = append(s.queries, q)
	return s.result, s.err
}
func huntContext(tenant shared.ID) context.Context {
	return shared.WithTenant(context.Background(), tenant)
}

func detectionRecord() detection.Record {
	evidence := detection.Event{
		Class: detection.ClassProcess, At: huntAt, Host: "host-1",
		Process: &detection.ProcessEvent{PID: 42, PPID: 1, Comm: "sh", Path: "/bin/sh", UID: 1000},
	}
	return detection.Record{
		ID: "detection-1", TenantID: "tenant-1", EngagementID: "engagement-1", AssetID: "asset-1",
		AgentID: "agent-1", EvidenceID: "evidence-1", BatchSeq: 7, RecordedAt: huntAt.Add(time.Minute),
		Detection: detection.Detection{
			RuleID: "rule.process", RuleVersion: 1, Class: detection.ClassProcess,
			Severity: shared.SeverityHigh, HostID: "host-1", AgentID: "agent-1",
			Evidence: []detection.Event{evidence}, ObservedCount: 1, Observed: huntAt,
		},
	}
}

func timelineEntry(eventID string, entityID shared.ID, at time.Time) endpoint.TimelineEntry {
	return endpoint.TimelineEntry{
		OccurredAt: at, TenantID: "tenant-1", AssetID: "asset-1", EntityKind: endpoint.EntityProcess,
		EntityID: entityID, Kind: endpoint.TimelineProcessExec, EventID: shared.ID(eventID), Summary: eventID,
	}
}

func TestAroundDetectionReturnsDeterministicLineageWindow(t *testing.T) {
	timeline := &timelineStub{entries: []endpoint.TimelineEntry{
		timelineEntry("event-parent", "entity-a", huntAt.Add(time.Minute)),
		timelineEntry("event-outside", "entity-z", huntAt.Add(-3*time.Minute)),
		timelineEntry("event-focus", "entity-z", huntAt.Add(-time.Minute)),
		timelineEntry("event-other", "entity-other", huntAt),
		timelineEntry("event-root", "entity-m", huntAt.Add(-2*time.Minute)),
	}}
	telemetry := &telemetryStub{result: ports.HuntResult{Complete: true, MaxSampleRate: 1, RowsScanned: 12}}
	service, err := NewService(timeline, telemetry, Config{Before: 2 * time.Minute, After: 3 * time.Minute, MaxEntries: 10})
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{
		Detection: detectionRecord(), EntityID: "entity-z",
		AncestorEntityIDs: []shared.ID{"entity-m", "entity-a", "entity-a"},
	})
	if err != nil {
		t.Fatalf("around detection: %v", err)
	}
	if !reflect.DeepEqual(result.EntityIDs, []shared.ID{"entity-a", "entity-m", "entity-z"}) {
		t.Fatalf("entity lineage is not canonical: %v", result.EntityIDs)
	}
	if len(result.Entries) != 3 || result.Entries[0].EventID != "event-root" ||
		result.Entries[1].EventID != "event-focus" || result.Entries[2].EventID != "event-parent" {
		t.Fatalf("timeline is not in deterministic event-time order: %+v", result.Entries)
	}
	if len(timeline.queries) != 3 {
		t.Fatalf("want one bounded query per canonical lineage entity, got %d", len(timeline.queries))
	}
	for index, query := range timeline.queries {
		if query.EntityID != result.EntityIDs[index] || query.Limit != 11 ||
			!query.From.Equal(huntAt.Add(-2*time.Minute)) || !query.To.Equal(huntAt.Add(3*time.Minute)) {
			t.Fatalf("unexpected timeline query %d: %+v", index, query)
		}
	}
	if len(telemetry.queries) != 1 {
		t.Fatalf("want one coverage query, got %d", len(telemetry.queries))
	}
	coverageQuery := telemetry.queries[0]
	if coverageQuery.Kind != ports.HuntContext || coverageQuery.HostID != "host-1" ||
		coverageQuery.AssetID != "asset-1" || coverageQuery.Limit != 1 {
		t.Fatalf("coverage query is not bound to the detection: %+v", coverageQuery)
	}
	if !result.Coverage.Complete || len(result.Coverage.Reasons) != 0 || !result.Coverage.TelemetryObserved {
		t.Fatalf("fully observed window must be complete: %+v", result.Coverage)
	}
}

func TestAroundDetectionAssetWidePivotUsesOneQuery(t *testing.T) {
	timeline := &timelineStub{entries: []endpoint.TimelineEntry{
		timelineEntry("event-b", "entity-b", huntAt), timelineEntry("event-a", "entity-a", huntAt),
	}}
	telemetry := &telemetryStub{result: ports.HuntResult{Complete: true, MaxSampleRate: 1, RowsScanned: 1}}
	service, _ := NewService(timeline, telemetry, Config{})
	result, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{Detection: detectionRecord()})
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.queries) != 1 || !timeline.queries[0].EntityID.IsZero() || len(result.EntityIDs) != 0 {
		t.Fatalf("asset-wide pivot issued unexpected queries: %+v", timeline.queries)
	}
	if len(result.Entries) != 2 || result.Entries[0].EventID != "event-a" || result.Entries[1].EventID != "event-b" {
		t.Fatalf("equal timestamps must use EventID tiebreak: %+v", result.Entries)
	}
	if !result.WindowStart.Equal(huntAt.Add(-DefaultBefore)) || !result.WindowEnd.Equal(huntAt.Add(DefaultAfter)) {
		t.Fatalf("default window was not applied: [%s,%s]", result.WindowStart, result.WindowEnd)
	}
}

func TestAroundDetectionReportsEveryCoverageGap(t *testing.T) {
	timeline := &timelineStub{entries: []endpoint.TimelineEntry{
		timelineEntry("event-c", "entity-a", huntAt.Add(time.Second)),
		timelineEntry("event-a", "entity-a", huntAt.Add(-time.Second)),
		timelineEntry("event-b", "entity-a", huntAt),
	}}
	telemetry := &telemetryStub{result: ports.HuntResult{
		Complete: true, Sampled: true, MaxSampleRate: 10, RowsScanned: 30,
		SequenceGaps: []ports.TelemetrySequenceGap{{HostID: "host-1", Class: detection.ClassProcess, Missing: 2}},
		Losses:       []ports.TelemetryLoss{{HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess}},
	}}
	record := detectionRecord()
	record.Detection.Truncated = true
	record.Detection.ObservedCount = 100
	service, _ := NewService(timeline, telemetry, Config{MaxEntries: 2})
	result, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{Detection: record, EntityID: "entity-a"})
	if err != nil {
		t.Fatal(err)
	}
	wantReasons := []CoverageReason{CoverageSampled, CoverageSequenceGap, CoverageLoss,
		CoverageTimelineTruncated, CoverageDetectionEvidenceTruncated}
	if result.Coverage.Complete || !reflect.DeepEqual(result.Coverage.Reasons, wantReasons) ||
		!result.Coverage.TimelineTruncated || len(result.Entries) != 2 {
		t.Fatalf("coverage gaps were not preserved: %+v entries=%v", result.Coverage, result.Entries)
	}
	if result.Entries[0].EventID != "event-a" || result.Entries[1].EventID != "event-b" {
		t.Fatalf("timeline cap must retain deterministic earliest entries: %+v", result.Entries)
	}
}

func TestAroundDetectionFailsClosed(t *testing.T) {
	validTimeline := &timelineStub{}
	validTelemetry := &telemetryStub{result: ports.HuntResult{Complete: true, MaxSampleRate: 1}}
	if _, err := NewService(nil, validTelemetry, Config{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil timeline must fail validation, got %v", err)
	}
	if _, err := NewService(validTimeline, nil, Config{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil telemetry must fail validation, got %v", err)
	}
	for name, config := range map[string]Config{
		"negative window": {Before: -time.Second}, "negative limit": {MaxEntries: -1},
		"oversized limit": {MaxEntries: maxEntries + 1},
	} {
		t.Run("config/"+name, func(t *testing.T) {
			if _, err := NewService(validTimeline, validTelemetry, config); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}

	service, _ := NewService(validTimeline, validTelemetry, Config{})
	tests := map[string]struct {
		ctx   context.Context
		pivot DetectionPivot
		want  error
	}{
		"nil context":    {ctx: nil, pivot: DetectionPivot{Detection: detectionRecord()}, want: shared.ErrValidation},
		"missing tenant": {ctx: context.Background(), pivot: DetectionPivot{Detection: detectionRecord()}, want: shared.ErrValidation},
		"cross tenant":   {ctx: huntContext("tenant-2"), pivot: DetectionPivot{Detection: detectionRecord()}, want: shared.ErrForbidden},
		"bad detection":  {ctx: huntContext("tenant-1"), pivot: DetectionPivot{Detection: detection.Record{}}, want: shared.ErrValidation},
		"lineage without focus": {
			ctx: huntContext("tenant-1"), pivot: DetectionPivot{Detection: detectionRecord(), AncestorEntityIDs: []shared.ID{"parent"}},
			want: shared.ErrValidation,
		},
		"empty ancestor": {
			ctx: huntContext("tenant-1"), pivot: DetectionPivot{Detection: detectionRecord(), EntityID: "focus", AncestorEntityIDs: []shared.ID{""}},
			want: shared.ErrValidation,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := service.AroundDetection(tc.ctx, tc.pivot); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}

	tooDeep := make([]shared.ID, maxLineageDepth+1)
	for index := range tooDeep {
		tooDeep[index] = shared.ID("ancestor-" + time.Duration(index).String())
	}
	if _, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{
		Detection: detectionRecord(), EntityID: "focus", AncestorEntityIDs: tooDeep,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbounded lineage must fail validation, got %v", err)
	}
}

func TestAroundDetectionPropagatesStoresAndRejectsCorruptRows(t *testing.T) {
	sentinel := errors.New("store unavailable")
	service, _ := NewService(&timelineStub{err: sentinel}, &telemetryStub{}, Config{})
	if _, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{Detection: detectionRecord()}); !errors.Is(err, sentinel) {
		t.Fatalf("timeline error lost: %v", err)
	}
	service, _ = NewService(&timelineStub{}, &telemetryStub{err: sentinel}, Config{})
	if _, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{Detection: detectionRecord()}); !errors.Is(err, sentinel) {
		t.Fatalf("telemetry error lost: %v", err)
	}

	bad := timelineEntry("event-1", "entity-a", huntAt)
	bad.TenantID = "tenant-2"
	service, _ = NewService(&timelineStub{entries: []endpoint.TimelineEntry{bad}}, &telemetryStub{}, Config{})
	if _, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{Detection: detectionRecord()}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant store row must fail closed, got %v", err)
	}

	first := timelineEntry("same-event", "entity-a", huntAt)
	second := timelineEntry("same-event", "entity-b", huntAt)
	second.Summary = "conflicting material"
	service, _ = NewService(&timelineStub{entries: []endpoint.TimelineEntry{first, second}}, &telemetryStub{}, Config{})
	if _, err := service.AroundDetection(huntContext("tenant-1"), DetectionPivot{
		Detection: detectionRecord(), EntityID: "entity-a", AncestorEntityIDs: []shared.ID{"entity-b"},
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting EventID material must fail closed, got %v", err)
	}
}

func TestCoverageUnknownIncompleteStateGetsReason(t *testing.T) {
	coverage := coverageFor(ports.HuntResult{Complete: false, MaxSampleRate: 1, RowsScanned: 1}, false, false)
	if coverage.Complete || !reflect.DeepEqual(coverage.Reasons, []CoverageReason{CoverageTelemetryIncomplete}) {
		t.Fatalf("unexplained incomplete telemetry must stay explicit: %+v", coverage)
	}
}

func TestCoverageCannotClaimCompleteAfterRawTelemetryExpires(t *testing.T) {
	coverage := coverageFor(ports.HuntResult{Complete: true, MaxSampleRate: 1, RowsScanned: 0}, false, false)
	if coverage.Complete || coverage.TelemetryObserved ||
		!reflect.DeepEqual(coverage.Reasons, []CoverageReason{CoverageTelemetryUnavailable}) {
		t.Fatalf("an empty telemetry window cannot prove completeness: %+v", coverage)
	}
}
