package correlationuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDetections struct{ recs []detection.Record }

func (f fakeDetections) ListDetections(context.Context, shared.ID) ([]detection.Record, error) {
	return f.recs, nil
}

// fakeIncidents records correlator output into an in-memory map, honoring RecordCorrelation's batch
// idempotency (an incident id seen before is skipped).
type fakeIncidents struct{ seen map[shared.ID]bool }

func (f *fakeIncidents) RecordCorrelation(_ context.Context, events []incident.IncidentEvent) ([]incident.Incident, error) {
	if f.seen == nil {
		f.seen = map[shared.ID]bool{}
	}
	var created []incident.Incident
	for _, e := range events {
		if f.seen[e.IncidentID] {
			continue
		}
		f.seen[e.IncidentID] = true
		created = append(created, incident.Incident{ID: e.IncidentID, State: incident.StateOpen})
	}
	return created, nil
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
	return detection.Record{
		ID: shared.ID(id), AssetID: "asset-1",
		Detection: detection.Detection{RuleID: "r1", RuleVersion: 1, Class: detection.ClassProcess, Severity: shared.SeverityHigh, HostID: shared.ID(host), Observed: at},
	}
}

func newSvc(t *testing.T, dets []detection.Record, re RiskReassessor) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	s, err := NewService(fakeDetections{recs: dets}, &fakeIncidents{}, re, correlation.Config{Window: time.Hour, MaxPerIncident: 50}, audit, func() time.Time { return time.Unix(0, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return s, audit
}

func TestCorrelateCreatesAndReassesses(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	// Two detections on the same host within the window → one incident.
	dets := []detection.Record{rec("d1", "host-1", base), rec("d2", "host-1", base.Add(time.Minute))}
	re := &fakeReassessor{}
	s, audit := newSvc(t, dets, re)

	res, err := s.CorrelateEngagement(context.Background(), "operator", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 {
		t.Fatalf("two same-host detections in-window must yield one incident, got %d", len(res.Created))
	}
	if res.Reassessed != 1 || res.ReassessFailed != 0 || re.calls != 1 {
		t.Fatalf("the created incident must be auto-reassessed once: %+v calls=%d", res, re.calls)
	}
	if audit.n != 1 {
		t.Fatalf("correlation must be audited once, got %d", audit.n)
	}
}

func TestReassessFailureIsCountedNotFatal(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	s, _ := newSvc(t, []detection.Record{rec("d1", "host-1", base)}, &fakeReassessor{err: errors.New("scorer down")})
	res, err := s.CorrelateEngagement(context.Background(), "operator", "eng-1")
	if err != nil {
		t.Fatalf("a reassess failure must NOT fail correlation (the incident is durably recorded): %v", err)
	}
	if len(res.Created) != 1 || res.Reassessed != 0 || res.ReassessFailed != 1 {
		t.Fatalf("a scoring failure must be counted, not fatal: %+v", res)
	}
}

func TestNilReassessorRecordsWithoutScoring(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	s, _ := newSvc(t, []detection.Record{rec("d1", "host-1", base)}, nil)
	res, err := s.CorrelateEngagement(context.Background(), "operator", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 || res.Reassessed != 0 || res.ReassessFailed != 0 {
		t.Fatalf("nil reassessor must record incidents without scoring: %+v", res)
	}
}

func TestValidation(t *testing.T) {
	if _, err := NewService(fakeDetections{}, &fakeIncidents{}, nil, correlation.Config{Window: 0, MaxPerIncident: 1}, &fakeAudit{}, func() time.Time { return time.Now() }); err == nil {
		t.Fatal("a non-positive window must be rejected")
	}
}
