package correlation

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	asset  = shared.ID("asset-1")
	entity = shared.ID("pe-1")
)

var base = time.Unix(1_800_000_000, 0).UTC()

func at(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

func sig(id string, occ time.Time, sev shared.Severity) Signal {
	return Signal{ID: shared.ID(id), AssetID: asset, EntityID: entity, OccurredAt: occ, Severity: sev, Title: "t-" + id}
}

func cfg() Config { return Config{Window: time.Minute, MaxPerIncident: 100} }

// project groups events by incident and folds each — proves the correlator output is a valid C1 log.
func project(t *testing.T, events []incident.IncidentEvent) map[shared.ID]incident.Incident {
	t.Helper()
	byInc := map[shared.ID][]incident.IncidentEvent{}
	var order []shared.ID
	for _, e := range events {
		if _, ok := byInc[e.IncidentID]; !ok {
			order = append(order, e.IncidentID)
		}
		byInc[e.IncidentID] = append(byInc[e.IncidentID], e)
	}
	out := map[shared.ID]incident.Incident{}
	for _, id := range order {
		inc, err := incident.Project(byInc[id])
		if err != nil {
			t.Fatalf("project incident %s: %v", id, err)
		}
		out[id] = inc
	}
	return out
}

func TestCorrelateGroupsSessionIntoOneIncident(t *testing.T) {
	events, err := Correlate(cfg(), []Signal{
		sig("d1", at(0), shared.SeverityLow),
		sig("d2", at(10), shared.SeverityHigh),
		sig("d3", at(20), shared.SeverityMedium),
	})
	if err != nil {
		t.Fatal(err)
	}
	incs := project(t, events)
	if len(incs) != 1 {
		t.Fatalf("one session must be one incident, got %d", len(incs))
	}
	for _, inc := range incs {
		if len(inc.DetectionIDs) != 3 {
			t.Fatalf("all 3 detections must attach: %+v", inc.DetectionIDs)
		}
		if inc.Severity != shared.SeverityHigh {
			t.Fatalf("incident severity must be the session max (high): %q", inc.Severity)
		}
		if inc.State != incident.StateNew {
			t.Fatalf("correlated incident starts new, got %q", inc.State)
		}
	}
}

func TestCorrelateSplitsOnWindowGap(t *testing.T) {
	// A gap > Window (60s) starts a new incident.
	events, err := Correlate(cfg(), []Signal{
		sig("d1", at(0), shared.SeverityMedium),
		sig("d2", at(30), shared.SeverityMedium),
		sig("d3", at(200), shared.SeverityMedium), // 170s after d2 -> new session
	})
	if err != nil {
		t.Fatal(err)
	}
	if incs := project(t, events); len(incs) != 2 {
		t.Fatalf("a window gap must split into 2 incidents, got %d", len(incs))
	}
}

func TestCorrelateDistinctEntitiesAreDistinctIncidents(t *testing.T) {
	other := Signal{ID: "d2", AssetID: asset, EntityID: "pe-2", OccurredAt: at(1), Severity: shared.SeverityLow, Title: "t"}
	events, err := Correlate(cfg(), []Signal{sig("d1", at(0), shared.SeverityLow), other})
	if err != nil {
		t.Fatal(err)
	}
	if incs := project(t, events); len(incs) != 2 {
		t.Fatalf("distinct entities must be distinct incidents, got %d", len(incs))
	}
}

func TestCorrelateIsOrderInvariantAndDedupes(t *testing.T) {
	forward := []Signal{sig("d1", at(0), shared.SeverityLow), sig("d2", at(10), shared.SeverityHigh), sig("d3", at(20), shared.SeverityLow)}
	reverse := []Signal{sig("d3", at(20), shared.SeverityLow), sig("d2", at(10), shared.SeverityHigh), sig("d1", at(0), shared.SeverityLow), sig("d2", at(10), shared.SeverityHigh)} // reversed + a duplicate d2
	a, err1 := Correlate(cfg(), forward)
	b, err2 := Correlate(cfg(), reverse)
	if err1 != nil || err2 != nil {
		t.Fatalf("errs: %v %v", err1, err2)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("correlation must be order-invariant + deduped:\n a=%+v\n b=%+v", a, b)
	}
	for _, inc := range project(t, a) {
		if len(inc.DetectionIDs) != 3 {
			t.Fatalf("duplicate signal must not double-attach: %+v", inc.DetectionIDs)
		}
	}
}

func TestCorrelateAntiStorm(t *testing.T) {
	c := Config{Window: time.Minute, MaxPerIncident: 3}
	var signals []Signal
	for i := 0; i < 10; i++ {
		signals = append(signals, sig("d"+string(rune('0'+i)), at(i), shared.SeverityMedium))
	}
	events, err := Correlate(c, signals)
	if err != nil {
		t.Fatal(err)
	}
	incs := project(t, events)
	if len(incs) != 1 {
		t.Fatalf("one storm session is one incident, got %d", len(incs))
	}
	for _, inc := range incs {
		// Created(1) + 2 attaches = 3 individually reflected; the other 7 are suppressed.
		if len(inc.DetectionIDs) != 3 {
			t.Fatalf("anti-storm must cap attaches at MaxPerIncident, got %d", len(inc.DetectionIDs))
		}
		if len(inc.Comments) != 1 {
			t.Fatalf("suppression must be recorded as one note (coverage honesty), got %d", len(inc.Comments))
		}
	}
}

func TestCorrelateDeterministicIncidentID(t *testing.T) {
	a, _ := Correlate(cfg(), []Signal{sig("d1", at(0), shared.SeverityLow)})
	b, _ := Correlate(cfg(), []Signal{sig("d1", at(0), shared.SeverityLow)})
	if a[0].IncidentID != b[0].IncidentID || a[0].IncidentID.IsZero() {
		t.Fatalf("incident id must be deterministic + non-zero: %s vs %s", a[0].IncidentID, b[0].IncidentID)
	}
}

func TestCorrelateValidatesConfigAndSignals(t *testing.T) {
	if _, err := Correlate(Config{Window: 0, MaxPerIncident: 1}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("zero window must be rejected")
	}
	if _, err := Correlate(Config{Window: time.Minute, MaxPerIncident: 0}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("zero max-per-incident must be rejected")
	}
	if _, err := Correlate(cfg(), []Signal{{AssetID: asset, OccurredAt: at(0)}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("signal without id must be rejected")
	}
	// Empty input is valid: no incidents.
	if evs, err := Correlate(cfg(), nil); err != nil || len(evs) != 0 {
		t.Fatalf("empty input: evs=%d err=%v", len(evs), err)
	}
}

func TestCorrelateDedupeFoldsToMaxSeverity(t *testing.T) {
	// The same detection id re-emitted with a higher severity (an escalation) must not be lost to dedupe.
	forward := []Signal{sig("d1", at(0), shared.SeverityLow), sig("d1", at(0), shared.SeverityCritical)}
	reverse := []Signal{sig("d1", at(0), shared.SeverityCritical), sig("d1", at(0), shared.SeverityLow)}
	a, err := Correlate(cfg(), forward)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Correlate(cfg(), reverse)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("escalation fold must be order-invariant")
	}
	inc := project(t, a)
	for _, i := range inc {
		if i.Severity != shared.SeverityCritical {
			t.Fatalf("escalated duplicate must raise severity to critical, got %q", i.Severity)
		}
		if len(i.DetectionIDs) != 1 {
			t.Fatalf("same id must fold to one detection, got %+v", i.DetectionIDs)
		}
	}
}

func TestCorrelateTitleFallsBackToRuleID(t *testing.T) {
	s := Signal{ID: "d1", AssetID: asset, EntityID: entity, OccurredAt: at(0), Severity: shared.SeverityHigh, RuleID: "T1059.exec"}
	events, err := Correlate(cfg(), []Signal{s})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Title != "T1059.exec" {
		t.Fatalf("empty title must fall back to rule id, got %q", events[0].Title)
	}
}
