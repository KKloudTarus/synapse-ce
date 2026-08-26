package riskscoreuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeIncidents struct {
	inc         incident.Incident
	getErr      error
	appendErr   error
	appended    []incident.IncidentEvent
	appendedRev int
}

func (f *fakeIncidents) Get(_ context.Context, _ shared.ID) (incident.Incident, error) {
	if f.getErr != nil {
		return incident.Incident{}, f.getErr
	}
	return f.inc, nil
}

func (f *fakeIncidents) Append(_ context.Context, id shared.ID, expectedRevision int, events []incident.IncidentEvent) (incident.Incident, error) {
	if f.appendErr != nil {
		return incident.Incident{}, f.appendErr
	}
	f.appended = events
	f.appendedRev = expectedRevision
	updated := f.inc
	if len(events) > 0 && events[0].Risk != nil {
		r := *events[0].Risk
		updated.Risk = &r
		updated.Revision = expectedRevision + len(events)
	}
	return updated, nil
}

type fakeFactor struct {
	f   FactorInput
	err error
}

func (x fakeFactor) ExposureFor(_ context.Context, _ shared.ID) (FactorInput, error) {
	return x.f, x.err
}
func (x fakeFactor) BehaviorFor(_ context.Context, _ shared.ID) (FactorInput, error) {
	return x.f, x.err
}

type fakeCoverage struct {
	cc  []detection.ClassCoverage
	err error
}

func (c fakeCoverage) ClassCoverageForAsset(_ context.Context, _ shared.ID) ([]detection.ClassCoverage, error) {
	return c.cc, c.err
}

type fakeAudit struct{ n int }

func (a *fakeAudit) Record(_ context.Context, _ ports.AuditEntry) error { a.n++; return nil }

type fixedIDs struct{}

func (fixedIDs) NewID() shared.ID { return "assess-1" }

func fullCoverage() []detection.ClassCoverage {
	out := make([]detection.ClassCoverage, 0, 4)
	for _, cl := range detection.Classes() {
		out = append(out, detection.ClassCoverage{Class: cl, State: detection.StateActive})
	}
	return out
}

func newSvc(t *testing.T, inc *fakeIncidents, exp, beh fakeFactor, cov fakeCoverage) (*Service, *fakeAudit) {
	t.Helper()
	scorer, err := riskassessment.NewScorer(riskassessment.DefaultPolicy())
	if err != nil {
		t.Fatalf("scorer: %v", err)
	}
	audit := &fakeAudit{}
	svc, err := NewService(inc, exp, beh, cov, scorer, audit, fixedIDs{}, func() time.Time { return time.Unix(1_800_000_000, 0).UTC() })
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, audit
}

func baseIncident() incident.Incident {
	return incident.Incident{ID: "inc-1", AssetID: "asset-1", Severity: shared.SeverityHigh, State: incident.StateOpen, Revision: 3}
}

func TestReassessHappyPath(t *testing.T) {
	inc := &fakeIncidents{inc: baseIncident()}
	exp := fakeFactor{f: FactorInput{Score: 60, Scoreable: true}}
	beh := fakeFactor{f: FactorInput{Score: 40, Scoreable: true}}
	svc, audit := newSvc(t, inc, exp, beh, fakeCoverage{cc: fullCoverage()})

	updated, err := svc.Reassess(context.Background(), "analyst", "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Risk == nil {
		t.Fatal("incident.Risk must be populated")
	}
	// Threat(high=80) dominates the weighted sum; Risk must be > 0 and in range.
	if !updated.Risk.Risk.Valid() || updated.Risk.Risk == 0 {
		t.Fatalf("risk must be a positive valid score, got %d", updated.Risk.Risk)
	}
	// Full coverage + all three factors present => high coverage/confidence.
	if updated.Risk.Coverage != 100 {
		t.Fatalf("full class coverage must yield Coverage 100, got %d", updated.Risk.Coverage)
	}
	// Appended under the incident's current revision, as a risk_reassessed event, attributed to the actor.
	if inc.appendedRev != 3 || len(inc.appended) != 1 || inc.appended[0].Kind != incident.EventRiskReassessed || inc.appended[0].Actor != "analyst" {
		t.Fatalf("append wrong: rev=%d events=%+v", inc.appendedRev, inc.appended)
	}
	if audit.n != 1 {
		t.Fatalf("reassessment must be audited once, got %d", audit.n)
	}
}

func TestReassessAbstainingFactorsLowerCoverageNotThreat(t *testing.T) {
	inc := &fakeIncidents{inc: baseIncident()}
	// Exposure + Behavior abstain; only Threat contributes.
	exp := fakeFactor{f: FactorInput{Scoreable: false, Reasons: []string{"no inventory data"}}}
	beh := fakeFactor{f: FactorInput{Scoreable: false}}
	svc, _ := newSvc(t, inc, exp, beh, fakeCoverage{cc: fullCoverage()})

	updated, err := svc.Reassess(context.Background(), "analyst", "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	// Threat (high) still drives a real Risk — a missing factor never lowers Risk.
	if updated.Risk.Risk == 0 {
		t.Fatal("threat alone must still produce a non-zero Risk")
	}
	// The abstain reasons must surface as ReasonCodes on the assessment.
	joined := ""
	for _, r := range updated.Risk.ReasonCodes {
		joined += r + "|"
	}
	if joined == "" {
		t.Fatal("abstaining factors must contribute reason codes")
	}
}

func TestReassessCoverageGapLowersCoverage(t *testing.T) {
	inc := &fakeIncidents{inc: baseIncident()}
	exp := fakeFactor{f: FactorInput{Score: 60, Scoreable: true}}
	beh := fakeFactor{f: FactorInput{Score: 40, Scoreable: true}}
	// Network class is a gap.
	cc := []detection.ClassCoverage{
		{Class: detection.ClassProcess, State: detection.StateActive},
		{Class: detection.ClassNetwork, State: detection.StateDegraded, Reason: "sensor degraded"},
		{Class: detection.ClassFile, State: detection.StateActive},
		{Class: detection.ClassPrivilege, State: detection.StateActive},
	}
	svc, _ := newSvc(t, inc, exp, beh, fakeCoverage{cc: cc})
	updated, err := svc.Reassess(context.Background(), "analyst", "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	// Coverage floor is the weakest class (network gap = 0), so Coverage must be 0.
	if updated.Risk.Coverage != 0 {
		t.Fatalf("a class gap must drop Coverage to the floor (0), got %d", updated.Risk.Coverage)
	}
	// Risk (from Threat/Exposure/Behavior) is unaffected by the coverage gap.
	if updated.Risk.Risk == 0 {
		t.Fatal("coverage gap must not zero Risk")
	}
}

func TestCoverageVectorDedupGapPreferringAndMissingClasses(t *testing.T) {
	// Duplicate network records (gap then active): the gap must NOT be erased.
	dup := []detection.ClassCoverage{
		{Class: detection.ClassNetwork, State: detection.StateDegraded, Reason: "degraded"},
		{Class: detection.ClassNetwork, State: detection.StateActive},
	}
	v := coverageVector(dup)
	if v.Network != 0 {
		t.Fatalf("a duplicate must not upgrade a network gap to observing, got %d", v.Network)
	}
	// Only network was reported; the other three classes are absent -> 0 with a "no report" reason each.
	if v.Process != 0 || v.File != 0 || v.Privilege != 0 {
		t.Fatalf("unreported classes must be 0, got %+v", v)
	}
	if len(v.Reasons) != 4 {
		t.Fatalf("every non-observing class (all 4 here) must carry a reason, got %d: %v", len(v.Reasons), v.Reasons)
	}
	// Reverse duplicate order (active then gap) is identical (deterministic, gap-preferring).
	rev := []detection.ClassCoverage{dup[1], dup[0]}
	if coverageVector(rev).Network != 0 {
		t.Fatal("dedup must be order-independent (gap wins regardless of order)")
	}
}

func TestReassessValidationAndErrorPropagation(t *testing.T) {
	inc := &fakeIncidents{inc: baseIncident()}
	exp := fakeFactor{f: FactorInput{Score: 10, Scoreable: true}}
	beh := fakeFactor{f: FactorInput{Score: 10, Scoreable: true}}
	svc, _ := newSvc(t, inc, exp, beh, fakeCoverage{cc: fullCoverage()})

	if _, err := svc.Reassess(context.Background(), "", "inc-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty actor must be rejected")
	}
	if _, err := svc.Reassess(context.Background(), "a", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty incident id must be rejected")
	}
	// A factor error propagates.
	boom := errors.New("db down")
	svc2, _ := newSvc(t, &fakeIncidents{inc: baseIncident()}, fakeFactor{err: boom}, beh, fakeCoverage{cc: fullCoverage()})
	if _, err := svc2.Reassess(context.Background(), "a", "inc-1"); !errors.Is(err, boom) {
		t.Fatalf("exposure error must propagate, got %v", err)
	}
	// A Get error propagates.
	svc3, _ := newSvc(t, &fakeIncidents{getErr: shared.ErrNotFound}, exp, beh, fakeCoverage{cc: fullCoverage()})
	if _, err := svc3.Reassess(context.Background(), "a", "inc-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get error must propagate, got %v", err)
	}
}

func TestNewServiceValidation(t *testing.T) {
	scorer, _ := riskassessment.NewScorer(riskassessment.DefaultPolicy())
	inc := &fakeIncidents{}
	exp := fakeFactor{}
	beh := fakeFactor{}
	cov := fakeCoverage{}
	audit := &fakeAudit{}
	now := func() time.Time { return time.Unix(1, 0) }
	if _, err := NewService(nil, exp, beh, cov, scorer, audit, fixedIDs{}, now); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil incidents rejected")
	}
	if _, err := NewService(inc, exp, beh, cov, nil, audit, fixedIDs{}, now); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil scorer rejected")
	}
	if _, err := NewService(inc, exp, beh, cov, scorer, audit, fixedIDs{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil clock rejected")
	}
}
