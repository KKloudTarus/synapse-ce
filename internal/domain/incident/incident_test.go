package incident

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	incID   = shared.ID("inc-1")
	assetID = shared.ID("asset-1")
)

var base = time.Unix(1_800_000_000, 0).UTC()

func at(n int) time.Time { return base.Add(time.Duration(n) * time.Second) }

func created(det shared.ID) IncidentEvent {
	return IncidentEvent{IncidentID: incID, Kind: EventCreated, At: at(0), Actor: "correlator",
		AssetID: assetID, Title: "suspicious exec", Severity: shared.SeverityHigh, DetectionID: det}
}

func TestProjectCreatedOpensIncident(t *testing.T) {
	inc, err := Project([]IncidentEvent{created("det-1")})
	if err != nil {
		t.Fatal(err)
	}
	if inc.ID != incID || inc.AssetID != assetID || inc.State != StateNew || inc.Disposition != DispositionUnknown {
		t.Fatalf("created projection wrong: %+v", inc)
	}
	if inc.Revision != 1 || len(inc.DetectionIDs) != 1 || inc.DetectionIDs[0] != "det-1" {
		t.Fatalf("created detection/revision wrong: %+v", inc)
	}
	if !inc.CreatedAt.Equal(at(0)) || !inc.UpdatedAt.Equal(at(0)) {
		t.Fatalf("created timestamps wrong: %+v", inc)
	}
}

func TestProjectFullLifecycle(t *testing.T) {
	risk := &riskassessment.RiskAssessment{
		AssessmentID: "ra-1", ScorerVersion: "v1", PolicyVersion: "p1",
		Risk: 88, Confidence: 61, Coverage: 43,
	}
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventDetectionAttached, At: at(1), Actor: "correlator", DetectionID: "det-2"},
		{IncidentID: incID, Kind: EventStatusChanged, At: at(2), Actor: "alice", To: StateInvestigating},
		{IncidentID: incID, Kind: EventOwnerChanged, At: at(3), Actor: "alice", Owner: "alice"},
		{IncidentID: incID, Kind: EventRiskReassessed, At: at(4), Actor: "scorer", Risk: risk},
		{IncidentID: incID, Kind: EventAnalystCommented, At: at(5), Actor: "alice", Comment: "looks real"},
		{IncidentID: incID, Kind: EventStatusChanged, At: at(6), Actor: "alice", To: StateContained},
		{IncidentID: incID, Kind: EventDispositionSet, At: at(7), Actor: "alice", Disposition: DispositionTruePositive},
		{IncidentID: incID, Kind: EventStatusChanged, At: at(8), Actor: "alice", To: StateResolved},
		{IncidentID: incID, Kind: EventStatusChanged, At: at(9), Actor: "alice", To: StateClosed},
	}
	inc, err := Project(events)
	if err != nil {
		t.Fatal(err)
	}
	if inc.State != StateClosed || inc.Disposition != DispositionTruePositive || inc.OwnerID != "alice" {
		t.Fatalf("lifecycle end state wrong: %+v", inc)
	}
	if len(inc.DetectionIDs) != 2 || inc.Risk == nil || inc.Risk.Risk != 88 || inc.Risk.Coverage != 43 {
		t.Fatalf("detections/risk wrong: %+v", inc)
	}
	if len(inc.Comments) != 1 || inc.Comments[0].Actor != "alice" {
		t.Fatalf("comments wrong: %+v", inc.Comments)
	}
	if inc.Revision != len(events) || !inc.UpdatedAt.Equal(at(9)) {
		t.Fatalf("revision/updated wrong: rev=%d", inc.Revision)
	}
	// State, Disposition, and Risk are independent: closed + true_positive + risk still 88.
	if inc.Risk.Risk != 88 {
		t.Fatal("risk must not be mutated by state/disposition changes")
	}
}

func TestProjectIsReplayDeterministic(t *testing.T) {
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventStatusChanged, At: at(1), Actor: "a", To: StateTriaged},
		{IncidentID: incID, Kind: EventStatusChanged, At: at(2), Actor: "a", To: StateInvestigating},
	}
	a, err1 := Project(events)
	b, err2 := Project(events)
	if err1 != nil || err2 != nil {
		t.Fatalf("errs: %v %v", err1, err2)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("replay must be deterministic")
	}
}

func TestProjectRejectsIllegalTransition(t *testing.T) {
	// new -> resolved is not legal (must pass through investigation/containment).
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventStatusChanged, At: at(1), Actor: "a", To: StateResolved},
	}
	if _, err := Project(events); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("illegal transition must be rejected, got %v", err)
	}
}

func TestProjectDetachAndDedupDetections(t *testing.T) {
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventDetectionAttached, At: at(1), Actor: "c", DetectionID: "det-2"},
		{IncidentID: incID, Kind: EventDetectionAttached, At: at(2), Actor: "c", DetectionID: "det-2"}, // dup no-op
		{IncidentID: incID, Kind: EventDetectionDetached, At: at(3), Actor: "c", DetectionID: "det-1"},
	}
	inc, err := Project(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(inc.DetectionIDs) != 1 || inc.DetectionIDs[0] != "det-2" {
		t.Fatalf("detach/dedup wrong: %+v", inc.DetectionIDs)
	}
}

func TestProjectResponseRefs(t *testing.T) {
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventStatusChanged, At: at(1), Actor: "a", To: StateInvestigating},
		{IncidentID: incID, Kind: EventResponseRequested, At: at(2), Actor: "a", ResponseActionID: "act-1"},
		{IncidentID: incID, Kind: EventResponseVerified, At: at(3), Actor: "agent", ResponseActionID: "act-1"},
		{IncidentID: incID, Kind: EventResponseVerified, At: at(4), Actor: "agent", ResponseActionID: "act-2"}, // verify w/o request → upsert
	}
	inc, err := Project(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(inc.Responses) != 2 {
		t.Fatalf("responses wrong: %+v", inc.Responses)
	}
	if !inc.Responses[0].Verified || inc.Responses[0].ActionID != "act-1" {
		t.Fatalf("act-1 must be verified: %+v", inc.Responses)
	}
	if !inc.Responses[1].Verified || inc.Responses[1].ActionID != "act-2" {
		t.Fatalf("act-2 upsert-verified: %+v", inc.Responses)
	}
}

func TestProjectMerged(t *testing.T) {
	events := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventMerged, At: at(1), Actor: "correlator", MergedInto: "inc-2"},
	}
	inc, err := Project(events)
	if err != nil {
		t.Fatal(err)
	}
	if !inc.IsMerged() || inc.MergedInto != "inc-2" {
		t.Fatalf("merged wrong: %+v", inc)
	}
}

func TestProjectFailsClosed(t *testing.T) {
	cases := map[string][]IncidentEvent{
		"empty": {},
		"first not created": {
			{IncidentID: incID, Kind: EventStatusChanged, At: at(0), Actor: "a", To: StateOpen},
		},
		"second created": {
			created("det-1"),
			{IncidentID: incID, Kind: EventCreated, At: at(1), Actor: "a", AssetID: assetID},
		},
		"wrong incident id": {
			created("det-1"),
			{IncidentID: "inc-other", Kind: EventAnalystCommented, At: at(1), Actor: "a", Comment: "x"},
		},
		"invalid event (no actor)": {
			{IncidentID: incID, Kind: EventCreated, At: at(0), AssetID: assetID},
		},
	}
	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Project(events); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("must fail closed, got %v", err)
			}
		})
	}
}

func TestIncidentEventValidatePerKind(t *testing.T) {
	ok := func(e IncidentEvent) IncidentEvent { e.IncidentID = incID; e.At = at(0); e.Actor = "a"; return e }
	bad := map[string]IncidentEvent{
		"created no asset":     ok(IncidentEvent{Kind: EventCreated}),
		"created bad severity": ok(IncidentEvent{Kind: EventCreated, AssetID: assetID, Severity: "nope"}),
		"attach no detection":  ok(IncidentEvent{Kind: EventDetectionAttached}),
		"status invalid":       ok(IncidentEvent{Kind: EventStatusChanged, To: "nope"}),
		"owner empty":          ok(IncidentEvent{Kind: EventOwnerChanged}),
		"disposition invalid":  ok(IncidentEvent{Kind: EventDispositionSet, Disposition: "nope"}),
		"risk nil":             ok(IncidentEvent{Kind: EventRiskReassessed}),
		"comment empty":        ok(IncidentEvent{Kind: EventAnalystCommented}),
		"merged no target":     ok(IncidentEvent{Kind: EventMerged}),
		"response no id":       ok(IncidentEvent{Kind: EventResponseRequested}),
		"unknown kind":         ok(IncidentEvent{Kind: "wat"}),
		"no incident id":       {Kind: EventCreated, At: at(0), Actor: "a", AssetID: assetID},
		"no timestamp":         {IncidentID: incID, Kind: EventCreated, Actor: "a", AssetID: assetID},
	}
	for name, e := range bad {
		if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s must be rejected, got %v", name, err)
		}
	}
	// A valid risk_reassessed with an INVALID assessment is rejected (delegates to RiskAssessment.Validate).
	e := ok(IncidentEvent{Kind: EventRiskReassessed, Risk: &riskassessment.RiskAssessment{AssessmentID: "r", ScorerVersion: "v", PolicyVersion: "p", Risk: 200}})
	if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("risk with out-of-range score must be rejected, got %v", err)
	}
}

func TestProjectRejectsBackdatedEvent(t *testing.T) {
	events := []IncidentEvent{
		created("det-1"), // at(0)
		{IncidentID: incID, Kind: EventStatusChanged, At: at(5), Actor: "a", To: StateInvestigating},  // at(5)
		{IncidentID: incID, Kind: EventAnalystCommented, At: at(2), Actor: "a", Comment: "backdated"}, // at(2) < at(5)
	}
	if _, err := Project(events); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a backdated event must be rejected, got %v", err)
	}
	// Equal timestamps are allowed (two changes in the same instant).
	ok := []IncidentEvent{
		created("det-1"),
		{IncidentID: incID, Kind: EventOwnerChanged, At: at(0), Actor: "a", Owner: "alice"},
	}
	if _, err := Project(ok); err != nil {
		t.Fatalf("equal timestamps must be allowed, got %v", err)
	}
}
