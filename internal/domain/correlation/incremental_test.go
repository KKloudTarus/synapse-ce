package correlation

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func incrementalCfg() Config {
	return Config{Window: time.Minute, AllowedLateness: 30 * time.Second, MaxPerIncident: 3}
}

func applyPlan(state State, plan IncrementalPlan) State {
	state.Checkpoint = plan.Next
	known := state.KnownSignalIDs
	if known == nil {
		known = make(map[shared.ID]struct{}, len(plan.Added))
	}
	for _, assignment := range plan.Added {
		known[assignment.SignalID] = struct{}{}
	}
	state.KnownSignalIDs = known
	state.ActiveSessions = append([]ActiveSession(nil), plan.ActiveSessions...)
	return state
}

func TestCorrelateIncrementalRevisesIncidentWithinAllowedLateness(t *testing.T) {
	cfg := incrementalCfg()
	processed := at(200)
	first, err := CorrelateIncremental(cfg, State{}, []Signal{
		sig("d1", at(100), shared.SeverityLow),
		sig("d3", at(140), shared.SeverityMedium),
	}, processed)
	if err != nil {
		t.Fatal(err)
	}
	state := applyPlan(State{}, first)
	late, err := CorrelateIncremental(cfg, state, []Signal{
		sig("d3", at(140), shared.SeverityMedium),
		sig("d2", at(115), shared.SeverityHigh),
	}, processed.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if late.TooLate != 0 || len(late.Added) != 1 || late.Added[0].IncidentID != first.Added[0].IncidentID {
		t.Fatalf("within-lateness signal must revise the existing incident: first=%+v late=%+v", first, late)
	}
	if len(late.Events) != 2 || late.Events[0].Kind != incident.EventDetectionAttached || late.Events[1].Kind != incident.EventSeverityChanged {
		t.Fatalf("late high-severity signal must attach and revise severity: %+v", late.Events)
	}
	if !late.Events[0].At.Equal(processed.Add(time.Second)) {
		t.Fatalf("revision must use causal processing time, got %s", late.Events[0].At)
	}
}

func TestCorrelateIncrementalTooLateIsVisibleAndIsolated(t *testing.T) {
	cfg := incrementalCfg()
	first, err := CorrelateIncremental(cfg, State{}, []Signal{sig("d1", at(100), shared.SeverityLow), sig("d2", at(140), shared.SeverityLow)}, at(150))
	if err != nil {
		t.Fatal(err)
	}
	state := applyPlan(State{}, first)
	plan, err := CorrelateIncremental(cfg, state, []Signal{sig("old", at(90), shared.SeverityHigh)}, at(160))
	if err != nil {
		t.Fatal(err)
	}
	if plan.TooLate != 1 || len(plan.Added) != 1 || plan.Added[0].Outcome != AssignmentTooLate {
		t.Fatalf("old signal must be classified too late: %+v", plan)
	}
	if plan.Added[0].IncidentID == first.Added[0].IncidentID {
		t.Fatal("too-late signal must not rewrite the finalized session")
	}
	if len(plan.Events) != 2 || plan.Events[0].Kind != incident.EventCreated || !strings.Contains(plan.Events[1].Comment, "arrived behind watermark") {
		t.Fatalf("too-late signal must produce a visible coverage note: %+v", plan.Events)
	}
}

func TestCorrelateIncrementalWatermarkBoundaryIsInclusive(t *testing.T) {
	cfg := incrementalCfg()
	first, err := CorrelateIncremental(cfg, State{}, []Signal{
		sig("d1", at(100), shared.SeverityLow),
		sig("d2", at(140), shared.SeverityLow),
	}, at(150))
	if err != nil {
		t.Fatal(err)
	}
	state := applyPlan(State{}, first)
	atBoundary, err := CorrelateIncremental(cfg, state, []Signal{sig("boundary", at(110), shared.SeverityLow)}, at(160))
	if err != nil {
		t.Fatal(err)
	}
	if atBoundary.TooLate != 0 || len(atBoundary.Added) != 1 || atBoundary.Added[0].Outcome != AssignmentAttached {
		t.Fatalf("signal exactly at watermark must remain eligible: %+v", atBoundary)
	}
	beforeBoundary, err := CorrelateIncremental(cfg, state, []Signal{{
		ID: "before", AssetID: asset, EntityID: entity, OccurredAt: at(110).Add(-time.Nanosecond), Severity: shared.SeverityLow,
	}}, at(160))
	if err != nil {
		t.Fatal(err)
	}
	if beforeBoundary.TooLate != 1 || len(beforeBoundary.Added) != 1 || beforeBoundary.Added[0].Outcome != AssignmentTooLate {
		t.Fatalf("signal before watermark must be isolated: %+v", beforeBoundary)
	}
}

func TestCorrelateIncrementalIsDeterministicAndDedupesAcrossRuns(t *testing.T) {
	input := []Signal{sig("d3", at(20), shared.SeverityLow), sig("d1", at(0), shared.SeverityLow), sig("d2", at(10), shared.SeverityHigh), sig("d2", at(10), shared.SeverityHigh)}
	reversed := []Signal{input[2], input[1], input[0]}
	a, err := CorrelateIncremental(incrementalCfg(), State{}, input, at(100))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CorrelateIncremental(incrementalCfg(), State{}, reversed, at(100))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("arrival permutation changed plan:\na=%+v\nb=%+v", a, b)
	}
	state := applyPlan(State{}, a)
	again, err := CorrelateIncremental(incrementalCfg(), state, input, at(101))
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Added) != 0 || len(again.Events) != 0 || again.Changed(state.Checkpoint) {
		t.Fatalf("replay must be a no-op: %+v", again)
	}
}

func TestCorrelateIncrementalBridgeSelectionIsDeterministic(t *testing.T) {
	cfg := Config{Window: time.Minute, AllowedLateness: 10 * time.Minute, MaxPerIncident: 10}
	first, err := CorrelateIncremental(cfg, State{}, []Signal{
		sig("left", at(1), shared.SeverityLow),
		sig("right", at(121), shared.SeverityLow),
	}, at(130))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Added) != 2 || first.Added[0].IncidentID == first.Added[1].IncidentID {
		t.Fatalf("initial gap must create two sessions: %+v", first.Added)
	}
	state := applyPlan(State{}, first)
	bridge := []Signal{sig("bridge", at(61), shared.SeverityHigh)}
	a, err := CorrelateIncremental(cfg, state, bridge, at(131))
	if err != nil {
		t.Fatal(err)
	}
	reversed := state
	reversed.ActiveSessions = append([]ActiveSession(nil), state.ActiveSessions...)
	reversed.ActiveSessions[0], reversed.ActiveSessions[1] = reversed.ActiveSessions[1], reversed.ActiveSessions[0]
	b, err := CorrelateIncremental(cfg, reversed, bridge, at(131))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(a.Added) != 1 {
		t.Fatalf("bridge selection must not depend on persisted assignment order:\na=%+v\nb=%+v", a, b)
	}
	canonical := first.Added[0].IncidentID
	merged := first.Added[1].IncidentID
	if merged < canonical {
		canonical, merged = merged, canonical
	}
	if a.Added[0].IncidentID != canonical {
		t.Fatalf("bridge incident = %s, want canonical %s", a.Added[0].IncidentID, canonical)
	}
	if len(a.Events) < 2 || a.Events[0].Kind != incident.EventMerged || a.Events[0].IncidentID != merged || a.Events[0].MergedInto != canonical {
		t.Fatalf("bridge must durably merge the second logical session: %+v", a.Events)
	}
	state = applyPlan(state, a)
	after, err := CorrelateIncremental(cfg, state, []Signal{sig("after", at(122), shared.SeverityLow)}, at(132))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Added) != 1 || after.Added[0].IncidentID != canonical {
		t.Fatalf("future signal must resolve through the canonical incident: %+v", after)
	}
	for _, event := range after.Events {
		if event.Kind == incident.EventMerged {
			t.Fatalf("persisted assignments must not repeat a logical merge: %+v", after.Events)
		}
	}
}

func TestCorrelateIncrementalBoundsStormAcrossRuns(t *testing.T) {
	cfg := incrementalCfg()
	first, err := CorrelateIncremental(cfg, State{}, []Signal{
		sig("d1", at(0), shared.SeverityLow), sig("d2", at(1), shared.SeverityLow), sig("d3", at(2), shared.SeverityLow),
	}, at(10))
	if err != nil {
		t.Fatal(err)
	}
	state := applyPlan(State{}, first)
	storm, err := CorrelateIncremental(cfg, state, []Signal{sig("d4", at(3), shared.SeverityLow), sig("d5", at(4), shared.SeverityLow)}, at(11))
	if err != nil {
		t.Fatal(err)
	}
	if storm.Suppressed != 2 || len(storm.Events) != 1 || storm.Events[0].Kind != incident.EventAnalystCommented {
		t.Fatalf("incremental storm must be bounded and visible: %+v", storm)
	}
	if storm.Events[0].CorrelationKey == "" {
		t.Fatal("suppression note needs a stable retry key")
	}
}

func TestCorrelateIncrementalRejectsInvalidStateAndConfig(t *testing.T) {
	bad := State{Checkpoint: Checkpoint{MaxObservedAt: at(1), Watermark: at(2)}}
	if _, err := CorrelateIncremental(incrementalCfg(), bad, nil, at(3)); err == nil {
		t.Fatal("watermark beyond max-observed must fail")
	}
	cfg := incrementalCfg()
	cfg.AllowedLateness = -time.Second
	if _, err := CorrelateIncremental(cfg, State{}, nil, at(3)); err == nil {
		t.Fatal("negative allowed lateness must fail")
	}
}

func TestCorrelateIncrementalPrunesSessionsButRetainsExactDedupe(t *testing.T) {
	cfg := Config{Window: time.Minute, AllowedLateness: 0, MaxPerIncident: 1}
	first, err := CorrelateIncremental(cfg, State{}, []Signal{sig("old", at(0), shared.SeverityHigh)}, at(1))
	if err != nil {
		t.Fatal(err)
	}
	state := applyPlan(State{}, first)
	advance, err := CorrelateIncremental(cfg, state, []Signal{sig("new", at(120), shared.SeverityLow)}, at(121))
	if err != nil {
		t.Fatal(err)
	}
	if len(advance.ActiveSessions) != 1 {
		t.Fatalf("active sessions=%+v, want compacted single new session", advance.ActiveSessions)
	}
	state = applyPlan(state, advance)
	replay, err := CorrelateIncremental(cfg, state, []Signal{sig("old", at(0), shared.SeverityHigh)}, at(122))
	if err != nil || len(replay.Added) != 0 || len(replay.Events) != 0 {
		t.Fatalf("compacted replay must be no-op: plan=%+v err=%v", replay, err)
	}
	tooLate, err := CorrelateIncremental(cfg, state, []Signal{sig("late", at(1), shared.SeverityLow)}, at(122))
	if err != nil {
		t.Fatal(err)
	}
	state = applyPlan(state, tooLate)
	replay, err = CorrelateIncremental(cfg, state, []Signal{sig("late", at(1), shared.SeverityLow)}, at(123))
	if err != nil || len(replay.Added) != 0 {
		t.Fatalf("too-late replay must be no-op: %+v err=%v", replay, err)
	}
}
