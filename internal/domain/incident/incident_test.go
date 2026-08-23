package incident

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var testTime = time.Unix(1_800_100_000, 0).UTC()

func createTestIncident(t *testing.T) (Incident, IncidentEvent) {
	t.Helper()
	current, event, err := Create(CreateCommand{
		EventID: "event-1", IncidentID: "incident-1", TenantID: "tenant-1",
		EngagementID: "engagement-1", AssetID: "asset-1", DetectionID: "detection-z",
		Actor: "system:correlator", Rationale: "correlation match",
		OccurredAt: testTime, RecordedAt: testTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	return current, event
}

func openTestIncident(t *testing.T, current Incident) (Incident, IncidentEvent) {
	t.Helper()
	next, event, err := current.TransitionState(StateTransitionCommand{
		EventID: "event-2", To: StateOpen, Actor: "system:correlator", Rationale: "opened after correlation",
		ExpectedRevision: current.Revision, OccurredAt: testTime.Add(30 * time.Second),
		RecordedAt: testTime.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("open incident: %v", err)
	}
	return next, event
}

func TestCreateDefaultsAndValidatesProjection(t *testing.T) {
	current, event := createTestIncident(t)
	if current.State != StateNew || current.Disposition != DispositionUnknown || current.Revision != 1 {
		t.Fatalf("unexpected initial lifecycle: %+v", current)
	}
	if len(current.DetectionIDs) != 1 || current.DetectionIDs[0] != "detection-z" {
		t.Fatalf("initial detection was not retained: %+v", current.DetectionIDs)
	}
	if current.LastEventID != event.ID || !current.FirstEventAt.Equal(testTime) ||
		!current.CreatedAt.Equal(testTime.Add(time.Minute)) {
		t.Fatalf("unexpected initial event projection: %+v", current)
	}
	if err := current.Validate(); err != nil {
		t.Fatalf("created incident must validate: %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("created event must validate: %v", err)
	}
}

func TestStateAndDispositionEvolveIndependently(t *testing.T) {
	current, _ := createTestIncident(t)
	current, _ = openTestIncident(t, current)

	classified, _, err := current.SetDisposition(DispositionCommand{
		EventID: "event-3", To: DispositionTruePositive, Actor: "analyst@example.com",
		Rationale: "confirmed malicious behavior", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(3 * time.Minute), RecordedAt: testTime.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if classified.State != StateOpen || classified.Disposition != DispositionTruePositive {
		t.Fatalf("disposition must not move state: %+v", classified)
	}

	investigating, _, err := classified.TransitionState(StateTransitionCommand{
		EventID: "event-4", To: StateInvestigating, Actor: "analyst@example.com",
		Rationale: "collecting surrounding telemetry", ExpectedRevision: classified.Revision,
		OccurredAt: testTime.Add(4 * time.Minute), RecordedAt: testTime.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if investigating.State != StateInvestigating || investigating.Disposition != DispositionTruePositive {
		t.Fatalf("state transition must preserve disposition: %+v", investigating)
	}
}

func TestRebuildIsOrderIndependentAndExactReplayIdempotent(t *testing.T) {
	current, created := createTestIncident(t)
	current, opened := openTestIncident(t, current)
	current, disposition, err := current.SetDisposition(DispositionCommand{
		EventID: "event-3", To: DispositionBenignPositive, Actor: "alice",
		Rationale: "expected administrative traffic", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(3 * time.Minute), RecordedAt: testTime.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	current, linked, err := current.LinkDetection(LinkDetectionCommand{
		EventID: "event-4", DetectionID: "detection-a", Actor: "system:correlator",
		Rationale: "late related detection", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(-time.Hour), RecordedAt: testTime.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Deliberately shuffled, with an exact retry of event-2.
	rebuilt, revisions, err := Rebuild([]IncidentEvent{linked, opened, created, disposition, opened})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !reflect.DeepEqual(rebuilt, current) {
		t.Fatalf("rebuild differs from command projection:\nrebuilt=%+v\ncurrent=%+v", rebuilt, current)
	}
	if len(revisions) != 4 {
		t.Fatalf("exact replay must not create a revision, got %d", len(revisions))
	}
	for index, revision := range revisions {
		if revision.Revision != uint64(index+1) {
			t.Fatalf("revision history not ordered: %+v", revisions)
		}
		if err := revision.Validate(); err != nil {
			t.Fatalf("revision %d invalid: %v", revision.Revision, err)
		}
	}
	if !rebuilt.FirstEventAt.Equal(testTime.Add(-time.Hour)) || !rebuilt.LastEventAt.Equal(testTime.Add(3*time.Minute)) {
		t.Fatalf("late event must widen event-time bounds: [%s,%s]", rebuilt.FirstEventAt, rebuilt.LastEventAt)
	}
	if !reflect.DeepEqual(rebuilt.DetectionIDs, []shared.ID{"detection-a", "detection-z"}) {
		t.Fatalf("detections must be deterministically sorted: %+v", rebuilt.DetectionIDs)
	}

	// Every returned snapshot owns its evidence slice.
	revisions[0].DetectionIDs[0] = "mutated"
	if rebuilt.DetectionIDs[0] == "mutated" || revisions[1].DetectionIDs[0] == "mutated" {
		t.Fatal("revision evidence slices alias each other or the current projection")
	}
}

func TestRebuildRejectsConflictingEventIDReplay(t *testing.T) {
	_, created := createTestIncident(t)
	conflict := created
	conflict.Rationale = "different correlation material"
	if _, _, err := Rebuild([]IncidentEvent{created, conflict}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting EventID replay must fail with ErrConflict, got %v", err)
	}
}

func TestRebuildRejectsCorruptStreams(t *testing.T) {
	current, created := createTestIncident(t)
	current, opened := openTestIncident(t, current)
	current, classified, err := current.SetDisposition(DispositionCommand{
		EventID: "event-3", To: DispositionFalsePositive, Actor: "alice",
		Rationale: "known scanner activity", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(3 * time.Minute), RecordedAt: testTime.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, linked, err := current.LinkDetection(LinkDetectionCommand{
		EventID: "event-4", DetectionID: "detection-y", Actor: "system:correlator",
		Rationale: "same process lineage", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(2 * time.Minute), RecordedAt: testTime.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		events   []IncidentEvent
		sentinel error
	}{
		"missing creation": {[]IncidentEvent{opened}, shared.ErrConflict},
		"revision hole": {[]IncidentEvent{created, opened, func() IncidentEvent {
			e := classified
			e.Revision = 4
			return e
		}()}, shared.ErrConflict},
		"duplicate revision": {[]IncidentEvent{created, opened, func() IncidentEvent {
			e := opened
			e.ID = "other-event"
			return e
		}()}, shared.ErrConflict},
		"cross tenant": {[]IncidentEvent{created, func() IncidentEvent {
			e := opened
			e.TenantID = "tenant-2"
			return e
		}()}, shared.ErrValidation},
		"stale from state": {[]IncidentEvent{created, func() IncidentEvent {
			e := opened
			e.FromState = StateReopened
			e.ToState = StateInvestigating
			return e
		}()}, shared.ErrConflict},
		"stale disposition": {[]IncidentEvent{created, opened, func() IncidentEvent {
			e := classified
			e.FromDisposition = DispositionTest
			return e
		}()}, shared.ErrConflict},
		"record time regression": {[]IncidentEvent{created, opened, classified, func() IncidentEvent {
			e := linked
			e.RecordedAt = classified.RecordedAt.Add(-time.Second)
			return e
		}()}, shared.ErrConflict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Rebuild(tc.events); !errors.Is(err, tc.sentinel) {
				t.Fatalf("want %v, got %v", tc.sentinel, err)
			}
		})
	}
}

func TestCommandsEnforceRevisionTransitionAndHumanDisposition(t *testing.T) {
	current, _ := createTestIncident(t)
	if _, _, err := current.TransitionState(StateTransitionCommand{
		EventID: "bad-transition", To: StateContained, Actor: "system:response",
		Rationale: "contain immediately", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(time.Minute), RecordedAt: testTime.Add(2 * time.Minute),
	}); !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid lifecycle transition must preserve both errors, got %v", err)
	}
	if _, _, err := current.TransitionState(StateTransitionCommand{
		EventID: "stale", To: StateOpen, Actor: "system:correlator", Rationale: "open incident",
		ExpectedRevision: 99, OccurredAt: testTime.Add(time.Minute), RecordedAt: testTime.Add(2 * time.Minute),
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	if _, _, err := current.SetDisposition(DispositionCommand{
		EventID: "machine-disposition", To: DispositionTruePositive, Actor: "llm:triage",
		Rationale: "model classified incident", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(time.Minute), RecordedAt: testTime.Add(2 * time.Minute),
	}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("machine disposition must be forbidden, got %v", err)
	}
	if _, _, err := current.SetDisposition(DispositionCommand{
		EventID: "stale-disposition", To: DispositionTruePositive, Actor: "alice",
		Rationale: "confirmed malicious behavior", ExpectedRevision: 99,
		OccurredAt: testTime.Add(time.Minute), RecordedAt: testTime.Add(2 * time.Minute),
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale disposition revision must conflict, got %v", err)
	}
	if _, _, err := current.LinkDetection(LinkDetectionCommand{
		EventID: "", DetectionID: "detection-a", Actor: "system:correlator",
		ExpectedRevision: current.Revision, OccurredAt: testTime, RecordedAt: testTime.Add(2 * time.Minute),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid link event must be rejected, got %v", err)
	}
	if _, _, err := current.TransitionState(StateTransitionCommand{
		EventID: "regressed-record-time", To: StateOpen, Actor: "system:correlator",
		Rationale: "open incident", ExpectedRevision: current.Revision,
		OccurredAt: testTime.Add(-time.Minute), RecordedAt: testTime.Add(30 * time.Second),
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("command with regressed record time must conflict, got %v", err)
	}
	if _, _, err := (Incident{}).TransitionState(StateTransitionCommand{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("command on invalid projection must fail validation, got %v", err)
	}

	// State transitions may be system-authored; analyst-only applies specifically to disposition.
	opened, _ := openTestIncident(t, current)
	closed, _, err := opened.TransitionState(StateTransitionCommand{
		EventID: "event-close", To: StateClosed, Actor: "system:policy", Rationale: "policy closed incident",
		ExpectedRevision: opened.Revision, OccurredAt: testTime.Add(3 * time.Minute), RecordedAt: testTime.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened, _, err := closed.TransitionState(StateTransitionCommand{
		EventID: "event-reopen", To: StateReopened, Actor: "alice", Rationale: "new supporting evidence",
		ExpectedRevision: closed.Revision, OccurredAt: testTime.Add(4 * time.Minute), RecordedAt: testTime.Add(4 * time.Minute),
	})
	if err != nil || reopened.State != StateReopened {
		t.Fatalf("explicit reopen must succeed: state=%s err=%v", reopened.State, err)
	}
}

func TestDetectionLinksAreUniqueSortedAndDoNotAlias(t *testing.T) {
	current, _ := createTestIncident(t)
	previous := current
	next, _, err := current.LinkDetection(LinkDetectionCommand{
		EventID: "event-2", DetectionID: "detection-a", Actor: "system:correlator",
		ExpectedRevision: current.Revision, OccurredAt: testTime, RecordedAt: testTime.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(next.DetectionIDs, []shared.ID{"detection-a", "detection-z"}) {
		t.Fatalf("unexpected evidence membership: %+v", next.DetectionIDs)
	}
	next.DetectionIDs[0] = "mutated"
	if previous.DetectionIDs[0] != "detection-z" {
		t.Fatal("command result aliases the previous projection")
	}

	// Use the unmodified projection to verify a semantic duplicate with a new event id is rejected.
	current, _, err = current.LinkDetection(LinkDetectionCommand{
		EventID: "event-2", DetectionID: "detection-a", Actor: "system:correlator",
		ExpectedRevision: current.Revision, OccurredAt: testTime, RecordedAt: testTime.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := current.LinkDetection(LinkDetectionCommand{
		EventID: "event-3", DetectionID: "detection-a", Actor: "system:correlator",
		ExpectedRevision: current.Revision, OccurredAt: testTime, RecordedAt: testTime.Add(3 * time.Minute),
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate detection membership must conflict, got %v", err)
	}
}

func TestIncidentEventValidation(t *testing.T) {
	current, created := createTestIncident(t)
	_, stateEvent := openTestIncident(t, current)
	_, dispositionEvent, err := current.SetDisposition(DispositionCommand{
		EventID: "event-disposition", To: DispositionTest, Actor: "alice", Rationale: "approved test activity",
		ExpectedRevision: current.Revision, OccurredAt: testTime.Add(time.Minute), RecordedAt: testTime.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]IncidentEvent{
		"missing id":    func() IncidentEvent { e := created; e.ID = ""; return e }(),
		"zero revision": func() IncidentEvent { e := created; e.Revision = 0; return e }(),
		"unknown kind":  func() IncidentEvent { e := created; e.Kind = "mystery"; return e }(),
		"missing timestamp": func() IncidentEvent {
			e := created
			e.RecordedAt = time.Time{}
			return e
		}(),
		"occurred after recorded": func() IncidentEvent {
			e := created
			e.OccurredAt = e.RecordedAt.Add(time.Second)
			return e
		}(),
		"uncanonical actor":  func() IncidentEvent { e := created; e.Actor = " alice "; return e }(),
		"oversized actor":    func() IncidentEvent { e := created; e.Actor = strings.Repeat("a", maxActorBytes+1); return e }(),
		"invalid actor utf8": func() IncidentEvent { e := created; e.Actor = string([]byte{0xff}); return e }(),
		"short rationale":    func() IncidentEvent { e := stateEvent; e.Rationale = "x"; return e }(),
		"uncanonical rationale": func() IncidentEvent {
			e := stateEvent
			e.Rationale = " padded "
			return e
		}(),
		"oversized rationale": func() IncidentEvent {
			e := stateEvent
			e.Rationale = strings.Repeat("a", maxRationaleRunes+1)
			return e
		}(),
		"control rationale": func() IncidentEvent { e := stateEvent; e.Rationale = "bad\x00text"; return e }(),
		"bad creation payload": func() IncidentEvent {
			e := created
			e.ToState = StateOpen
			return e
		}(),
		"ambiguous state payload": func() IncidentEvent {
			e := stateEvent
			e.DetectionID = "detection-extra"
			return e
		}(),
		"bad disposition payload": func() IncidentEvent {
			e := dispositionEvent
			e.ToDisposition = e.FromDisposition
			return e
		}(),
		"machine disposition": func() IncidentEvent { e := dispositionEvent; e.Actor = "service:triage"; return e }(),
		"bad detection payload": func() IncidentEvent {
			return IncidentEvent{
				ID: "link", IncidentID: created.IncidentID, TenantID: created.TenantID,
				EngagementID: created.EngagementID, AssetID: created.AssetID, Revision: 2,
				Kind: EventDetectionLinked, Actor: "system:correlator", OccurredAt: testTime,
				RecordedAt: testTime.Add(2 * time.Minute), DetectionID: "detection-a", ToState: StateOpen,
			}
		}(),
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			if err := event.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	otherZone := time.FixedZone("other", 2*60*60)
	equalInstant := created
	equalInstant.OccurredAt = created.OccurredAt.In(otherZone)
	equalInstant.RecordedAt = created.RecordedAt.In(otherZone)
	if !created.Equal(equalInstant) {
		t.Fatal("event equality must compare timestamp instants, not locations")
	}
	equalInstant.Actor = "different"
	if created.Equal(equalInstant) {
		t.Fatal("different provenance must not be an exact replay")
	}
}

func TestProjectionAndRevisionValidationRejectCorruption(t *testing.T) {
	current, event := createTestIncident(t)
	revision := snapshot(current, event)
	cases := map[string]Incident{
		"missing scope": func() Incident { i := current; i.TenantID = ""; return i }(),
		"bad state":     func() Incident { i := current; i.State = "bad"; return i }(),
		"duplicate detections": func() Incident {
			i := current.clone()
			i.DetectionIDs = []shared.ID{"detection-z", "detection-z"}
			return i
		}(),
		"unsorted detections": func() Incident {
			i := current.clone()
			i.DetectionIDs = []shared.ID{"z", "a"}
			return i
		}(),
		"bad event bounds": func() Incident { i := current; i.LastEventAt = i.UpdatedAt.Add(time.Second); return i }(),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if err := value.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}
	if err := revision.Validate(); err != nil {
		t.Fatalf("valid revision rejected: %v", err)
	}
	revisionCases := map[string]IncidentRevision{
		"missing identity": func() IncidentRevision { r := revision; r.IncidentID = ""; return r }(),
		"bad lifecycle":    func() IncidentRevision { r := revision; r.State = "bad"; return r }(),
		"missing detection": func() IncidentRevision {
			r := revision
			r.DetectionIDs = nil
			return r
		}(),
		"event outside bounds": func() IncidentRevision {
			r := revision
			r.EventOccurredAt = r.FirstEventAt.Add(-time.Second)
			return r
		}(),
	}
	for name, value := range revisionCases {
		t.Run("revision "+name, func(t *testing.T) {
			if err := value.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("corrupt revision must be rejected, got %v", err)
			}
		})
	}
}

func TestLifecycleVocabularyAndGraph(t *testing.T) {
	states := []State{StateNew, StateOpen, StateTriaged, StateInvestigating, StateContained,
		StateRemediated, StateResolved, StateClosed, StateReopened}
	for _, state := range states {
		if !state.Valid() || state.CanTransitionTo(state) {
			t.Fatalf("invalid state semantics for %q", state)
		}
	}
	if State("bogus").Valid() || State("bogus").CanTransitionTo(StateOpen) {
		t.Fatal("unknown states must fail closed")
	}
	if !StateResolved.CanTransitionTo(StateReopened) || !StateClosed.CanTransitionTo(StateReopened) ||
		StateClosed.CanTransitionTo(StateOpen) {
		t.Fatal("terminal states must reopen explicitly")
	}
	allowed := map[State]State{
		StateNew:           StateOpen,
		StateOpen:          StateTriaged,
		StateTriaged:       StateInvestigating,
		StateInvestigating: StateContained,
		StateContained:     StateRemediated,
		StateRemediated:    StateResolved,
		StateResolved:      StateReopened,
		StateClosed:        StateReopened,
		StateReopened:      StateInvestigating,
	}
	for from, to := range allowed {
		if !from.CanTransitionTo(to) {
			t.Fatalf("expected transition %s -> %s to be allowed", from, to)
		}
	}

	dispositions := []Disposition{DispositionUnknown, DispositionTruePositive, DispositionBenignPositive,
		DispositionFalsePositive, DispositionDuplicate, DispositionTest}
	for _, disposition := range dispositions {
		if !disposition.Valid() {
			t.Fatalf("known disposition %q rejected", disposition)
		}
	}
	if Disposition("model_guess").Valid() {
		t.Fatal("unknown disposition must fail closed")
	}
}

func TestCreateRejectsInvalidCommand(t *testing.T) {
	_, _, err := Create(CreateCommand{
		EventID: "event-1", IncidentID: "incident-1", TenantID: "tenant-1",
		EngagementID: "engagement-1", DetectionID: "detection-1", Actor: "system:correlator",
		OccurredAt: testTime, RecordedAt: testTime.Add(time.Minute),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing asset must fail validation, got %v", err)
	}
}
