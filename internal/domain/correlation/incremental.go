package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssignmentOutcome records how a signal was represented by the correlation graph.
type AssignmentOutcome string

const (
	AssignmentAttached   AssignmentOutcome = "attached"
	AssignmentSuppressed AssignmentOutcome = "suppressed"
	AssignmentTooLate    AssignmentOutcome = "too_late"
)

func (o AssignmentOutcome) valid() bool {
	return o == AssignmentAttached || o == AssignmentSuppressed || o == AssignmentTooLate
}

// Assignment is the durable, immutable dedupe and graph edge from one signal to one incident.
type Assignment struct {
	SignalID   shared.ID
	IncidentID shared.ID
	AssetID    shared.ID
	EntityID   shared.ID
	OccurredAt time.Time
	Severity   shared.Severity
	Outcome    AssignmentOutcome
}

// ValidateForStore validates an immutable ledger row before persistence.
func (a Assignment) ValidateForStore() error { return a.validate() }

func (a Assignment) validate() error {
	if a.SignalID.IsZero() || a.IncidentID.IsZero() || a.AssetID.IsZero() || a.OccurredAt.IsZero() || !a.Outcome.valid() {
		return fmt.Errorf("%w: invalid correlation assignment", shared.ErrValidation)
	}
	if a.Severity != "" && !a.Severity.Valid() {
		return fmt.Errorf("%w: correlation assignment has invalid severity %q", shared.ErrValidation, a.Severity)
	}
	return nil
}

// ActiveSession is the bounded, mutable summary needed to match future event-time signals.
type ActiveSession struct {
	AssetID        shared.ID
	EntityID       shared.ID
	IncidentID     shared.ID
	MinOccurredAt  time.Time
	MaxOccurredAt  time.Time
	ReflectedCount int
	MaxSeverity    shared.Severity
}

// ValidateForStore validates an active-session summary before persistence.
func (s ActiveSession) ValidateForStore() error { return s.validate() }

func (s ActiveSession) validate() error {
	if s.AssetID.IsZero() || s.IncidentID.IsZero() || s.MinOccurredAt.IsZero() || s.MaxOccurredAt.IsZero() || s.MinOccurredAt.After(s.MaxOccurredAt) || s.ReflectedCount < 0 {
		return fmt.Errorf("%w: invalid active correlation session", shared.ErrValidation)
	}
	if s.MaxSeverity != "" && !s.MaxSeverity.Valid() {
		return fmt.Errorf("%w: active correlation session has invalid severity %q", shared.ErrValidation, s.MaxSeverity)
	}
	return nil
}

type Phase string

const (
	PhaseSource  Phase = "source"
	PhaseConsume Phase = "consume"
)

// SourcePosition is the immutable recorded-order position of a source detection.
type SourcePosition struct {
	RecordedAt time.Time
	ID         shared.ID
}

// SignalPosition is a deterministic staged-signal event-time cursor.
type SignalPosition struct {
	OccurredAt time.Time
	ID         shared.ID
}

// Checkpoint is the durable two-phase position for one engagement's correlation stream.
type Checkpoint struct {
	Revision      uint64
	MaxObservedAt time.Time
	Watermark     time.Time
	Phase         Phase
	Completed     SourcePosition
	Snapshot      SourcePosition
	RetentionAsOf time.Time
	SourceCursor  SourcePosition
	StagedCursor  SignalPosition
	PolicyDigest  string
}

// State contains a checkpoint, exact dedupe answers for the current input, and bounded active sessions.
type State struct {
	Checkpoint     Checkpoint
	KnownSignalIDs map[shared.ID]struct{}
	ActiveSessions []ActiveSession
}

// Validate rejects corrupt persisted state before it can influence incident assignment.
func (s State) Validate() error {
	if s.Checkpoint.Phase != "" && s.Checkpoint.Phase != PhaseSource && s.Checkpoint.Phase != PhaseConsume {
		return fmt.Errorf("%w: invalid correlation phase", shared.ErrValidation)
	}
	if s.Checkpoint.Phase == PhaseConsume && (s.Checkpoint.Snapshot.RecordedAt.IsZero() || s.Checkpoint.Snapshot.ID.IsZero() || s.Checkpoint.RetentionAsOf.IsZero()) {
		return fmt.Errorf("%w: consuming correlation snapshot is incomplete", shared.ErrValidation)
	}
	if s.Checkpoint.Phase == "" && (!s.Checkpoint.Snapshot.RecordedAt.IsZero() || !s.Checkpoint.Snapshot.ID.IsZero() || !s.Checkpoint.RetentionAsOf.IsZero()) {
		return fmt.Errorf("%w: idle correlation checkpoint retains a snapshot", shared.ErrValidation)
	}
	if !s.Checkpoint.Watermark.IsZero() && s.Checkpoint.MaxObservedAt.IsZero() {
		return fmt.Errorf("%w: correlation watermark has no max-observed time", shared.ErrValidation)
	}
	if s.Checkpoint.Watermark.After(s.Checkpoint.MaxObservedAt) {
		return fmt.Errorf("%w: correlation watermark exceeds max-observed time", shared.ErrValidation)
	}
	seen := make(map[shared.ID]struct{}, len(s.ActiveSessions))
	for _, session := range s.ActiveSessions {
		if err := session.validate(); err != nil {
			return err
		}
		key := activeSessionID(session.AssetID, session.EntityID, session.IncidentID)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate active correlation session %s", shared.ErrValidation, session.IncidentID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// IncrementalPlan is one deterministic state transition. Events, Added, ActiveSessions, and Next form one durable commit.
type IncrementalPlan struct {
	Events         []incident.IncidentEvent
	Added          []Assignment
	ActiveSessions []ActiveSession
	Next           Checkpoint
	TooLate        int
	Suppressed     int
	Evicted        int
}

type activeSessionEviction struct {
	Session   ActiveSession
	TriggerID shared.ID
	At        time.Time
}

func (p IncrementalPlan) Changed(previous Checkpoint) bool {
	return len(p.Added) > 0 || p.Next != previous
}

// CorrelateIncremental assigns unseen signals using bounded session summaries and exact ledger lookups.
func CorrelateIncremental(cfg Config, state State, signals []Signal, processedAt time.Time) (IncrementalPlan, error) {
	return CorrelateIncrementalPage(cfg, state, signals, processedAt, true)
}

// CorrelateIncrementalPage applies a globally event-ordered staged page. Only the
// final page advances the finalized watermark and prunes active sessions.
func CorrelateIncrementalPage(cfg Config, state State, signals []Signal, processedAt time.Time, finalPage bool) (IncrementalPlan, error) {
	cfg = cfg.Normalize()
	if cfg.Window <= 0 || cfg.MaxPerIncident <= 0 || cfg.MaxActiveSessions <= 0 || cfg.AllowedLateness < 0 || processedAt.IsZero() {
		return IncrementalPlan{}, fmt.Errorf("%w: invalid incremental correlation configuration", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return IncrementalPlan{}, err
	}
	ordered, err := dedupeAndOrder(signals)
	if err != nil {
		return IncrementalPlan{}, err
	}

	plan := IncrementalPlan{Next: state.Checkpoint}
	signalsByID := make(map[shared.ID]Signal, len(ordered))
	sessions := sessionsByKey(state.ActiveSessions)
	prior := make(map[shared.ID]struct{})
	maxBefore := make(map[shared.ID]shared.Severity)
	for _, session := range state.ActiveSessions {
		prior[session.IncidentID] = struct{}{}
		maxBefore[session.IncidentID] = session.MaxSeverity
	}
	merges := make(map[shared.ID]shared.ID)
	activeSessionCount := len(state.ActiveSessions)
	var evictions []activeSessionEviction
	recordEvictions := func(signal Signal) {
		if activeSessionCount <= cfg.MaxActiveSessions {
			return
		}
		reduced := reduceActiveSessions(sessions, cfg.MaxActiveSessions)
		activeSessionCount -= len(reduced)
		for _, session := range reduced {
			evictions = append(evictions, activeSessionEviction{Session: session, TriggerID: signal.ID, At: maxTime(signal.OccurredAt.UTC(), session.MaxOccurredAt)})
		}
	}
	for _, signal := range ordered {
		signalsByID[signal.ID] = signal
		if signal.OccurredAt.After(plan.Next.MaxObservedAt) {
			plan.Next.MaxObservedAt = signal.OccurredAt.UTC()
		}
		if _, known := state.KnownSignalIDs[signal.ID]; known {
			recordEvictions(signal)
			continue
		}
		assignment := Assignment{SignalID: signal.ID, AssetID: signal.AssetID, EntityID: signal.EntityID, OccurredAt: signal.OccurredAt.UTC(), Severity: signal.Severity}
		if !state.Checkpoint.Watermark.IsZero() && signal.OccurredAt.Before(state.Checkpoint.Watermark) {
			assignment.IncidentID, assignment.Outcome = incidentID(signal.AssetID, signal.EntityID, signal.ID), AssignmentTooLate
			plan.TooLate++
			plan.Added = append(plan.Added, assignment)
			recordEvictions(signal)
			continue
		}
		key := signal.key()
		matched, merged := matchingActive(sessions[key], signal.OccurredAt, cfg.Window)
		if matched == nil {
			matched = &ActiveSession{AssetID: signal.AssetID, EntityID: signal.EntityID, IncidentID: incidentID(signal.AssetID, signal.EntityID, signal.ID), MinOccurredAt: signal.OccurredAt.UTC(), MaxOccurredAt: signal.OccurredAt.UTC()}
			sessions[key] = append(sessions[key], matched)
			activeSessionCount++
		} else {
			for _, old := range merged {
				if old.IncidentID == matched.IncidentID {
					continue
				}
				activeSessionCount--
				merges[old.IncidentID] = matched.IncidentID
				matched.MinOccurredAt = minTime(matched.MinOccurredAt, old.MinOccurredAt)
				matched.MaxOccurredAt = maxTime(matched.MaxOccurredAt, old.MaxOccurredAt)
				matched.ReflectedCount += old.ReflectedCount
				matched.MaxSeverity = higherSeverity(matched.MaxSeverity, old.MaxSeverity)
			}
			sessions[key] = removeMerged(sessions[key], matched.IncidentID, merges)
		}
		assignment.IncidentID = matched.IncidentID
		if matched.ReflectedCount >= cfg.MaxPerIncident {
			assignment.Outcome = AssignmentSuppressed
			plan.Suppressed++
		} else {
			assignment.Outcome = AssignmentAttached
			matched.ReflectedCount++
		}
		matched.MinOccurredAt = minTime(matched.MinOccurredAt, assignment.OccurredAt)
		matched.MaxOccurredAt = maxTime(matched.MaxOccurredAt, assignment.OccurredAt)
		matched.MaxSeverity = higherSeverity(matched.MaxSeverity, assignment.Severity)
		plan.Added = append(plan.Added, assignment)
		recordEvictions(signal)
	}
	if finalPage && !plan.Next.MaxObservedAt.IsZero() {
		candidate := minTime(plan.Next.MaxObservedAt, processedAt).Add(-cfg.AllowedLateness).UTC()
		if candidate.After(plan.Next.Watermark) {
			plan.Next.Watermark = candidate
		}
	}
	if len(plan.Added) > 0 || plan.Next != state.Checkpoint {
		plan.Next.Revision = state.Checkpoint.Revision + 1
	}
	if finalPage {
		plan.ActiveSessions = flattenActive(sessions, plan.Next.Watermark.Add(-cfg.Window))
	} else {
		plan.ActiveSessions = flattenActive(sessions, time.Time{})
	}
	plan.Evicted = len(evictions)
	plan.Events = incrementalEvents(cfg, plan.Added, signalsByID, prior, maxBefore, merges, evictions, processedAt.UTC(), state.Checkpoint.Watermark)
	return plan, nil
}

func sessionsByKey(active []ActiveSession) map[correlationKey][]*ActiveSession {
	out := make(map[correlationKey][]*ActiveSession)
	for _, session := range active {
		copy := session
		key := correlationKey{asset: copy.AssetID, entity: copy.EntityID}
		out[key] = append(out[key], &copy)
	}
	return out
}
func matchingActive(items []*ActiveSession, at time.Time, window time.Duration) (*ActiveSession, []*ActiveSession) {
	var matches []*ActiveSession
	for _, item := range items {
		if !at.Before(item.MinOccurredAt.Add(-window)) && !at.After(item.MaxOccurredAt.Add(window)) {
			matches = append(matches, item)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].IncidentID < matches[j].IncidentID })
	if len(matches) == 0 {
		return nil, nil
	}
	return matches[0], matches
}
func removeMerged(items []*ActiveSession, canonical shared.ID, merges map[shared.ID]shared.ID) []*ActiveSession {
	out := items[:0]
	for _, item := range items {
		if item.IncidentID == canonical {
			out = append(out, item)
			continue
		}
		if _, merged := merges[item.IncidentID]; !merged {
			out = append(out, item)
		}
	}
	return out
}

// reduceActiveSessions keeps the K most recently active sessions. Its total ordering makes
// the post-signal prefix state independent of how the globally ordered stream is paged.
func reduceActiveSessions(byKey map[correlationKey][]*ActiveSession, limit int) []ActiveSession {
	all := flattenActive(byKey, time.Time{})
	if len(all) <= limit {
		return nil
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].MaxOccurredAt.Equal(all[j].MaxOccurredAt) {
			return all[i].MaxOccurredAt.Before(all[j].MaxOccurredAt)
		}
		if !all[i].MinOccurredAt.Equal(all[j].MinOccurredAt) {
			return all[i].MinOccurredAt.Before(all[j].MinOccurredAt)
		}
		if all[i].AssetID != all[j].AssetID {
			return all[i].AssetID < all[j].AssetID
		}
		if all[i].EntityID != all[j].EntityID {
			return all[i].EntityID < all[j].EntityID
		}
		return all[i].IncidentID < all[j].IncidentID
	})
	evicted := append([]ActiveSession(nil), all[:len(all)-limit]...)
	for _, session := range evicted {
		key := correlationKey{asset: session.AssetID, entity: session.EntityID}
		items := byKey[key]
		out := items[:0]
		for _, item := range items {
			if item.IncidentID != session.IncidentID {
				out = append(out, item)
			}
		}
		if len(out) == 0 {
			delete(byKey, key)
		} else {
			byKey[key] = out
		}
	}
	return evicted
}

func flattenActive(byKey map[correlationKey][]*ActiveSession, cutoff time.Time) []ActiveSession {
	var out []ActiveSession
	for _, list := range byKey {
		for _, session := range list {
			if !session.MaxOccurredAt.Before(cutoff) {
				out = append(out, *session)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AssetID != out[j].AssetID {
			return out[i].AssetID < out[j].AssetID
		}
		if out[i].EntityID != out[j].EntityID {
			return out[i].EntityID < out[j].EntityID
		}
		return out[i].IncidentID < out[j].IncidentID
	})
	return out
}
func minTime(left, right time.Time) time.Time {
	if left.IsZero() || right.Before(left) {
		return right
	}
	return left
}
func maxTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
func activeSessionID(asset, entity, incidentID shared.ID) shared.ID {
	return asset + "\x00" + entity + "\x00" + incidentID
}

func incrementalEvents(cfg Config, added []Assignment, signals map[shared.ID]Signal, prior map[shared.ID]struct{}, maxBefore map[shared.ID]shared.Severity, merges map[shared.ID]shared.ID, evictions []activeSessionEviction, processedAt, priorWatermark time.Time) []incident.IncidentEvent {
	byIncident := make(map[shared.ID][]Assignment)
	evictedByIncident := make(map[shared.ID][]activeSessionEviction)
	ids := make(map[shared.ID]struct{})
	for _, assignment := range added {
		ids[assignment.IncidentID] = struct{}{}
		byIncident[assignment.IncidentID] = append(byIncident[assignment.IncidentID], assignment)
	}
	for _, eviction := range evictions {
		ids[eviction.Session.IncidentID] = struct{}{}
		evictedByIncident[eviction.Session.IncidentID] = append(evictedByIncident[eviction.Session.IncidentID], eviction)
	}
	orderedIDs := make([]shared.ID, 0, len(ids))
	for id := range ids {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Slice(orderedIDs, func(i, j int) bool { return orderedIDs[i] < orderedIDs[j] })
	var events []incident.IncidentEvent
	var mergedIDs []shared.ID
	for id := range merges {
		mergedIDs = append(mergedIDs, id)
	}
	sort.Slice(mergedIDs, func(i, j int) bool { return mergedIDs[i] < mergedIDs[j] })
	for _, id := range mergedIDs {
		events = append(events, incident.IncidentEvent{IncidentID: id, Kind: incident.EventMerged, At: processedAt, Actor: cfg.Actor, CorrelationKey: eventKey("merged", merges[id].String()), MergedInto: merges[id]})
	}
	for _, id := range orderedIDs {
		assignments := byIncident[id]
		sort.Slice(assignments, func(i, j int) bool {
			if !assignments[i].OccurredAt.Equal(assignments[j].OccurredAt) {
				return assignments[i].OccurredAt.Before(assignments[j].OccurredAt)
			}
			return assignments[i].SignalID < assignments[j].SignalID
		})
		_, existed := prior[id]
		local := make([]incident.IncidentEvent, 0)
		start := 0
		if !existed {
			first := assignments[0]
			signal := signals[first.SignalID]
			severity := maxBefore[id]
			for _, a := range assignments {
				severity = higherSeverity(severity, a.Severity)
			}
			created := incident.IncidentEvent{IncidentID: id, Kind: incident.EventCreated, At: first.OccurredAt, Actor: cfg.Actor, CorrelationKey: eventKey("created", first.SignalID.String()), AssetID: first.AssetID, EngagementID: cfg.EngagementID, Title: signalTitle(signal), Severity: severity}
			if signal.Timeline == nil {
				created.DetectionID = first.SignalID
			}
			local = append(local, created)
			if signal.Timeline != nil && first.Outcome == AssignmentAttached {
				local = append(local, timelineAttached(cfg, id, first.SignalID, *signal.Timeline, first.OccurredAt))
			}
			start = 1
		}
		for _, a := range assignments[start:] {
			if a.Outcome != AssignmentAttached {
				continue
			}
			signal := signals[a.SignalID]
			if signal.Timeline != nil {
				local = append(local, timelineAttached(cfg, id, a.SignalID, *signal.Timeline, a.OccurredAt))
			} else {
				local = append(local, incident.IncidentEvent{IncidentID: id, Kind: incident.EventDetectionAttached, At: a.OccurredAt, Actor: cfg.Actor, CorrelationKey: eventKey("detection", a.SignalID.String()), DetectionID: a.SignalID})
			}
		}
		maxAfter := maxBefore[id]
		for _, a := range assignments {
			maxAfter = higherSeverity(maxAfter, a.Severity)
		}
		if existed && shared.SeverityRank(maxAfter) > shared.SeverityRank(maxBefore[id]) {
			local = append(local, incident.IncidentEvent{IncidentID: id, Kind: incident.EventSeverityChanged, At: processedAt, Actor: cfg.Actor, CorrelationKey: eventKey("severity", string(maxAfter)), Severity: maxAfter})
		}
		var suppressed []string
		for _, a := range assignments {
			if a.Outcome == AssignmentSuppressed {
				suppressed = append(suppressed, a.SignalID.String())
			}
		}
		if len(suppressed) > 0 {
			local = append(local, incident.IncidentEvent{IncidentID: id, Kind: incident.EventAnalystCommented, At: processedAt, Actor: cfg.Actor, CorrelationKey: eventKey("suppressed", strings.Join(suppressed, "\x00")), Comment: fmt.Sprintf("correlation storm: %d further signal(s) suppressed from this incident", len(suppressed))})
		}
		for _, a := range assignments {
			if a.Outcome == AssignmentTooLate {
				local = append(local, incident.IncidentEvent{IncidentID: id, Kind: incident.EventAnalystCommented, At: a.OccurredAt, Actor: cfg.Actor, CorrelationKey: eventKey("too-late", a.SignalID.String()), Comment: fmt.Sprintf("correlation lateness coverage: detection %s at %s arrived behind watermark %s and was isolated", a.SignalID, a.OccurredAt.Format(time.RFC3339Nano), priorWatermark.Format(time.RFC3339Nano))})
			}
		}
		for _, eviction := range evictedByIncident[id] {
			local = append(local, incident.IncidentEvent{IncidentID: id, Kind: incident.EventAnalystCommented, At: eviction.At, Actor: cfg.Actor, CorrelationKey: eventKey("active-session-evicted", string(eviction.Session.AssetID)+"\x00"+string(eviction.Session.EntityID)+"\x00"+string(eviction.Session.IncidentID)+"\x00"+string(eviction.TriggerID)), Comment: fmt.Sprintf("correlation active-session coverage: session evicted while processing signal %s", eviction.TriggerID)})
		}
		sort.SliceStable(local, func(i, j int) bool {
			if local[i].Kind == incident.EventCreated {
				return true
			}
			if local[j].Kind == incident.EventCreated {
				return false
			}
			return local[i].At.Before(local[j].At)
		})
		events = append(events, local...)
	}
	return events
}
func timelineAttached(cfg Config, id, signalID shared.ID, ref incident.TimelineRef, at time.Time) incident.IncidentEvent {
	return incident.IncidentEvent{IncidentID: id, Kind: incident.EventTimelineAttached, At: at, Actor: cfg.Actor, CorrelationKey: eventKey("timeline", signalID.String()), Timeline: ref}
}
func higherSeverity(left, right shared.Severity) shared.Severity {
	if shared.SeverityRank(right) > shared.SeverityRank(left) {
		return right
	}
	return left
}
func signalTitle(signal Signal) string {
	if signal.Title != "" {
		return signal.Title
	}
	if signal.RuleID != "" {
		return signal.RuleID
	}
	return "correlated detection " + signal.ID.String()
}
func eventKey(kind, value string) string {
	sum := sha256.Sum256([]byte("correlation:event:v1\x00" + kind + "\x00" + value))
	return "corr_" + hex.EncodeToString(sum[:])
}
