package endpoint

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// maxAncestorWalk bounds the lineage walk so a malformed parent cycle can never loop forever.
const maxAncestorWalk = 256

// EndpointState is the projected endpoint-visibility state for ONE (tenant, asset): its process entities
// (B1), network connections (B2), file targets (B3), privilege transitions (B4), container instances (B5),
// and the State Timeline (B7) of their transitions. It is built by folding telemetry envelopes with
// Observe and is a pure, deterministic aggregate — no I/O, no clock. The zero value is not usable;
// construct it with NewEndpointState.
type EndpointState struct {
	tenantID  shared.ID
	assetID   shared.ID
	processes map[shared.ID]*ProcessEntity
	conns     map[shared.ID]*NetworkConnection
	// connsByProcess is a derived index used to reconcile an unknown attribution in O(flows for process)
	// when an out-of-order process observation arrives. Empty process ids are intentionally not indexed:
	// there is no stable identity by which a later process event could resolve them.
	connsByProcess map[shared.ID][]*NetworkConnection
	files          map[shared.ID]*FileTarget
	containers     map[shared.ID]*ContainerInstance
	privileges     []PrivilegeTransition
	timeline       *StateTimeline
	processed      map[shared.ID]struct{}
}

// NewEndpointState creates the projection for one asset. Both ids are required — endpoint visibility is
// always scoped to a concrete tenant and asset, and Observe rejects an envelope for a different asset.
func NewEndpointState(tenantID, assetID shared.ID) (*EndpointState, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: endpoint state requires a tenant id", shared.ErrValidation)
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: endpoint state requires an asset id", shared.ErrValidation)
	}
	return &EndpointState{
		tenantID:       tenantID,
		assetID:        assetID,
		processes:      make(map[shared.ID]*ProcessEntity),
		conns:          make(map[shared.ID]*NetworkConnection),
		connsByProcess: make(map[shared.ID][]*NetworkConnection),
		files:          make(map[shared.ID]*FileTarget),
		containers:     make(map[shared.ID]*ContainerInstance),
		timeline:       newStateTimeline(),
		processed:      make(map[shared.ID]struct{}),
	}, nil
}

// Observe folds one telemetry envelope into the endpoint state and returns the timeline entries the fold
// produced (possibly none). It is:
//   - deterministic and reorder-invariant — entities and the timeline depend only on envelope content,
//     not on the order envelopes are folded in (descriptor fields resolve latest-by-event-time,
//     started/first-seen are the earliest event time, last-seen the latest);
//   - idempotent by EventID — re-applying the same envelope changes nothing and returns no entries;
//   - fail-closed — the envelope is fully validated (telemetry.Validate) and a wrong-asset envelope is
//     rejected, never silently folded.
//
// All four telemetry classes are projected: process (B1), network (B2), file (B3), privilege (B4); and
// every event, whatever its class, feeds the runtime container inventory (B5) from its ResourceContext.
func (s *EndpointState) Observe(env telemetry.TelemetryEnvelope) ([]TimelineEntry, error) {
	if err := env.Validate(); err != nil {
		return nil, fmt.Errorf("endpoint: reject malformed telemetry envelope: %w", err)
	}
	if env.AssetID != s.assetID {
		return nil, fmt.Errorf("%w: envelope asset %s does not belong to endpoint state asset %s", shared.ErrValidation, env.AssetID, s.assetID)
	}
	if _, done := s.processed[env.EventID]; done {
		return nil, nil
	}

	var entries []TimelineEntry
	switch env.EventClass {
	case detection.ClassProcess:
		entries = s.applyProcess(env)
	case detection.ClassNetwork:
		entries = s.applyNetwork(env)
	case detection.ClassFile:
		entries = s.applyFile(env)
	case detection.ClassPrivilege:
		entries = s.applyPrivilege(env)
	}
	// Runtime container inventory (B5) is cross-cutting: any event observed from inside a container
	// inventories it, regardless of the event's class. Inventory only — container presence is not a
	// timeline transition (start/stop events are a sensor tail A1 does not carry yet).
	s.observeContainer(env)
	s.processed[env.EventID] = struct{}{}
	return entries, nil
}

// applyProcess folds a validated process envelope. env is already telemetry-validated by Observe, so the
// process payload is present and well-formed.
func (s *EndpointState) applyProcess(env telemetry.TelemetryEnvelope) []TimelineEntry {
	obs := env.Event.Process

	pe, existed := s.processes[obs.EntityID]
	if !existed {
		pe = &ProcessEntity{
			EntityID: obs.EntityID,
			TenantID: s.tenantID,
			AssetID:  s.assetID,
			State:    ProcessRunning,
		}
		s.processes[obs.EntityID] = pe
	} else if pe.State == ProcessUnknown {
		// A parent stub is now directly observed: promote it (its real start is set by the min below).
		pe.State = ProcessRunning
	}

	// Descriptor fields are resolved by EVENT time: an observation only overwrites them when it is the
	// latest one seen for this entity, with EventID breaking an exact-timestamp tie. This makes the
	// projection invariant to the order envelopes are folded in — an out-of-order (or same-instant, lower
	// EventID) envelope never clobbers newer descriptors. An exec replaces the image.
	descriptorIsLatest := !existed || laterEvent(env.OccurredAt, env.EventID, pe.LastSeenAt, pe.descEventID)
	if descriptorIsLatest {
		pe.PID = obs.PID
		pe.PPID = obs.PPID
		pe.ParentEntityID = obs.ParentEntityID
		pe.UID = obs.UID
		pe.Resource = env.ResourceContext
		pe.descEventID = env.EventID
		if obs.Comm != "" {
			pe.Comm = obs.Comm
		}
		if obs.Kind == "exec" || obs.Path != "" {
			pe.Path = obs.Path
			pe.Args = append([]string(nil), obs.Args...)
			pe.ArgsTruncated = obs.ArgsTruncated
			pe.PathTruncated = obs.PathTruncated
		}
	}
	// StartedAt is the EARLIEST event time observed for the entity; LastSeenAt the latest. Both take a
	// min/max so they are order-independent (a stub's zero StartedAt is filled by its first real event).
	if pe.StartedAt.IsZero() || env.OccurredAt.Before(pe.StartedAt) {
		pe.StartedAt = env.OccurredAt
	}
	if env.OccurredAt.After(pe.LastSeenAt) {
		pe.LastSeenAt = env.OccurredAt
	}

	// A network observation may have arrived before this process observation. Promote every flow that
	// references this now-directly-observed entity; the transition is monotonic and therefore independent
	// of fold order.
	s.markProcessAttributionObserved(obs.EntityID)

	s.ensureParentStub(obs)

	return s.appendTimeline(env)
}

// appendTimeline appends the envelope's timeline transition (built by the shared timelineEntryFor) and
// returns it, or nil if there is none or it was a duplicate.
func (s *EndpointState) appendTimeline(env telemetry.TelemetryEnvelope) []TimelineEntry {
	entry, ok := timelineEntryFor(s.tenantID, env)
	if !ok {
		return nil
	}
	stored, appended := s.timeline.append(entry)
	if !appended {
		return nil
	}
	return []TimelineEntry{stored}
}

// ensureParentStub records a referenced-but-unobserved parent as an explicit ProcessUnknown entity, so a
// lineage gap is visible (coverage honesty) rather than a silently broken chain. The stub's LastSeenAt is
// left zero — it was never directly observed — so a later real observation of the parent (whose event time
// may predate the child that referenced it) is always treated as the latest descriptor and promotes it.
func (s *EndpointState) ensureParentStub(obs *telemetry.ProcessObservation) {
	if obs.ParentEntityID.IsZero() || obs.ParentEntityID == obs.EntityID {
		return
	}
	if _, ok := s.processes[obs.ParentEntityID]; ok {
		return
	}
	s.processes[obs.ParentEntityID] = &ProcessEntity{
		EntityID: obs.ParentEntityID,
		TenantID: s.tenantID,
		AssetID:  s.assetID,
		PID:      obs.PPID,
		State:    ProcessUnknown,
	}
}

// applyNetwork folds a validated network envelope. env is already telemetry-validated by Observe.
func (s *EndpointState) applyNetwork(env telemetry.TelemetryEnvelope) []TimelineEntry {
	obs := env.Event.Network

	id := ConnectionID(s.assetID, obs.ProcessEntityID, obs.Proto, obs.Direction, obs.LocalAddr, obs.LocalPort, obs.RemoteAddr, obs.RemotePort)
	conn, existed := s.conns[id]
	if !existed {
		conn = &NetworkConnection{
			ConnectionID:       id,
			TenantID:           s.tenantID,
			AssetID:            s.assetID,
			ProcessEntityID:    obs.ProcessEntityID,
			Proto:              obs.Proto,
			Direction:          obs.Direction,
			LocalAddr:          obs.LocalAddr,
			LocalPort:          obs.LocalPort,
			RemoteAddr:         obs.RemoteAddr,
			RemotePort:         obs.RemotePort,
			Comm:               obs.Comm,
			ProcessAttribution: s.processAttribution(obs.ProcessEntityID),
			FirstSeenAt:        env.OccurredAt,
			LastSeenAt:         env.OccurredAt,
			State:              ConnectionObserved,
		}
		s.conns[id] = conn
		if !obs.ProcessEntityID.IsZero() {
			s.connsByProcess[obs.ProcessEntityID] = append(s.connsByProcess[obs.ProcessEntityID], conn)
		}
	} else {
		// The connection ENTITY deduplicates the flow: re-observing widens its seen window. Both bounds
		// take a min/max so the window is order-independent (reorder-invariant).
		if env.OccurredAt.After(conn.LastSeenAt) {
			conn.LastSeenAt = env.OccurredAt
		}
		if env.OccurredAt.Before(conn.FirstSeenAt) {
			conn.FirstSeenAt = env.OccurredAt
		}
	}

	// The TIMELINE records one entry per connect EVENT (deduped by EventID), so it is a complete,
	// reorder-invariant log of observations. Deduplication of the flow itself lives on the connection
	// entity above, not on the timeline — a per-flow entry would have to take the timestamp of whichever
	// connect was folded first, which would not be reorder-invariant.
	return s.appendTimeline(env)
}

// processAttribution reports only what this projection can prove. Merely having an entity id, including
// an id represented by a ProcessUnknown parent stub, is not enough: a direct process observation must
// have been folded before attribution becomes observed.
func (s *EndpointState) processAttribution(processEntityID shared.ID) ProcessAttribution {
	pe, ok := s.processes[processEntityID]
	if ok && pe.State != ProcessUnknown {
		return ProcessAttributionObserved
	}
	return ProcessAttributionUnknown
}

// markProcessAttributionObserved reconciles flows that arrived before their process event. Connections
// with no process id remain explicitly unknown because there is no safe identity to join on.
func (s *EndpointState) markProcessAttributionObserved(processEntityID shared.ID) {
	if processEntityID.IsZero() {
		return
	}
	for _, conn := range s.connsByProcess[processEntityID] {
		conn.ProcessAttribution = ProcessAttributionObserved
	}
}

// Process returns a copy of one process entity by id.
func (s *EndpointState) Process(id shared.ID) (ProcessEntity, bool) {
	pe, ok := s.processes[id]
	if !ok {
		return ProcessEntity{}, false
	}
	return pe.clone(), true
}

// Processes returns a copy of all process entities, ordered by entity id for a stable result.
func (s *EndpointState) Processes() []ProcessEntity {
	out := make([]ProcessEntity, 0, len(s.processes))
	for _, pe := range s.processes {
		out = append(out, pe.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntityID < out[j].EntityID })
	return out
}

// Connections returns a copy of all network connections, ordered by connection id for a stable result.
func (s *EndpointState) Connections() []NetworkConnection {
	out := make([]NetworkConnection, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, c.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectionID < out[j].ConnectionID })
	return out
}

// Timeline returns the event-time-ordered State Timeline.
func (s *EndpointState) Timeline() []TimelineEntry { return s.timeline.Entries() }

// Ancestors returns the process lineage of an entity, nearest parent first, walking ParentEntityID while
// the ancestor is a known entity. The walk stops at the first unobserved link and is bounded against a
// malformed cycle.
func (s *EndpointState) Ancestors(id shared.ID) []ProcessEntity {
	var out []ProcessEntity
	seen := make(map[shared.ID]struct{})
	cur, ok := s.processes[id]
	if !ok {
		return nil
	}
	for i := 0; i < maxAncestorWalk; i++ {
		parentID := cur.ParentEntityID
		if parentID.IsZero() {
			return out
		}
		if _, loop := seen[parentID]; loop {
			return out
		}
		seen[parentID] = struct{}{}
		parent, ok := s.processes[parentID]
		if !ok {
			return out
		}
		out = append(out, parent.clone())
		cur = parent
	}
	return out
}

// timelineEntryFor returns the single timeline transition an envelope produces, and whether it produces
// one (a container-only event produces none). It is PURE — it depends only on the envelope, not on any
// accumulated state — so the timeline is a stateless per-envelope projection: the same envelope always
// yields the same entry, and both the live fold (Observe) and the persistence path (TimelineEntriesFor)
// build entries through this one function, so they can never drift. The envelope must already be validated.
func timelineEntryFor(tenantID shared.ID, env telemetry.TelemetryEnvelope) (TimelineEntry, bool) {
	e := TimelineEntry{OccurredAt: env.OccurredAt, TenantID: tenantID, AssetID: env.AssetID, EventID: env.EventID}
	switch env.EventClass {
	case detection.ClassProcess:
		obs := env.Event.Process
		e.EntityKind, e.EntityID, e.Summary = EntityProcess, obs.EntityID, processObsSummary(obs)
		e.Kind = TimelineProcessStart
		if obs.Kind == "exec" {
			e.Kind = TimelineProcessExec
		}
		return e, true
	case detection.ClassNetwork:
		obs := env.Event.Network
		e.EntityKind = EntityNetwork
		e.EntityID = ConnectionID(env.AssetID, obs.ProcessEntityID, obs.Proto, obs.Direction, obs.LocalAddr, obs.LocalPort, obs.RemoteAddr, obs.RemotePort)
		e.Kind, e.Summary = TimelineNetworkConnect, connectionObsSummary(obs)
		return e, true
	case detection.ClassFile:
		obs := env.Event.File
		e.EntityKind, e.EntityID = EntityFile, obs.TargetID()
		e.Kind, e.Summary = fileTimelineKind(obs.Op), fileObsSummary(obs)
		return e, true
	case detection.ClassPrivilege:
		obs := env.Event.Privilege
		e.EntityKind, e.EntityID = EntityIdentity, obs.ProcessEntityID
		e.Kind, e.Summary = TimelinePrivilegeChange, privilegeSummary(obs)
		return e, true
	}
	return TimelineEntry{}, false
}

// TimelineEntriesFor is the stateless State-Timeline projection of one telemetry envelope, for the
// persistence path (a store appends what this returns, deduplicating by EventID). It validates the
// envelope first (fail-closed) and stamps entries with the given tenant and the envelope's asset. It
// returns no entries for a class that has no transition (container-only). Because it shares
// timelineEntryFor with the live fold, a persisted timeline is identical to the in-memory one.
func TimelineEntriesFor(tenantID shared.ID, env telemetry.TelemetryEnvelope) ([]TimelineEntry, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: timeline projection requires a tenant id", shared.ErrValidation)
	}
	if err := env.Validate(); err != nil {
		return nil, fmt.Errorf("endpoint: reject malformed telemetry envelope: %w", err)
	}
	if entry, ok := timelineEntryFor(tenantID, env); ok {
		return []TimelineEntry{entry}, nil
	}
	return nil, nil
}

// laterEvent reports whether the event (occ, eventID) is strictly later than a reference event by event
// time, with EventID as the deterministic tiebreak for an identical timestamp. It is the single rule the
// folds use to resolve "latest wins" descriptor fields so the outcome never depends on fold order.
func laterEvent(occ time.Time, eventID shared.ID, refOcc time.Time, refEventID shared.ID) bool {
	if occ.After(refOcc) {
		return true
	}
	if occ.Equal(refOcc) {
		return eventID > refEventID
	}
	return false
}

// processObsSummary / connectionObsSummary build a timeline entry's human summary from the OBSERVATION,
// not from the accumulated entity, so the summary is a stable record of what that event carried and does
// not change with the order envelopes are folded in.
func processObsSummary(obs *telemetry.ProcessObservation) string {
	name := obs.Comm
	if name == "" {
		name = obs.Path
	}
	return fmt.Sprintf("pid=%d %s", obs.PID, name)
}

func connectionObsSummary(obs *telemetry.NetworkObservation) string {
	return fmt.Sprintf("%s %s %s:%d->%s:%d", obs.Proto, obs.Direction, obs.LocalAddr, obs.LocalPort, obs.RemoteAddr, obs.RemotePort)
}
