// Package endpoint is Phase B of the security data plane (#594): it turns the raw, per-event telemetry
// the A-phase data plane delivers (telemetry.TelemetryEnvelope) into queryable ENDPOINT VISIBILITY —
// stable entities (processes, network connections, …) with lifecycle state, plus a per-asset State
// Timeline of their transitions. Phase C correlation and retro-hunt read this layer instead of racing
// over raw PIDs and ingest-ordered events.
//
// The whole package is a pure, deterministic projection: it folds already-normalized envelopes into
// entity state and timeline entries with no I/O and no clock of its own. The kernel/eBPF collection that
// produces the envelopes is the A-phase sensor tail and lives elsewhere; here we only project what has
// already been observed, so the logic is fully testable off a Linux host.
package endpoint

import (
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EntityKind names the sort of endpoint entity a timeline entry is about. Process and network are
// projected in B1/B2; file and identity are reserved for B3/B4.
type EntityKind string

const (
	EntityProcess  EntityKind = "process"
	EntityNetwork  EntityKind = "network"
	EntityFile     EntityKind = "file"
	EntityIdentity EntityKind = "identity"
)

// TimelineEntryKind is the specific state transition an entry records.
type TimelineEntryKind string

const (
	// Process lifecycle (B1). A fork creates a child; an exec replaces the image of an existing entity.
	TimelineProcessStart TimelineEntryKind = "process_start"
	TimelineProcessExec  TimelineEntryKind = "process_exec"
	// Network (B2): the first time a flow is seen. Re-observing the same flow widens its last-seen time
	// but is not a new transition, so it does not add a second entry.
	TimelineNetworkConnect TimelineEntryKind = "network_connect"
)

// TimelineEntry is one endpoint state transition, ordered by EVENT time (when it happened on the host),
// never by ingest order. It stays explainable after the raw telemetry that produced it expires because it
// carries its own summary and the identities it links.
type TimelineEntry struct {
	// Seq is the assignment order within one StateTimeline. It is the deterministic tiebreak when two
	// transitions share an OccurredAt; it is not a host-wide sequence.
	Seq        uint64
	OccurredAt time.Time
	TenantID   shared.ID
	AssetID    shared.ID
	EntityKind EntityKind
	EntityID   shared.ID
	Kind       TimelineEntryKind
	// EventID is the source envelope's event id; it is the dedupe key so a replayed envelope never adds
	// a duplicate transition.
	EventID shared.ID
	Summary string
}

// StateTimeline is a per-asset, event-time-ordered, EventID-deduplicated sequence of transitions (B7).
// It is the substrate B1–B6 append to and Phase C reads. The zero value is not usable; use
// newStateTimeline.
type StateTimeline struct {
	entries []TimelineEntry
	seen    map[shared.ID]struct{}
	nextSeq uint64
}

func newStateTimeline() *StateTimeline {
	return &StateTimeline{seen: make(map[shared.ID]struct{})}
}

// append records a transition unless its EventID is already on the timeline. It returns the stored entry
// (with its assigned Seq) and whether it was newly appended; a duplicate EventID returns (zero, false)
// and changes nothing.
func (t *StateTimeline) append(e TimelineEntry) (TimelineEntry, bool) {
	if _, dup := t.seen[e.EventID]; dup {
		return TimelineEntry{}, false
	}
	e.Seq = t.nextSeq
	t.nextSeq++
	t.seen[e.EventID] = struct{}{}
	t.entries = append(t.entries, e)
	return e, true
}

// has reports whether an EventID has already been recorded on the timeline.
func (t *StateTimeline) has(eventID shared.ID) bool {
	_, ok := t.seen[eventID]
	return ok
}

// Entries returns a copy of the timeline ordered by event time, with insertion order (Seq) as the
// deterministic tiebreak for equal timestamps. Callers may mutate the returned slice freely.
func (t *StateTimeline) Entries() []TimelineEntry {
	out := make([]TimelineEntry, len(t.entries))
	copy(out, t.entries)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// Len reports how many transitions the timeline holds.
func (t *StateTimeline) Len() int { return len(t.entries) }
