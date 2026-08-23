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
	EntityProcess   EntityKind = "process"
	EntityNetwork   EntityKind = "network"
	EntityFile      EntityKind = "file"
	EntityIdentity  EntityKind = "identity"
	EntityContainer EntityKind = "container"
)

// TimelineEntryKind is the specific state transition an entry records.
type TimelineEntryKind string

const (
	// Process lifecycle (B1). A fork creates a child; an exec replaces the image of an existing entity.
	TimelineProcessStart TimelineEntryKind = "process_start"
	TimelineProcessExec  TimelineEntryKind = "process_exec"
	// Network (B2): one entry per connect event; the connection entity deduplicates the flow.
	TimelineNetworkConnect TimelineEntryKind = "network_connect"
	// File (B3): one entry per file access event, tagged with the observed op.
	TimelineFileOpen   TimelineEntryKind = "file_open"
	TimelineFileWrite  TimelineEntryKind = "file_write"
	TimelineFileRename TimelineEntryKind = "file_rename"
	// Identity/privilege (B4): a privilege or capability transition on a process. Never-sampled upstream
	// (A0.6), so every one surfaces here.
	TimelinePrivilegeChange TimelineEntryKind = "privilege_change"
)

// TimelineEntry is one endpoint state transition, ordered by EVENT time (when it happened on the host),
// never by ingest order. It stays explainable after the raw telemetry that produced it expires because it
// carries its own summary and the identities it links. Every field is content-derived, so a given set of
// envelopes yields byte-identical entries regardless of fold order — the property Phase C evidence sealing
// depends on.
type TimelineEntry struct {
	OccurredAt time.Time
	TenantID   shared.ID
	AssetID    shared.ID
	EntityKind EntityKind
	EntityID   shared.ID
	Kind       TimelineEntryKind
	// EventID is the source envelope's event id; it is the dedupe key so a replayed envelope never adds
	// a duplicate transition, and the tiebreak that orders transitions sharing an OccurredAt.
	EventID shared.ID
	Summary string
}

// StateTimeline is a per-asset, event-time-ordered, EventID-deduplicated sequence of transitions (B7).
// It is the substrate B1–B6 append to and Phase C reads. The zero value is not usable; use
// newStateTimeline.
type StateTimeline struct {
	entries []TimelineEntry
	seen    map[shared.ID]struct{}
}

func newStateTimeline() *StateTimeline {
	return &StateTimeline{seen: make(map[shared.ID]struct{})}
}

// append records a transition unless its EventID is already on the timeline. It returns the stored entry
// and whether it was newly appended; a duplicate EventID returns (zero, false) and changes nothing.
func (t *StateTimeline) append(e TimelineEntry) (TimelineEntry, bool) {
	if _, dup := t.seen[e.EventID]; dup {
		return TimelineEntry{}, false
	}
	t.seen[e.EventID] = struct{}{}
	t.entries = append(t.entries, e)
	return e, true
}

// has reports whether an EventID has already been recorded on the timeline.
func (t *StateTimeline) has(eventID shared.ID) bool {
	_, ok := t.seen[eventID]
	return ok
}

// Entries returns a copy of the timeline ordered by event time, with EventID as the tiebreak for equal
// timestamps. EventID (not insertion order) is the tiebreak so the order is fully reorder-invariant: two
// transitions at the same instant sort the same way no matter which order they were folded in — the
// property Phase C evidence sealing depends on. Callers may mutate the returned slice freely.
func (t *StateTimeline) Entries() []TimelineEntry {
	out := make([]TimelineEntry, len(t.entries))
	copy(out, t.entries)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

// Len reports how many transitions the timeline holds.
func (t *StateTimeline) Len() int { return len(t.entries) }
