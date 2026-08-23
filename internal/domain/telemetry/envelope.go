package telemetry

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SchemaVersion is the current canonical raw-telemetry schema version. It is stamped on every envelope so
// the schema can evolve (A0.3, #608) without an agent-version coupling; SchemaMin..SchemaMax is the range
// a reader accepts.
const (
	SchemaVersion = 1
	SchemaMin     = 1
	SchemaMax     = 1
)

// TelemetryEnvelope is the canonical unit of raw telemetry (A1, fixes D4): a class-typed observation plus
// the identity, three distinct timestamps, sequencing, coverage/quality honesty, and host/K8s placement
// that the whole data plane (A2 spool, A3 transport, A5 evidence, B/C detection) is built on. It is
// telemetry's own type; it does not reuse detection.Event as the observation schema.
//
// The three timestamps are deliberately separate and mean different things:
//   - OccurredAt  — when the event happened, from the KERNEL source clock (the truth).
//   - ObservedAt  — when the agent collector decoded it (userspace).
//   - ReceivedAt  — when the control plane ingested it (stamped at ingest, A3; zero on the agent).
//
// The old thin path stamped a single userspace time.Now() for all three, which is D4.
type TelemetryEnvelope struct {
	SchemaVersion int
	EventID       shared.ID
	// EventType is the stable dotted type name (e.g. "process.exec"); it must equal Event.EventType().
	EventType string
	// EventClass is the top-level class for coarse indexing; it must equal Event.Class.
	EventClass     detection.Class
	AgentID        shared.ID
	AgentSessionID shared.ID
	AssetID        shared.ID
	BootID         shared.ID
	StreamID       shared.ID
	SensorID       string
	SensorVersion  string
	OccurredAt     time.Time
	ObservedAt     time.Time
	ReceivedAt     time.Time
	// Sequence is the per-stream monotonic sequence number (within one incarnation/Epoch — see #594
	// identity conventions; the incarnation is embedded in StreamID upstream).
	Sequence        uint64
	CoverageFlags   CoverageFlags
	DataQuality     DataQuality
	ResourceContext ResourceContext
	// RedactionPolicyDigest names the source-side privacy policy that scrubbed this event (A6, #627),
	// recorded WITH the data so a reader knows how it was redacted. It is DISTINCT from any sampling-policy
	// digest. Empty when no redaction policy was applied (pre-A6 path); set by privacy.Scrub.
	RedactionPolicyDigest string
	// Event is the typed payload (the "TypedPayload" contract slot).
	Event TelemetryEvent
}

// Validate enforces a well-formed envelope: an accepted schema version, the mandatory identity, a class
// that matches its payload, and the timestamp ordering invariant. ReceivedAt is optional (zero on the
// agent, stamped at ingest) but, when present, must not precede ObservedAt.
func (e TelemetryEnvelope) Validate() error {
	if e.SchemaVersion < SchemaMin || e.SchemaVersion > SchemaMax {
		return fmt.Errorf("%w: telemetry envelope schema version %d outside [%d,%d]", shared.ErrValidation, e.SchemaVersion, SchemaMin, SchemaMax)
	}
	if e.EventID.IsZero() {
		return fmt.Errorf("%w: telemetry envelope has no event id", shared.ErrValidation)
	}
	if e.AgentID.IsZero() {
		return fmt.Errorf("%w: telemetry envelope has no agent id", shared.ErrValidation)
	}
	if e.AssetID.IsZero() {
		return fmt.Errorf("%w: telemetry envelope has no asset id", shared.ErrValidation)
	}
	if e.EventClass != e.Event.Class {
		return fmt.Errorf("%w: telemetry envelope class %q disagrees with payload class %q", shared.ErrValidation, e.EventClass, e.Event.Class)
	}
	if e.EventType != e.Event.EventType() {
		return fmt.Errorf("%w: telemetry envelope type %q disagrees with payload type %q", shared.ErrValidation, e.EventType, e.Event.EventType())
	}
	if err := e.Event.Validate(); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("%w: telemetry envelope has no occurred-at timestamp", shared.ErrValidation)
	}
	if e.ObservedAt.IsZero() {
		return fmt.Errorf("%w: telemetry envelope has no observed-at timestamp", shared.ErrValidation)
	}
	if e.OccurredAt.After(e.ObservedAt) {
		return fmt.Errorf("%w: telemetry envelope occurred-at %s is after observed-at %s", shared.ErrValidation, e.OccurredAt, e.ObservedAt)
	}
	if !e.ReceivedAt.IsZero() && e.ObservedAt.After(e.ReceivedAt) {
		return fmt.Errorf("%w: telemetry envelope observed-at %s is after received-at %s", shared.ErrValidation, e.ObservedAt, e.ReceivedAt)
	}
	return nil
}

// StampReceived sets ReceivedAt at ingest (A3), enforcing the ordering invariant against ObservedAt. It
// is the ONLY sanctioned way to set the control-plane timestamp, so the ordering can never be violated by
// a caller assigning the field directly and skipping the check.
func (e *TelemetryEnvelope) StampReceived(t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("%w: received-at timestamp is zero", shared.ErrValidation)
	}
	if e.ObservedAt.After(t) {
		return fmt.Errorf("%w: received-at %s precedes observed-at %s", shared.ErrValidation, t, e.ObservedAt)
	}
	e.ReceivedAt = t
	return nil
}

// Clone returns a deep copy, so an envelope handed downstream (spool, batch, evidence) cannot be mutated
// through the original's payload pointers.
func (e TelemetryEnvelope) Clone() TelemetryEnvelope {
	c := e
	c.Event = e.Event.clone()
	return c
}

// DeriveEventID computes a deterministic, collision-resistant event id from the per-stream coordinates
// that uniquely place an event: (AssetID, BootID, StreamID, Sequence, Class, OccurredAt). Determinism
// makes ingest idempotent (a re-delivered event derives the same id) and makes golden fixtures stable.
func DeriveEventID(assetID, bootID, streamID shared.ID, sequence uint64, class detection.Class, occurredAtNanos int64) shared.ID {
	sum := hashFields("telemetry:event-id:v1",
		assetID.String(), bootID.String(), streamID.String(),
		uint64Str(sequence), string(class), uint64Str(uint64(occurredAtNanos)))
	return shared.ID("te_" + sum[:32])
}
