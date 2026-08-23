package telemetry

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SchemaVersion is the current canonical raw-telemetry schema version. The reader keeps the
// previous version in-range so mixed fleets can coexist during rollout. v2 makes the concrete
// delivery-incarnation identity mandatory; v1 remains readable for historical compatibility.
const (
	SchemaVersion = 2
	SchemaMin     = 1
	SchemaMax     = 2
)

// TelemetryEnvelope is the canonical unit of raw telemetry (A1, fixes D4): a class-typed observation plus
// the identity, three distinct timestamps, sequencing, coverage/quality honesty, and host/K8s placement
// that the whole data plane (A2 spool, A3 transport, A5 evidence, B/C detection) is built on.
type TelemetryEnvelope struct {
	SchemaVersion   int
	EventID         shared.ID
	EventType       string
	EventClass      detection.Class
	AgentID         shared.ID
	AgentSessionID  shared.ID
	AssetID         shared.ID
	BootID          shared.ID
	StreamID        shared.ID
	SensorID        string
	SensorVersion   string
	OccurredAt      time.Time
	ObservedAt      time.Time
	ReceivedAt      time.Time
	Sequence        uint64
	CoverageFlags   CoverageFlags
	DataQuality     DataQuality
	ResourceContext ResourceContext
	// RedactionPolicyDigest names the source-side privacy policy that scrubbed this event (A6, #627),
	// recorded WITH the data so a reader knows how it was redacted. It is DISTINCT from any sampling-policy
	// digest. Empty when no redaction policy was applied (pre-A6 path); set by privacy.Scrub.
	RedactionPolicyDigest string
	Event                 TelemetryEvent
}

// Validate enforces a well-formed envelope. v1 tolerates an absent session/boot/stream for historical
// compatibility; v2 requires all three so the canonical event is attributable to one concrete agent
// incarnation rather than only to a long-lived agent id.
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
	if e.SchemaVersion >= 2 {
		if e.AgentSessionID.IsZero() {
			return fmt.Errorf("%w: telemetry v2 envelope has no agent session id", shared.ErrValidation)
		}
		if e.BootID.IsZero() {
			return fmt.Errorf("%w: telemetry v2 envelope has no boot id", shared.ErrValidation)
		}
		if e.StreamID.IsZero() {
			return fmt.Errorf("%w: telemetry v2 envelope has no source stream id", shared.ErrValidation)
		}
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

func (e TelemetryEnvelope) Clone() TelemetryEnvelope {
	c := e
	c.Event = e.Event.clone()
	return c
}

func DeriveEventID(assetID, bootID, streamID shared.ID, sequence uint64, class detection.Class, occurredAtNanos int64) shared.ID {
	sum := hashFields("telemetry:event-id:v1",
		assetID.String(), bootID.String(), streamID.String(),
		uint64Str(sequence), string(class), uint64Str(uint64(occurredAtNanos)))
	return shared.ID("te_" + sum[:32])
}
