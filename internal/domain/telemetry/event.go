package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryEvent is the class-typed observation carried by a TelemetryEnvelope. It is telemetry's OWN
// observation type — the whole point of A1 (fixing D4) is that raw telemetry stops reusing
// detection.Event (a thin, single-timestamp shape built for rule matching) as the canonical schema.
//
// Exactly one payload is set — the one matching Class — mirroring the closed-set discipline of
// detection.Event but over telemetry's richer payloads. Class reuses detection.Class as the shared,
// four-value class vocabulary (process/network/file/privilege) so the whole data plane names classes the
// same way; it is only the enum, never the detection observation type.
type TelemetryEvent struct {
	Class     detection.Class
	Process   *ProcessObservation
	Network   *NetworkObservation
	File      *FileObservation
	Privilege *PrivilegeObservation
}

// payloadClass reports which class actually carries a payload, and whether exactly one does.
func (e TelemetryEvent) payloadClass() (detection.Class, bool) {
	set := make([]detection.Class, 0, 1)
	if e.Process != nil {
		set = append(set, detection.ClassProcess)
	}
	if e.Network != nil {
		set = append(set, detection.ClassNetwork)
	}
	if e.File != nil {
		set = append(set, detection.ClassFile)
	}
	if e.Privilege != nil {
		set = append(set, detection.ClassPrivilege)
	}
	if len(set) != 1 {
		return "", false
	}
	return set[0], true
}

// Validate enforces a well-formed event: a known class carrying exactly its own, individually-valid
// payload. A malformed event must never silently match or silently miss downstream.
func (e TelemetryEvent) Validate() error {
	if !e.Class.Valid() {
		return fmt.Errorf("%w: telemetry event has an unknown class %q", shared.ErrValidation, e.Class)
	}
	pc, ok := e.payloadClass()
	if !ok || pc != e.Class {
		return fmt.Errorf("%w: telemetry event of class %s must carry exactly its own payload", shared.ErrValidation, e.Class)
	}
	switch e.Class {
	case detection.ClassProcess:
		return e.Process.Validate()
	case detection.ClassNetwork:
		return e.Network.Validate()
	case detection.ClassFile:
		return e.File.Validate()
	case detection.ClassPrivilege:
		return e.Privilege.Validate()
	default:
		return fmt.Errorf("%w: telemetry event of class %s has no validator", shared.ErrValidation, e.Class)
	}
}

// EventType returns the stable dotted per-event-type name (e.g. "process.exec", "network.connect") used
// for indexing and coarse routing. It is derived from the class and the payload's kind/op, so it never
// drifts from the payload it names.
func (e TelemetryEvent) EventType() string {
	switch e.Class {
	case detection.ClassProcess:
		if e.Process != nil {
			return "process." + e.Process.Kind
		}
	case detection.ClassNetwork:
		if e.Network != nil {
			return "network." + e.Network.Kind
		}
	case detection.ClassFile:
		if e.File != nil {
			return "file." + e.File.Op
		}
	case detection.ClassPrivilege:
		if e.Privilege != nil {
			return "privilege." + e.Privilege.Kind
		}
	}
	return string(e.Class)
}

// clone returns a deep copy so a caller (or a sensor reusing event structs) cannot mutate an event after
// it has been enveloped and, downstream, sealed as evidence.
func (e TelemetryEvent) clone() TelemetryEvent {
	c := TelemetryEvent{Class: e.Class}
	if e.Process != nil {
		c.Process = e.Process.clone()
	}
	if e.Network != nil {
		c.Network = e.Network.clone()
	}
	if e.File != nil {
		c.File = e.File.clone()
	}
	if e.Privilege != nil {
		c.Privilege = e.Privilege.clone()
	}
	return c
}
