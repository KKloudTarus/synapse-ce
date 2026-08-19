// Package normalize turns a decoded kernel event (the sensor's raw, pre-identity output) into the
// canonical telemetry.TelemetryEnvelope the whole data plane consumes (A1, #622). It is PURE and
// DETERMINISTIC: the same DecodedEvent always yields the same envelope, including its derived entity ids
// and event id, so ingest is idempotent (A3) and golden fixtures are stable. It owns no I/O and no clock —
// the collector stamps ObservedAt and resolves the kernel OccurredAt before calling Normalize; ReceivedAt
// is stamped later at ingest via TelemetryEnvelope.StampReceived.
package normalize

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// DecodedEvent is the sensor decode output the normalizer consumes: the raw per-class fields plus the
// identity, sequencing, timestamps, and placement the sensor already knows. Exactly one payload pointer
// is set — the one matching Class. The eBPF decode side (internal/infrastructure/ebpf) builds this from a
// kernel record; the normalizer never touches the kernel or the wire.
type DecodedEvent struct {
	Class detection.Class

	AgentID        shared.ID
	AgentSessionID shared.ID
	AssetID        shared.ID
	BootID         shared.ID
	StreamID       shared.ID
	SensorID       string
	SensorVersion  string
	Sequence       uint64

	// OccurredAt is the KERNEL source time of the event; zero when the sensor could not read a kernel
	// timestamp (the normalizer then falls back to ObservedAt and records the quality flag).
	OccurredAt time.Time
	// ObservedAt is when the collector decoded the event (userspace); it is required.
	ObservedAt time.Time

	Resource telemetry.ResourceContext
	Coverage telemetry.CoverageFlags

	Process   *DecodedProcess
	Network   *DecodedNetwork
	File      *DecodedFile
	Privilege *DecodedPrivilege
}

// DecodedProcess carries the raw process fields including the parent pid and the kernel start times the
// normalizer needs to derive stable entity ids (the fields D4 was missing).
type DecodedProcess struct {
	Kind                 string // "exec" | "fork"
	PID                  int
	PPID                 int
	StartTimeNanos       uint64 // this process's kernel start time; 0 => unknown
	ParentStartTimeNanos uint64 // the parent's kernel start time; 0 => unknown
	Comm                 string
	Path                 string
	Args                 []string
	ArgsTruncated        bool
	PathTruncated        bool
	UID                  int
}

// DecodedNetwork carries the raw flow fields. ProcStartTimeNanos (resolved by the sensor's process table)
// lets the normalizer link the flow to a stable ProcessEntityID; 0 leaves the link empty (honest).
type DecodedNetwork struct {
	Kind               string // "connect" | "sendmsg"
	Proto              string
	Direction          string
	LocalAddr          string
	LocalPort          int
	RemoteAddr         string
	RemotePort         int
	PID                int
	ProcStartTimeNanos uint64
	Comm               string
}

// DecodedFile carries the raw file fields plus device+inode for a stable target id.
type DecodedFile struct {
	Op                 string // "open" | "write" | "rename"
	Path               string
	Device             uint64
	Inode              uint64
	ContentHash        string
	PathTruncated      bool
	PID                int
	ProcStartTimeNanos uint64
	Comm               string
}

// DecodedPrivilege carries the raw privilege-change fields.
type DecodedPrivilege struct {
	Kind               string // "setuid" | "setresuid" | "capset"
	PID                int
	ProcStartTimeNanos uint64
	Comm               string
	FromUID            int
	ToUID              int
	Cap                string
}

// Normalizer maps DecodedEvent → telemetry.TelemetryEnvelope. It is stateless; a zero value is ready to
// use. It is a type (not just a function) so a future caller can inject it behind an interface without a
// signature change.
type Normalizer struct{}

// Normalize produces the canonical envelope for one decoded event, deriving stable entity ids, resolving
// the source timestamp, recording coverage/quality honesty, and validating the result. It returns a
// wrapped shared.ErrValidation for any malformed input so the caller maps it to a 4xx at the edge.
func (Normalizer) Normalize(d DecodedEvent) (telemetry.TelemetryEnvelope, error) {
	if d.ObservedAt.IsZero() {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: decoded event has no observed-at timestamp", shared.ErrValidation)
	}
	if err := exactlyOnePayload(d); err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}

	dq := telemetry.DataQuality(0)

	// Resolve the source timestamp. A missing kernel ts, or one that is after the collector saw the event
	// (clock-domain skew), falls back to ObservedAt so the OccurredAt<=ObservedAt invariant always holds,
	// and is flagged so a reader knows the two are equal by fallback, not by coincidence.
	occurred := d.OccurredAt
	if occurred.IsZero() || occurred.After(d.ObservedAt) {
		occurred = d.ObservedAt
		dq = dq.With(telemetry.QualityKernelTimestampUnavailable)
	}

	event, dq, err := d.buildEvent(dq)
	if err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}

	env := telemetry.TelemetryEnvelope{
		SchemaVersion:   telemetry.SchemaVersion,
		EventID:         telemetry.DeriveEventID(d.AssetID, d.BootID, d.StreamID, d.Sequence, d.Class, occurred.UnixNano()),
		EventType:       event.EventType(),
		EventClass:      d.Class,
		AgentID:         d.AgentID,
		AgentSessionID:  d.AgentSessionID,
		AssetID:         d.AssetID,
		BootID:          d.BootID,
		StreamID:        d.StreamID,
		SensorID:        d.SensorID,
		SensorVersion:   d.SensorVersion,
		OccurredAt:      occurred,
		ObservedAt:      d.ObservedAt,
		Sequence:        d.Sequence,
		CoverageFlags:   d.Coverage,
		DataQuality:     dq,
		ResourceContext: d.Resource,
		Event:           event,
	}
	if err := env.Validate(); err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}
	return env, nil
}

func exactlyOnePayload(d DecodedEvent) error {
	n := 0
	if d.Process != nil {
		n++
	}
	if d.Network != nil {
		n++
	}
	if d.File != nil {
		n++
	}
	if d.Privilege != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("%w: decoded event must carry exactly one payload, found %d", shared.ErrValidation, n)
	}
	return nil
}

func (d DecodedEvent) buildEvent(dq telemetry.DataQuality) (telemetry.TelemetryEvent, telemetry.DataQuality, error) {
	switch d.Class {
	case detection.ClassProcess:
		if d.Process == nil {
			return telemetry.TelemetryEvent{}, dq, mismatch(d.Class)
		}
		return d.buildProcess(dq)
	case detection.ClassNetwork:
		if d.Network == nil {
			return telemetry.TelemetryEvent{}, dq, mismatch(d.Class)
		}
		return d.buildNetwork(dq)
	case detection.ClassFile:
		if d.File == nil {
			return telemetry.TelemetryEvent{}, dq, mismatch(d.Class)
		}
		return d.buildFile(dq)
	case detection.ClassPrivilege:
		if d.Privilege == nil {
			return telemetry.TelemetryEvent{}, dq, mismatch(d.Class)
		}
		return d.buildPrivilege(dq)
	default:
		return telemetry.TelemetryEvent{}, dq, fmt.Errorf("%w: decoded event has unknown class %q", shared.ErrValidation, d.Class)
	}
}

func mismatch(c detection.Class) error {
	return fmt.Errorf("%w: decoded event class %q has no matching payload", shared.ErrValidation, c)
}

func (d DecodedEvent) buildProcess(dq telemetry.DataQuality) (telemetry.TelemetryEvent, telemetry.DataQuality, error) {
	p := d.Process
	if p.StartTimeNanos == 0 {
		dq = dq.With(telemetry.QualityMissingStartTime)
	}
	if p.ArgsTruncated {
		dq = dq.With(telemetry.QualityTruncatedArgv)
	}
	if p.PathTruncated {
		dq = dq.With(telemetry.QualityTruncatedPath)
	}
	obs := &telemetry.ProcessObservation{
		Kind:           p.Kind,
		PID:            p.PID,
		PPID:           p.PPID,
		StartTimeNanos: p.StartTimeNanos,
		EntityID:       telemetry.ProcessEntityID(d.AssetID, d.BootID, p.PID, p.StartTimeNanos),
		Comm:           p.Comm,
		Path:           p.Path,
		Args:           append([]string(nil), p.Args...),
		ArgsTruncated:  p.ArgsTruncated,
		PathTruncated:  p.PathTruncated,
		UID:            p.UID,
	}
	// Derive the parent entity id ONLY when it can be trustworthy. A known parent pid with an unknown
	// start time must NOT be synthesized as a start=0 id: it would silently fail to match the parent's
	// real entity, and could alias the wrong process under parent-PID reuse — the D4 failure mode this
	// change exists to prevent. Leave it empty and record the gap honestly, mirroring linkProcess.
	switch {
	case p.PPID <= 0:
		dq = dq.With(telemetry.QualityMissingPPID)
	case p.ParentStartTimeNanos == 0:
		dq = dq.With(telemetry.QualityMissingParentStartTime)
	default:
		obs.ParentEntityID = telemetry.ProcessEntityID(d.AssetID, d.BootID, p.PPID, p.ParentStartTimeNanos)
	}
	return telemetry.TelemetryEvent{Class: detection.ClassProcess, Process: obs}, dq, nil
}

func (d DecodedEvent) buildNetwork(dq telemetry.DataQuality) (telemetry.TelemetryEvent, telemetry.DataQuality, error) {
	n := d.Network
	obs := &telemetry.NetworkObservation{
		Kind:            n.Kind,
		Proto:           n.Proto,
		Direction:       n.Direction,
		LocalAddr:       n.LocalAddr,
		LocalPort:       n.LocalPort,
		RemoteAddr:      n.RemoteAddr,
		RemotePort:      n.RemotePort,
		PID:             n.PID,
		ProcessEntityID: d.linkProcess(n.PID, n.ProcStartTimeNanos),
		Comm:            n.Comm,
	}
	return telemetry.TelemetryEvent{Class: detection.ClassNetwork, Network: obs}, dq, nil
}

func (d DecodedEvent) buildFile(dq telemetry.DataQuality) (telemetry.TelemetryEvent, telemetry.DataQuality, error) {
	f := d.File
	if f.PathTruncated {
		dq = dq.With(telemetry.QualityTruncatedPath)
	}
	obs := &telemetry.FileObservation{
		Op:              f.Op,
		Path:            f.Path,
		Device:          f.Device,
		Inode:           f.Inode,
		ContentHash:     f.ContentHash,
		PathTruncated:   f.PathTruncated,
		PID:             f.PID,
		ProcessEntityID: d.linkProcess(f.PID, f.ProcStartTimeNanos),
		Comm:            f.Comm,
	}
	return telemetry.TelemetryEvent{Class: detection.ClassFile, File: obs}, dq, nil
}

func (d DecodedEvent) buildPrivilege(dq telemetry.DataQuality) (telemetry.TelemetryEvent, telemetry.DataQuality, error) {
	p := d.Privilege
	obs := &telemetry.PrivilegeObservation{
		Kind:            p.Kind,
		PID:             p.PID,
		ProcessEntityID: d.linkProcess(p.PID, p.ProcStartTimeNanos),
		Comm:            p.Comm,
		FromUID:         p.FromUID,
		ToUID:           p.ToUID,
		Cap:             p.Cap,
	}
	return telemetry.TelemetryEvent{Class: detection.ClassPrivilege, Privilege: obs}, dq, nil
}

// linkProcess derives the stable ProcessEntityID for a non-process event's originating process, or empty
// when the sensor could not resolve the process's start time (correlation unavailable — honestly empty,
// never a wrong-but-present id).
func (d DecodedEvent) linkProcess(pid int, startTimeNanos uint64) shared.ID {
	if pid <= 0 || startTimeNanos == 0 {
		return ""
	}
	return telemetry.ProcessEntityID(d.AssetID, d.BootID, pid, startTimeNanos)
}
