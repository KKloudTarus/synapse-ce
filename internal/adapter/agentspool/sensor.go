// Package agentspool adapts the existing detection sensor and sink contracts to
// the canonical telemetry normalizer and the durable agent spool. It contains
// orchestration only: normalization remains a pure use case and persistence is
// owned by infrastructure/spool.
package agentspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/normalize"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const telemetryContentType = "application/vnd.synapse.telemetry-envelope+json;version=1"

// SensorIdentity contains the stable attribution needed to turn the legacy
// detection sensor's decoded event into A1's canonical envelope.
type SensorIdentity struct {
	AgentID       shared.ID
	AssetID       shared.ID
	AgentSession  shared.ID
	BootID        shared.ID
	SensorID      string
	SensorVersion string
}

func (i SensorIdentity) validate() error {
	if i.AgentID.IsZero() || i.AssetID.IsZero() || i.AgentSession.IsZero() || i.BootID.IsZero() {
		return fmt.Errorf("%w: telemetry sensor identity is incomplete", shared.ErrValidation)
	}
	if i.SensorID == "" || i.SensorVersion == "" {
		return fmt.Errorf("%w: telemetry sensor id/version is required", shared.ErrValidation)
	}
	return nil
}

// DurableSensor tees every decoded event through Normalize and the WAL before
// exposing it to the detection engine. This ordering means a confirmed
// detection never references a raw event which was silently discarded first.
type DurableSensor struct {
	source   ports.DetectionSensor
	spool    ports.TelemetrySpool
	identity SensorIdentity
	policy   privacy.Policy
	now      func() time.Time
	runID    string

	mu       sync.Mutex
	started  bool
	events   chan detection.Event
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	failures map[detection.Class]uint64
	sequence map[detection.Class]uint64
}

// NewDurableSensor validates dependencies and returns a sensor wrapper. A
// zero-buffer output intentionally propagates pressure back to the kernel
// reader rather than growing an unbounded second queue in memory.
func NewDurableSensor(source ports.DetectionSensor, durable ports.TelemetrySpool, identity SensorIdentity) (*DurableSensor, error) {
	if source == nil || durable == nil {
		return nil, fmt.Errorf("%w: durable sensor needs a source and spool", shared.ErrValidation)
	}
	if err := identity.validate(); err != nil {
		return nil, err
	}
	return &DurableSensor{
		source: source, spool: durable, identity: identity, policy: privacy.DefaultPolicy(), now: time.Now,
		runID:  uuid.NewString(),
		events: make(chan detection.Event), failures: make(map[detection.Class]uint64),
		sequence: make(map[detection.Class]uint64),
	}, nil
}

// SetRedactionPolicy overrides the source-side redaction policy (A6, #627). A DurableSensor is created with
// privacy.DefaultPolicy(); an operator/tenant policy is applied here before Start. An invalid policy is
// rejected so the sensor never ships with a broken (fail-open) redaction config.
func (s *DurableSensor) SetRedactionPolicy(p privacy.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("%w: cannot change the redaction policy after the sensor has started", shared.ErrValidation)
	}
	s.policy = p
	return nil
}

func (s *DurableSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("%w: durable sensor already started", shared.ErrValidation)
	}
	s.started = true
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()
	if err := s.source.Start(runCtx); err != nil {
		cancel()
		return err
	}
	s.wg.Add(1)
	go s.pump(runCtx)
	return nil
}

func (s *DurableSensor) Events() <-chan detection.Event { return s.events }

func (s *DurableSensor) pump(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.events)
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.source.Events():
			if !ok {
				return
			}
			if !s.persist(ctx, event) {
				return
			}
			select {
			case s.events <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *DurableSensor) persist(ctx context.Context, event detection.Event) bool {
	s.mu.Lock()
	s.sequence[event.Class]++
	sequence := s.sequence[event.Class]
	s.mu.Unlock()

	decoded, err := s.decoded(event, sequence)
	if err != nil {
		s.recordFailure(event.Class)
		return true // detection can still evaluate; coverage reports raw loss
	}
	envelope, err := (normalize.Normalizer{}).Normalize(decoded)
	if err != nil {
		s.recordFailure(event.Class)
		return true
	}
	// A6 (#627): redact at the SOURCE — before the WAL/ship — so unredacted secrets/PII never persist on
	// disk or leave the host. The scrubbed envelope carries its RedactionPolicyDigest + a QualityRedacted
	// flag so the redaction travels with the data.
	envelope, _, err = privacy.Scrub(envelope, s.policy)
	if err != nil {
		s.recordFailure(event.Class)
		return true
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		s.recordFailure(event.Class)
		return true
	}
	priority, err := fleetagent.TelemetryPriority(event.Class)
	if err != nil {
		s.recordFailure(event.Class)
		return true
	}
	item := ports.SpoolItem{
		Kind: ports.SpoolRecordTelemetry, Priority: priority, EventID: envelope.EventID,
		EventClass: event.Class, ContentType: telemetryContentType, Payload: payload,
		ObservedAt: envelope.ObservedAt, MustNotShed: telemetry.MustNotShed(event.Class),
		SchemaVersion: envelope.SchemaVersion,
	}
	for {
		if _, err := s.spool.Enqueue(ctx, item); err == nil {
			return true
		} else if !errors.Is(err, ports.ErrTelemetrySpoolSaturated) {
			s.recordFailure(event.Class)
			return true
		}
		if priority == fleetagent.PriorityP3 {
			// P3 is explicitly sheddable. The spool persisted an unknown-coordinate
			// quota gap before returning saturation, so continue observation and
			// report degraded coverage instead of head-of-line blocking P0..P2.
			s.recordFailure(event.Class)
			return true
		}
		// A non-sheddable class applies real backpressure. The spool has already
		// persisted a quota-backpressure gap; retry until A3 ACKs free space or
		// shutdown cancels the observation.
		if err := waitForSpoolCapacity(ctx); err != nil {
			s.recordFailure(event.Class)
			return false
		}
	}
}

func (s *DurableSensor) decoded(event detection.Event, sequence uint64) (normalize.DecodedEvent, error) {
	if err := event.Validate(); err != nil {
		return normalize.DecodedEvent{}, err
	}
	observed := s.now().UTC()
	d := normalize.DecodedEvent{
		Class: event.Class, AgentID: s.identity.AgentID, AgentSessionID: s.identity.AgentSession,
		AssetID: s.identity.AssetID, BootID: s.identity.BootID,
		StreamID: shared.ID(fmt.Sprintf("%s:%s:%s:%s", s.identity.SensorID, s.identity.BootID, s.runID, event.Class)),
		SensorID: s.identity.SensorID, SensorVersion: s.identity.SensorVersion,
		// The legacy sensor's Event.At is a userspace decode timestamp, not a
		// kernel-source timestamp. Leave OccurredAt zero so A1's normalizer
		// honestly applies its fallback and quality flag instead of relabeling it.
		Sequence: sequence, ObservedAt: observed,
	}
	switch event.Class {
	case detection.ClassProcess:
		d.Process = &normalize.DecodedProcess{
			Kind: "exec", PID: event.Process.PID, PPID: event.Process.PPID,
			Comm: event.Process.Comm, Path: event.Process.Path,
			Args: append([]string(nil), event.Process.Args...), UID: event.Process.UID,
		}
	case detection.ClassNetwork:
		d.Network = &normalize.DecodedNetwork{
			Kind: "connect", Proto: event.Network.Proto, Direction: event.Network.Direction,
			RemoteAddr: event.Network.RemoteAddr, RemotePort: event.Network.RemotePort,
			PID: event.Network.PID, Comm: event.Network.Comm,
		}
	case detection.ClassFile:
		d.File = &normalize.DecodedFile{
			Op: event.File.Op, Path: event.File.Path, PID: event.File.PID, Comm: event.File.Comm,
		}
	case detection.ClassPrivilege:
		d.Privilege = &normalize.DecodedPrivilege{
			Kind: event.Privilege.Kind, PID: event.Privilege.PID, Comm: event.Privilege.Comm,
			FromUID: event.Privilege.FromUID, ToUID: event.Privilege.ToUID, Cap: event.Privilege.Cap,
		}
	}
	return d, nil
}

func (s *DurableSensor) recordFailure(class detection.Class) {
	s.mu.Lock()
	s.failures[class]++
	s.mu.Unlock()
}

func (s *DurableSensor) Coverage() []detection.ClassCoverage {
	coverage := append([]detection.ClassCoverage(nil), s.source.Coverage()...)
	s.mu.Lock()
	failures := make(map[detection.Class]uint64, len(s.failures))
	for class, count := range s.failures {
		failures[class] = count
	}
	s.mu.Unlock()
	for index := range coverage {
		if failures[coverage[index].Class] == 0 || coverage[index].State != detection.StateActive {
			continue
		}
		coverage[index].State = detection.StateDegraded
		coverage[index].Reason = fmt.Sprintf("durable telemetry spool rejected %d event(s)", failures[coverage[index].Class])
	}
	return coverage
}

func (s *DurableSensor) Dropped() map[detection.Class]uint64 {
	sourceDropped := s.source.Dropped()
	dropped := make(map[detection.Class]uint64, len(sourceDropped))
	for class, count := range sourceDropped {
		dropped[class] = count
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for class, count := range s.failures {
		dropped[class] += count
	}
	return dropped
}

func (s *DurableSensor) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	err := s.source.Close()
	s.wg.Wait()
	return err
}

var _ ports.DetectionSensor = (*DurableSensor)(nil)
