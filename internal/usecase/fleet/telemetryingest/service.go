// Package telemetryingest is the control-plane side of the A3 (#624) agent→control-plane telemetry
// transport: it accepts a signed TelemetryBatchManifest plus its events, verifies the agent's identity,
// signing key, and schema SERVER-SIDE (fail-closed), sequences the batch idempotently per stream
// incarnation, derives transport gaps from the ACK snapshot, durably stores the events, and returns the
// highest-contiguous ACK so the agent can delete acknowledged batches.
package telemetryingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// maxForwardGap bounds how far a batch's sequence may jump ahead of the acknowledged (contiguous) mark
	// in one stream incarnation. It caps the pending set (and thus per-request O(n) work and stored array
	// size) so a compromised agent streaming sparse sequences cannot grow unbounded state — the back-pressure
	// the AckLedger contract designates to A3 ingest. A well-behaved agent lets the ACK catch up long before
	// this many holes accumulate.
	maxForwardGap = 4096
	// maxIngestRetries bounds the optimistic-concurrency retry loop when concurrent batches for one
	// (agent, stream, epoch) race on the ACK snapshot. Each retry re-reads fresh state; a handful suffices
	// because a well-behaved agent ships one stream sequentially.
	maxIngestRetries = 8
)

// Provenance is the coarse ingest lifecycle state returned to the caller.
type Provenance string

const (
	ProvenanceAcknowledged Provenance = "acknowledged" // stored durably and acknowledged
	ProvenanceRejected     Provenance = "rejected"
)

// EventPayload is one shipped raw telemetry event: its stable id, class, opaque bytes, and source time.
type EventPayload struct {
	EventID    shared.ID
	Class      detection.Class
	Payload    []byte
	ObservedAt time.Time
}

// IngestRequest is a signed batch manifest plus the events it commits to.
type IngestRequest struct {
	Manifest fleetagent.TelemetryBatchManifest
	Events   []EventPayload
}

// IngestResult is the outcome the agent needs: the highest-contiguous ACK for the stream (so it can
// delete acked batches), whether this delivery was newly accepted or an idempotent replay, and whether the
// stream still has an open (derived) gap below the received frontier so a forward-gap is visible.
type IngestResult struct {
	Accepted   bool
	Duplicate  bool
	ACK        uint64
	Provenance Provenance
	GapOpen    bool
}

// SigningKeyResolver is the narrow slice of ports.AgentSigningKeyStore this usecase consumes: resolve a
// telemetry-signing key by (agentID, keyID) to verify a manifest server-side. Defined here (consumer
// side) so the dependency is minimal and the composition root's full store satisfies it directly.
type SigningKeyResolver interface {
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
}

// Service orchestrates verified, idempotent telemetry ingest.
type Service struct {
	transport ports.TelemetryTransportStore
	keys      SigningKeyResolver
	audit     ports.AuditLogger
	clock     ports.Clock
}

// NewService validates and constructs the ingest service.
func NewService(transport ports.TelemetryTransportStore, keys SigningKeyResolver, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if transport == nil || keys == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry ingest service needs a transport store, signing-key store, audit log and clock", shared.ErrValidation)
	}
	return &Service{transport: transport, keys: keys, audit: audit, clock: clock}, nil
}

// Ingest verifies and stores one telemetry batch. authAgentID is the canonical id of the AUTHENTICATED
// agent (from the agent-plane credential, never a wire field); a manifest claiming any other agent is
// rejected. Every rejection is audited. The tenant is bound from ctx by the stores.
func (s *Service) Ingest(ctx context.Context, authAgentID shared.ID, req IngestRequest) (IngestResult, error) {
	now := s.clock.Now().UTC()
	m := req.Manifest
	if err := m.Validate(); err != nil {
		return IngestResult{}, err
	}
	// A0.1 server-authoritative identity: the manifest's agent MUST be the authenticated agent.
	if authAgentID.IsZero() || m.AgentID != authAgentID {
		s.reject(ctx, authAgentID, m, "identity_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest agent %q is not the authenticated agent %q", shared.ErrForbidden, m.AgentID, authAgentID)
	}
	// The shipped events must be exactly the ones the signed manifest commits to (id set + per-event
	// digest), so a transport cannot add, drop, or swap an event body under a signed manifest.
	if err := verifyEventBinding(m, req.Events); err != nil {
		s.reject(ctx, authAgentID, m, "event_binding", now)
		return IngestResult{}, err
	}
	// A0.2 signing key: resolve the named key for this agent and verify the manifest signature fail-closed.
	key, err := s.keys.ResolveSigningKey(ctx, m.AgentID, m.KeyID)
	if err != nil {
		s.reject(ctx, authAgentID, m, "key_unresolved", now)
		return IngestResult{}, fmt.Errorf("%w: resolve telemetry signing key %q: %v", shared.ErrForbidden, m.KeyID, err)
	}
	if err := fleetagent.VerifyTelemetryManifestWithKey(key, now, m); err != nil {
		s.reject(ctx, authAgentID, m, "signature_invalid", now)
		return IngestResult{}, err
	}
	// A0.3 schema: validate the wire schema version against the supported range, fail-closed.
	if err := telemetryschema.Validate(m.SchemaVersion); err != nil {
		s.reject(ctx, authAgentID, m, "schema_unsupported", now)
		return IngestResult{}, err
	}
	// A0.4 incarnation: a batch for an epoch the stream has already advanced past is a stale incarnation.
	// The stream state is keyed by the AUTHENTICATED agent id, so an agent-chosen StreamID can only ever
	// address this agent's own stream space — never a sibling agent's within the tenant.
	maxEpoch, err := s.transport.MaxEpoch(ctx, m.AgentID, m.StreamID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read stream max epoch: %w", err)
	}
	if m.Position.Epoch < maxEpoch {
		s.reject(ctx, authAgentID, m, "stale_incarnation", now)
		return IngestResult{}, fmt.Errorf("%w: telemetry batch epoch %d is behind the stream's current incarnation %d", shared.ErrValidation, m.Position.Epoch, maxEpoch)
	}

	// Delivery sequencing per (agent, stream, epoch), under optimistic concurrency: read the ACK snapshot,
	// classify the sequence, store the events, then write the snapshot back only if its version is unchanged.
	// A concurrent batch for the same stream loses the CAS and we retry from a fresh read — so a race can
	// never lose-update the ACK or fabricate a gap. Each incarnation is an independent ledger, so a reboot's
	// reset-to-1 is a fresh sequence, never a replay of the previous incarnation.
	for attempt := 0; ; attempt++ {
		state, err := s.transport.StreamState(ctx, m.AgentID, m.StreamID, m.Position.Epoch)
		if err != nil {
			return IngestResult{}, fmt.Errorf("read stream state: %w", err)
		}
		// Back-pressure: reject an implausible forward jump before it grows the pending set (A0.4/HIGH-DoS).
		if m.Position.Sequence > state.Contiguous && m.Position.Sequence-state.Contiguous > maxForwardGap {
			s.reject(ctx, authAgentID, m, "forward_jump_too_large", now)
			return IngestResult{}, fmt.Errorf("%w: telemetry batch sequence %d jumps more than %d ahead of the acked mark %d; let the ACK catch up", shared.ErrValidation, m.Position.Sequence, maxForwardGap, state.Contiguous)
		}
		ledger := state.LoadAckLedger()
		if !ledger.Observe(m.Position.Sequence) {
			// Idempotent replay/duplicate within this incarnation: no re-store, ACK is the current mark.
			s.record(ctx, authAgentID, m, "fleet.telemetry.replay", false, now)
			return IngestResult{Accepted: false, Duplicate: true, ACK: ledger.HighestContiguous(), Provenance: ProvenanceAcknowledged}, nil
		}
		// Newly accepted: durably store the events (idempotent), then CAS the ACK snapshot. Events are stored
		// before the snapshot so a crash between them re-heals on retransmit and the ACK never covers unstored
		// data; re-storing on a retry is a no-op.
		if _, err := s.transport.IngestBatchEvents(ctx, s.eventBatch(m, req.Events)); err != nil {
			return IngestResult{}, fmt.Errorf("store telemetry events: %w", err)
		}
		next := ports.TelemetryStreamState{
			AgentID: m.AgentID, StreamID: m.StreamID, Epoch: m.Position.Epoch,
			Contiguous: ledger.HighestContiguous(), Pending: ledger.Pending(), Version: state.Version, UpdatedAt: now,
		}
		err = s.transport.SaveStreamState(ctx, next)
		if errors.Is(err, shared.ErrConflict) {
			if attempt+1 >= maxIngestRetries {
				return IngestResult{}, fmt.Errorf("%w: telemetry stream %q is too contended to sequence after %d attempts", shared.ErrConflict, m.StreamID, maxIngestRetries)
			}
			continue // a concurrent batch advanced the stream; re-read and reclassify
		}
		if err != nil {
			return IngestResult{}, fmt.Errorf("save stream state: %w", err)
		}
		// Gaps are DERIVED from the snapshot (not a separate log), so a filled gap simply stops being open.
		gapOpen := len(ledger.Gaps()) > 0
		s.record(ctx, authAgentID, m, "fleet.telemetry.ingest", gapOpen, now)
		return IngestResult{Accepted: true, ACK: ledger.HighestContiguous(), Provenance: ProvenanceAcknowledged, GapOpen: gapOpen}, nil
	}
}

// verifyEventBinding checks the shipped events are exactly the manifest's committed set: same count, same
// id set (unique), and each event's recomputed digest matches the manifest's EventRef for that id.
func verifyEventBinding(m fleetagent.TelemetryBatchManifest, events []EventPayload) error {
	if len(events) != m.KeptCount {
		return fmt.Errorf("%w: batch ships %d events but manifest kept count is %d", shared.ErrValidation, len(events), m.KeptCount)
	}
	want := make(map[shared.ID]string, len(m.Events))
	for _, ref := range m.Events {
		want[ref.ID] = ref.Digest
	}
	seen := make(map[shared.ID]struct{}, len(events))
	for i, e := range events {
		if e.EventID.IsZero() {
			return fmt.Errorf("%w: shipped event[%d] has no id", shared.ErrValidation, i)
		}
		if !e.Class.Valid() {
			return fmt.Errorf("%w: shipped event[%d] has an unknown class %q", shared.ErrValidation, i, e.Class)
		}
		if len(e.Payload) == 0 {
			return fmt.Errorf("%w: shipped event[%d] has no payload", shared.ErrValidation, i)
		}
		if _, dup := seen[e.EventID]; dup {
			return fmt.Errorf("%w: shipped event id %q is duplicated", shared.ErrValidation, e.EventID)
		}
		seen[e.EventID] = struct{}{}
		wantDigest, ok := want[e.EventID]
		if !ok {
			return fmt.Errorf("%w: shipped event %q is not in the signed manifest", shared.ErrValidation, e.EventID)
		}
		if got := fleetagent.TelemetryEventDigest(e.Payload, m.AssetID); got != wantDigest {
			return fmt.Errorf("%w: shipped event %q digest does not match the signed manifest", shared.ErrValidation, e.EventID)
		}
	}
	// The signed batch-level PayloadDigest must be the digest OF the manifest's event refs, so the field
	// cannot be a stray value under an otherwise-valid signature (go-arch: verify the signed field).
	if got := fleetagent.TelemetryPayloadDigest(m.Events); got != m.PayloadDigest {
		return fmt.Errorf("%w: manifest payload digest does not match its event refs", shared.ErrValidation)
	}
	return nil
}

func (s *Service) eventBatch(m fleetagent.TelemetryBatchManifest, events []EventPayload) ports.TelemetryEventBatch {
	stored := make([]ports.StoredTelemetryEvent, len(events))
	for i, e := range events {
		stored[i] = ports.StoredTelemetryEvent{
			EventID: e.EventID, Class: e.Class,
			Digest:  fleetagent.TelemetryEventDigest(e.Payload, m.AssetID),
			Payload: e.Payload, ObservedAt: e.ObservedAt.UTC(),
		}
	}
	return ports.TelemetryEventBatch{
		StreamID: m.StreamID, AgentID: m.AgentID, AssetID: m.AssetID,
		Epoch: m.Position.Epoch, Sequence: m.Position.Sequence, SchemaVersion: m.SchemaVersion, Events: stored,
	}
}

func (s *Service) record(ctx context.Context, actor shared.ID, m fleetagent.TelemetryBatchManifest, action string, gap bool, at time.Time) {
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: action, Target: m.StreamID.String(), At: at,
		Metadata: map[string]string{
			"batch_id": m.BatchID.String(), "asset_id": m.AssetID.String(),
			"epoch": fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
			"schema_version": fmt.Sprintf("%d", m.SchemaVersion), "gap": fmt.Sprintf("%t", gap),
		},
	})
}

func (s *Service) reject(ctx context.Context, actor shared.ID, m fleetagent.TelemetryBatchManifest, reason string, at time.Time) {
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: "fleet.telemetry.reject", Target: m.StreamID.String(), At: at,
		Metadata: map[string]string{
			"batch_id": m.BatchID.String(), "manifest_agent_id": m.AgentID.String(),
			"epoch": fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
			"reason": reason,
		},
	})
}
