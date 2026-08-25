// Package telemetryingest is the control-plane side of the A3 (#624) agent→control-plane telemetry
// transport: it accepts a signed TelemetryBatchManifest plus its events, verifies the agent's identity,
// signing key, schema, canonical envelope attribution, and then sequences the batch idempotently.
package telemetryingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxForwardGap    = 4096
	maxIngestRetries = 8
)

type Provenance string

const (
	ProvenanceAcknowledged Provenance = "acknowledged"
	ProvenanceRejected     Provenance = "rejected"
)

type EventPayload struct {
	EventID    shared.ID
	Class      detection.Class
	Payload    []byte
	ObservedAt time.Time
}

type IngestRequest struct {
	Manifest fleetagent.TelemetryBatchManifest
	Events   []EventPayload
}

type IngestResult struct {
	Accepted   bool
	Duplicate  bool
	ACK        uint64
	Provenance Provenance
	GapOpen    bool
}

type SigningKeyResolver interface {
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
}

type Service struct {
	transport ports.TelemetryTransportStore
	keys      SigningKeyResolver
	bindings  ports.TelemetryAssetBindingStore
	audit     ports.AuditLogger
	clock     ports.Clock
}

func NewService(transport ports.TelemetryTransportStore, keys SigningKeyResolver, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if transport == nil || keys == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry ingest service needs a transport store, signing-key store, audit log and clock", shared.ErrValidation)
	}
	return &Service{transport: transport, keys: keys, bindings: transport, audit: audit, clock: clock}, nil
}

func (s *Service) Ingest(ctx context.Context, authAgentID shared.ID, req IngestRequest) (IngestResult, error) {
	now := s.clock.Now().UTC()
	m := req.Manifest
	if err := m.Validate(); err != nil {
		return IngestResult{}, err
	}
	if authAgentID.IsZero() || m.AgentID != authAgentID {
		s.reject(ctx, authAgentID, m, "identity_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest agent %q is not the authenticated agent %q", shared.ErrForbidden, m.AgentID, authAgentID)
	}
	if m.HostID != authAgentID {
		s.reject(ctx, authAgentID, m, "host_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest host %q is not the authenticated agent host %q", shared.ErrForbidden, m.HostID, authAgentID)
	}
	wantSession := fleetagent.CanonicalSessionID(authAgentID)
	if m.AgentSessionID() != wantSession {
		s.reject(ctx, authAgentID, m, "session_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest session is not the authenticated enrollment session", shared.ErrForbidden)
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(authAgentID, wantSession, m.Position.Priority)
	if err != nil {
		return IngestResult{}, err
	}
	if m.StreamID != wantStream {
		s.reject(ctx, authAgentID, m, "stream_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest stream is not server-derived for the authenticated agent/session/lane", shared.ErrForbidden)
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		s.reject(ctx, authAgentID, m, "asset_binding_missing", now)
		return IngestResult{}, err
	}
	if assetID.IsZero() || m.AssetID != assetID {
		s.reject(ctx, authAgentID, m, "asset_mismatch", now)
		return IngestResult{}, fmt.Errorf("%w: manifest asset does not match the server-authoritative host binding", shared.ErrForbidden)
	}

	// Authenticate the compact manifest before parsing potentially expensive event payloads.
	key, err := s.keys.ResolveSigningKey(ctx, m.AgentID, m.KeyID)
	if err != nil {
		s.reject(ctx, authAgentID, m, "key_unresolved", now)
		return IngestResult{}, fmt.Errorf("%w: resolve telemetry signing key %q: %v", shared.ErrForbidden, m.KeyID, err)
	}
	if err := fleetagent.VerifyTelemetryManifestWithKey(key, now, m); err != nil {
		s.reject(ctx, authAgentID, m, "signature_invalid", now)
		return IngestResult{}, err
	}
	if err := telemetryschema.Validate(m.SchemaVersion); err != nil {
		s.reject(ctx, authAgentID, m, "schema_unsupported", now)
		return IngestResult{}, err
	}
	if err := verifyEventBinding(m, req.Events); err != nil {
		s.reject(ctx, authAgentID, m, "event_binding", now)
		return IngestResult{}, err
	}

	maxEpoch, err := s.transport.MaxEpoch(ctx, m.AgentID, m.StreamID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read stream max epoch: %w", err)
	}
	if m.Position.Epoch < maxEpoch {
		s.reject(ctx, authAgentID, m, "stale_incarnation", now)
		return IngestResult{}, fmt.Errorf("%w: telemetry batch epoch %d is behind the stream's current incarnation %d", shared.ErrValidation, m.Position.Epoch, maxEpoch)
	}

	batch := s.eventBatch(m, req.Events)
	for attempt := 0; ; attempt++ {
		state, err := s.transport.StreamState(ctx, m.AgentID, m.StreamID, m.Position.Epoch)
		if err != nil {
			return IngestResult{}, fmt.Errorf("read stream state: %w", err)
		}
		if m.Position.Sequence > state.Contiguous && m.Position.Sequence-state.Contiguous > maxForwardGap {
			s.reject(ctx, authAgentID, m, "forward_jump_too_large", now)
			return IngestResult{}, fmt.Errorf("%w: telemetry batch sequence %d jumps more than %d ahead of the acked mark %d; let the ACK catch up", shared.ErrValidation, m.Position.Sequence, maxForwardGap, state.Contiguous)
		}
		if err := s.transport.CommitBatch(ctx, batch); err != nil {
			if errors.Is(err, shared.ErrConflict) {
				s.reject(ctx, authAgentID, m, "sequence_equivocation", now)
			}
			return IngestResult{}, fmt.Errorf("commit telemetry batch identity: %w", err)
		}

		ledger := state.LoadAckLedger()
		if !ledger.Observe(m.Position.Sequence) {
			s.record(ctx, authAgentID, m, "fleet.telemetry.replay", false, now)
			return IngestResult{Accepted: false, Duplicate: true, ACK: ledger.HighestContiguous(), Provenance: ProvenanceAcknowledged}, nil
		}
		if _, err := s.transport.IngestBatchEvents(ctx, batch); err != nil {
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
			continue
		}
		if err != nil {
			return IngestResult{}, fmt.Errorf("save stream state: %w", err)
		}
		gapOpen := len(ledger.Gaps()) > 0
		s.record(ctx, authAgentID, m, "fleet.telemetry.ingest", gapOpen, now)
		return IngestResult{Accepted: true, ACK: ledger.HighestContiguous(), Provenance: ProvenanceAcknowledged, GapOpen: gapOpen}, nil
	}
}

func verifyEventBinding(m fleetagent.TelemetryBatchManifest, events []EventPayload) error {
	if len(events) != m.KeptCount {
		return fmt.Errorf("%w: batch ships %d events but manifest kept count is %d", shared.ErrValidation, len(events), m.KeptCount)
	}
	want := make(map[shared.ID]string, len(m.Events))
	for _, ref := range m.Events {
		want[ref.ID] = ref.Digest
	}
	seen := make(map[shared.ID]struct{}, len(events))
	var minObserved, maxObserved time.Time
	for i, e := range events {
		if e.EventID.IsZero() {
			return fmt.Errorf("%w: shipped event[%d] has no id", shared.ErrValidation, i)
		}
		if !e.Class.Valid() {
			return fmt.Errorf("%w: shipped event[%d] has an unknown class %q", shared.ErrValidation, i, e.Class)
		}
		if e.ObservedAt.IsZero() {
			return fmt.Errorf("%w: shipped event[%d] has no observed-at timestamp", shared.ErrValidation, i)
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
		if err := verifyCanonicalEnvelope(m, e); err != nil {
			return fmt.Errorf("shipped event %q: %w", e.EventID, err)
		}
		at := e.ObservedAt.UTC()
		if minObserved.IsZero() || at.Before(minObserved) {
			minObserved = at
		}
		if maxObserved.IsZero() || at.After(maxObserved) {
			maxObserved = at
		}
	}
	if got := fleetagent.TelemetryPayloadDigest(m.Events); got != m.PayloadDigest {
		return fmt.Errorf("%w: manifest payload digest does not match its event refs", shared.ErrValidation)
	}
	if len(events) > 0 && (!m.EventTimeMin.Equal(minObserved) || !m.EventTimeMax.Equal(maxObserved)) {
		return fmt.Errorf("%w: manifest event-time bounds do not match the canonical shipped events", shared.ErrValidation)
	}
	return nil
}

func verifyCanonicalEnvelope(m fleetagent.TelemetryBatchManifest, e EventPayload) error {
	var env telemetry.TelemetryEnvelope
	if err := json.Unmarshal(e.Payload, &env); err != nil {
		return fmt.Errorf("%w: payload is not a canonical telemetry envelope", shared.ErrValidation)
	}
	if err := env.Validate(); err != nil {
		return err
	}
	if env.SchemaVersion != m.SchemaVersion {
		return fmt.Errorf("%w: payload schema version %d does not match manifest version %d", shared.ErrValidation, env.SchemaVersion, m.SchemaVersion)
	}
	if env.EventID != e.EventID || env.EventClass != e.Class {
		return fmt.Errorf("%w: payload event identity/class disagrees with the transport wrapper", shared.ErrValidation)
	}
	if !env.ObservedAt.Equal(e.ObservedAt) {
		return fmt.Errorf("%w: payload observed-at disagrees with the transport wrapper", shared.ErrValidation)
	}
	if env.AgentID != m.AgentID || env.AssetID != m.AssetID {
		return fmt.Errorf("%w: payload agent/asset identity disagrees with the server-authoritative manifest", shared.ErrForbidden)
	}
	wantSession := shared.ID(m.AgentSessionID())
	if !env.AgentSessionID.IsZero() && env.AgentSessionID != wantSession {
		return fmt.Errorf("%w: payload agent session disagrees with the server-authoritative manifest", shared.ErrForbidden)
	}
	wantBoot := shared.ID(m.Position.Boot)
	if !env.BootID.IsZero() && env.BootID != wantBoot {
		return fmt.Errorf("%w: payload boot id disagrees with the signed delivery incarnation", shared.ErrForbidden)
	}
	if env.SchemaVersion >= 2 && (env.AgentSessionID != wantSession || env.BootID != wantBoot || env.StreamID.IsZero()) {
		return fmt.Errorf("%w: telemetry v2 payload is not bound to the signed agent incarnation", shared.ErrForbidden)
	}
	if !env.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: agent payload must not pre-stamp server-authoritative received-at", shared.ErrForbidden)
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
		BatchID: m.BatchID, PayloadDigest: m.PayloadDigest,
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
			"batch_id": m.BatchID.String(), "manifest_agent_id": m.AgentID.String(), "manifest_host_id": m.HostID.String(),
			"epoch": fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
			"reason": reason,
		},
	})
}
