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
	transport    ports.TelemetryAuditStore
	sensorStates ports.SensorStateAuditStore
	coverage     ports.CoverageReconciler
	detections   ports.PendingDetectionReconciler
	keys         SigningKeyResolver
	policies     ports.PrivacyPolicyResolver
	bindings     ports.TelemetryAssetBindingStore
	audit        ports.IdempotentAuditLogger
	clock        ports.Clock
}

func NewService(
	transport ports.TelemetryAuditStore,
	keys SigningKeyResolver,
	policies ports.PrivacyPolicyResolver,
	audit ports.IdempotentAuditLogger,
	clock ports.Clock,
) (*Service, error) {
	if transport == nil || keys == nil || policies == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry ingest service needs a transport store, signing-key store, privacy-policy resolver, audit log and clock", shared.ErrValidation)
	}
	return &Service{
		transport: transport,
		keys:      keys,
		policies:  policies,
		bindings:  transport,
		audit:     audit,
		clock:     clock,
	}, nil
}

// SetSensorStateStore enables signed P0 sensor-state history ingest. It is kept
// optional so existing telemetry-only compositions remain compatible.
func (s *Service) SetSensorStateStore(store ports.SensorStateAuditStore) {
	s.sensorStates = store
}

// SetCoverageReconciler enables post-durability fixed-window recomposition.
func (s *Service) SetCoverageReconciler(reconciler ports.CoverageReconciler) {
	s.coverage = reconciler
}

// SetDetectionReconciler enables post-durability repair of detections that reference this telemetry.
func (s *Service) SetDetectionReconciler(reconciler ports.PendingDetectionReconciler) {
	s.detections = reconciler
}

func (s *Service) reconcilePendingDetections(ctx context.Context) error {
	if s.detections == nil {
		return nil
	}
	if _, err := s.detections.ReconcilePendingDetections(ctx); err != nil {
		return fmt.Errorf("reconcile pending detections: %w", err)
	}
	return nil
}

func (s *Service) reconcileCoverage(
	ctx context.Context,
	agentID, assetID, hostID shared.ID,
	fromAt, toAt time.Time,
) error {
	if s.coverage == nil {
		return nil
	}
	return s.coverage.ReconcileCoverage(ctx, ports.CoverageReconcileRequest{
		AgentID: agentID,
		AssetID: assetID,
		HostID:  hostID,
		Since:   fromAt,
		Until:   toAt,
	})
}

func (s *Service) reconcileTelemetryCoverage(
	ctx context.Context,
	manifest fleetagent.TelemetryBatchManifest,
	assetID shared.ID,
) error {
	if err := s.reconcileCoverage(
		ctx, manifest.AgentID, assetID, manifest.HostID,
		manifest.EventTimeMin, manifest.EventTimeMax,
	); err != nil {
		return err
	}
	if s.coverage == nil {
		return nil
	}
	gaps, err := s.transport.ListGapChanges(
		ctx, manifest.AgentID, manifest.StreamID,
		manifest.Position.Epoch, manifest.Position.Sequence,
	)
	if err != nil {
		return fmt.Errorf("read inferred telemetry gap changes: %w", err)
	}
	for _, gap := range gaps {
		if gap.AgentID != manifest.AgentID || gap.AssetID != assetID ||
			gap.StreamID != manifest.StreamID || gap.Epoch != manifest.Position.Epoch ||
			gap.FromAt.IsZero() || gap.ToAt.IsZero() || gap.ToAt.Before(gap.FromAt) {
			return fmt.Errorf("%w: inferred telemetry gap change contradicts the authenticated batch identity", shared.ErrValidation)
		}
		if err := s.reconcileCoverage(
			ctx, manifest.AgentID, assetID, manifest.HostID,
			gap.FromAt, gap.ToAt,
		); err != nil {
			return fmt.Errorf("reconcile inferred telemetry gap coverage: %w", err)
		}
	}
	return nil
}

func (s *Service) Ingest(ctx context.Context, authAgentID shared.ID, req IngestRequest) (IngestResult, error) {
	now := s.clock.Now().UTC()
	m := req.Manifest
	if err := m.Validate(); err != nil {
		return IngestResult{}, err
	}
	if authAgentID.IsZero() || m.AgentID != authAgentID {
		if auditErr := s.reject(ctx, authAgentID, m, "identity_mismatch", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: manifest agent %q is not the authenticated agent %q", shared.ErrForbidden, m.AgentID, authAgentID)
	}
	if m.HostID != authAgentID {
		if auditErr := s.reject(ctx, authAgentID, m, "host_mismatch", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: manifest host %q is not the authenticated agent host %q", shared.ErrForbidden, m.HostID, authAgentID)
	}
	wantSession := fleetagent.CanonicalSessionID(authAgentID)
	if m.AgentSessionID() != wantSession {
		if auditErr := s.reject(ctx, authAgentID, m, "session_mismatch", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: manifest session is not the authenticated enrollment session", shared.ErrForbidden)
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(authAgentID, wantSession, m.Position.Priority)
	if err != nil {
		return IngestResult{}, err
	}
	if m.StreamID != wantStream {
		if auditErr := s.reject(ctx, authAgentID, m, "stream_mismatch", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: manifest stream is not server-derived for the authenticated agent/session/lane", shared.ErrForbidden)
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		if auditErr := s.reject(ctx, authAgentID, m, "asset_binding_missing", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, err
	}
	if assetID.IsZero() || m.AssetID != assetID {
		if auditErr := s.reject(ctx, authAgentID, m, "asset_mismatch", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: manifest asset does not match the server-authoritative host binding", shared.ErrForbidden)
	}

	// Authenticate the compact manifest before parsing potentially expensive event payloads.
	key, err := s.keys.ResolveSigningKey(ctx, m.AgentID, m.KeyID)
	if err != nil {
		if auditErr := s.reject(ctx, authAgentID, m, "key_unresolved", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: resolve telemetry signing key %q: %v", shared.ErrForbidden, m.KeyID, err)
	}
	if err := fleetagent.VerifyTelemetryManifestWithKey(key, now, m); err != nil {
		if auditErr := s.reject(ctx, authAgentID, m, "signature_invalid", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, err
	}
	if err := telemetryschema.Validate(m.SchemaVersion); err != nil {
		if auditErr := s.reject(ctx, authAgentID, m, "schema_unsupported", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, err
	}
	verified, err := verifyEventBinding(m, req.Events)
	if err != nil {
		if auditErr := s.reject(ctx, authAgentID, m, "event_binding", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, err
	}
	if err := s.authorizeRedactionPolicies(ctx, verified); err != nil {
		if auditErr := s.reject(ctx, authAgentID, m, "privacy_policy", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, err
	}

	maxEpoch, err := s.transport.MaxEpoch(ctx, m.AgentID, m.StreamID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read stream max epoch: %w", err)
	}
	if m.Position.Epoch < maxEpoch {
		if auditErr := s.reject(ctx, authAgentID, m, "stale_incarnation", now); auditErr != nil {
			return IngestResult{}, auditErr
		}
		return IngestResult{}, fmt.Errorf("%w: telemetry batch epoch %d is behind the stream's current incarnation %d", shared.ErrValidation, m.Position.Epoch, maxEpoch)
	}

	batch := s.eventBatch(m, verified)
	batchIntentID := telemetryAuditKey("fleet.telemetry.batch_commit", m)
	batchIntent := ports.FleetAuditIntent{
		ID: batchIntentID,
		Entry: ports.AuditEntry{
			Actor: authAgentID.String(), Action: "fleet.telemetry.batch_commit", Target: m.StreamID.String(), At: now,
			Metadata: map[string]string{
				"idempotency_key": batchIntentID,
				"batch_id":        m.BatchID.String(), "asset_id": assetID.String(),
				"payload_digest": m.PayloadDigest,
				"epoch":          fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
				"schema_version": fmt.Sprintf("%d", m.SchemaVersion),
			},
		},
	}
	for attempt := 0; ; attempt++ {
		state, err := s.transport.StreamState(ctx, m.AgentID, m.StreamID, m.Position.Epoch)
		if err != nil {
			return IngestResult{}, fmt.Errorf("read stream state: %w", err)
		}
		if m.Position.Sequence > state.Contiguous && m.Position.Sequence-state.Contiguous > maxForwardGap {
			if auditErr := s.reject(ctx, authAgentID, m, "forward_jump_too_large", now); auditErr != nil {
				return IngestResult{}, auditErr
			}
			return IngestResult{}, fmt.Errorf("%w: telemetry batch sequence %d jumps more than %d ahead of the acked mark %d; let the ACK catch up", shared.ErrValidation, m.Position.Sequence, maxForwardGap, state.Contiguous)
		}
		committedIntent, err := s.transport.CommitBatchWithAudit(ctx, batch, batchIntent)
		if err != nil {
			if errors.Is(err, shared.ErrConflict) {
				if auditErr := s.reject(ctx, authAgentID, m, "sequence_equivocation", now); auditErr != nil {
					return IngestResult{}, auditErr
				}
			}
			return IngestResult{}, fmt.Errorf("commit telemetry batch identity: %w", err)
		}
		if err := s.audit.RecordOnce(ctx, committedIntent.Entry); err != nil {
			return IngestResult{}, fmt.Errorf("audit telemetry batch commitment: %w", err)
		}
		if err := s.transport.AcknowledgeFleetAudit(ctx, committedIntent.ID); err != nil {
			return IngestResult{}, fmt.Errorf("acknowledge telemetry batch commitment audit: %w", err)
		}

		ledger := state.LoadAckLedger()
		if !ledger.Observe(m.Position.Sequence) {
			if err := s.reconcileTelemetryCoverage(ctx, m, assetID); err != nil {
				return IngestResult{}, fmt.Errorf("reconcile telemetry coverage after duplicate: %w", err)
			}
			if err := s.reconcilePendingDetections(ctx); err != nil {
				return IngestResult{}, err
			}
			if err := s.record(ctx, authAgentID, m, "fleet.telemetry.ingest", telemetryBatchGapOpen(m), now); err != nil {
				return IngestResult{}, err
			}
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
		if err := s.reconcileTelemetryCoverage(ctx, m, assetID); err != nil {
			return IngestResult{}, fmt.Errorf("reconcile telemetry coverage: %w", err)
		}
		if err := s.reconcilePendingDetections(ctx); err != nil {
			return IngestResult{}, err
		}
		if err := s.record(ctx, authAgentID, m, "fleet.telemetry.ingest", telemetryBatchGapOpen(m), now); err != nil {
			return IngestResult{}, err
		}
		return IngestResult{Accepted: true, ACK: ledger.HighestContiguous(), Provenance: ProvenanceAcknowledged, GapOpen: gapOpen}, nil
	}
}

type verifiedEvent struct {
	payload  EventPayload
	envelope telemetry.TelemetryEnvelope
}

func verifyEventBinding(m fleetagent.TelemetryBatchManifest, events []EventPayload) ([]verifiedEvent, error) {
	if len(events) != m.KeptCount {
		return nil, fmt.Errorf("%w: batch ships %d events but manifest kept count is %d", shared.ErrValidation, len(events), m.KeptCount)
	}
	want := make(map[shared.ID]string, len(m.Events))
	for _, ref := range m.Events {
		want[ref.ID] = ref.Digest
	}
	seen := make(map[shared.ID]struct{}, len(events))
	verified := make([]verifiedEvent, len(events))
	var minObserved, maxObserved time.Time
	for i, e := range events {
		if e.EventID.IsZero() {
			return nil, fmt.Errorf("%w: shipped event[%d] has no id", shared.ErrValidation, i)
		}
		if !e.Class.Valid() {
			return nil, fmt.Errorf("%w: shipped event[%d] has an unknown class %q", shared.ErrValidation, i, e.Class)
		}
		if e.ObservedAt.IsZero() {
			return nil, fmt.Errorf("%w: shipped event[%d] has no observed-at timestamp", shared.ErrValidation, i)
		}
		if len(e.Payload) == 0 {
			return nil, fmt.Errorf("%w: shipped event[%d] has no payload", shared.ErrValidation, i)
		}
		if _, dup := seen[e.EventID]; dup {
			return nil, fmt.Errorf("%w: shipped event id %q is duplicated", shared.ErrValidation, e.EventID)
		}
		seen[e.EventID] = struct{}{}
		wantDigest, ok := want[e.EventID]
		if !ok {
			return nil, fmt.Errorf("%w: shipped event %q is not in the signed manifest", shared.ErrValidation, e.EventID)
		}
		if got := fleetagent.TelemetryEventDigest(e.Payload, m.AssetID); got != wantDigest {
			return nil, fmt.Errorf("%w: shipped event %q digest does not match the signed manifest", shared.ErrValidation, e.EventID)
		}
		env, err := verifyCanonicalEnvelope(m, e)
		if err != nil {
			return nil, fmt.Errorf("shipped event %q: %w", e.EventID, err)
		}
		if env.RedactionPolicyDigest == "" {
			return nil, fmt.Errorf("%w: shipped event %q has no source redaction policy digest", shared.ErrValidation, e.EventID)
		}
		verified[i] = verifiedEvent{payload: e, envelope: env}
		at := e.ObservedAt.UTC()
		if minObserved.IsZero() || at.Before(minObserved) {
			minObserved = at
		}
		if maxObserved.IsZero() || at.After(maxObserved) {
			maxObserved = at
		}
	}
	if got := fleetagent.TelemetryPayloadDigest(m.Events); got != m.PayloadDigest {
		return nil, fmt.Errorf("%w: manifest payload digest does not match its event refs", shared.ErrValidation)
	}
	if len(events) > 0 && (!m.EventTimeMin.Equal(minObserved) || !m.EventTimeMax.Equal(maxObserved)) {
		return nil, fmt.Errorf("%w: manifest event-time bounds do not match the canonical shipped events", shared.ErrValidation)
	}
	return verified, nil
}

func (s *Service) authorizeRedactionPolicies(ctx context.Context, events []verifiedEvent) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: telemetry ingest requires tenant context", shared.ErrForbidden)
	}
	resolved := make(map[string]struct{}, len(events))
	for _, event := range events {
		digest := event.envelope.RedactionPolicyDigest
		if _, ok := resolved[digest]; ok {
			continue
		}
		assignment, err := s.policies.PrivacyPolicyByDigest(ctx, tenantID, digest)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return fmt.Errorf("%w: source redaction policy is not authorized for this tenant", shared.ErrForbidden)
			}
			return fmt.Errorf("resolve source redaction policy: %w", err)
		}
		if assignment.TenantID != tenantID || assignment.Digest != digest {
			return fmt.Errorf("%w: source redaction policy resolver returned contradictory identity", shared.ErrConflict)
		}
		resolved[digest] = struct{}{}
	}
	return nil
}

func verifyCanonicalEnvelope(
	m fleetagent.TelemetryBatchManifest,
	e EventPayload,
) (telemetry.TelemetryEnvelope, error) {
	var env telemetry.TelemetryEnvelope
	if err := json.Unmarshal(e.Payload, &env); err != nil {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload is not a canonical telemetry envelope", shared.ErrValidation)
	}
	if err := env.Validate(); err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}
	if env.SchemaVersion != m.SchemaVersion {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload schema version %d does not match manifest version %d", shared.ErrValidation, env.SchemaVersion, m.SchemaVersion)
	}
	if env.EventID != e.EventID || env.EventClass != e.Class {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload event identity/class disagrees with the transport wrapper", shared.ErrValidation)
	}
	if !env.ObservedAt.Equal(e.ObservedAt) {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload observed-at disagrees with the transport wrapper", shared.ErrValidation)
	}
	if env.AgentID != m.AgentID || env.AssetID != m.AssetID {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload agent/asset identity disagrees with the server-authoritative manifest", shared.ErrForbidden)
	}
	wantSession := shared.ID(m.AgentSessionID())
	if !env.AgentSessionID.IsZero() && env.AgentSessionID != wantSession {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload agent session disagrees with the server-authoritative manifest", shared.ErrForbidden)
	}
	wantBoot := shared.ID(m.Position.Boot)
	if !env.BootID.IsZero() && env.BootID != wantBoot {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: payload boot id disagrees with the signed delivery incarnation", shared.ErrForbidden)
	}
	if env.SchemaVersion >= 2 && (env.AgentSessionID != wantSession || env.BootID != wantBoot || env.StreamID.IsZero()) {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: telemetry v2 payload is not bound to the signed agent incarnation", shared.ErrForbidden)
	}
	if !env.ReceivedAt.IsZero() {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("%w: agent payload must not pre-stamp server-authoritative received-at", shared.ErrForbidden)
	}
	return env, nil
}

func (s *Service) eventBatch(m fleetagent.TelemetryBatchManifest, events []verifiedEvent) ports.TelemetryEventBatch {
	stored := make([]ports.StoredTelemetryEvent, len(events))
	for i, event := range events {
		e := event.payload
		stored[i] = ports.StoredTelemetryEvent{
			EventID: e.EventID, Class: e.Class,
			Digest:                fleetagent.TelemetryEventDigest(e.Payload, m.AssetID),
			RedactionPolicyDigest: event.envelope.RedactionPolicyDigest,
			Payload:               e.Payload, ObservedAt: e.ObservedAt.UTC(),
		}
	}
	return ports.TelemetryEventBatch{
		BatchID: m.BatchID, PayloadDigest: m.PayloadDigest,
		StreamID: m.StreamID, AgentID: m.AgentID, AssetID: m.AssetID,
		Priority: m.Position.Priority, Epoch: m.Position.Epoch, Sequence: m.Position.Sequence,
		SchemaVersion: m.SchemaVersion, EventTimeMin: m.EventTimeMin.UTC(), EventTimeMax: m.EventTimeMax.UTC(),
		ObservedCount: m.ObservedCount, KeptCount: m.KeptCount,
		SampledOutCount: m.SampledOutCount, TruncatedCount: m.TruncatedCount,
		DroppedCount: m.DroppedCount, SamplingPolicyDigest: m.SamplingPolicyDigest,
		Events: stored,
	}
}

// record makes the durable-admission audit mandatory. Telemetry admission is
// already idempotent, so an exact retry after an audit failure re-runs this with
// the same deterministic key and repairs the missing line instead of duplicating it.
func (s *Service) record(ctx context.Context, actor shared.ID, m fleetagent.TelemetryBatchManifest, action string, gap bool, at time.Time) error {
	if err := s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: action, Target: m.StreamID.String(), At: at,
		Metadata: map[string]string{
			"idempotency_key": telemetryAuditKey(action, m),
			"batch_id":        m.BatchID.String(), "asset_id": m.AssetID.String(),
			"epoch": fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
			"schema_version": fmt.Sprintf("%d", m.SchemaVersion), "gap": fmt.Sprintf("%t", gap),
		},
	}); err != nil {
		return fmt.Errorf("audit telemetry %s: %w", action, err)
	}
	return nil
}

func telemetryAuditKey(action string, m fleetagent.TelemetryBatchManifest) string {
	return fmt.Sprintf("%s:%s:%s:%d:%d", action, m.AgentID, m.StreamID, m.Position.Epoch, m.Position.Sequence)
}

// telemetryBatchGapOpen reconstructs immutable admission metadata from the signed
// manifest. It intentionally does not inspect mutable stream state, so an exact
// retry after an audit outage records the same metadata as the first attempt.
func telemetryBatchGapOpen(m fleetagent.TelemetryBatchManifest) bool {
	return m.Position.Sequence > m.PreviousSequence &&
		m.Position.Sequence-m.PreviousSequence > 1
}

func (s *Service) reject(ctx context.Context, actor shared.ID, m fleetagent.TelemetryBatchManifest, reason string, at time.Time) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: "fleet.telemetry.reject", Target: m.StreamID.String(), At: at,
		Metadata: map[string]string{
			"batch_id": m.BatchID.String(), "manifest_agent_id": m.AgentID.String(), "manifest_host_id": m.HostID.String(),
			"epoch": fmt.Sprintf("%d", m.Position.Epoch), "sequence": fmt.Sprintf("%d", m.Position.Sequence),
			"reason": reason,
		},
	}); err != nil {
		return fmt.Errorf("%w: audit telemetry rejection: %v", shared.ErrSaturated, err)
	}
	return nil
}
