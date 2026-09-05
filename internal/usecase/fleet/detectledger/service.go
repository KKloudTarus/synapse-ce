// Package detectledger turns the agent-side detection engine's output (#422) into hash-chained,
// attributable evidence (#423). It does NOT own a chain: a detection is sealed into the SAME evidence
// spine as findings and judgments, with kind = "detection", so it is defensible in an audit and joins
// the correlation graph.
//
// Boundary (enforced here and asserted by test): DETECTIONS are chained; raw telemetry is NOT. This
// package has no method that seals a detection.Event — only a detection.Detection becomes a chain link.
// Per-event chaining would collapse throughput and is deliberately impossible through this API.
package detectledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// evidenceKindDetection is the chain kind for a sealed detection. It sits alongside "finding",
// "judgment_*", "exploitation_step", etc. in the one evidence chain.
const evidenceKindDetection = "detection"

// EvidenceChain is the narrow slice of the evidence vault this package needs: seal a detection into the
// chain, and verify the chain. It is a consumer-side interface bridged to *evidence.Service at the
// composition root (like offensivepolicy's EvidenceSealer), so this package never depends on the
// concrete vault or the domain Evidence shape.
type EvidenceChain interface {
	// SealOnce appends content under the given kind, bound to the engagement's chain head, and returns
	// the new link's id. It is IDEMPOTENT on idempotencyKey (the detection id): if a link was already
	// sealed for (engagementID, idempotencyKey) it returns that existing link's id and appends NOTHING.
	//
	// This is what closes D3 (#610): sealing a detection into the permanent chain and writing its
	// projection row are two stores with no shared transaction, so a projection write that fails AFTER a
	// successful seal would, on retry, seal a SECOND chain link for the same detection. Keying the seal on
	// the detection id makes the retry return the first link instead — a detection can never be sealed
	// into the chain twice.
	SealOnce(ctx context.Context, engagementID shared.ID, kind string, idempotencyKey string, content []byte, createdBy string) (shared.ID, error)
	// Verify checks the engagement's chain and returns a non-nil error (wrapping evidence.ErrChainBroken)
	// when it is broken, so a dependent report can be blocked.
	//
	// IMPORTANT for the composition-root bridge: evidence.Service.Verify returns (Report, error) and
	// signals a BROKEN chain via Report.Intact=false with a NIL error (the non-nil error is reserved for
	// I/O failures). A bridge must therefore inspect Report.Intact and synthesize an
	// evidence.ErrChainBroken-wrapping error itself — returning the raw error would report a tampered
	// chain as healthy. This contract exists precisely so that mistake cannot be made silently.
	Verify(ctx context.Context, engagementID shared.ID) error
}

// AgentKeyResolver resolves the content-signing key an incoming batch names (#607, A0.2). The batch
// carries a KeyID; the resolver returns the AgentSigningKey bound to (agentID, keyID), and Ingest gates
// on purpose + validity window + revocation + agent binding via VerifyBatchWithKey before trusting the
// signature. An unknown key resolves to an error and the batch is refused — fail closed.
type AgentKeyResolver interface {
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
}

// IngestItem is one detection in a batch together with the asset it was observed on (#423 requirement 5:
// a detection joins the asset model).
type IngestItem = fleetagent.DetectionBatchItem

// IngestResult reports the outcome of ingesting a batch.
type IngestResult struct {
	EngagementID  shared.ID
	SealedRecords []shared.ID
	EvidenceIDs   []shared.ID
	Skipped       []shared.ID // already-sealed detections skipped on an idempotent retry
	Gap           fleetagent.SequenceGap
	// IncidentsCreated is what the correlator opened for this engagement right after the batch sealed new
	// detections; CorrelationFailed marks a correlator error that was audited and did not fail the ingest.
	IncidentsCreated  int
	CorrelationFailed bool
}

// CorrelateFunc folds an engagement's sealed detections into incidents and returns how many it created.
// correlationuc.Service.CorrelateEngagement is adapted to it in the composition root.
type CorrelateFunc func(ctx context.Context, actor string, engagementID shared.ID) (created int, err error)

// Service ingests agent detection batches into the evidence ledger.
type Service struct {
	records    ports.DetectionRecordStore
	provenance ports.DetectionProvenanceStore
	telemetry  ports.TelemetryReferenceResolver
	chain      EvidenceChain
	keys       AgentKeyResolver
	audit      ports.IdempotentAuditLogger
	clock      ports.Clock
	ids        ports.IDGenerator
	retention  time.Duration    // 0 = keep the projection forever (the chain is always permanent)
	holds      legalHoldChecker // optional (#635): when set, an active hold blocks retention expiry
	correlate  CorrelateFunc    // optional: when set, a batch that seals new detections is correlated at once
}

// SetCorrelator wires correlation-on-ingest. With it, an incident exists as soon as the detections behind
// it are sealed, without an operator calling the correlate route. A correlator failure is audited and
// reported in the result; the sealed detections are never rolled back.
func (s *Service) SetCorrelator(f CorrelateFunc) { s.correlate = f }

// legalHoldChecker reports whether an engagement is under an active legal hold. legalholduc.Service
// satisfies it. When wired, Expire refuses to delete a held engagement's data (fail-closed preservation).
type legalHoldChecker interface {
	IsHeld(ctx context.Context, engagementID shared.ID) (bool, error)
}

// SetLegalHoldChecker wires the #635 legal-hold guard (nil ⇒ retention expiry is not hold-gated).
func (s *Service) SetLegalHoldChecker(h legalHoldChecker) { s.holds = h }

// NewService validates its dependencies. Every one is required: a ledger that cannot seal, resolve an
// agent key, persist, or audit is not producing attributable evidence.
func NewService(records ports.DetectionRecordStore, chain EvidenceChain, keys AgentKeyResolver, audit ports.IdempotentAuditLogger, clock ports.Clock, ids ports.IDGenerator, retention time.Duration) (*Service, error) {
	return NewServiceWithProvenance(records, nil, nil, chain, keys, audit, clock, ids, retention)
}

// NewServiceWithProvenance adds the #610 durable provenance seam. Passing both optional dependencies
// enables v2 admission and lifecycle transitions; the legacy constructor retains v1 callers unchanged.
func NewServiceWithProvenance(records ports.DetectionRecordStore, provenance ports.DetectionProvenanceStore, telemetry ports.TelemetryReferenceResolver, chain EvidenceChain, keys AgentKeyResolver, audit ports.IdempotentAuditLogger, clock ports.Clock, ids ports.IDGenerator, retention time.Duration) (*Service, error) {
	if records == nil || chain == nil || keys == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: detection ledger is missing a dependency", shared.ErrValidation)
	}
	if (provenance == nil) != (telemetry == nil) {
		return nil, fmt.Errorf("%w: detection provenance and telemetry resolver must be wired together", shared.ErrValidation)
	}
	if retention < 0 {
		return nil, fmt.Errorf("%w: retention cannot be negative", shared.ErrValidation)
	}
	return &Service{records: records, provenance: provenance, telemetry: telemetry, chain: chain, keys: keys, audit: audit, clock: clock, ids: ids, retention: retention}, nil
}

// Ingest admits one signed, sequenced agent batch: it verifies the signature, detects a sequence gap
// (reported as a potential loss, never silently accepted), seals each detection into the evidence chain
// as kind="detection", and persists the projection rows bound to their chain links and asset.
//
// authAgentID is the canonical id of the AUTHENTICATED agent (from the agent-plane credential, never a
// wire field). A0.1 server-authoritative identity: a batch whose manifest claims any other agent is
// refused BEFORE key resolution or sealing, so a valid agent cannot ship a batch attributed to another —
// the sealed detection always carries the authenticated agent id, never a self-declared one.
func (s *Service) Ingest(ctx context.Context, authAgentID shared.ID, batch fleetagent.AgentBatch, items []IngestItem) (IngestResult, error) {
	if err := batch.Validate(); err != nil {
		return IngestResult{}, err
	}
	if authAgentID.IsZero() || batch.AgentID != authAgentID {
		if err := s.recordAudit(ctx, "detection.batch_rejected", authAgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"manifest_agent_id": batch.AgentID.String(), "reason": "identity_mismatch",
		}); err != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected detection batch: %v", shared.ErrSaturated, err)
		}
		return IngestResult{}, fmt.Errorf("%w: batch agent %q is not the authenticated agent %q", shared.ErrForbidden, batch.AgentID, authAgentID)
	}
	refByID, err := membership(batch, items)
	if err != nil {
		return IngestResult{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return IngestResult{}, fmt.Errorf("%w: detection ingest requires a tenant in context", shared.ErrValidation)
	}

	// Signature: fail closed under the keyed lifecycle (#607). Resolve the signing key the batch names by
	// KeyID; an unknown key admits nothing. VerifyBatchWithKey then refuses — before any detection is
	// sealed — a key of the wrong purpose, a key bound to another agent, an envelope naming a different
	// key, a pending/expired/revoked key, or a bad signature.
	key, err := s.keys.ResolveSigningKey(ctx, batch.AgentID, batch.KeyID)
	if err != nil {
		if auditErr := s.recordAudit(ctx, "detection.batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unknown_key",
		}); auditErr != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected detection batch: %v", shared.ErrSaturated, auditErr)
		}
		return IngestResult{}, fmt.Errorf("%w: no signing key %s for agent %s: %v", shared.ErrForbidden, batch.KeyID, batch.AgentID, err)
	}
	if err := fleetagent.VerifyBatchWithKey(key, fleetagent.PurposeDetectionBatch, s.clock.Now().UTC(), batch); err != nil {
		if auditErr := s.recordAudit(ctx, "detection.batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unverified",
		}); auditErr != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected detection batch: %v", shared.ErrSaturated, auditErr)
		}
		return IngestResult{}, err
	}

	// Sequence gap: a missing or replayed/out-of-order sequence is a batch_gap coverage event on the
	// agent. It must NEVER be silently accepted, so the coverage event is a HARD requirement: if it
	// cannot be recorded, the ingest fails rather than admitting an unrecorded gap.
	last, err := s.records.LastBatchSequence(ctx, batch.AgentID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read last batch sequence: %w", err)
	}
	gap := fleetagent.DetectSequenceGap(last, batch.Sequence)
	if gap.HasGap() {
		if aerr := s.audit.Record(ctx, ports.AuditEntry{
			Actor: batch.AgentID.String(), Action: "detection.batch_gap", Target: batch.EngagementID.String(),
			At: s.clock.Now().UTC(), Metadata: map[string]string{
				"engagement": batch.EngagementID.String(), "last_sequence": fmt.Sprint(last),
				"incoming_sequence": fmt.Sprint(batch.Sequence), "missing": fmt.Sprint(gap.Missing), "replay": fmt.Sprint(gap.Replay),
			},
		}); aerr != nil {
			return IngestResult{Gap: gap}, fmt.Errorf("%w: could not record the batch_gap coverage event: %v", shared.ErrSaturated, aerr)
		}
	}
	// A replay/out-of-order batch is NOT hard-refused: refusing it after a prior partial ingest would
	// strand the un-sealed items forever. Instead ingest is idempotent — each already-sealed detection is
	// skipped below (never sealed twice), so a retry safely completes a partial batch and a pure duplicate
	// seals nothing new. The gap is already reported above.

	result := IngestResult{EngagementID: batch.EngagementID, Gap: gap}
	now := s.clock.Now().UTC()
	for _, it := range items {
		if err := it.Detection.Validate(); err != nil {
			return result, fmt.Errorf("%w: batch detection %s is malformed: %v", shared.ErrValidation, it.ID, err)
		}
		if it.AssetID == "" {
			return result, fmt.Errorf("%w: batch detection %s has no asset", shared.ErrValidation, it.ID)
		}
		payload, err := json.Marshal(it.Detection)
		if err != nil {
			return result, fmt.Errorf("marshal detection %s: %w", it.ID, err)
		}
		// Content binding: the signed ref for this id must match a digest of the bytes the agent committed
		// to (detection + asset). A body swapped in transit for a known id is refused here.
		if got := fleetagent.DetectionContentHash(payload, it.AssetID); got != refByID[it.ID].ContentSHA256 {
			return result, fmt.Errorf("%w: detection %s content does not match its signed digest", shared.ErrValidation, it.ID)
		}
		// A5 (#626): seal a SELF-CONTAINED DetectionEvidenceEnvelope as the permanent chain link — the
		// detection plus its full attribution (tenant/agent/asset/engagement), the admitting batch identity,
		// the agent's content commitment, and rule provenance — so the link stays verifiable and explainable
		// after the expirable projection row is swept. The envelope is deterministic (no ingest clock), so
		// the SealOnce content comparison still converges on an idempotent retry. Provenance is Complete: the
		// detection evidence is durably sealed (the raw-telemetry-durability cross-check is a read-layer tail).
		envelope, err := fleetagent.NewDetectionEvidenceEnvelope(
			tenantID, batch.EngagementID, batch.AgentID, it.AssetID, it.ID, batch.Sequence,
			batch.KeyID, refByID[it.ID].ContentSHA256, fleetagent.ProvenanceComplete, it.Detection,
		)
		if err != nil {
			return result, fmt.Errorf("build detection %s evidence envelope: %w", it.ID, err)
		}
		content, err := envelope.Canonical()
		if err != nil {
			return result, fmt.Errorf("canonicalize detection %s evidence envelope: %w", it.ID, err)
		}
		// Fast-path idempotent resume: skip a detection whose projection row already exists FOR THIS
		// engagement (a retry after a fully-completed item). The skip is engagement-scoped to match the
		// per-engagement seal below — a tenant-wide skip would silently drop the same id in another
		// engagement. The AUTHORITATIVE no-double-seal guarantee is SealOnce, keyed on (engagement,
		// detection id) — so a retry after a seal-then-append crash (no projection row, so HasDetection
		// is false here) still cannot seal a second chain link.
		if exists, err := s.records.HasDetection(ctx, batch.EngagementID, it.ID); err != nil {
			return result, fmt.Errorf("check detection %s: %w", it.ID, err)
		} else if exists {
			result.Skipped = append(result.Skipped, it.ID)
			continue
		}
		evID, err := s.chain.SealOnce(ctx, batch.EngagementID, evidenceKindDetection, it.ID.String(), content, batch.AgentID.String())
		if err != nil {
			return result, fmt.Errorf("seal detection %s: %w", it.ID, err)
		}
		rec := detection.Record{
			ID: it.ID, TenantID: tenantID, EngagementID: batch.EngagementID, AssetID: it.AssetID,
			AgentID: batch.AgentID, Detection: it.Detection, EvidenceID: evID, BatchSeq: batch.Sequence,
			RecordedAt: now,
		}
		if s.retention > 0 {
			rec.ExpiresAt = now.Add(s.retention)
		}
		if err := rec.Validate(); err != nil {
			return result, err
		}
		if err := s.records.AppendDetection(ctx, rec); err != nil {
			return result, fmt.Errorf("persist detection %s: %w", it.ID, err)
		}
		result.SealedRecords = append(result.SealedRecords, rec.ID)
		result.EvidenceIDs = append(result.EvidenceIDs, evID)
	}
	if err := s.recordAuditOnce(ctx, "detection.batch_sealed", batch.AgentID.String(),
		detectionBatchAuditKey("detection.batch_sealed", batch.AgentID, batch.EngagementID, batch.Sequence), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"sealed": fmt.Sprint(len(result.SealedRecords)), "skipped": fmt.Sprint(len(result.Skipped)),
		}); err != nil {
		return result, fmt.Errorf("audit sealed detection batch: %w", err)
	}
	s.correlateAfterIngest(ctx, batch.AgentID, batch.EngagementID, &result)
	return result, nil
}

// correlateAfterIngest runs the wired correlator when the batch sealed at least one new detection. It is
// best effort: the detections are durable, so a correlator failure is audited and surfaced in the result
// rather than returned, and the operator route can still correlate later.
func (s *Service) correlateAfterIngest(ctx context.Context, agentID, engagementID shared.ID, result *IngestResult) {
	if s.correlate == nil || len(result.SealedRecords) == 0 {
		return
	}
	created, err := s.correlate(ctx, agentID.String(), engagementID)
	if err != nil {
		result.CorrelationFailed = true
		_ = s.recordAudit(ctx, "detection.correlate_on_ingest_failed", agentID.String(), map[string]string{
			"engagement": engagementID.String(), "sealed": fmt.Sprint(len(result.SealedRecords)), "error": err.Error(),
		})
		return
	}
	result.IncidentsCreated = created
}

// IngestV2 admits a separately signed v2 detection batch. A v2 item cannot be admitted without its
// actual causal telemetry coordinates: it records their receipt first, seals immutable attribution once,
// and becomes complete only after both the commitment and referenced telemetry are durable.
func (s *Service) IngestV2(ctx context.Context, authAgentID shared.ID, batch fleetagent.AgentBatchV2, items []fleetagent.DetectionBatchItemV2) (IngestResult, error) {
	if s.provenance == nil || s.telemetry == nil {
		return IngestResult{}, fmt.Errorf("%w: attributed detection ingest is not enabled", shared.ErrValidation)
	}
	if err := batch.Validate(); err != nil {
		return IngestResult{}, err
	}
	if authAgentID.IsZero() || batch.AgentID != authAgentID {
		if err := s.recordAudit(ctx, "detection.v2_batch_rejected", authAgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"manifest_agent_id": batch.AgentID.String(), "reason": "identity_mismatch",
		}); err != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected attributed detection batch: %v", shared.ErrSaturated, err)
		}
		return IngestResult{}, fmt.Errorf("%w: batch agent %q is not the authenticated agent %q", shared.ErrForbidden, batch.AgentID, authAgentID)
	}
	if _, err := v2RefByID(batch, items); err != nil {
		return IngestResult{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return IngestResult{}, fmt.Errorf("%w: detection ingest requires a tenant in context", shared.ErrValidation)
	}
	key, err := s.keys.ResolveSigningKey(ctx, batch.AgentID, batch.KeyID)
	if err != nil {
		if auditErr := s.recordAudit(ctx, "detection.v2_batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unknown_key",
		}); auditErr != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected attributed detection batch: %v", shared.ErrSaturated, auditErr)
		}
		return IngestResult{}, fmt.Errorf("%w: no signing key %s for agent %s: %v", shared.ErrForbidden, batch.KeyID, batch.AgentID, err)
	}
	if err := fleetagent.VerifyBatchV2WithKey(key, fleetagent.PurposeDetectionBatch, s.clock.Now().UTC(), batch); err != nil {
		if auditErr := s.recordAudit(ctx, "detection.v2_batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unverified",
		}); auditErr != nil {
			return IngestResult{}, fmt.Errorf("%w: audit rejected attributed detection batch: %v", shared.ErrSaturated, auditErr)
		}
		return IngestResult{}, err
	}
	last, err := s.records.LastBatchSequence(ctx, batch.AgentID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read last batch sequence: %w", err)
	}
	gap := fleetagent.DetectSequenceGap(last, batch.Sequence)
	if gap.HasGap() {
		if err := s.audit.Record(ctx, ports.AuditEntry{Actor: batch.AgentID.String(), Action: "detection.batch_gap", Target: batch.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{
			"engagement": batch.EngagementID.String(), "last_sequence": fmt.Sprint(last),
			"incoming_sequence": fmt.Sprint(batch.Sequence), "missing": fmt.Sprint(gap.Missing), "replay": fmt.Sprint(gap.Replay),
		}}); err != nil {
			return IngestResult{Gap: gap}, fmt.Errorf("%w: could not record the batch_gap coverage event: %v", shared.ErrSaturated, err)
		}
	}

	result := IngestResult{EngagementID: batch.EngagementID, Gap: gap}
	wasComplete := make(map[shared.ID]bool, len(items))
	for _, item := range items {
		if item.Detection.AgentID != batch.AgentID {
			return result, fmt.Errorf("%w: v2 detection %s belongs to agent %s, not %s", shared.ErrForbidden, item.ID, item.Detection.AgentID, batch.AgentID)
		}
		state, found, err := s.provenance.Current(ctx, batch.EngagementID, item.ID)
		if err != nil {
			return result, fmt.Errorf("read v2 detection %s provenance: %w", item.ID, err)
		}
		wasComplete[item.ID] = found && state.Status == detectionprovenance.StatusComplete

		pendingInput, err := (fleetagent.PendingDetectionV2{Batch: batch, Item: item}).Canonical()
		if err != nil {
			return result, fmt.Errorf("canonicalize pending v2 detection %s: %w", item.ID, err)
		}
		if err := admitProvenance(ctx, s.provenance, tenantID, batch.EngagementID, batch, item, pendingInput, s.clock); err != nil {
			return result, err
		}
	}
	completed, err := s.ReconcilePending(ctx, batch.EngagementID)
	if err != nil {
		return result, err
	}
	for _, item := range items {
		state, found, err := s.provenance.Current(ctx, batch.EngagementID, item.ID)
		if err != nil {
			return result, fmt.Errorf("read v2 detection %s provenance: %w", item.ID, err)
		}
		if !found || state.Status != detectionprovenance.StatusComplete {
			continue
		}
		if wasComplete[item.ID] {
			result.Skipped = append(result.Skipped, item.ID)
		} else {
			result.SealedRecords = append(result.SealedRecords, item.ID)
		}
		result.EvidenceIDs = append(result.EvidenceIDs, state.EvidenceID)
	}
	if err := s.recordAuditOnce(ctx, "detection.v2_batch_reconciled", batch.AgentID.String(),
		detectionBatchAuditKey("detection.v2_batch_reconciled", batch.AgentID, batch.EngagementID, batch.Sequence), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence), "completed": fmt.Sprint(completed),
		}); err != nil {
		return result, fmt.Errorf("audit reconciled v2 detection batch: %w", err)
	}
	s.correlateAfterIngest(ctx, batch.AgentID, batch.EngagementID, &result)
	return result, nil
}

// ReconcilePending advances pending v2 provenance only when the original transport coordinates are now
// durably present. It never rewrites a sealed envelope and deliberately cannot invent a missing commitment.
func (s *Service) reconcileDetection(ctx context.Context, state detectionprovenance.Current) (bool, shared.ID, error) {
	history, err := s.provenance.ListTransitions(ctx, state.EngagementID, state.DetectionID)
	if err != nil {
		return false, "", fmt.Errorf("list provenance for detection %s: %w", state.DetectionID, err)
	}
	var received *detectionprovenance.Transition
	var sealed *detectionprovenance.Transition
	telemetryDurable := false
	commitmentPending := false
	for i := range history {
		transition := &history[i]
		switch transition.Kind {
		case detectionprovenance.Received:
			received = transition
		case detectionprovenance.TelemetryDurable:
			telemetryDurable = true
		case detectionprovenance.CommitmentPending:
			commitmentPending = true
		case detectionprovenance.CommitmentSealed:
			sealed = transition
		case detectionprovenance.Acknowledged:
			return true, transition.EvidenceID, nil
		case detectionprovenance.Broken, detectionprovenance.Expired:
			return false, transition.EvidenceID, nil
		}
	}
	if received == nil || len(state.PendingInput) == 0 {
		return false, "", fmt.Errorf("%w: pending detection %s has no durable verified input", shared.ErrConflict, state.DetectionID)
	}
	pending, err := fleetagent.DecodePendingDetectionV2(state.PendingInput)
	if err != nil {
		if appendErr := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, state.EvidenceID, "durable pending input is invalid", s.clock); appendErr != nil {
			return false, "", appendErr
		}
		return false, "", nil
	}
	key, err := s.keys.ResolveSigningKey(ctx, pending.Batch.AgentID, pending.Batch.KeyID)
	if err != nil {
		return false, "", fmt.Errorf("resolve signing key for pending detection %s: %w", state.DetectionID, err)
	}
	if key.Purpose != fleetagent.PurposeDetectionBatch || key.AgentID != pending.Batch.AgentID || key.KeyID != pending.Batch.KeyID {
		if appendErr := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, state.EvidenceID, "durable pending input signing attribution is invalid", s.clock); appendErr != nil {
			return false, "", appendErr
		}
		return false, "", nil
	}
	if err := fleetagent.VerifyBatchV2(key.PublicKey, pending.Batch); err != nil {
		if appendErr := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, state.EvidenceID, "durable pending input signature is invalid", s.clock); appendErr != nil {
			return false, "", appendErr
		}
		return false, "", nil
	}
	if pending.Batch.EngagementID != state.EngagementID || pending.Item.ID != state.DetectionID ||
		pending.Batch.AgentID != received.AgentID || pending.Item.AssetID != received.AssetID ||
		!sameTelemetryReferences(pending.Item.TelemetryRefs, received.TelemetryRefs) {
		if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, state.EvidenceID, "durable pending input contradicts received attribution", s.clock); err != nil {
			return false, "", err
		}
		return false, "", nil
	}

	status, err := s.telemetry.ResolveTelemetryReferences(ctx, received.AgentID, received.AssetID, pending.Item.RedactionPolicyDigest, received.TelemetryRefs)
	if err != nil {
		return false, "", fmt.Errorf("resolve causal telemetry for detection %s: %w", state.DetectionID, err)
	}
	switch status {
	case ports.TelemetryReferencesMissing:
		return false, "", nil
	case ports.TelemetryReferencesContradictory:
		if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, "", "causal telemetry attribution contradicts durable content", s.clock); err != nil {
			return false, "", err
		}
		return false, "", nil
	case ports.TelemetryReferencesDurable:
	default:
		return false, "", fmt.Errorf("%w: unknown telemetry reference status %q", shared.ErrValidation, status)
	}
	if !telemetryDurable {
		if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, "", "causal telemetry durable", s.clock); err != nil {
			return false, "", err
		}
	}
	if sealed == nil {
		if !commitmentPending {
			if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
				detectionprovenance.CommitmentPending, detectionprovenance.StatusPending, "", "evidence commitment pending", s.clock); err != nil {
				return false, "", err
			}
		}
		envelope, err := fleetagent.NewDetectionEvidenceEnvelopeV2(state.TenantID, state.EngagementID, pending.Batch.AgentID,
			pending.Batch.Sequence, pending.Batch.KeyID, pending.Item)
		if err != nil {
			return false, "", fmt.Errorf("build v2 detection %s evidence envelope: %w", state.DetectionID, err)
		}
		content, err := envelope.Canonical()
		if err != nil {
			return false, "", fmt.Errorf("canonicalize v2 detection %s evidence envelope: %w", state.DetectionID, err)
		}
		evidenceID, err := s.chain.SealOnce(ctx, state.EngagementID, evidenceKindDetection, state.DetectionID.String(), content, received.AgentID.String())
		if err != nil {
			return false, "", fmt.Errorf("seal v2 detection %s: %w", state.DetectionID, err)
		}
		if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
			detectionprovenance.CommitmentSealed, detectionprovenance.StatusPending, evidenceID, "evidence commitment sealed", s.clock); err != nil {
			return false, "", err
		}
		sealed = &detectionprovenance.Transition{EvidenceID: evidenceID}
	}
	if sealed.EvidenceID.IsZero() {
		return false, "", fmt.Errorf("%w: sealed detection %s has no evidence identity", shared.ErrConflict, state.DetectionID)
	}
	exists, err := s.records.HasDetection(ctx, state.EngagementID, state.DetectionID)
	if err != nil {
		return false, "", fmt.Errorf("check v2 detection %s: %w", state.DetectionID, err)
	}
	if !exists {
		now := s.clock.Now().UTC()
		record := detection.Record{
			ID: state.DetectionID, TenantID: state.TenantID, EngagementID: state.EngagementID,
			AssetID: pending.Item.AssetID, AgentID: pending.Batch.AgentID, Detection: pending.Item.Detection,
			EvidenceID: sealed.EvidenceID, BatchSeq: pending.Batch.Sequence, RecordedAt: now,
		}
		if s.retention > 0 {
			record.ExpiresAt = now.Add(s.retention)
		}
		if err := record.Validate(); err != nil {
			return false, "", err
		}
		if err := s.records.AppendDetection(ctx, record); err != nil {
			return false, "", fmt.Errorf("persist v2 detection %s: %w", state.DetectionID, err)
		}
	}
	if err := appendProvenance(ctx, s.provenance, state.TenantID, state.EngagementID, state.DetectionID,
		detectionprovenance.Acknowledged, detectionprovenance.StatusComplete, sealed.EvidenceID, "telemetry reconciliation complete", s.clock); err != nil {
		return false, "", err
	}
	return true, sealed.EvidenceID, nil
}

func (s *Service) ReconcilePending(ctx context.Context, engagementID shared.ID) (int, error) {
	if s.provenance == nil || s.telemetry == nil {
		return 0, fmt.Errorf("%w: attributed detection reconciliation is not enabled", shared.ErrValidation)
	}
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: reconciliation requires an engagement", shared.ErrValidation)
	}
	current, err := s.provenance.ListCurrent(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list pending detection provenance: %w", err)
	}
	completed := 0
	for _, state := range current {
		if state.Status != detectionprovenance.StatusPending {
			continue
		}
		wasCompleted, _, err := s.reconcileDetection(ctx, state)
		if err != nil {
			return completed, err
		}
		if wasCompleted {
			completed++
		}
	}
	return completed, nil
}

// ReconcilePendingDetections repairs every pending detection in the tenant bound to ctx. It is safe
// to call after each durable telemetry commit and during tenant-scoped startup/background repair.
func (s *Service) ReconcilePendingDetections(ctx context.Context) (int, error) {
	if s.provenance == nil || s.telemetry == nil {
		return 0, fmt.Errorf("%w: attributed detection reconciliation is not enabled", shared.ErrValidation)
	}
	current, err := s.provenance.ListPending(ctx)
	if err != nil {
		return 0, fmt.Errorf("list pending detection provenance: %w", err)
	}
	completed := 0
	for _, state := range current {
		wasCompleted, _, err := s.reconcileDetection(ctx, state)
		if err != nil {
			return completed, err
		}
		if wasCompleted {
			completed++
		}
	}
	return completed, nil
}

// ReconciliationRunner repairs pending detection provenance across every persisted tenant.
// Tenant discovery is global; each repair call is rebound to exactly one tenant context.
// VerifyChain checks the engagement's evidence chain. When it is broken, the terminal provenance facts
// are retained alongside the original failure so every downstream report remains blocked by that cause.
func (s *Service) VerifyChain(ctx context.Context, engagementID shared.ID) error {
	err := s.chain.Verify(ctx, engagementID)
	if err == nil || s.provenance == nil {
		return err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return err
	}
	current, listErr := s.provenance.ListCurrent(ctx, engagementID)
	if listErr != nil {
		return fmt.Errorf("verify detection chain: %w; list provenance after failure: %v", err, listErr)
	}
	for _, state := range current {
		if state.Status == detectionprovenance.StatusBroken || state.Status == detectionprovenance.StatusExpired {
			continue
		}
		if appendErr := appendProvenance(ctx, s.provenance, tenantID, engagementID, state.DetectionID,
			detectionprovenance.Broken, detectionprovenance.StatusBroken, state.EvidenceID, "evidence chain verification failed", s.clock); appendErr != nil {
			return fmt.Errorf("verify detection chain: %w; record broken provenance: %v", err, appendErr)
		}
	}
	return err
}

// ListDetections returns the engagement's (non-expired) detection records, tenant-scoped by the store.
func (s *Service) ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error) {
	return s.records.ListDetections(ctx, engagementID)
}

// Reader is the read-only projection of the ledger, for the HTTP read routes. It needs only the record
// store — no chain, key resolver, or audit — so the read surface can be wired live before the agent
// batch-ingest transport is. The full Service handles the write (ingest/seal/expire) path.
type Reader struct{ records ports.DetectionRecordStore }

// NewReader builds the read-only ledger view.
func NewReader(records ports.DetectionRecordStore) (*Reader, error) {
	if records == nil {
		return nil, fmt.Errorf("%w: detection reader needs a record store", shared.ErrValidation)
	}
	return &Reader{records: records}, nil
}

// ListDetections returns the engagement's non-expired detection records, tenant-scoped.
func (r *Reader) ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error) {
	return r.records.ListDetections(ctx, engagementID)
}

// Incidents returns the incident rollup over the engagement's detections.
func (r *Reader) Incidents(ctx context.Context, engagementID shared.ID) ([]detection.Incident, error) {
	recs, err := r.records.ListDetections(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return detection.Rollup(recs), nil
}

// Incidents returns the incident-level rollup for an engagement. The rollup is a view: the individual
// attributable detections remain the ledger underneath.
func (s *Service) Incidents(ctx context.Context, engagementID shared.ID) ([]detection.Incident, error) {
	recs, err := s.records.ListDetections(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return detection.Rollup(recs), nil
}

// Expire removes projection rows whose retention has elapsed, as an AUDITED action carrying the actor
// and reason. It never removes chain links (those are permanent) and never runs silently: deleting
// evidence without a trail is exactly what this project exists to prevent.
func (s *Service) Expire(ctx context.Context, engagementID shared.ID, actor, reason string) (int, error) {
	if strings.TrimSpace(actor) == "" {
		return 0, fmt.Errorf("%w: expiry must name the actor", shared.ErrValidation)
	}
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: expiry must carry a reason", shared.ErrValidation)
	}
	// Legal hold (#635): a held engagement's data must NOT be expired, even past its retention window.
	// Fail-closed — a checker error blocks the deletion rather than risk destroying held evidence.
	if s.holds != nil {
		held, herr := s.holds.IsHeld(ctx, engagementID)
		if herr != nil {
			return 0, fmt.Errorf("legal-hold check before expiry: %w", herr)
		}
		if held {
			return 0, fmt.Errorf("%w: engagement %s is under a legal hold; retention expiry is suspended", shared.ErrForbidden, engagementID)
		}
	}

	expired, err := s.records.ListExpiredDetections(ctx, engagementID, s.clock.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("list expired detections: %w", err)
	}
	if len(expired) == 0 {
		return 0, nil
	}
	if s.provenance == nil {
		return s.deleteExpiredProjections(ctx, engagementID, expired, actor, reason)
	}

	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return 0, fmt.Errorf("%w: provenance expiry requires a tenant in context", shared.ErrValidation)
	}
	for _, detectionID := range expired {
		current, found, err := s.provenance.Current(ctx, engagementID, detectionID)
		if err != nil {
			return 0, fmt.Errorf("read provenance before expiry: %w", err)
		}
		if !found {
			return 0, fmt.Errorf("%w: detection %s has no durable provenance", shared.ErrConflict, detectionID)
		}
		if current.Status == detectionprovenance.StatusBroken {
			return 0, fmt.Errorf("%w: detection %s provenance is broken", shared.ErrConflict, detectionID)
		}
		if current.Status != detectionprovenance.StatusExpired {
			if err := appendProvenance(ctx, s.provenance, tenantID, engagementID, detectionID,
				detectionprovenance.Expired, detectionprovenance.StatusExpired, current.EvidenceID, reason, s.clock); err != nil {
				return 0, err
			}
		}
	}
	return s.deleteExpiredProjections(ctx, engagementID, expired, actor, reason)
}

// deleteExpiredProjections audits the actor and reason BEFORE dropping any projection row.
// The permanent chain and (when enabled) the Expired provenance tombstone already record the
// lifecycle, but the human actor/reason attribution exists only here — so a failed audit must
// stop the deletion rather than leave unattributable data loss behind. The key is derived from
// the immutable expiry set, so an exact retry reuses the same line instead of duplicating it.
func (s *Service) deleteExpiredProjections(ctx context.Context, engagementID shared.ID, ids []shared.ID, actor, reason string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if err := s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: actor, Action: "detection.expired", Target: engagementID.String(), At: s.clock.Now().UTC(),
		Metadata: map[string]string{
			"idempotency_key": deletionAuditKey("detection.expired", engagementID, ids, actor, reason),
			"engagement":      engagementID.String(), "reason": reason, "expired": fmt.Sprint(len(ids)),
		},
	}); err != nil {
		return 0, fmt.Errorf("audit detection expiry before deletion: %w", err)
	}
	deleted := 0
	for _, detectionID := range ids {
		removed, err := s.records.DeleteDetection(ctx, engagementID, detectionID)
		if err != nil {
			return deleted, fmt.Errorf("delete expired detection %s: %w", detectionID, err)
		}
		if removed {
			deleted++
		}
	}
	return deleted, nil
}

// Purge is an on-demand governed deletion of ALL of an engagement's current detection projection
// rows (#635 data deletion / right-to-erasure). Unlike Expire it is not gated on the retention
// window — an operator/DPO purges the engagement's queryable data on demand — but it is otherwise
// the SAME governed removal as retention expiry: legal-hold-checked (a held engagement refuses,
// fail-closed), audited with the actor+reason BEFORE any row is dropped, provenance-tombstoned when
// provenance is enabled, and it never touches the permanent hash chain — only the projection is
// removed. Raw PII never enters that chain (source-side redaction), so purging the projection is
// the deletion this platform can honestly offer. Returns the count purged.
func (s *Service) Purge(ctx context.Context, engagementID shared.ID, actor, reason string) (int, error) {
	if strings.TrimSpace(actor) == "" {
		return 0, fmt.Errorf("%w: purge must name the actor", shared.ErrValidation)
	}
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: purge must carry a reason", shared.ErrValidation)
	}
	// Legal hold (#635): a held engagement's data must NOT be deleted, even on an erasure request —
	// preservation trumps erasure. Fail-closed: a checker error blocks the deletion.
	if s.holds != nil {
		held, herr := s.holds.IsHeld(ctx, engagementID)
		if herr != nil {
			return 0, fmt.Errorf("legal-hold check before purge: %w", herr)
		}
		if held {
			return 0, fmt.Errorf("%w: engagement %s is under a legal hold; data deletion is suspended", shared.ErrForbidden, engagementID)
		}
	}

	recs, err := s.records.ListDetections(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list detections for purge: %w", err)
	}
	if len(recs) == 0 {
		return 0, nil
	}
	ids := make([]shared.ID, 0, len(recs))
	for _, r := range recs {
		ids = append(ids, r.ID)
	}

	if s.provenance != nil {
		tenantID, ok := shared.TenantFrom(ctx)
		if !ok || tenantID.IsZero() {
			return 0, fmt.Errorf("%w: provenance purge requires a tenant in context", shared.ErrValidation)
		}
		for _, detectionID := range ids {
			current, found, err := s.provenance.Current(ctx, engagementID, detectionID)
			if err != nil {
				return 0, fmt.Errorf("read provenance before purge: %w", err)
			}
			if !found {
				return 0, fmt.Errorf("%w: detection %s has no durable provenance", shared.ErrConflict, detectionID)
			}
			if current.Status == detectionprovenance.StatusBroken {
				return 0, fmt.Errorf("%w: detection %s provenance is broken", shared.ErrConflict, detectionID)
			}
			if current.Status != detectionprovenance.StatusExpired {
				if err := appendProvenance(ctx, s.provenance, tenantID, engagementID, detectionID,
					detectionprovenance.Expired, detectionprovenance.StatusExpired, current.EvidenceID, reason, s.clock); err != nil {
					return 0, err
				}
			}
		}
	}
	return s.purgeProjections(ctx, engagementID, ids, actor, reason)
}

// purgeProjections audits the actor+reason (action detection.purged) BEFORE dropping any row, on the
// same fail-closed contract as deleteExpiredProjections — a failed audit stops the deletion so no
// unattributable data loss is left behind. The key is derived from the purged set, so an exact retry
// reuses the same line instead of duplicating it.
func (s *Service) purgeProjections(ctx context.Context, engagementID shared.ID, ids []shared.ID, actor, reason string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if err := s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: actor, Action: "detection.purged", Target: engagementID.String(), At: s.clock.Now().UTC(),
		Metadata: map[string]string{
			"idempotency_key": deletionAuditKey("detection.purged", engagementID, ids, actor, reason),
			"engagement":      engagementID.String(), "reason": reason, "purged": fmt.Sprint(len(ids)),
		},
	}); err != nil {
		return 0, fmt.Errorf("audit detection purge before deletion: %w", err)
	}
	deleted := 0
	for _, detectionID := range ids {
		removed, err := s.records.DeleteDetection(ctx, engagementID, detectionID)
		if err != nil {
			return deleted, fmt.Errorf("delete detection %s: %w", detectionID, err)
		}
		if removed {
			deleted++
		}
	}
	return deleted, nil
}

// deletionAuditKey binds the audit line to the exact deletion set (per action) so a retry of the
// same deletion repairs a missing line, while a later deletion of different detections records its
// own. The action prefix keeps expiry and purge lines distinct even over an identical set.
func deletionAuditKey(action string, engagementID shared.ID, ids []shared.ID, actor, reason string) string {
	sorted := make([]string, 0, len(ids))
	for _, id := range ids {
		sorted = append(sorted, id.String())
	}
	sort.Strings(sorted)
	h := sha256.New()
	write := func(value string) {
		_, _ = fmt.Fprintf(h, "%d:", len(value))
		_, _ = h.Write([]byte(value))
	}
	// The action is NOT hashed — the returned key is prefixed with it, which already keeps expiry and
	// purge lines distinct over an identical set. Keeping it out of the preimage leaves the expiry
	// digest byte-identical to the pre-refactor key, so a retry straddling a binary upgrade still dedups.
	write(engagementID.String())
	write(strings.TrimSpace(actor))
	write(strings.TrimSpace(reason))
	write(fmt.Sprint(len(sorted)))
	for _, id := range sorted {
		write(id)
	}
	return action + ":" + engagementID.String() + ":" + hex.EncodeToString(h.Sum(nil))
}

// membership asserts the supplied items are EXACTLY the signed batch membership — a multiset match, so a
// duplicate item id or a missing/extra signed id is rejected (not just a subset+count check). It returns
// the ref-by-id map so the caller can check each item's content digest against its signed ref.
func membership(batch fleetagent.AgentBatch, items []IngestItem) (map[shared.ID]fleetagent.DetectionRef, error) {
	refByID := make(map[shared.ID]fleetagent.DetectionRef, len(batch.Detections))
	for _, ref := range batch.Detections {
		if _, dup := refByID[ref.ID]; dup {
			return nil, fmt.Errorf("%w: signed batch names detection %s more than once", shared.ErrValidation, ref.ID)
		}
		refByID[ref.ID] = ref
	}
	if len(items) != len(refByID) {
		return nil, fmt.Errorf("%w: batch names %d detections but %d were supplied", shared.ErrValidation, len(refByID), len(items))
	}
	seen := make(map[shared.ID]struct{}, len(items))
	for _, it := range items {
		if _, ok := refByID[it.ID]; !ok {
			return nil, fmt.Errorf("%w: detection %s is not in the signed batch membership", shared.ErrValidation, it.ID)
		}
		if _, dup := seen[it.ID]; dup {
			return nil, fmt.Errorf("%w: detection %s supplied more than once", shared.ErrValidation, it.ID)
		}
		seen[it.ID] = struct{}{}
	}
	return refByID, nil
}

func detectionBatchAuditKey(action string, agentID, engagementID shared.ID, sequence uint64) string {
	return fmt.Sprintf("%s:%s:%s:%d", action, agentID, engagementID, sequence)
}

// recordAuditOnce makes successful custody outcomes retry-repairable without
// weakening SealOnce or coupling the evidence chain to the audit store.
func (s *Service) recordAuditOnce(ctx context.Context, action, actor, key string, meta map[string]string) error {
	metadata := make(map[string]string, len(meta)+1)
	for name, value := range meta {
		metadata[name] = value
	}
	metadata["idempotency_key"] = key
	return s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: actor, Action: action, Target: metadata["engagement"],
		At: s.clock.Now().UTC(), Metadata: metadata,
	})
}

// recordAudit is the best-effort path for rejected input that mutated no state.
// Successful custody paths use recordAuditOnce and surface failures.
func (s *Service) recordAudit(ctx context.Context, action, actor string, meta map[string]string) error {
	return s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: action, Target: meta["engagement"],
		At: s.clock.Now().UTC(), Metadata: meta,
	})
}
