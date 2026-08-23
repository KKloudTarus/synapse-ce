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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
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
}

// Service ingests agent detection batches into the evidence ledger.
type Service struct {
	records   ports.DetectionRecordStore
	chain     EvidenceChain
	keys      AgentKeyResolver
	audit     ports.AuditLogger
	clock     ports.Clock
	ids       ports.IDGenerator
	retention time.Duration // 0 = keep the projection forever (the chain is always permanent)
}

// NewService validates its dependencies. Every one is required: a ledger that cannot seal, resolve an
// agent key, persist, or audit is not producing attributable evidence.
func NewService(records ports.DetectionRecordStore, chain EvidenceChain, keys AgentKeyResolver, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, retention time.Duration) (*Service, error) {
	if records == nil || chain == nil || keys == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: detection ledger is missing a dependency", shared.ErrValidation)
	}
	if retention < 0 {
		return nil, fmt.Errorf("%w: retention cannot be negative", shared.ErrValidation)
	}
	return &Service{records: records, chain: chain, keys: keys, audit: audit, clock: clock, ids: ids, retention: retention}, nil
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
		s.recordAudit(ctx, "detection.batch_rejected", authAgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"manifest_agent_id": batch.AgentID.String(), "reason": "identity_mismatch",
		})
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
		s.recordAudit(ctx, "detection.batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unknown_key",
		})
		return IngestResult{}, fmt.Errorf("%w: no signing key %s for agent %s: %v", shared.ErrForbidden, batch.KeyID, batch.AgentID, err)
	}
	if err := fleetagent.VerifyBatchWithKey(key, fleetagent.PurposeDetectionBatch, s.clock.Now().UTC(), batch); err != nil {
		s.recordAudit(ctx, "detection.batch_rejected", batch.AgentID.String(), map[string]string{
			"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
			"key_id": batch.KeyID, "reason": "unverified",
		})
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
	s.recordAudit(ctx, "detection.batch_sealed", batch.AgentID.String(), map[string]string{
		"engagement": batch.EngagementID.String(), "sequence": fmt.Sprint(batch.Sequence),
		"sealed": fmt.Sprint(len(result.SealedRecords)), "skipped": fmt.Sprint(len(result.Skipped)),
	})
	return result, nil
}

// VerifyChain checks the engagement's evidence chain; a broken chain returns an error wrapping
// evidence.ErrChainBroken so the report that depends on it is blocked, exactly as any chain break is.
func (s *Service) VerifyChain(ctx context.Context, engagementID shared.ID) error {
	return s.chain.Verify(ctx, engagementID)
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
	expired, err := s.records.ExpireDetections(ctx, engagementID, s.clock.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("expire detections: %w", err)
	}
	s.recordAudit(ctx, "detection.expired", actor, map[string]string{
		"engagement": engagementID.String(), "reason": reason, "expired": fmt.Sprint(len(expired)),
	})
	return len(expired), nil
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

func (s *Service) recordAudit(ctx context.Context, action, actor string, meta map[string]string) {
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: meta["engagement"], At: s.clock.Now().UTC(), Metadata: meta}); err != nil {
		// Audit is best-effort here (the seal already happened / is about to), but never swallowed silently
		// at the type level: callers that require a guaranteed audit use the evidence chain, which is the
		// authoritative record. A dropped audit line is logged by the audit adapter, not here.
		_ = err
	}
}
