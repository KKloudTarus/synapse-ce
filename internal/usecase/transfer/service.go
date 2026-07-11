// Package transfer implements engagement export/import: a portable bundle
// of an engagement's scope/findings/comments and its tamper-evident evidence chain.
// On import the chain is RE-VERIFIED and the bundle structurally validated BEFORE
// anything is written – a bundle whose hash chain does not verify (or whose internal
// references are inconsistent) is rejected, so chain-of-custody survives moving an
// engagement between Synapse instances.
package transfer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BundleVersion identifies the bundle schema so an importer can refuse unknown formats.
const BundleVersion = "synapse.engagement-bundle/v1"

// Sanity caps so a hostile/oversized bundle can't drive unbounded inserts (the
// transport body is also capped at the handler). Generous for real engagements.
const (
	maxBundleFindings = 50_000
	maxBundleComments = 100_000
	maxBundleEvidence = 100_000
)

// Bundle is the portable export of one engagement. Domain types are marshaled
// natively so export/import round-trip symmetrically; evidence items carry their
// Content + Hash so the chain re-verifies on import.
type Bundle struct {
	Version      string                 `json:"version"`
	ExportedAt   time.Time              `json:"exportedAt"`
	Engagement   *engagement.Engagement `json:"engagement"`
	Findings     []finding.Finding      `json:"findings"`
	Comments     []finding.Comment      `json:"comments"`
	Evidence     []evdom.Evidence       `json:"evidence"`
	EvidenceHead string                 `json:"evidenceHead"`
	// Attestation is the exporter's ed25519 signature over EvidenceHead, so the
	// recipient can verify the chain's ORIGIN, not just its integrity. Optional (the
	// exporting instance may not sign); verified on import when present.
	Attestation *evdom.Attestation `json:"attestation,omitempty"`
}

// Service exports and imports engagement bundles.
type Service struct {
	engagements ports.EngagementRepository
	findings    ports.FindingRepository
	comments    ports.CommentRepository
	evidence    *evidence.Service
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
}

// NewService validates dependencies and returns the transfer service.
func NewService(engagements ports.EngagementRepository, findings ports.FindingRepository, comments ports.CommentRepository, ev *evidence.Service, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if engagements == nil || findings == nil || comments == nil || ev == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: transfer service is missing a dependency", shared.ErrValidation)
	}
	return &Service{engagements: engagements, findings: findings, comments: comments, evidence: ev, audit: audit, clock: clock, ids: ids}, nil
}

// Export assembles a portable bundle for the engagement (its scope, findings,
// comments, and the full evidence chain) and records the egress on the audit log
// (a bundle leaves the instance with the whole custody chain).
func (s *Service) Export(ctx context.Context, actor string, tenantID, engagementID shared.ID) (Bundle, error) {
	eng, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID)
	if err != nil {
		return Bundle{}, fmt.Errorf("load engagement: %w", err)
	}
	// Publishability gate: a bundle is a customer-facing artifact that
	// leaves the instance, so it carries only promotable findings – an unproven
	// exploitation finding (EvidenceScore < bar) must not travel in it.
	findings, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return Bundle{}, fmt.Errorf("load findings: %w", err)
	}
	var comments []finding.Comment
	for _, f := range findings {
		cs, err := s.comments.ListByEngagementFinding(ctx, engagementID, f.ID)
		if err != nil {
			return Bundle{}, fmt.Errorf("load comments: %w", err)
		}
		comments = append(comments, cs...)
	}
	// Verify-on-export (not just List): a bundle leaves with its whole custody chain,
	// so we re-verify it here – this also alerts on tamper and yields the chain-head
	// attestation (origin proof) to travel with the bundle.
	rep, err := s.evidence.Verify(ctx, engagementID)
	if err != nil {
		return Bundle{}, fmt.Errorf("verify evidence: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "engagement.exported", Target: engagementID.String(),
		Metadata: map[string]string{"findings": strconv.Itoa(len(findings)), "evidence_links": strconv.Itoa(len(rep.Items)), "evidence_intact": strconv.FormatBool(rep.Intact)},
		At:       s.clock.Now(),
	}); err != nil {
		return Bundle{}, fmt.Errorf("audit export: %w", err)
	}
	return Bundle{
		Version:      BundleVersion,
		ExportedAt:   s.clock.Now().UTC(),
		Engagement:   eng,
		Findings:     findings,
		Comments:     comments,
		Evidence:     rep.Items,
		EvidenceHead: rep.Head,
		Attestation:  rep.Attestation,
	}, nil
}

// Import re-verifies + structurally validates the bundle, then materializes a NEW
// engagement (fresh id, so import never clobbers existing data) with the bundle's
// findings/comments/evidence remapped to it. ALL validation happens before the
// first write; if any write then fails, the partially-materialized engagement is
// rolled back (Delete cascades), so a broken/partial import never lingers. Audited.
func (s *Service) Import(ctx context.Context, actor string, tenantID shared.ID, b Bundle) (*engagement.Engagement, error) {
	if b.Version != BundleVersion {
		return nil, fmt.Errorf("%w: unsupported bundle version %q", shared.ErrValidation, b.Version)
	}
	if b.Engagement == nil {
		return nil, fmt.Errorf("%w: bundle has no engagement", shared.ErrValidation)
	}
	// Re-verify the chain and validate internal references BEFORE any write.
	if err := evdom.VerifyChain(b.Evidence); err != nil {
		return nil, fmt.Errorf("%w: evidence chain failed verification, import rejected: %v", shared.ErrValidation, err)
	}
	// If the bundle carries an origin attestation, it must be a valid signature
	// over THIS chain's head – a bundle claiming an attestation that does not verify
	// (or signs a different head) is forged/tampered and is rejected. We do not require
	// the key to be pre-trusted here (cross-org transfer); the operator pins keys.
	if b.Attestation != nil {
		// The attestation must be an EVIDENCE-head attestation (domain separation): an
		// audit-head signature carried here is rejected. Empty context = a legacy
		// bare-head attestation, still allowed (the head-equality check below binds it).
		if c := b.Attestation.Context; c != "" && c != evdom.AttestationContextEvidence {
			return nil, fmt.Errorf("%w: bundle attestation is not an evidence-head attestation (context %q)", shared.ErrValidation, c)
		}
		if err := evdom.VerifyAttestation(*b.Attestation); err != nil {
			return nil, fmt.Errorf("%w: evidence attestation failed verification, import rejected: %v", shared.ErrValidation, err)
		}
		head := ""
		if n := len(b.Evidence); n > 0 {
			head = b.Evidence[n-1].Hash
		}
		if b.Attestation.Head != head {
			return nil, fmt.Errorf("%w: evidence attestation signs a different chain head than the bundle", shared.ErrValidation)
		}
	}
	if err := validateBundle(b); err != nil {
		return nil, err
	}

	now := s.clock.Now()
	newEngID := s.ids.NewID()
	// Tenant is set server-side from the importing principal, NEVER trusted from the
	// bundle – an imported engagement belongs to the tenant that imported it ('' = default tenant).
	eng, err := engagement.New(newEngID, tenantID, b.Engagement.Name+" (imported)", b.Engagement.Client, now)
	if err != nil {
		return nil, err
	}
	// Carry over scope/window/RoE; status stays draft and live-recon stays off so the
	// operator re-activates deliberately on this instance.
	eng.Scope = b.Engagement.Scope
	eng.RoE = b.Engagement.RoE
	eng.AuthorizedFrom = b.Engagement.AuthorizedFrom
	eng.AuthorizedTo = b.Engagement.AuthorizedTo
	eng.Timezone = b.Engagement.Timezone
	if err := s.engagements.Create(ctx, eng); err != nil {
		return nil, fmt.Errorf("create imported engagement: %w", err)
	}

	// Materialize children; on ANY failure roll the engagement back (cascade removes
	// whatever was written) so a partial import can never linger.
	if err := s.materialize(ctx, newEngID, b); err != nil {
		if delErr := s.engagements.Delete(ctx, newEngID); delErr != nil {
			return nil, fmt.Errorf("%w (rollback failed: %v)", err, delErr)
		}
		return nil, err
	}

	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "engagement.imported", Target: newEngID.String(),
		Metadata: map[string]string{
			"source_engagement": b.Engagement.ID.String(),
			"findings":          strconv.Itoa(len(b.Findings)),
			"evidence_links":    strconv.Itoa(len(b.Evidence)),
			"evidence_head":     b.EvidenceHead,
		},
		At: now,
	}); err != nil {
		return nil, fmt.Errorf("audit import: %w", err)
	}
	return eng, nil
}

// materialize writes the bundle's findings/comments/evidence under the new
// engagement id, remapping ids. Comment finding refs are guaranteed present by
// validateBundle; evidence refs to an unknown finding are nulled (mirroring the
// evidence.finding_id ON DELETE SET NULL semantics).
func (s *Service) materialize(ctx context.Context, newEngID shared.ID, b Bundle) error {
	idMap := make(map[shared.ID]shared.ID, len(b.Findings))
	newFindings := make([]finding.Finding, 0, len(b.Findings))
	for _, f := range b.Findings {
		nid := s.ids.NewID()
		idMap[f.ID] = nid
		f.ID = nid
		f.EngagementID = newEngID
		newFindings = append(newFindings, f)
	}
	if len(newFindings) > 0 {
		if err := s.findings.Upsert(ctx, newFindings); err != nil {
			return fmt.Errorf("import findings: %w", err)
		}
	}
	for _, c := range b.Comments {
		c.ID = s.ids.NewID()
		c.EngagementID = newEngID
		c.FindingID = idMap[c.FindingID] // present: validateBundle rejects unknown refs
		if err := s.comments.Add(ctx, c); err != nil {
			return fmt.Errorf("import comment: %w", err)
		}
	}
	remapped := make([]evdom.Evidence, 0, len(b.Evidence))
	for _, e := range b.Evidence {
		e.ID = s.ids.NewID()
		e.EngagementID = newEngID
		if e.FindingID != "" {
			e.FindingID = idMap[e.FindingID] // unknown ref -> "" (SET NULL semantics)
		}
		remapped = append(remapped, e)
	}
	if err := s.evidence.ImportVerified(ctx, remapped); err != nil {
		return err
	}
	return nil
}

// validateBundle enforces size caps and internal referential integrity before any
// write, so a hostile/garbled bundle is rejected up front (reject-before-write).
func validateBundle(b Bundle) error {
	if len(b.Findings) > maxBundleFindings || len(b.Comments) > maxBundleComments || len(b.Evidence) > maxBundleEvidence {
		return fmt.Errorf("%w: bundle exceeds size limits", shared.ErrValidation)
	}
	ids := make(map[shared.ID]bool, len(b.Findings))
	for _, f := range b.Findings {
		ids[f.ID] = true
	}
	for _, c := range b.Comments {
		if !ids[c.FindingID] {
			return fmt.Errorf("%w: bundle comment references a finding not in the bundle", shared.ErrValidation)
		}
	}
	return nil
}
