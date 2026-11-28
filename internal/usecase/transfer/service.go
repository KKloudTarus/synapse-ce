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

// Bundle versions identify the bundle schema so an importer can refuse unknown formats. Each version is
// the oldest one whose importers verify every link the bundle carries; a label may be newer than its
// content requires, never older.
const (
	// BundleVersion is written when any link carries a SealedFindingID (a finding-linked link that was
	// itself imported, #1722). An importer before this release recomputes such a link over its remapped
	// FindingID and would reject the chain as tampered; it refuses the format by version instead.
	BundleVersion = "synapse.engagement-bundle/v3"
	// BundleVersionFramed is written when any link is framed (evidence.HashSchemeFramed) and none carries
	// a sealed finding id. v0.4.0 importers accept it.
	BundleVersionFramed = "synapse.engagement-bundle/v2"
	// BundleVersionLegacy is written when every link is legacy, so v0.3.0 and older importers still
	// accept a bundle they can verify.
	BundleVersionLegacy = "synapse.engagement-bundle/v1"
)

// bundleVersionRank orders the versions an importer knows; an unknown label ranks below every one.
func bundleVersionRank(version string) int {
	switch version {
	case BundleVersionLegacy:
		return 1
	case BundleVersionFramed:
		return 2
	case BundleVersion:
		return 3
	default:
		return 0
	}
}

// bundleVersionFor returns the oldest bundle version whose importers verify every link in items.
func bundleVersionFor(items []evdom.Evidence) string {
	version := BundleVersionLegacy
	for _, e := range items {
		if !e.SealedFindingID.IsZero() {
			return BundleVersion
		}
		if e.HashScheme == evdom.HashSchemeFramed {
			version = BundleVersionFramed
		}
	}
	return version
}

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
	localScope  func(path string) error
	// transactions, when set, makes Import one unit of work: the engagement, its findings, comments,
	// evidence and the engagement.imported audit entry commit together or not at all. Without it the
	// writes commit one by one, and a failure after the evidence is written cannot be undone, because
	// evidence is append-only; the Postgres composition root always sets it.
	transactions ports.TenantTransactionRunner
}

// SetTransactionRunner makes Import atomic. Every store the transfer service writes joins the bound
// transaction, as does the audit log.
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
}

// SetLocalScopeCheck installs the operator's floor on local repository scope entries, so an imported
// scope meets the same check as one written through the API (#1701).
func (s *Service) SetLocalScopeCheck(check func(path string) error) { s.localScope = check }

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
		Version:      bundleVersionFor(rep.Items),
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
// first write. With a transaction runner the writes and the audit entry are one unit of work;
// without one, a failure after the engagement exists deletes it again. Audited.
func (s *Service) Import(ctx context.Context, actor string, tenantID shared.ID, b Bundle) (*engagement.Engagement, error) {
	if bundleVersionRank(b.Version) == 0 {
		return nil, fmt.Errorf("%w: unsupported bundle version %q", shared.ErrValidation, b.Version)
	}
	// A label promises what the importers of that version can verify. A link that needs a newer
	// version under an older label is a relabelled bundle.
	if required := bundleVersionFor(b.Evidence); bundleVersionRank(b.Version) < bundleVersionRank(required) {
		return nil, fmt.Errorf("%w: a %s bundle cannot carry evidence links that need %s", shared.ErrValidation, b.Version, required)
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
	// operator re-activates deliberately on this instance. Scope must cross the same
	// canonical validation boundary as an API edit before the first repository write.
	if err := eng.SetScope(b.Engagement.Scope.InScope, b.Engagement.Scope.OutOfScope, now); err != nil {
		return nil, fmt.Errorf("%w: imported engagement scope: %v", shared.ErrValidation, err)
	}
	if err := engagement.CheckLocalRepos(eng.Scope.InScope, nil, s.localScope); err != nil {
		return nil, fmt.Errorf("imported engagement scope: %w", err)
	}
	eng.RoE = b.Engagement.RoE
	eng.AuthorizedFrom = b.Engagement.AuthorizedFrom
	eng.AuthorizedTo = b.Engagement.AuthorizedTo
	eng.Timezone = b.Engagement.Timezone
	record := func(ctx context.Context) error {
		return s.audit.Record(ctx, ports.AuditEntry{
			Actor: actor, Action: "engagement.imported", Target: newEngID.String(),
			Metadata: map[string]string{
				"source_engagement": b.Engagement.ID.String(),
				"findings":          strconv.Itoa(len(b.Findings)),
				"evidence_links":    strconv.Itoa(len(b.Evidence)),
				"evidence_head":     b.EvidenceHead,
			},
			At: now,
		})
	}
	if s.transactions != nil {
		// One transaction: a failure anywhere, the audit append included, undoes every write.
		err := s.transactions.Run(ctx, shared.TenantOrDefault(tenantID), func(txCtx context.Context) error {
			if err := s.engagements.Create(txCtx, eng); err != nil {
				return fmt.Errorf("create imported engagement: %w", err)
			}
			if err := s.materialize(txCtx, newEngID, b); err != nil {
				return err
			}
			if err := record(txCtx); err != nil {
				return fmt.Errorf("audit import: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return eng, nil
	}
	// No transaction runner (in-memory backend, dev): the writes commit one by one. A failure after the
	// engagement exists is compensated by deleting it, which the memory store allows. On Postgres the
	// evidence chain is append-only and that delete is refused, which is why the composition root sets
	// a runner there.
	if err := s.engagements.Create(ctx, eng); err != nil {
		return nil, fmt.Errorf("create imported engagement: %w", err)
	}
	if err := s.materialize(ctx, newEngID, b); err != nil {
		if delErr := s.engagements.Delete(ctx, newEngID); delErr != nil {
			return nil, fmt.Errorf("%w (rollback failed: %v)", err, delErr)
		}
		return nil, err
	}
	if err := record(ctx); err != nil {
		if delErr := s.engagements.Delete(ctx, newEngID); delErr != nil {
			return nil, fmt.Errorf("audit import: %w (rollback failed: %v)", err, delErr)
		}
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
			// The hash binds the finding id the link was sealed with. Keep that id as SealedFindingID
			// (a link imported before keeps the one it already carries) and point FindingID at the
			// finding on this instance; an unknown ref leaves it empty (SET NULL semantics).
			if e.SealedFindingID.IsZero() {
				e.SealedFindingID = e.FindingID
			}
			e.FindingID = idMap[e.FindingID]
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
