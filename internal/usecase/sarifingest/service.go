package sarifingest

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IngestRequest is one ingest of one document.
type IngestRequest struct {
	TenantID     shared.ID
	EngagementID shared.ID
	Document     []byte
	Actor        shared.ID
	AssetID      shared.ID
}

// IngestResult reports exactly what happened, including what was NOT ingested.
type IngestResult struct {
	// Accepted is the number of findings newly stored; Deduped already existed.
	Accepted int
	Deduped  int
	// Matched counts findings linked to an agreeing first-party finding.
	Matched int
	// Disagreements are surfaced rather than resolved: when this system and an external tool assign
	// different severities to the same issue, that difference is information a reader must see.
	Disagreements []Disagreement
	// Refused lists every result that could not be ingested, with a typed reason. It is a list rather
	// than a count because a silent refusal is indistinguishable from a clean ingest.
	Refused  []importedfinding.RefusalReason
	Coverage []importedfinding.CoverageIssue
}

// Disagreement records that a first-party finding and an external result describe the same issue but
// assign it different severities.
type Disagreement struct {
	FindingID       shared.ID
	Rule            string
	Tool            string
	FirstPartyLevel shared.Severity
	ExternalLevel   shared.Severity
}

// findingReader is the narrow read the deduplicator needs over first-party findings.
type findingReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
}

// engagementReader resolves the target engagement WITHIN the caller's tenant.
//
// The use case does this itself rather than trusting the HTTP layer, for the same reason the sibling
// SBOM import does: a second caller (a worker, the CLI, an MCP tool) must not be able to write governed
// findings into an arbitrary engagement id. It also settles which tenant owns the rows — the
// engagement's, not the principal's — so the authorization check and the write can never disagree.
type engagementReader interface {
	GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
}

// Service ingests SARIF documents.
type Service struct {
	store       ports.ImportedFindingStore
	findings    findingReader
	engagements engagementReader
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
	limits      Limits
	attributor  ports.FindingAttributor
}

// NewService validates and returns the ingest service.
func NewService(store ports.ImportedFindingStore, findings findingReader, engagements engagementReader, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || engagements == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: sarif ingest needs a store, an engagement reader, an audit log, a clock and an id generator", shared.ErrValidation)
	}
	return &Service{store: store, findings: findings, engagements: engagements, audit: audit, clock: clock, ids: ids, limits: DefaultLimits()}, nil
}

// SetAttributor wires explicit asset attribution for SARIF producers.
func (s *Service) SetAttributor(a ports.FindingAttributor) { s.attributor = a }

// withLimits overrides the ingest bounds. It is an unexported seam so a running service's budgets cannot
// be changed from another package (which would also be a data race on a shared instance).
func (s *Service) withLimits(limits Limits) *Service {
	s.limits = limits
	return s
}

// Ingest parses a SARIF document and persists the results that can be attributed.
//
// A bound breach or an unparseable document returns an error and persists NOTHING. A result-level
// problem is a typed refusal, so the caller sees what was dropped.
func (s *Service) Ingest(ctx context.Context, req IngestRequest) (IngestResult, error) {
	if req.EngagementID.IsZero() {
		return IngestResult{}, fmt.Errorf("%w: sarif ingest needs an engagement", shared.ErrValidation)
	}
	if req.Actor.IsZero() {
		// Without an actor the provenance cannot be completed, and an unattributable finding is refused
		// rather than stored.
		return IngestResult{}, fmt.Errorf("%w: sarif ingest needs an ingesting actor", shared.ErrValidation)
	}

	// Resolve the engagement inside the CALLER's tenant, and then take the row tenant from the
	// engagement itself. Normalizing the principal's tenant before this check instead would let an
	// empty-tenant principal pass a wildcard gate and write the rows into a different partition than the
	// one that authorized them. An engagement the caller cannot see is ErrNotFound, never a 403.
	eng, err := s.engagements.GetByIDInTenant(ctx, req.TenantID, req.EngagementID)
	if err != nil {
		return IngestResult{}, fmt.Errorf("load engagement: %w", err)
	}
	// The store is RLS-partitioned and the empty tenant means DENY there, so the single-tenant default
	// is normalized to its non-empty id at the STORE boundary — after authorization, not before it.
	tenantID := shared.TenantOrDefault(eng.TenantID)

	if !req.AssetID.IsZero() {
		if s.attributor == nil {
			return IngestResult{}, fmt.Errorf("%w: sarif finding attribution is not configured", shared.ErrValidation)
		}
		if err := s.attributor.ValidateAsset(ctx, req.EngagementID, req.AssetID); err != nil {
			return IngestResult{}, fmt.Errorf("validate sarif attribution asset: %w", err)
		}
	}

	parsedDoc, err := parseDocument(ctx, req.Document, s.limits)
	if err != nil {
		return IngestResult{}, err
	}

	result := IngestResult{Refused: parsedDoc.refusals, Coverage: parsedDoc.coverage}
	if req.AssetID.IsZero() {
		result.Coverage = append(result.Coverage, importedfinding.CoverageIssue{Detail: "asset attribution was not supplied: imported findings cannot enter attack paths"})
	}
	if s.findings == nil {
		// Deduplication against first-party findings is part of what this ingest claims to do. Skipping
		// it silently would leave Matched=0, which is indistinguishable from "no agreement was found".
		result.Coverage = append(result.Coverage, importedfinding.CoverageIssue{
			Detail: "first-party deduplication was not performed: no finding reader was configured, so agreement with existing findings is unknown",
		})
	}

	// Idempotency by document digest: re-posting the same report must not duplicate findings.
	alreadyIngested, err := s.store.ExistsDigest(ctx, tenantID, req.EngagementID, parsedDoc.digest)
	if err != nil {
		return IngestResult{}, fmt.Errorf("check sarif document digest: %w", err)
	}
	if alreadyIngested {
		result.Deduped = len(parsedDoc.results)
		if err := s.bindDocument(ctx, tenantID, req, parsedDoc.digest); err != nil {
			return result, err
		}
		// A short-circuited ingest is still a state-changing request whose response tells the caller
		// whether this exact document was seen before, so it is audited like any other.
		if auditErr := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  req.Actor.String(),
			Action: "finding.imported.deduplicated",
			Target: req.EngagementID.String(),
			Metadata: map[string]string{
				"source_digest": parsedDoc.digest,
				"deduplicated":  strconv.Itoa(result.Deduped),
			},
			At: s.clock.Now().UTC(),
		}); auditErr != nil {
			return IngestResult{}, fmt.Errorf("audit sarif ingest: %w", auditErr)
		}
		sortRefusals(result.Refused)
		return result, nil
	}

	firstParty, err := s.firstPartyIndex(ctx, req.EngagementID)
	if err != nil {
		return IngestResult{}, err
	}

	now := s.clock.Now().UTC()
	batch := make([]importedfinding.ImportedFinding, 0, len(parsedDoc.results))
	matchedIDs := make([]shared.ID, 0, len(parsedDoc.results))
	for _, c := range parsedDoc.results {
		imported := importedfinding.ImportedFinding{
			ID:           s.ids.NewID(),
			TenantID:     tenantID,
			EngagementID: req.EngagementID,
			Severity:     c.severity,
			Title:        c.title,
			Message:      c.message,
			Location:     c.location,
			Suppressed:   c.suppressed,
			Fingerprint:  c.fingerprint,
			Provenance: importedfinding.Provenance{
				ToolName:     c.toolName,
				ToolVersion:  c.toolVersion,
				RuleID:       c.ruleID,
				SourceDigest: parsedDoc.digest,
				IngestedBy:   req.Actor,
				IngestedAt:   now,
			},
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		// A finding whose provenance cannot be established is refused, never stored.
		if err := imported.Validate(); err != nil {
			result.Refused = append(result.Refused, importedfinding.RefusalReason{
				RunIndex: c.runIndex, ResultIndex: c.resultIndex,
				Code: importedfinding.RefusalNoProvenance, Detail: "provenance could not be completed",
			})
			continue
		}

		// Deduplication against first-party findings records BOTH sources rather than dropping one, and
		// surfaces a severity disagreement instead of silently resolving it.
		if match, ok := firstParty[dedupKey(c.location.Path, c.location.StartLine)]; ok {
			imported.FindingID = match.ID
			matchedIDs = append(matchedIDs, match.ID)
			result.Matched++
			if match.Severity != imported.Severity {
				result.Disagreements = append(result.Disagreements, Disagreement{
					FindingID:       match.ID,
					Rule:            c.ruleID,
					Tool:            c.toolName,
					FirstPartyLevel: match.Severity,
					ExternalLevel:   imported.Severity,
				})
			}
		}
		batch = append(batch, imported)
	}

	stored, existing, err := s.store.Save(ctx, tenantID, batch)
	if err != nil {
		return IngestResult{}, fmt.Errorf("persist imported findings: %w", err)
	}
	result.Accepted = stored
	result.Deduped += existing

	sortRefusals(result.Refused)
	if auditErr := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  req.Actor.String(),
		Action: "finding.imported",
		Target: req.EngagementID.String(),
		Metadata: map[string]string{
			"source_digest": parsedDoc.digest,
			"accepted":      strconv.Itoa(result.Accepted),
			"deduplicated":  strconv.Itoa(result.Deduped),
			"refused":       strconv.Itoa(len(result.Refused)),
		},
		At: now,
	}); auditErr != nil {
		// The findings are ALREADY persisted at this point. Saying only "audit failed" would leave the
		// caller believing nothing was written, so the error states both facts: the state change
		// happened and the record of it did not.
		return IngestResult{}, fmt.Errorf("sarif ingest persisted %d findings but could not be audited: %w",
			result.Accepted, auditErr)
	}
	if err := s.bindDocument(ctx, tenantID, req, parsedDoc.digest, matchedIDs...); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) bindDocument(ctx context.Context, tenantID shared.ID, req IngestRequest, digest string, matchedIDs ...shared.ID) error {
	if req.AssetID.IsZero() {
		return nil
	}
	persisted, err := s.store.ListByEngagement(ctx, tenantID, req.EngagementID)
	if err != nil {
		return fmt.Errorf("list persisted sarif findings: %w", err)
	}
	bound := make([]attackpath.FindingTarget, 0, len(persisted)+len(matchedIDs))
	for _, imported := range persisted {
		if imported.Provenance.SourceDigest == digest {
			bound = append(bound, attackpath.FindingTarget{ID: imported.ID, Kind: attackpath.TargetImported})
			if !imported.FindingID.IsZero() {
				bound = append(bound, attackpath.FindingTarget{ID: imported.FindingID, Kind: attackpath.TargetCanonical})
			}
		}
	}
	for _, id := range matchedIDs {
		bound = append(bound, attackpath.FindingTarget{ID: id, Kind: attackpath.TargetCanonical})
	}
	bound = uniqueTargets(bound)
	producer := shared.ID("sarif:" + req.AssetID.String() + ":" + digest)
	if err := s.attributor.RecordTargets(ctx, req.EngagementID, req.AssetID, producer, shared.ID(digest), asset.EdgeObserved, bound); err != nil {
		ids := make([]shared.ID, len(bound))
		for i, target := range bound {
			ids[i] = target.ID
		}
		return &ports.PartialWriteError{Operation: "sarif document", IDs: ids, Err: fmt.Errorf("record sarif finding attribution: %w", err)}
	}
	return nil
}

// firstPartyIndex indexes existing findings by location so an external result can be matched to one.
func (s *Service) firstPartyIndex(ctx context.Context, engagementID shared.ID) (map[string]finding.Finding, error) {
	out := map[string]finding.Finding{}
	if s.findings == nil {
		return out, nil
	}
	existing, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list first-party findings: %w", err)
	}
	for _, f := range existing {
		if f.SourceLocation == nil {
			continue
		}
		if key := dedupKey(f.SourceLocation.File, f.SourceLocation.StartLine); key != "" {
			if _, taken := out[key]; !taken {
				out[key] = f
			}
		}
	}
	return out, nil
}

// dedupKey is the documented deduplication key: the file path plus the start line. It is deliberately
// coarse — matching should surface agreement between tools, not demand identical wording.
//
// The path is compared case-SENSITIVELY. Folding the case would conflate src/App.go with src/app.go on
// the case-sensitive filesystems this system scans, and a false match links an external result to the
// wrong first-party finding — which is worse than reporting no agreement at all.
func dedupKey(path string, line int) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return trimmed + ":" + strconv.Itoa(line)
}

func sortRefusals(in []importedfinding.RefusalReason) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].RunIndex != in[j].RunIndex {
			return in[i].RunIndex < in[j].RunIndex
		}
		return in[i].ResultIndex < in[j].ResultIndex
	})
}

// Validate parses a document and reports exactly what an ingest WOULD accept and refuse, without a
// store, an engagement, a tenant or an actor — and therefore without persisting anything.
//
// It exists so the CLI can share this package's parsing and refusal rules rather than reimplementing
// them, while being structurally incapable of writing. A validate-only command backed by a real Service
// pointed at a throwaway store would print an accepted count that means nothing; this cannot.
func Validate(ctx context.Context, document []byte, limits Limits) (IngestResult, error) {
	parsedDoc, err := parseDocument(ctx, document, limits)
	if err != nil {
		return IngestResult{}, err
	}
	result := IngestResult{
		Accepted: len(parsedDoc.results),
		Refused:  parsedDoc.refusals,
		Coverage: append(parsedDoc.coverage, importedfinding.CoverageIssue{
			Detail: "validation only: nothing was persisted, and agreement with existing first-party findings was not checked",
		}),
	}
	sortRefusals(result.Refused)
	return result, nil
}

func uniqueTargets(targets []attackpath.FindingTarget) []attackpath.FindingTarget {
	seen := make(map[attackpath.FindingTarget]bool, len(targets))
	out := make([]attackpath.FindingTarget, 0, len(targets))
	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	return out
}
