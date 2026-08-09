package sarifingest

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

// Service ingests SARIF documents.
type Service struct {
	store    ports.ImportedFindingStore
	findings findingReader
	audit    ports.AuditLogger
	clock    ports.Clock
	ids      ports.IDGenerator
	limits   Limits
}

// NewService validates and returns the ingest service.
func NewService(store ports.ImportedFindingStore, findings findingReader, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: sarif ingest needs a store, an audit log, a clock and an id generator", shared.ErrValidation)
	}
	return &Service{store: store, findings: findings, audit: audit, clock: clock, ids: ids, limits: DefaultLimits()}, nil
}

// WithLimits overrides the ingest bounds; used by tests to exercise each budget.
func (s *Service) WithLimits(limits Limits) *Service {
	s.limits = limits
	return s
}

// Ingest parses a SARIF document and persists the results that can be attributed.
//
// A bound breach or an unparseable document returns an error and persists NOTHING. A result-level
// problem is a typed refusal, so the caller sees what was dropped.
func (s *Service) Ingest(ctx context.Context, req IngestRequest) (IngestResult, error) {
	if req.EngagementID.IsZero() || req.TenantID.IsZero() {
		return IngestResult{}, fmt.Errorf("%w: sarif ingest needs a tenant and an engagement", shared.ErrValidation)
	}
	if req.Actor.IsZero() {
		// Without an actor the provenance cannot be completed, and an unattributable finding is refused
		// rather than stored.
		return IngestResult{}, fmt.Errorf("%w: sarif ingest needs an ingesting actor", shared.ErrValidation)
	}

	parsedDoc, err := parseDocument(req.Document, s.limits)
	if err != nil {
		return IngestResult{}, err
	}

	result := IngestResult{Refused: parsedDoc.refusals, Coverage: parsedDoc.coverage}

	// Idempotency by document digest: re-posting the same report must not duplicate findings.
	alreadyIngested, err := s.store.ExistsDigest(ctx, req.TenantID, req.EngagementID, parsedDoc.digest)
	if err != nil {
		return IngestResult{}, fmt.Errorf("check sarif document digest: %w", err)
	}
	if alreadyIngested {
		result.Deduped = len(parsedDoc.results)
		return result, nil
	}

	firstParty, err := s.firstPartyIndex(ctx, req.EngagementID)
	if err != nil {
		return IngestResult{}, err
	}

	now := s.clock.Now().UTC()
	batch := make([]importedfinding.ImportedFinding, 0, len(parsedDoc.results))
	for _, c := range parsedDoc.results {
		imported := importedfinding.ImportedFinding{
			ID:           s.ids.NewID(),
			TenantID:     req.TenantID,
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
				IngestedAt:   now.Format("2006-01-02T15:04:05Z"),
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

	stored, existing, err := s.store.Save(ctx, req.TenantID, batch)
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
			"accepted":      fmt.Sprint(result.Accepted),
			"deduplicated":  fmt.Sprint(result.Deduped),
			"refused":       fmt.Sprint(len(result.Refused)),
		},
		At: now,
	}); auditErr != nil {
		return IngestResult{}, fmt.Errorf("audit sarif ingest: %w", auditErr)
	}
	return result, nil
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

// dedupKey is the documented deduplication key: the normalized file path plus the start line. It is
// deliberately coarse — matching should surface agreement between tools, not demand identical wording.
func dedupKey(path string, line int) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(trimmed) + ":" + fmt.Sprint(line)
}

func sortRefusals(in []importedfinding.RefusalReason) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].RunIndex != in[j].RunIndex {
			return in[i].RunIndex < in[j].RunIndex
		}
		return in[i].ResultIndex < in[j].ResultIndex
	})
}
