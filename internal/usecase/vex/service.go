// Package vex consumes OpenVEX documents (CRA-aligned): a client hands Synapse a
// VEX doc asserting the exploitability status of vulnerabilities in their products,
// and Synapse applies each statement to the matching finding – e.g. not_affected
// suppresses it (false positive), fixed marks it remediated. Every applied change is
// recorded on the append-only audit log. This is the inverse of the
// OpenVEX the export service emits.
package vex

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service applies OpenVEX statements to an engagement's findings.
type Service struct {
	engagements  ports.EngagementRepository
	findings     ports.FindingRepository
	audit        ports.AuditLogger
	clock        ports.Clock
	transactions ports.TenantTransactionRunner
}

// SetTransactionRunner makes one Apply atomic. Without it each status change commits on its own
// connection and the audit entry opens a separate transaction, so an audit failure part way through
// leaves findings already retired with no attributable record. Optional because the in-memory and
// file stores have no transactions; the Postgres composition roots set it.
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
}

// NewService validates dependencies and returns the VEX service.
func NewService(engagements ports.EngagementRepository, findings ports.FindingRepository, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if engagements == nil || findings == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: vex service is missing a dependency", shared.ErrValidation)
	}
	return &Service{engagements: engagements, findings: findings, audit: audit, clock: clock}, nil
}

// ApplyResult summarizes what an import did.
type ApplyResult struct {
	Statements int `json:"statements"` // statements in the document
	Matched    int `json:"matched"`    // findings a statement matched
	Applied    int `json:"applied"`    // findings whose status actually changed
}

// Apply parses an OpenVEX document and applies each statement to the matching
// findings of the engagement, returning what changed. A statement matches a finding
// by advisory id + component (+ version when the product carries one); the optimistic
// version guards each update.
func (s *Service) Apply(ctx context.Context, actor string, tenantID, engagementID shared.ID, vexJSON []byte) (ApplyResult, error) {
	doc, err := vex.Parse(vexJSON)
	if err != nil {
		return ApplyResult{}, err
	}
	// Confirm the engagement exists AND belongs to the caller's tenant (404 cross-tenant;
	// defense-in-depth behind the withEngTenant route wrapper – parity with SBOM import).
	if _, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID); err != nil {
		return ApplyResult{}, fmt.Errorf("load engagement: %w", err)
	}

	if s.transactions != nil {
		var res ApplyResult
		if err := s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
			var applyErr error
			res, applyErr = s.apply(txCtx, actor, engagementID, doc)
			return applyErr
		}); err != nil {
			// The transaction rolled back, so nothing was applied. Reporting a partial count
			// would describe changes that no longer exist.
			return ApplyResult{Statements: len(doc.Statements)}, err
		}
		return res, nil
	}
	return s.apply(ctx, actor, engagementID, doc)
}

// apply walks the document against the engagement's findings. When the caller wrapped it in a
// tenant transaction, every status change and every audit append lands on that one transaction, so
// a failure anywhere undoes the whole apply.
func (s *Service) apply(ctx context.Context, actor string, engagementID shared.ID, doc vex.Document) (ApplyResult, error) {
	findings, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("load findings: %w", err)
	}

	res := ApplyResult{Statements: len(doc.Statements)}
	for _, st := range doc.Statements {
		target, ok := vexTargetStatus(st.Status)
		if !ok {
			continue // a status we don't map (e.g. unknown) – leave findings untouched
		}
		for i := range findings {
			f := &findings[i]
			a, comp, ver, ok := vulnerability.ParseDedupKey(f.DedupKey)
			if !ok || !st.MatchesFinding(a, comp, ver) {
				continue
			}
			res.Matched++
			if f.Status == target {
				continue // already in the asserted state
			}
			updated, err := s.findings.UpdateStatus(ctx, engagementID, f.ID, target, f.Version)
			if err != nil {
				continue // conflict/not-found: skip this finding, keep applying others
			}
			*f = updated
			res.Applied++
			// The status change and its audit record are one unit when the service has a
			// transaction runner: both land on the bound transaction, so an audit failure
			// rolls the status change back with it. A VEX statement that silently retires a
			// finding with no attributable record is exactly the case the append-only audit
			// chain exists to prevent.
			if err := s.audit.Record(ctx, ports.AuditEntry{
				Actor: actor, Action: "finding.vex", Target: f.ID.String(),
				Metadata: map[string]string{
					"engagement":    engagementID.String(),
					"advisory":      st.Vulnerability,
					"vex_status":    st.Status,
					"new_status":    string(target),
					"justification": st.Justification,
				},
				At: s.clock.Now(),
			}); err != nil {
				return res, fmt.Errorf("record vex status change for finding %s: %w", f.ID, err)
			}
		}
	}
	return res, nil
}

// vexTargetStatus maps an OpenVEX status to the finding status it implies.
func vexTargetStatus(s string) (finding.Status, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected":
		return finding.StatusFalsePos, true
	case "fixed":
		return finding.StatusRemediated, true
	case "affected":
		return finding.StatusConfirmed, true
	case "under_investigation":
		return finding.StatusTriage, true
	default:
		return "", false
	}
}
