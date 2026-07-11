// Package crosscheckjudge turns cross-check DISAGREEMENTS into Judgments for human review.
// For each vulnerability that some detection sources reported but others (that ran) did not, it PROPOSES an
// ungated CapCorrelation judgment under a RESERVED system identity – the human acknowledges it via Accept; it
// is NEVER auto-resolved (the disagreement is itself the signal). It reuses the existing audited propose path
// (no new confirmed-state path) and is injected only from the composition root, so it is not agent-reachable.
package crosscheckjudge

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// proposerActor is the reserved, non-agent/non-human identity that proposes disagreement judgments. The
// "system:" namespace can't collide with the "agent:<sid>" / "human:<id>" namespaces; a human then Accepts.
const proposerActor = "system:cross-check"

// proposer is the NARROW judgment-lifecycle slice the coordinator needs (analysis.Service satisfies it):
// Propose (mint at score 0) + List (idempotent dedup). It has NO Verify/Accept – correlation is ungated and
// a human acknowledges it, so the coordinator can never confirm its own judgments. Composition-root only.
type proposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Coordinator mints cross-check disagreement judgments. It implements ports.CorrelationRecorder so the SCA
// pipeline can drive it without importing this package.
type Coordinator struct {
	proposer proposer
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.CorrelationRecorder = (*Coordinator)(nil)

// NewCoordinator validates and returns the coordinator.
func NewCoordinator(p proposer, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	if p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: cross-check coordinator is missing a dependency", shared.ErrValidation)
	}
	return &Coordinator{proposer: p, audit: audit, clock: clock}, nil
}

// Record proposes one ungated CapCorrelation judgment per disagreement in the report – a human acknowledges
// each via Accept (never auto-resolved). Idempotent: a disagreement whose vulnerability subject already has a
// correlation judgment is skipped (no churn on re-scan, and no duplicate from a repeated subject within one
// report). Agreements mint nothing. Returns the number minted; a propose/audit error aborts with the partial
// count (the disagreement report stays the source of truth).
func (c *Coordinator) Record(ctx context.Context, engagementID shared.ID, report vulnerability.CrossCheckReport) (int, error) {
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if len(report.Disagreements) == 0 {
		return 0, nil
	}
	existing, err := c.proposer.List(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list judgments: %w", err)
	}
	seen := map[shared.ID]bool{}
	for _, j := range existing {
		if j.Capability == judgment.CapCorrelation {
			seen[j.SubjectID] = true
		}
	}
	minted := 0
	for _, d := range report.Disagreements {
		if strings.TrimSpace(d.AdvisoryID) == "" {
			// A title-only cluster (no advisory id) has no stable, distinct cross-check subject – two such
			// disagreements on the same component@version would collapse to one id and silently drop a
			// signal. An id-less, low-confidence vuln is not a meaningful "which source named which CVE"
			// disagreement, so skip it (no judgment minted) rather than risk the collision.
			continue
		}
		subject := correlationSubjectID(d)
		if seen[subject] {
			continue
		}
		j, perr := c.proposer.Propose(ctx, proposerActor, engagementID, judgment.CapCorrelation,
			judgment.SubjectVulnerability, subject, judgment.CorrelationClaim{Reporters: d.Reporters, Missing: d.Missing})
		if perr != nil {
			return minted, fmt.Errorf("propose correlation judgment for %s: %w", subject, perr)
		}
		seen[subject] = true
		minted++
		if aerr := c.audit.Record(ctx, ports.AuditEntry{
			Actor: proposerActor, Action: "judgment.correlation_proposed", Target: j.ID.String(),
			Metadata: map[string]string{"engagement": engagementID.String(), "subject": subject.String(), "missing": strings.Join(d.Missing, ",")},
			At:       c.clock.Now(),
		}); aerr != nil {
			return minted, fmt.Errorf("audit correlation judgment: %w", aerr)
		}
	}
	return minted, nil
}

// correlationSubjectID is the stable vulnerability subject id for a disagreement. It deliberately follows the
// SCA pipeline's vulnDedupKey convention ("vuln:"+id+":"+component+":"+version) so the two canonical encodings
// of the same (id, component, version) triple can't drift; the same vuln across re-scans yields the same id
// (stable dedup). The id is compared for EQUALITY only, never parsed, so the unescaped ":" (which can appear
// in a Maven component) is harmless – matching the house convention.
func correlationSubjectID(d vulnerability.CrossCheckItem) shared.ID {
	return shared.ID(vulnerability.DedupKey(d.AdvisoryID, d.Component, d.Version))
}
