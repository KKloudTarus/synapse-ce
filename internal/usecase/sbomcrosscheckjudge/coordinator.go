// Package sbomcrosscheckjudge (SBOM side) turns SBOM-PRODUCER cross-check DISAGREEMENTS
// into Judgments for human review. When ≥2 SBOM producers run (an owned parser registry + a vendor tool
// like Syft) over one target, a component only one producer emitted is the human-review signal: this
// PROPOSES an ungated CapCorrelation judgment (subject = component) under a RESERVED system identity, which
// a human acknowledges via Accept – NEVER auto-resolved (the disagreement is itself the signal). It reuses
// the existing audited propose path (no new confirmed-state path) and is injected only from the composition
// root, so it is not agent-reachable. Mirrors crosscheckjudge – the advisory analogue.
package sbomcrosscheckjudge

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// proposerActor is the reserved, non-agent/non-human identity that proposes disagreement judgments. The
// "system:" namespace can't collide with the "agent:<sid>" / "human:<id>" namespaces; a human then Accepts.
const proposerActor = "system:sbom-cross-check"

// proposer is the NARROW judgment-lifecycle slice the coordinator needs (analysis.Service satisfies it):
// Propose (mint at score 0) + List (idempotent dedup). It has NO Verify/Accept – correlation is ungated and
// a human acknowledges it, so the coordinator can never confirm its own judgments. Composition-root only.
type proposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Coordinator mints SBOM-producer cross-check disagreement judgments. It implements
// ports.SBOMCrossCheckRecorder so the SCA pipeline can drive it without importing this package.
type Coordinator struct {
	proposer proposer
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.SBOMCrossCheckRecorder = (*Coordinator)(nil)

// NewCoordinator validates and returns the coordinator.
func NewCoordinator(p proposer, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	if p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: sbom cross-check coordinator is missing a dependency", shared.ErrValidation)
	}
	return &Coordinator{proposer: p, audit: audit, clock: clock}, nil
}

// Record proposes one ungated CapCorrelation judgment per disagreement in the report – a human acknowledges
// each via Accept (never auto-resolved). Idempotent: a disagreement whose component subject already has a
// component-correlation judgment is skipped (no churn on re-scan, no duplicate from a repeated subject within
// one report). Agreements mint nothing. Returns the number minted; a propose/audit error aborts with the
// partial count (the disagreement report stays the source of truth).
func (c *Coordinator) Record(ctx context.Context, engagementID shared.ID, report sbom.CrossCheckReport) (int, error) {
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
		// Filter on BOTH capability AND subject kind so a vulnerability-correlation judgment (same
		// CapCorrelation) can never suppress a component disagreement (and vice versa).
		if j.Capability == judgment.CapCorrelation && j.SubjectKind == judgment.SubjectComponent {
			seen[j.SubjectID] = true
		}
	}
	minted := 0
	for _, d := range report.Disagreements {
		subject := componentSubjectID(d)
		if subject.IsZero() || seen[subject] {
			continue // a fully-blank component has no stable subject; sbom.CrossCheck already drops those
		}
		j, perr := c.proposer.Propose(ctx, proposerActor, engagementID, judgment.CapCorrelation,
			judgment.SubjectComponent, subject, judgment.CorrelationClaim{Reporters: d.Reporters, Missing: d.Missing})
		if perr != nil {
			return minted, fmt.Errorf("propose sbom correlation judgment for %s: %w", subject, perr)
		}
		seen[subject] = true
		minted++
		if aerr := c.audit.Record(ctx, ports.AuditEntry{
			Actor: proposerActor, Action: "judgment.sbom_correlation_proposed", Target: j.ID.String(),
			Metadata: map[string]string{"engagement": engagementID.String(), "subject": subject.String(), "missing": strings.Join(d.Missing, ",")},
			At:       c.clock.Now(),
		}); aerr != nil {
			return minted, fmt.Errorf("audit sbom correlation judgment: %w", aerr)
		}
	}
	return minted, nil
}

// componentSubjectID is the stable component subject id for a disagreement. It follows the domain's
// ComponentID convention (PURL, else name@version, else name), prefixed with "component:" so the subject
// kind is self-evident and can't collide with the vulnerability cross-check's "vuln:" subjects. The id is
// compared for EQUALITY only, never parsed, so an unescaped ":" inside a PURL is harmless. A fully-blank
// component yields the empty id (skipped) – though sbom.CrossCheck already drops blank components upstream.
func componentSubjectID(d sbom.CrossCheckItem) shared.ID {
	id := sbom.ComponentID(d.Name, d.Version, d.PURL)
	if id == "" {
		return ""
	}
	return shared.ID("component:" + id)
}
