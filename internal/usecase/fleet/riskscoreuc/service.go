// Package riskscoreuc is the tri-score ASSEMBLER (#594, C3/D/X5 integration): the seam that gathers the
// three independent risk factors for an incident — Threat (from the incident's own correlated severity),
// Exposure (X5, exposureuc), Behavior (D, baselineuc) — plus per-class telemetry Coverage, runs the
// deterministic riskassessment.Scorer (previously called only in tests), and records the resulting
// RiskAssessment onto the incident via an EventRiskReassessed event. The composition-root wiring that
// bridges its consumer-side ports to exposureuc / baselineuc / a detection coverage source, and the caller
// that triggers a reassessment, are the remaining step to run this in production.
//
// Discipline: each factor is placed ONLY when its producer says it is scoreable; an abstaining factor
// contributes 0 to Risk and its reason is carried into the CoverageVector, so a missing factor lowers
// Coverage/Confidence, never fabricates Risk (the scorer enforces this — coverage is never a Risk term).
// The producers stay propose-only; this assembler does no scoring math of its own beyond the factor
// mappings, and the LLM is nowhere in this path.
package riskscoreuc

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FactorInput is one coverage-honest factor from a producer: its 0..100 Score, whether it is trustworthy
// (Scoreable), and any human reasons for an abstain/limitation. It is the local shape both the Exposure
// and Behavior producers are bridged to, so this assembler depends on no sibling usecase.
type FactorInput struct {
	Score     riskassessment.Score
	Scoreable bool
	Reasons   []string
}

// IncidentStore is the read+append view of the incident log this assembler needs. incidentuc.Service
// satisfies it structurally (defined here so the assembler does not import a sibling usecase).
type IncidentStore interface {
	Get(ctx context.Context, id shared.ID) (incident.Incident, error)
	Append(ctx context.Context, id shared.ID, expectedRevision int, events []incident.IncidentEvent) (incident.Incident, error)
}

// ExposureAssessor yields the RiskContext.Exposure factor for an asset (bridged to exposureuc at the
// composition root). BehaviorAssessor likewise yields RiskContext.Behavior (bridged to baselineuc). Both
// return a coverage-honest FactorInput; a real error propagates, an abstain is Scoreable=false.
//
// CONTRACT for all consumer-side ports here: the implementing adapter MUST scope by the tenant derived
// from ctx (tenant isolation is the adapter's responsibility), and MUST return factor Reasons in a
// deterministic order — the scored RiskAssessment's InputSnapshotHash is order-sensitive on the assembled
// reasons, so a producer backed by a map must sort before returning.
type ExposureAssessor interface {
	ExposureFor(ctx context.Context, assetID shared.ID) (FactorInput, error)
}

// BehaviorAssessor yields the RiskContext.Behavior factor for an asset.
type BehaviorAssessor interface {
	BehaviorFor(ctx context.Context, assetID shared.ID) (FactorInput, error)
}

// CoverageSource yields the per-telemetry-class detection coverage for an asset's host. It is the
// detection engine's honest coverage (active vs gap), not the fleet capability coverage model. Duplicate
// class records are tolerated (the assembler dedups gap-preferring), but the adapter should prefer to
// return already-normalized coverage (e.g. via detection.NewHostCoverage).
type CoverageSource interface {
	ClassCoverageForAsset(ctx context.Context, assetID shared.ID) ([]detection.ClassCoverage, error)
}

// Service assembles the tri-score for an incident.
type Service struct {
	incidents IncidentStore
	exposure  ExposureAssessor
	behavior  BehaviorAssessor
	coverage  CoverageSource
	scorer    *riskassessment.Scorer
	audit     ports.AuditLogger
	ids       ports.IDGenerator
	now       func() time.Time
}

// NewService constructs the assembler. All collaborators are required.
func NewService(incidents IncidentStore, exposure ExposureAssessor, behavior BehaviorAssessor, coverage CoverageSource, scorer *riskassessment.Scorer, audit ports.AuditLogger, ids ports.IDGenerator, now func() time.Time) (*Service, error) {
	switch {
	case incidents == nil:
		return nil, fmt.Errorf("%w: assembler requires an incident store", shared.ErrValidation)
	case exposure == nil:
		return nil, fmt.Errorf("%w: assembler requires an exposure assessor", shared.ErrValidation)
	case behavior == nil:
		return nil, fmt.Errorf("%w: assembler requires a behavior assessor", shared.ErrValidation)
	case coverage == nil:
		return nil, fmt.Errorf("%w: assembler requires a coverage source", shared.ErrValidation)
	case scorer == nil:
		return nil, fmt.Errorf("%w: assembler requires a scorer", shared.ErrValidation)
	case audit == nil:
		return nil, fmt.Errorf("%w: assembler requires an audit logger", shared.ErrValidation)
	case ids == nil:
		return nil, fmt.Errorf("%w: assembler requires an id generator", shared.ErrValidation)
	case now == nil:
		return nil, fmt.Errorf("%w: assembler requires a clock", shared.ErrValidation)
	}
	return &Service{incidents: incidents, exposure: exposure, behavior: behavior, coverage: coverage, scorer: scorer, audit: audit, ids: ids, now: now}, nil
}

// Reassess gathers the three factors + coverage for the incident, scores them deterministically, and
// records the RiskAssessment onto the incident as an EventRiskReassessed event under optimistic
// concurrency (the incident's current revision). It returns the updated incident (whose .Risk now carries
// the assessment). The event IS the primary attributable record (Actor + At on the append-only log); the
// audit logger is a secondary trail written AFTER the durable append — on an audit error the reassessment
// is committed, so the caller must NOT blindly retry (a retry would append a duplicate assessment).
func (s *Service) Reassess(ctx context.Context, actor string, incidentID shared.ID) (incident.Incident, error) {
	if actor == "" {
		return incident.Incident{}, fmt.Errorf("%w: risk reassessment requires an actor", shared.ErrValidation)
	}
	if incidentID.IsZero() {
		return incident.Incident{}, fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	inc, err := s.incidents.Get(ctx, incidentID)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("load incident: %w", err)
	}

	var reasons []string

	// Threat: the incident's own correlated severity. Unknown severity abstains (0 + reason).
	threat := riskassessment.ThreatFromSeverity(inc.Severity)
	if !inc.Severity.Valid() || inc.Severity == shared.SeverityUnknown {
		reasons = append(reasons, "threat: incident severity unknown")
	}

	// Exposure (X5).
	exp, err := s.exposure.ExposureFor(ctx, inc.AssetID)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("exposure factor: %w", err)
	}
	var exposureScore riskassessment.Score
	if exp.Scoreable {
		exposureScore = exp.Score
	} else {
		reasons = append(reasons, "exposure: not scoreable")
	}
	reasons = append(reasons, exp.Reasons...)

	// Behavior (D).
	beh, err := s.behavior.BehaviorFor(ctx, inc.AssetID)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("behavior factor: %w", err)
	}
	var behaviorScore riskassessment.Score
	if beh.Scoreable {
		behaviorScore = beh.Score
	} else {
		reasons = append(reasons, "behavior: not scoreable")
	}
	reasons = append(reasons, beh.Reasons...)

	// Coverage: per-class detection coverage for the asset's host.
	cc, err := s.coverage.ClassCoverageForAsset(ctx, inc.AssetID)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("coverage: %w", err)
	}
	cv := coverageVector(cc)
	cv.Reasons = append(cv.Reasons, reasons...)

	at := s.now().UTC()
	ra, err := s.scorer.Score(riskassessment.ScoreInput{
		AssessmentID:     s.ids.NewID(),
		IncidentRevision: inc.Revision,
		Context:          riskassessment.RiskContext{Threat: threat, Exposure: exposureScore, Behavior: behaviorScore},
		Coverage:         cv,
		CreatedAt:        at,
	})
	if err != nil {
		return incident.Incident{}, fmt.Errorf("score: %w", err)
	}

	updated, err := s.incidents.Append(ctx, incidentID, inc.Revision, []incident.IncidentEvent{{
		IncidentID: incidentID,
		Kind:       incident.EventRiskReassessed,
		At:         at,
		Actor:      actor,
		Risk:       &ra,
	}})
	if err != nil {
		return incident.Incident{}, err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "incident.risk_reassessed",
		Target: incidentID.String(),
		At:     at,
		Metadata: map[string]string{
			"risk":       fmt.Sprintf("%d", ra.Risk),
			"confidence": fmt.Sprintf("%d", ra.Confidence),
			"coverage":   fmt.Sprintf("%d", ra.Coverage),
		},
	}); err != nil {
		return incident.Incident{}, fmt.Errorf("audit incident.risk_reassessed: %w", err)
	}
	return updated, nil
}

// coverageVector maps per-class detection coverage into a riskassessment.CoverageVector: an actively
// observing class scores 100, an observation gap or an unreported class scores 0 and contributes a reason.
// It iterates the FIXED detection.Classes() order (deterministic, so the scorer's order-sensitive input
// hash is reproducible), and dedups duplicate class records GAP-PREFERRING — a class once seen as a gap is
// never upgraded to observing by a later duplicate (mirroring detection.NewHostCoverage's refusal to let a
// duplicate silently erase a gap, which would read as over-confident on a partial view).
func coverageVector(cc []detection.ClassCoverage) riskassessment.CoverageVector {
	seen := make(map[detection.Class]detection.ClassCoverage, len(cc))
	for _, c := range cc {
		if prev, ok := seen[c.Class]; ok && !prev.Observing() {
			continue // keep the gap; a later duplicate cannot erase it
		}
		seen[c.Class] = c
	}
	var v riskassessment.CoverageVector
	for _, cls := range detection.Classes() {
		c, reported := seen[cls]
		observing := reported && c.Observing()
		var score riskassessment.Score
		if observing {
			score = 100
		}
		switch cls {
		case detection.ClassProcess:
			v.Process = score
		case detection.ClassNetwork:
			v.Network = score
		case detection.ClassFile:
			v.File = score
		case detection.ClassPrivilege:
			v.Privilege = score
		}
		if !observing {
			reason := "no report"
			if reported && c.Reason != "" {
				reason = c.Reason
			}
			v.Reasons = append(v.Reasons, string(cls)+": "+reason)
		}
	}
	return v
}
