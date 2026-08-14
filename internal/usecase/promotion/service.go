// Package promotion implements the use-case layer for deterministic finding-priority
// promotion. It contains two narrow authorities:
//
//   - [Evaluator]: loads findings, attack-path graph, detections, and reachability
//     judgments, builds [promotion.Snapshot] values, calls the pure [promotion.Evaluate]
//     function, and proposes typed [judgment.PromotionClaim] judgments. Its local reader
//     interfaces expose no finding, judgment, or promotion mutation.
//
//   - [ConfirmedRecorder]: receives an already publishable confirmed
//     [judgment.Judgment] with CapPromotion, seals a finding-linked evidence
//     payload, and atomically applies the promotion through [ports.PromotionStore].
//
// Neither authority imports model/pillar/MCP code. Inputs are sourced, sorted, and
// tenant-bound; the caller never provides a tenant ID.
package promotion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
)

// proposer is the narrow judgment-lifecycle slice the evaluator needs.
// It has NO Verify, Accept, or List methods; the evaluator can only propose.
type proposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
}

type findingReader interface {
	ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error)
}

type confirmedFindingReader interface {
	GetByEngagementAndID(context.Context, shared.ID, shared.ID) (finding.Finding, error)
}

type confirmedPromotionStore interface {
	Apply(context.Context, shared.ID, shared.ID, ports.PromotionCommand) (finding.Finding, error)
	FindByJudgment(context.Context, shared.ID, shared.ID, shared.ID) (promotion.PromotionEvent, bool, error)
	MarkAuditComplete(context.Context, shared.ID) error
}

type judgmentReader interface {
	ListByEngagement(context.Context, shared.ID) ([]judgment.Judgment, error)
}

type attackPathReader interface {
	ListBindings(context.Context, shared.ID) ([]attackpath.Binding, error)
}

type assetReader interface {
	ListAssets(context.Context, shared.ID) ([]*asset.Asset, error)
	ListEdges(context.Context, shared.ID) ([]*asset.Edge, error)
}

type detectionReader interface {
	ListDetections(context.Context, shared.ID) ([]detection.Record, error)
}

type engagementReader interface {
	GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error)
}

type promotionEventReader interface {
	ListByFinding(context.Context, shared.ID, shared.ID) ([]promotion.PromotionEvent, error)
}

type clock interface {
	Now() time.Time
}

type proposalAuditRecorder interface {
	RecordOnce(context.Context, ports.AuditEntry) error
}

type confirmedAuditRecorder interface {
	RecordOnce(context.Context, ports.AuditEntry) error
}

// proposerActor is the reserved, non-agent identity that proposes promotion claims.
const proposerActor = "system:promotion"

// PromotionEvidenceKind is the evidence-chain kind for sealed promotion applications.
const PromotionEvidenceKind = "promotion_application"

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

// Evaluator loads deterministic inputs and proposes promotion claims. It holds no
// finding, judgment, or promotion mutation authority.
type Evaluator struct {
	proposer   proposer
	findings   findingReader
	judgments  judgmentReader
	bindings   attackPathReader
	assets     assetReader
	detections detectionReader
	engagement engagementReader
	promotions promotionEventReader
	clock      clock
	audit      proposalAuditRecorder
}

// NewEvaluator validates dependencies and returns an Evaluator.
func NewEvaluator(
	p proposer,
	findings findingReader,
	judgments judgmentReader,
	bindings attackPathReader,
	assets assetReader,
	detections detectionReader,
	engagement engagementReader,
	promotions promotionEventReader,
	clock clock,
	audit proposalAuditRecorder,
) (*Evaluator, error) {
	if p == nil || findings == nil || judgments == nil || bindings == nil ||
		assets == nil || detections == nil || engagement == nil || promotions == nil ||
		clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: promotion evaluator is missing a dependency", shared.ErrValidation)
	}
	return &Evaluator{
		proposer: p, findings: findings, judgments: judgments, bindings: bindings,
		assets: assets, detections: detections, engagement: engagement,
		promotions: promotions, clock: clock, audit: audit,
	}, nil
}

// Evaluate loads all promotion-relevant signals for the engagement, evaluates
// the deterministic promotion rules for every finding, and proposes new
// [judgment.PromotionClaim] judgments through the narrow proposer. It requires
// tenant context and validates engagement ownership through the chokepoint.
//
// Stable ordering: findings are sorted by ID; duplicate fingerprints are
// skipped; existing proposals with unchanged fingerprints are not re-proposed.
// Evaluate never verifies or mutates a finding.
func (e *Evaluator) Evaluate(ctx context.Context, engagementID shared.ID) (int, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return 0, fmt.Errorf("%w: promotion evaluation requires tenant context", shared.ErrValidation)
	}
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if _, err := e.engagement.GetByIDInTenant(ctx, tenantID, engagementID); err != nil {
		return 0, fmt.Errorf("validate engagement ownership: %w", err)
	}
	findings, err := e.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list findings: %w", err)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	judgments, err := e.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list judgments: %w", err)
	}
	reachabilityByFinding := indexReachability(judgments)
	existingProposals := indexPromotionProposals(judgments)
	allBindings, err := e.bindings.ListBindings(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("list attack-path bindings: %w", err)
	}
	findingSet := make(map[shared.ID]struct{}, len(findings))
	for _, f := range findings {
		findingSet[f.ID] = struct{}{}
	}
	bindings := make([]attackpath.Binding, 0, len(allBindings))
	for _, b := range allBindings {
		if b.EngagementID == engagementID {
			if _, ok := findingSet[b.FindingID]; ok {
				bindings = append(bindings, b)
			}
		}
	}
	assetsList, err := e.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("list assets: %w", err)
	}
	edgePtrs, err := e.assets.ListEdges(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("list edges: %w", err)
	}
	edges := make([]asset.Edge, len(edgePtrs))
	for i, ep := range edgePtrs {
		edges[i] = *ep
	}
	graph, err := buildGraph(tenantID, assetsList, edges, bindings, findings, reachabilityByFinding)
	if err != nil {
		return 0, fmt.Errorf("build attack-path graph: %w", err)
	}
	detRecords, err := e.detections.ListDetections(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list detections: %w", err)
	}
	activeDetections := filterActive(detRecords, e.clock.Now())
	latestEvents, err := e.loadLatestEvents(ctx, engagementID, findings, graph, activeDetections, reachabilityByFinding)
	if err != nil {
		return 0, fmt.Errorf("load latest promotion events: %w", err)
	}

	proposed := 0
	for _, f := range findings {
		snap, err := e.buildSnapshot(ctx, f, graph, activeDetections, reachabilityByFinding, latestEvents)
		if err != nil {
			return proposed, fmt.Errorf("build promotion snapshot for finding %s: %w", f.ID, err)
		}
		claim, err := promotion.Evaluate(snap)
		if err != nil {
			return proposed, fmt.Errorf("evaluate finding %s: %w", f.ID, err)
		}
		if claim == nil {
			continue
		}
		if _, ok := existingProposals[f.ID][claim.Fingerprint]; ok {
			if err := e.recordProposalAudit(ctx, engagementID, f.ID, claim); err != nil {
				return proposed, err
			}
			continue
		}
		if _, err := e.proposer.Propose(ctx, proposerActor, engagementID, judgment.CapPromotion, judgment.SubjectFinding, f.ID, claim); err != nil {
			return proposed, fmt.Errorf("propose promotion for finding %s: %w", f.ID, err)
		}
		if err := e.recordProposalAudit(ctx, engagementID, f.ID, claim); err != nil {
			return proposed, err
		}
		proposed++
	}
	return proposed, nil
}

// recordProposalAudit appends the audit record only after proposal persistence.
// The deterministic key lets retries recover a proposal whose audit write failed.
func (e *Evaluator) recordProposalAudit(ctx context.Context, engagementID, findingID shared.ID, claim *judgment.PromotionClaim) error {
	if err := e.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor:  proposerActor,
		Action: "promotion.proposed",
		Target: findingID.String(),
		Metadata: map[string]string{
			"idempotency_key": "promotion.proposed:" + engagementID.String() + ":" + findingID.String() + ":" + claim.Fingerprint,
			"engagement":      engagementID.String(),
			"finding":         findingID.String(),
			"rule":            claim.Rule,
			"effect":          string(claim.Proposed),
			"fingerprint":     claim.Fingerprint,
		},
		At: e.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit promotion proposal for %s: %w", findingID, err)
	}
	return nil
}

// buildSnapshot constructs a [promotion.Snapshot] for a finding by correlating
// the attack-path graph, active detections, reachability judgments, and prior
// promotion events.
func (e *Evaluator) buildSnapshot(
	ctx context.Context,
	f finding.Finding,
	graph *attackpath.Graph,
	activeDetections []detection.Record,
	reachability map[shared.ID]reachInfo,
	latestEvents map[shared.ID]promotion.PriorEscalation,
) (promotion.Snapshot, error) {
	snap := promotion.Snapshot{
		FindingID:      f.ID,
		FindingVersion: f.Version,
		Priority:       f.Priority,
	}

	// Reachability signal from judgments.
	if ri, ok := reachability[f.ID]; ok {
		snap.Reachability = ri.state
		snap.ReachabilityPublishable = ri.publishable
		snap.ReachabilityDeterministic = ri.deterministic
		snap.ReachabilitySignal = promotion.Signal{
			Kind: judgment.PromotionInputReachability,
			ID:   ri.judgmentID,
		}
	}

	// Attack-path signal: evaluate each path independently so that
	// confidence, attack-path provenance, and detection match come from
	// THE SAME path. Do not union assets across paths then use first
	// path's confidence (that contaminates evaluation).
	if graph != nil {
		result, err := graph.Traverse(ctx,
			attackpath.Query{Finding: f.ID},
			attackpath.Limits{MaxLength: 32, MaxPaths: 100},
		)
		if err != nil {
			return promotion.Snapshot{}, fmt.Errorf("traverse attack paths for finding %s: %w", f.ID, err)
		}
		if len(result.Paths) > 0 {
			type pathEval struct {
				path      attackpath.Path
				dets      []detection.Record
				confident bool
			}
			pevals := make([]pathEval, 0, len(result.Paths))
			for _, p := range result.Paths {
				pe := pathEval{path: p, confident: p.Confident}
				pathAssets := make(map[shared.ID]struct{})
				for _, n := range p.Nodes {
					if n.Asset != nil {
						pathAssets[n.Asset.Asset.ID] = struct{}{}
					}
				}
				for _, d := range activeDetections {
					if _, on := pathAssets[d.AssetID]; on {
						pe.dets = append(pe.dets, d)
					}
				}
				pevals = append(pevals, pe)
			}

			// Stable deterministic selection: confident paths with detections
			// first, then uncertain paths with detections, then paths without
			// detections. This keeps confidence/provenance/detection together.
			sort.Slice(pevals, func(i, j int) bool {
				rank := func(p pathEval) int {
					if len(p.dets) == 0 {
						return 2
					}
					if p.confident {
						return 0
					}
					return 1
				}
				if ri, rj := rank(pevals[i]), rank(pevals[j]); ri != rj {
					return ri < rj
				}
				return pevals[i].path.ID < pevals[j].path.ID
			})

			best := pevals[0]
			snap.PathPresent = true
			snap.PathConfident = best.confident
			snap.AttackPathSignal = promotion.Signal{
				Kind: judgment.PromotionInputAttackPath,
				ID:   shared.ID(best.path.ID),
			}
			snap.DetectionSignals = make([]promotion.Signal, 0, len(best.dets))
			for _, d := range best.dets {
				snap.DetectionSignals = append(snap.DetectionSignals, promotion.Signal{
					Kind:       judgment.PromotionInputDetection,
					ID:         d.ID,
					EvidenceID: d.EvidenceID,
				})
			}
		}
	}

	// Prior escalation for reversal detection.
	if prior, ok := latestEvents[f.ID]; ok {
		snap.PriorEscalation = &prior
	}

	return snap, nil
}

// loadLatestEvents returns the latest active (non-flag_for_review) promotion
// event for each finding that has one. Signal-loss reversal compares prior
// escalation inputs against the CURRENT active detections so that expired,
// removed, or superseded detections correctly set InputsActive=false.
func (e *Evaluator) loadLatestEvents(
	ctx context.Context,
	engagementID shared.ID,
	findings []finding.Finding,
	graph *attackpath.Graph,
	activeDetections []detection.Record,
	reachability map[shared.ID]reachInfo,
) (map[shared.ID]promotion.PriorEscalation, error) {
	out := make(map[shared.ID]promotion.PriorEscalation, len(findings))
	for _, f := range findings {
		events, err := e.promotions.ListByFinding(ctx, engagementID, f.ID)
		if err != nil {
			return nil, fmt.Errorf("list promotions for finding %s: %w", f.ID, err)
		}
		// Events are oldest-first. Reconstruct unresolved escalations as a stack:
		// an exact corroborating-signal-loss reversal pops only its referenced event.
		var stack []promotion.PromotionEvent
		var latestDeescalation *promotion.PromotionEvent
		for _, evt := range events {
			if evt.Effect == judgment.PromotionFlagForReview {
				continue
			}
			switch evt.Effect {
			case judgment.PromotionEscalate:
				stack = append(stack, evt)
				latestDeescalation = nil
			case judgment.PromotionDeescalate:
				if evt.Rule == judgment.RuleCorroboratingSignalLoss {
					for _, input := range evt.Inputs {
						if input.Kind != judgment.PromotionInputPrior {
							continue
						}
						for i := len(stack) - 1; i >= 0; i-- {
							if stack[i].ID == input.ID {
								stack = stack[:i]
								break
							}
						}
					}
				} else {
					copy := evt
					latestDeescalation = &copy
				}
			}
		}
		if len(stack) > 0 {
			evt := stack[len(stack)-1]
			inputsActive, err := inputsStillActive(ctx, evt, f.ID, graph, activeDetections, reachability)
			if err != nil {
				return nil, fmt.Errorf("check active escalation inputs for finding %s: %w", f.ID, err)
			}
			inputsMatch, err := escalationInputsMatch(ctx, evt, f.ID, graph, activeDetections, reachability)
			if err != nil {
				return nil, fmt.Errorf("check matching escalation inputs for finding %s: %w", f.ID, err)
			}
			out[f.ID] = promotion.PriorEscalation{EventID: evt.ID, BeforePriority: evt.BeforePriority, InputsActive: inputsActive, InputsMatch: inputsMatch}
		} else if latestDeescalation != nil {
			out[f.ID] = promotion.PriorEscalation{DeescalationInputsMatch: deescalationInputsMatch(*latestDeescalation, f.ID, reachability)}
		}
	}
	return out, nil
}

// inputsStillActive reports whether the detection inputs that drove a prior
// escalation are still present in the current active detection set. A detection
// that was expired, removed, or superseded means InputsActive=false. The caller
// passes the evaluator clock's active detections (already filtered by filterActive).
func inputsStillActive(ctx context.Context, evt promotion.PromotionEvent, findingID shared.ID, graph *attackpath.Graph, activeDetections []detection.Record, reachability map[shared.ID]reachInfo) (bool, error) {
	var pathID shared.ID
	var reachabilityID shared.ID
	detectionInputs := make(map[shared.ID]struct{})
	for _, in := range evt.Inputs {
		switch in.Kind {
		case judgment.PromotionInputAttackPath:
			if pathID != "" {
				return false, nil
			}
			pathID = in.ID
		case judgment.PromotionInputReachability:
			if reachabilityID != "" {
				return false, nil
			}
			reachabilityID = in.ID
		case judgment.PromotionInputDetection:
			detectionInputs[in.ID] = struct{}{}
		}
	}
	if pathID == "" || reachabilityID == "" || len(detectionInputs) == 0 || graph == nil {
		return false, nil
	}
	ri, ok := reachability[findingID]
	if !ok || !ri.publishable || ri.state != judgment.Reachable || ri.judgmentID != reachabilityID {
		return false, nil
	}
	result, err := graph.Traverse(ctx, attackpath.Query{Finding: findingID}, attackpath.Limits{MaxLength: 32, MaxPaths: 100})
	if err != nil {
		return false, err
	}
	active := make(map[shared.ID]detection.Record, len(activeDetections))
	for _, d := range activeDetections {
		active[d.ID] = d
	}
	for _, path := range result.Paths {
		if shared.ID(path.ID) != pathID || !path.Confident {
			continue
		}
		assets := make(map[shared.ID]struct{})
		for _, node := range path.Nodes {
			if node.Asset != nil {
				assets[node.Asset.Asset.ID] = struct{}{}
			}
		}
		for id := range detectionInputs {
			d, ok := active[id]
			if !ok {
				return false, nil
			}
			if _, onPath := assets[d.AssetID]; !onPath {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

// escalationInputsMatch reports whether an active escalation has exactly the
// same reachability judgment, confident path, and detection evidence as the
// current snapshot. It gates repeat escalation only; inputsStillActive remains
// deliberately weaker so loss of any original signal still triggers reversal.
func escalationInputsMatch(ctx context.Context, evt promotion.PromotionEvent, findingID shared.ID, graph *attackpath.Graph, activeDetections []detection.Record, reachability map[shared.ID]reachInfo) (bool, error) {
	var pathID, reachabilityID shared.ID
	detectionInputs := make(map[shared.ID]shared.ID)
	for _, in := range evt.Inputs {
		switch in.Kind {
		case judgment.PromotionInputAttackPath:
			if !pathID.IsZero() {
				return false, nil
			}
			pathID = in.ID
		case judgment.PromotionInputReachability:
			if !reachabilityID.IsZero() {
				return false, nil
			}
			reachabilityID = in.ID
		case judgment.PromotionInputDetection:
			if _, exists := detectionInputs[in.ID]; exists {
				return false, nil
			}
			detectionInputs[in.ID] = in.EvidenceID
		}
	}
	if pathID.IsZero() || reachabilityID.IsZero() || len(detectionInputs) == 0 || graph == nil {
		return false, nil
	}
	ri, ok := reachability[findingID]
	if !ok || !ri.publishable || ri.state != judgment.Reachable || ri.judgmentID != reachabilityID {
		return false, nil
	}
	result, err := graph.Traverse(ctx, attackpath.Query{Finding: findingID}, attackpath.Limits{MaxLength: 32, MaxPaths: 100})
	if err != nil {
		return false, err
	}
	for _, path := range result.Paths {
		if shared.ID(path.ID) != pathID || !path.Confident {
			continue
		}
		assets := make(map[shared.ID]struct{})
		for _, node := range path.Nodes {
			if node.Asset != nil {
				assets[node.Asset.Asset.ID] = struct{}{}
			}
		}
		current := make(map[shared.ID]shared.ID)
		for _, detection := range activeDetections {
			if _, onPath := assets[detection.AssetID]; onPath {
				current[detection.ID] = detection.EvidenceID
			}
		}
		if len(current) != len(detectionInputs) {
			return false, nil
		}
		for id, evidenceID := range detectionInputs {
			if current[id] != evidenceID {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

// deescalationInputsMatch reports whether a deterministic unreachability event
// was applied from the same reachability judgment as the current snapshot.
func deescalationInputsMatch(evt promotion.PromotionEvent, findingID shared.ID, reachability map[shared.ID]reachInfo) bool {
	if evt.Rule != judgment.RuleDeterministicUnreachable {
		return false
	}
	var reachabilityID shared.ID
	for _, input := range evt.Inputs {
		if input.Kind != judgment.PromotionInputReachability || !reachabilityID.IsZero() {
			return false
		}
		reachabilityID = input.ID
	}
	ri, ok := reachability[findingID]
	return ok && ri.publishable && ri.deterministic && ri.state == judgment.NotReachable && ri.judgmentID == reachabilityID
}

// ---------------------------------------------------------------------------
// ConfirmedRecorder
// ---------------------------------------------------------------------------

// evidenceSealer extends the basic seal with a finding-linked variant and a
// lookup method for crash-recoverable evidence reservation.
type evidenceSealer interface {
	SealForFindingWithID(ctx context.Context, evidenceID, engagementID, findingID shared.ID, kind string, content []byte, storageRef, createdBy string) (evdom.Evidence, error)
	LookupSealedByID(ctx context.Context, engagementID, evidenceID shared.ID) (evdom.Evidence, bool, error)
}

// ConfirmedRecorder receives an already publishable confirmed
// [judgment.Judgment] with CapPromotion, loads the finding for CAS fields,
// validates subject/engagement consistency, seals a finding-linked evidence
// payload (crash-recoverable), and atomically applies the promotion through
// [ports.PromotionStore]. It cannot propose or verify.
type ConfirmedRecorder struct {
	evidence   evidenceSealer
	promotions confirmedPromotionStore
	findings   confirmedFindingReader
	engagement engagementReader
	audit      confirmedAuditRecorder
	clock      ports.Clock
}

// NewConfirmedRecorder validates dependencies and returns a ConfirmedRecorder.
func NewConfirmedRecorder(
	evidence evidenceSealer,
	promotions confirmedPromotionStore,
	findings confirmedFindingReader,
	engagement engagementReader,
	audit confirmedAuditRecorder,
	clock ports.Clock,
) (*ConfirmedRecorder, error) {
	if evidence == nil || promotions == nil || findings == nil || engagement == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: promotion recorder is missing a dependency", shared.ErrValidation)
	}
	return &ConfirmedRecorder{
		evidence: evidence, promotions: promotions, findings: findings, engagement: engagement,
		audit: audit, clock: clock,
	}, nil
}

// RecordConfirmed applies a confirmed promotion judgment. The judgment must:
//   - be CapPromotion
//   - be Publishable (confirmed + meets evidence bar)
//   - have evidence score >= verdict.EvidenceThreshold
//   - have SubjectKind == SubjectFinding and SubjectID == claim.FindingID
//   - belong to the same engagement as the finding
//   - contain a valid PromotionClaim
//
// On success the method loads the finding for CAS fields, seals a
// finding-linked evidence payload (crash-recoverable via LookupSealedForFinding),
// then atomically applies the promotion through the store. For flag_for_review
// effects, lifecycle evidence is recorded without priority/version mutation.
// Retries with the same judgment + fingerprint are idempotent.
//
// Audit reliability: the mutation and audit are ordered so that we never
// return success without a required audit. If audit fails AFTER the store
// mutation succeeded, we return the audit error (lifecycle/evidence are
// canonical and the caller can retry the audit). Deterministic event and
// evidence IDs ensure retry is recoverable.
func (r *ConfirmedRecorder) RecordConfirmed(ctx context.Context, j judgment.Judgment) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: promotion recording requires tenant context", shared.ErrValidation)
	}
	if _, err := r.engagement.GetByIDInTenant(ctx, tenantID, j.EngagementID); err != nil {
		return fmt.Errorf("validate engagement ownership: %w", err)
	}

	// Validate the judgment meets all gate requirements.
	if j.Capability != judgment.CapPromotion {
		return fmt.Errorf("%w: expected CapPromotion, got %s", shared.ErrValidation, j.Capability)
	}
	if !j.Publishable() {
		return fmt.Errorf("%w: judgment is not publishable", shared.ErrValidation)
	}
	if !j.MeetsEvidenceBar() {
		return fmt.Errorf("%w: evidence score %d does not meet threshold", shared.ErrValidation, j.EvidenceScore)
	}

	// Extract and validate the PromotionClaim.
	pc, err := extractPromotionClaim(j)
	if err != nil {
		return fmt.Errorf("extract promotion claim: %w", err)
	}

	// (5) Subject/engagement validation: the judgment must target the same
	// finding and engagement as the claim.
	if j.SubjectKind != judgment.SubjectFinding {
		return fmt.Errorf("%w: expected SubjectFinding, got %s", shared.ErrValidation, j.SubjectKind)
	}
	if j.SubjectID != pc.FindingID {
		return fmt.Errorf("%w: judgment subject %s != claim finding %s", shared.ErrValidation, j.SubjectID, pc.FindingID)
	}
	if j.EngagementID.IsZero() {
		return fmt.Errorf("%w: judgment engagement id is required", shared.ErrValidation)
	}

	if j.VerifiedBy == "" || j.VerdictRationale == "" || j.VerifiedBy == j.ProposedBy {
		return fmt.Errorf("%w: publishable promotion needs a distinct verifier and rationale", shared.ErrValidation)
	}

	// Recover an applied lifecycle event before testing the finding's pre-application
	// state. A failed audit leaves the finding at the event's post-application state.
	evidenceID := deriveStableEvidenceID(tenantID, j.ID, pc.Fingerprint)
	expected, err := expectedPromotionEvent(j, pc, evidenceID)
	if err != nil {
		return fmt.Errorf("construct expected promotion event: %w", err)
	}
	existing, found, err := r.promotions.FindByJudgment(ctx, j.EngagementID, pc.FindingID, j.ID)
	if err != nil {
		return fmt.Errorf("find applied promotion: %w", err)
	}
	if found {
		if existing.ID != expected.ID || !existing.Equals(expected) {
			return fmt.Errorf("%w: judgment %s replay differs from stored event", shared.ErrConflict, j.ID)
		}
		return r.recordAudit(ctx, existing)
	}

	// Load the finding for CAS fields. The store requires ExpectedPriority and
	// ExpectedVersion to match before applying any mutation.
	f, err := r.findings.GetByEngagementAndID(ctx, j.EngagementID, pc.FindingID)
	if err != nil {
		return fmt.Errorf("load finding for CAS: %w", err)
	}
	if f.Version != pc.FindingVersion || f.Priority != pc.BeforePriority {
		return fmt.Errorf("%w: finding state changed since promotion claim", shared.ErrConflict)
	}

	// Evidence sealing must be crash-recoverable. Reserve a stable
	// evidence ID from the tenant + judgment + fingerprint. If we crashed
	// between seal and apply, retry finds THIS exact reserved link rather
	// than another promotion link for the same finding.
	evContent, err := marshalPromotionEvidence(pc, j)
	if err != nil {
		return fmt.Errorf("marshal promotion evidence: %w", err)
	}
	var ev evdom.Evidence
	if existing, found, err := r.evidence.LookupSealedByID(ctx, j.EngagementID, evidenceID); err != nil {
		return fmt.Errorf("lookup sealed evidence: %w", err)
	} else if found {
		if existing.FindingID != pc.FindingID || existing.Kind != PromotionEvidenceKind || string(existing.Content) != string(evContent) {
			return fmt.Errorf("%w: reserved evidence %s conflicts with promotion payload", shared.ErrConflict, evidenceID)
		}
		ev = existing
	} else {
		ev, err = r.evidence.SealForFindingWithID(ctx, evidenceID, j.EngagementID, pc.FindingID,
			PromotionEvidenceKind, evContent, "", proposerActor)
		if err != nil {
			return fmt.Errorf("seal promotion evidence: %w", err)
		}
	}

	cmd := ports.PromotionCommand{
		EventID:        deriveStableEventID(j.EngagementID, j.ID),
		JudgmentID:     j.ID,
		FindingVersion: pc.FindingVersion,
		// (1) CAS fields from the actual finding state.
		ExpectedPriority: f.Priority,
		ExpectedVersion:  f.Version,
		Rule:             pc.Rule,
		Effect:           pc.Proposed,
		BeforePriority:   pc.BeforePriority,
		AfterPriority:    pc.AfterPriority,
		Inputs:           pc.Inputs,
		Fingerprint:      pc.Fingerprint,
		// (6) Verdict provenance from the judgment.
		VerdictScore:     j.EvidenceScore,
		VerdictRationale: j.VerdictRationale,
		EvidenceID:       ev.ID,
		Verifier:         j.VerifiedBy,
		Uncertainty:      pc.Uncertainty,
		AppliedBy:        proposerActor,
	}

	// For flag_for_review, before == after (no priority mutation).
	if pc.Proposed == judgment.PromotionFlagForReview {
		cmd.AfterPriority = cmd.BeforePriority
	}

	// Atomically apply: CAS update finding priority/version + append lifecycle event.
	// The evidence and lifecycle records are canonical. If audit fails after
	// this succeeds, return the audit error so callers retry; the exact-replay
	// branch above retries the audit rather than claiming success.
	if _, err = r.promotions.Apply(ctx, j.EngagementID, pc.FindingID, cmd); err != nil {
		return fmt.Errorf("apply promotion: %w", err)
	}
	stored, found, err := r.promotions.FindByJudgment(ctx, j.EngagementID, pc.FindingID, j.ID)
	if err != nil {
		return fmt.Errorf("load applied promotion: %w", err)
	}
	if !found {
		return fmt.Errorf("apply promotion: stored event missing: %w", shared.ErrNotFound)
	}
	return r.recordAudit(ctx, stored)
}

// expectedPromotionEvent reconstructs every immutable lifecycle field from the
// confirmed judgment and claim. AppliedAt is intentionally excluded by Equals.
func expectedPromotionEvent(j judgment.Judgment, pc judgment.PromotionClaim, evidenceID shared.ID) (promotion.PromotionEvent, error) {
	afterVersion := pc.FindingVersion
	if pc.Proposed != judgment.PromotionFlagForReview {
		afterVersion++
	}
	afterPriority := pc.AfterPriority
	if pc.Proposed == judgment.PromotionFlagForReview {
		afterPriority = pc.BeforePriority
	}
	return promotion.NewPromotionEvent(
		deriveStableEventID(j.EngagementID, j.ID),
		j.EngagementID,
		j.ID,
		pc.FindingID,
		pc.FindingVersion,
		afterVersion,
		pc.Rule,
		pc.Proposed,
		pc.BeforePriority,
		afterPriority,
		pc.Inputs,
		pc.Fingerprint,
		j.EvidenceScore,
		j.VerdictRationale,
		evidenceID,
		j.VerifiedBy,
		pc.Uncertainty,
		proposerActor,
		time.Time{},
	)
}

// recordAudit records and durably acknowledges the required audit entry after
// the canonical lifecycle event exists.
func (r *ConfirmedRecorder) recordAudit(ctx context.Context, evt promotion.PromotionEvent) error {
	if err := recordPromotionAudit(ctx, r.audit, r.clock, evt); err != nil {
		return err
	}
	if err := r.promotions.MarkAuditComplete(ctx, evt.ID); err != nil {
		return fmt.Errorf("mark promotion audit complete: %w", err)
	}
	return nil
}

// Reconciler is the distinct recovery authority for confirmed promotions. It
// applies already-confirmed judgments and retries only outstanding audits; it
// has no proposal or verdict authority.
type Reconciler struct {
	judgments judgmentReader
	audits    ports.PromotionAuditTracker
	recorder  ports.ConfirmedPromotionRecorder
	audit     ports.IdempotentAuditLogger
	clock     ports.Clock
}

// NewReconciler creates the durable promotion recovery authority.
func NewReconciler(judgments judgmentReader, audits ports.PromotionAuditTracker, recorder ports.ConfirmedPromotionRecorder, audit ports.IdempotentAuditLogger, clock ports.Clock) (*Reconciler, error) {
	if judgments == nil || audits == nil || recorder == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: promotion reconciler is missing a dependency", shared.ErrValidation)
	}
	return &Reconciler{judgments: judgments, audits: audits, recorder: recorder, audit: audit, clock: clock}, nil
}

var _ ports.PromotionReconciler = (*Reconciler)(nil)

// Reconcile recovers confirmed CapPromotion judgments that have no event, then
// retries every event whose audit completion was not durably acknowledged.
func (r *Reconciler) Reconcile(ctx context.Context, engagementID shared.ID) error {
	judgments, err := r.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return fmt.Errorf("list judgments for promotion reconciliation: %w", err)
	}
	var errs []error
	for _, j := range judgments {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if j.Capability != judgment.CapPromotion || !j.Publishable() {
			continue
		}
		if err := r.recorder.RecordConfirmed(ctx, j); err != nil {
			if ctx.Err() != nil {
				return errors.Join(append(errs, ctx.Err())...)
			}
			errs = append(errs, fmt.Errorf("recover confirmed promotion %s: %w", j.ID, err))
		}
	}
	pending, err := r.audits.ListPendingAudits(ctx, engagementID)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list pending promotion audits: %w", err))...)
	}
	for _, evt := range pending {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := recordPromotionAudit(ctx, r.audit, r.clock, evt); err != nil {
			if ctx.Err() != nil {
				return errors.Join(append(errs, ctx.Err())...)
			}
			errs = append(errs, fmt.Errorf("recover promotion audit %s: %w", evt.ID, err))
			continue
		}
		if err := r.audits.MarkAuditComplete(ctx, evt.ID); err != nil {
			if ctx.Err() != nil {
				return errors.Join(append(errs, ctx.Err())...)
			}
			errs = append(errs, fmt.Errorf("mark recovered promotion audit complete %s: %w", evt.ID, err))
		}
	}
	return errors.Join(errs...)
}

func recordPromotionAudit(ctx context.Context, audit confirmedAuditRecorder, clock ports.Clock, evt promotion.PromotionEvent) error {
	at := evt.AppliedAt
	if at.IsZero() {
		at = clock.Now()
	}
	if err := audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: proposerActor, Action: "promotion.applied", Target: evt.FindingID.String(),
		Metadata: map[string]string{
			"idempotency_key": evt.ID.String(), "engagement": evt.EngagementID.String(), "finding": evt.FindingID.String(),
			"judgment": evt.JudgmentID.String(), "rule": evt.Rule, "effect": string(evt.Effect),
			"fingerprint": evt.Fingerprint, "evidence": evt.EvidenceID.String(),
		},
		At: at,
	}); err != nil {
		return fmt.Errorf("audit promotion application: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// reachInfo holds reachability state derived from judgments.
type reachInfo struct {
	judgmentID    shared.ID
	state         judgment.ReachabilityState
	tier          judgment.ReachabilityTier
	publishable   bool
	deterministic bool
	evidenceScore int
	version       int
	updatedAt     time.Time
}

// deriveStableEventID produces a deterministic event ID from the engagement
// and judgment IDs so that retries always produce the same ID. This makes
// the promotion store's EventID uniqueness guard a crash-recovery mechanism:
// if the recorder applied the event but crashed before returning, the retry
// produces the same EventID and the store returns the existing event.
func deriveStableEventID(engagementID, judgmentID shared.ID) shared.ID {
	h := sha256.Sum256([]byte("promotion:event:" + string(engagementID) + ":" + string(judgmentID)))
	return shared.ID(hex.EncodeToString(h[:16]))
}

func deriveStableEvidenceID(tenantID, judgmentID shared.ID, fingerprint string) shared.ID {
	h := sha256.Sum256([]byte("promotion:evidence:" + string(tenantID) + ":" + string(judgmentID) + ":" + fingerprint))
	return shared.ID(hex.EncodeToString(h[:16]))
}

// indexReachability indexes the current publishable finding-scoped reachability
// judgment. Stronger tiers supersede weaker ones; within a tier, later judgment
// chronology wins so a contradictory later proof replaces the earlier state.
func indexReachability(judgments []judgment.Judgment) map[shared.ID]reachInfo {
	out := make(map[shared.ID]reachInfo)
	for _, j := range judgments {
		if j.Capability != judgment.CapReachability || j.SubjectKind != judgment.SubjectFinding || !j.Publishable() {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		existing, exists := out[j.SubjectID]
		if exists && !reachabilitySupersedes(j, rc, existing) {
			continue
		}
		out[j.SubjectID] = reachInfo{
			judgmentID:    j.ID,
			state:         rc.Reachable,
			tier:          rc.Tier,
			publishable:   true,
			deterministic: j.EvidenceScore >= verdict.DeterministicProofScore && judgment.IsDeterministicReachabilityProof(rc.Tier, j.ProposedBy, j.VerifiedBy),
			evidenceScore: j.EvidenceScore,
			version:       j.Version,
			updatedAt:     j.Audit.UpdatedAt,
		}
	}
	return out
}

func reachabilitySupersedes(j judgment.Judgment, rc judgment.ReachabilityClaim, existing reachInfo) bool {
	if rc.Tier.Rank() != existing.tier.Rank() {
		return rc.Tier.Rank() > existing.tier.Rank()
	}
	if j.Audit.UpdatedAt != existing.updatedAt {
		return j.Audit.UpdatedAt.After(existing.updatedAt)
	}
	if j.Version != existing.version {
		return j.Version > existing.version
	}
	return j.ID > existing.judgmentID
}

// indexPromotionProposals indexes the latest promotion proposal claim per
// finding for idempotency. Only CapPromotion judgments in proposed/confirmed
// state are considered.
func indexPromotionProposals(judgments []judgment.Judgment) map[shared.ID]map[string]struct{} {
	out := make(map[shared.ID]map[string]struct{})
	for _, j := range judgments {
		if j.Capability != judgment.CapPromotion {
			continue
		}
		var pc judgment.PromotionClaim
		switch claim := j.Claim.(type) {
		case judgment.PromotionClaim:
			pc = claim
		case *judgment.PromotionClaim:
			if claim == nil {
				continue
			}
			pc = *claim
		default:
			continue
		}
		if out[pc.FindingID] == nil {
			out[pc.FindingID] = make(map[string]struct{})
		}
		out[pc.FindingID][pc.Fingerprint] = struct{}{}
	}
	return out
}

// filterActive returns only detections that are active at now. Expiry is
// evaluated against the evaluator clock, never RecordedAt, so an old record
// that has since expired cannot keep a promotion escalated.
func filterActive(records []detection.Record, now time.Time) []detection.Record {
	out := make([]detection.Record, 0, len(records))
	for _, r := range records {
		if r.ExpiresAt.IsZero() || r.ExpiresAt.After(now) {
			out = append(out, r)
		}
	}
	return out
}

// buildGraph constructs an [attackpath.Graph] from raw assets, edges, bindings,
// and findings. Returns nil (without error) if the graph has no assets.
func buildGraph(
	tenantID shared.ID,
	assetsList []*asset.Asset,
	edges []asset.Edge,
	bindings []attackpath.Binding,
	findings []finding.Finding,
	reachability map[shared.ID]reachInfo,
) (*attackpath.Graph, error) {
	if len(assetsList) == 0 {
		return nil, nil
	}
	domAssets := make([]asset.Asset, len(assetsList))
	for i, a := range assetsList {
		domAssets[i] = *a
	}
	findingInputs := make([]attackpath.FindingInput, len(findings))
	for i, f := range findings {
		fi := attackpath.FindingInput{
			Target:  attackpath.FindingTarget{ID: f.ID, Kind: attackpath.TargetCanonical},
			Finding: f,
		}
		if ri, ok := reachability[f.ID]; ok && ri.publishable {
			fi.Reachability = ri.state
			fi.Confirmed = true
			fi.Tier = ri.tier
			fi.Provenance = ri.judgmentID
		}
		findingInputs[i] = fi
	}
	// Filter bindings to this tenant.
	tenantBindings := make([]attackpath.Binding, 0, len(bindings))
	for _, b := range bindings {
		if b.TenantID == tenantID {
			tenantBindings = append(tenantBindings, b)
		}
	}
	g, err := attackpath.NewGraph(attackpath.Input{
		TenantID: tenantID,
		Assets:   domAssets,
		Edges:    edges,
		Bindings: tenantBindings,
		Findings: findingInputs,
	})
	if err != nil {
		return nil, fmt.Errorf("new graph: %w", err)
	}
	return g, nil
}

// extractPromotionClaim unmarshals the claim from a judgment as a PromotionClaim.
func extractPromotionClaim(j judgment.Judgment) (judgment.PromotionClaim, error) {
	switch pc := j.Claim.(type) {
	case judgment.PromotionClaim:
		if err := pc.Validate(); err != nil {
			return judgment.PromotionClaim{}, fmt.Errorf("invalid promotion claim: %w", err)
		}
		return pc, nil
	case *judgment.PromotionClaim:
		if pc == nil {
			return judgment.PromotionClaim{}, fmt.Errorf("%w: nil promotion claim", shared.ErrValidation)
		}
		if err := pc.Validate(); err != nil {
			return judgment.PromotionClaim{}, fmt.Errorf("invalid promotion claim: %w", err)
		}
		return *pc, nil
	default:
		return judgment.PromotionClaim{}, fmt.Errorf("%w: judgment claim is not a PromotionClaim", shared.ErrValidation)
	}
}

// marshalPromotionEvidence creates the canonical evidence payload for a
// promotion application. The payload is deterministic and includes the
// claim, verdict metadata, and judgment identity.
func marshalPromotionEvidence(pc judgment.PromotionClaim, j judgment.Judgment) ([]byte, error) {
	payload := struct {
		JudgmentID       string                    `json:"judgment_id"`
		EngagementID     string                    `json:"engagement_id"`
		FindingID        string                    `json:"finding_id"`
		Rule             string                    `json:"rule"`
		Effect           judgment.PromotionChange  `json:"effect"`
		Fingerprint      string                    `json:"fingerprint"`
		FindingVersion   int                       `json:"finding_version"`
		BeforePriority   int                       `json:"before_priority"`
		AfterPriority    int                       `json:"after_priority"`
		Inputs           []judgment.PromotionInput `json:"inputs"`
		VerdictScore     int                       `json:"verdict_score"`
		VerifiedBy       string                    `json:"verified_by"`
		VerdictRationale string                    `json:"verdict_rationale"`
	}{
		JudgmentID:       j.ID.String(),
		EngagementID:     j.EngagementID.String(),
		FindingID:        pc.FindingID.String(),
		Rule:             pc.Rule,
		Effect:           pc.Proposed,
		Fingerprint:      pc.Fingerprint,
		FindingVersion:   pc.FindingVersion,
		BeforePriority:   pc.BeforePriority,
		AfterPriority:    pc.AfterPriority,
		Inputs:           pc.Inputs,
		VerdictScore:     j.EvidenceScore,
		VerifiedBy:       j.VerifiedBy,
		VerdictRationale: j.VerdictRationale,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal promotion evidence: %w", err)
	}
	return data, nil
}
