// Package reachproof is the coordinator that turns a deterministic Tier-2
// call-graph reachability result into a CONFIRMED reachability Judgment, reusing the existing audited
// propose→verify gate rather than any new confirmed-state path. It runs the reachability analysis for an
// engagement's target, and for each finding mints a Tier-2 ReachabilityClaim that supersedes a weaker
// (e.g. LLM Tier-1.5) prior judgment.
//
// SAFETY (security-reviewed):
// Two RESERVED, mutually-distinct, non-agent/non-human identities: proposer = the scan, verifier
// = the engine. The domain self-confirm guard is satisfied because they differ, and it stays meaningful
// for the agent path (no agent is involved; this coordinator is not agent-reachable).
// The proof IS the evidence: the verdict carries the call path + a fixed deterministic score.
// No coverage (build failed) mints NOTHING – the weaker prior judgment stands, never a false
// "not reachable". Only a SUCCESSFUL build yields reachable / not-reachable judgments.
// Supersession is append-only: a NEW judgment row + an audit entry naming BOTH sides; the prior
// judgment is never mutated or deleted.
package reachproof

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// Reserved deterministic-proof identities. They use the "system:" namespace – distinct from the
// "agent:<sid>" and "human:<id>" namespaces no real principal can collide with – and are mutually
// distinct so verdict.SelfConfirm(verifierActor, proposerActor) is always false. Neither is mintable by
// the agent/human actor factories.
const (
	proposerActor = "system:callgraph-scan"   // the scan that asked "is this symbol reachable?"
	verifierActor = "system:callgraph-engine" // the deterministic engine whose proof answers it
)

// analyzer runs the reachability query for a target (reachability.Service satisfies it). A build error
// means NO coverage.
type analyzer interface {
	Analyze(ctx context.Context, targetRef string, symbols []string) (*reachability.Analysis, error)
}

// recorder is the NARROW judgment-lifecycle slice the coordinator needs (analysis.Service satisfies it).
// It is injected only from the composition root – never handed to the agent tool catalog, so adding
// a Verify caller here does not widen the agent's reach.
type recorder interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Coordinator records deterministic Tier-2 reachability judgments. It implements ports.ReachabilityRecorder
// (a subject is ports.ReachabilitySubject), so the SCA pipeline can drive it without importing this package.
type Coordinator struct {
	analyzer analyzer
	recorder recorder
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.ReachabilityRecorder = (*Coordinator)(nil)

// NewCoordinator validates and returns the coordinator.
func NewCoordinator(a analyzer, r recorder, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	if a == nil || r == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: reachproof coordinator is missing a dependency", shared.ErrValidation)
	}
	return &Coordinator{analyzer: a, recorder: r, audit: audit, clock: clock}, nil
}

// Record builds the engagement target's call graph ONCE and mints a deterministic Tier-2 reachability
// judgment per subject. It returns the number of judgments minted. A no-coverage build error aborts the
// whole pass (mints nothing – the weaker prior judgments stand). Per subject, a judgment is minted
// only when it SUPERSEDES the prior reachability judgment (or there is none) – same-or-stronger prior is
// left untouched (no churn). Subjects must have DISTINCT FindingIDs (the supersession check reads the
// stored prior, not in-flight mints) – the post-scan trigger produces one Subject per finding.
func (c *Coordinator) Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (int, error) {
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	// One build for the whole engagement: the union of every subject's affected symbols.
	var allSymbols []string
	for _, s := range subjects {
		allSymbols = append(allSymbols, s.Symbols...)
	}
	analysis, err := c.analyzer.Analyze(ctx, targetRef, allSymbols)
	if err != nil {
		return 0, fmt.Errorf("reachability analysis (no coverage – prior tier stands): %w", err)
	}
	if analysis == nil { // defensive: a contract-violating analyzer returning (nil,nil) is no-coverage, not a deref
		return 0, fmt.Errorf("%w: reachability analysis returned no result", shared.ErrValidation)
	}
	reachableBy := map[string]reachability.Result{}
	for _, r := range analysis.Results {
		reachableBy[r.Symbol] = r
	}
	prior, err := c.priorReachability(ctx, engagementID)
	if err != nil {
		return 0, err
	}
	minted := 0
	for _, sub := range subjects {
		if sub.FindingID.IsZero() {
			continue
		}
		claim := subjectClaim(sub, reachableBy)
		if p, ok := prior[sub.FindingID]; ok && !claim.Supersedes(p.claim) {
			continue // a same-or-stronger prior reachability judgment stands – don't churn
		}
		if err := c.mint(ctx, engagementID, sub.FindingID, claim, prior[sub.FindingID]); err != nil {
			return minted, err
		}
		minted++
	}
	return minted, nil
}

// deterministicClaimConfidence is the claim's OWN self-reported confidence for a deterministic Tier-2
// result: maximal (100) – the engine is fully confident in its computed call graph. This is deliberately
// distinct from the evidence/verdict score (verdict.DeterministicProofScore=90), which is where the
// VTA-over-approximation discount lives: the claim asserts itself with full confidence; the gate
// weighs how much we trust that assertion as publishable evidence.
const deterministicClaimConfidence = 100

// subjectClaim aggregates a subject's affected symbols into a Tier-2 claim: reachable (with the proof
// path) if ANY affected symbol is reached, else not-reachable.
func subjectClaim(sub ports.ReachabilitySubject, reachableBy map[string]reachability.Result) judgment.ReachabilityClaim {
	for _, sym := range sub.Symbols {
		if r, ok := reachableBy[sym]; ok && r.Reachable {
			return judgment.ReachabilityClaim{
				Reachable: judgment.Reachable, Tier: judgment.Tier2, Path: r.Path,
				Confidence: deterministicClaimConfidence,
			}
		}
	}
	return judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: deterministicClaimConfidence}
}

// priorJudgment pairs a stored reachability judgment with its decoded claim (append-only supersession
// never touches the prior row, so only its id + tier + claim are needed).
type priorJudgment struct {
	id    shared.ID
	tier  judgment.ReachabilityTier
	claim judgment.ReachabilityClaim
}

// priorReachability indexes the latest reachability judgment per finding subject (highest tier wins, so
// the supersession check compares against the strongest existing proof).
func (c *Coordinator) priorReachability(ctx context.Context, engagementID shared.ID) (map[shared.ID]priorJudgment, error) {
	js, err := c.recorder.List(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list prior judgments: %w", err)
	}
	out := map[shared.ID]priorJudgment{}
	for _, j := range js {
		if j.Capability != judgment.CapReachability || j.SubjectKind != judgment.SubjectFinding {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		if cur, seen := out[j.SubjectID]; seen && cur.tier.Rank() >= rc.Tier.Rank() {
			continue // keep the strongest prior
		}
		out[j.SubjectID] = priorJudgment{id: j.ID, tier: rc.Tier, claim: rc}
	}
	return out, nil
}

// mint records the deterministic Tier-2 judgment via the audited propose→verify gate (reserved identities,
// deterministic score, clean rationale) and, when it superseded a prior judgment, audits BOTH sides.
func (c *Coordinator) mint(ctx context.Context, engagementID, findingID shared.ID, claim judgment.ReachabilityClaim, prior priorJudgment) error {
	proposed, err := c.recorder.Propose(ctx, proposerActor, engagementID, judgment.CapReachability, judgment.SubjectFinding, findingID, claim)
	if err != nil {
		return fmt.Errorf("propose reachability judgment: %w", err)
	}
	if _, err := c.recorder.Verify(ctx, verifierActor, engagementID, proposed.ID, verdict.DeterministicProofScore, proofRationale(claim), proposed.Version); err != nil {
		return fmt.Errorf("verify reachability judgment: %w", err)
	}
	if !prior.id.IsZero() { // append-only – the prior row is untouched; record the supersession with BOTH ids/tiers
		if err := c.audit.Record(ctx, ports.AuditEntry{
			Actor: verifierActor, Action: "judgment.superseded", Target: proposed.ID.String(),
			Metadata: map[string]string{
				"engagement": engagementID.String(), "subject": findingID.String(),
				"superseded_id": prior.id.String(), "superseded_tier": string(prior.tier),
				"superseding_tier": string(claim.Tier),
			},
			At: c.clock.Now(),
		}); err != nil {
			return fmt.Errorf("audit supersession: %w", err)
		}
	}
	return nil
}

// proofRationale renders the sealed verdict rationale from ONLY normalized importPath.Symbol frames + the
// tier (no file contents, env, or paths). The reachability.Result.Path is already importPath.Symbol.
func proofRationale(claim judgment.ReachabilityClaim) string {
	if claim.Reachable == judgment.Reachable && len(claim.Path) > 0 {
		return "tier-2 call-graph proof: reachable via " + strings.Join(claim.Path, " → ")
	}
	return "tier-2 call-graph proof: no entrypoint reaches the affected symbol(s)"
}
