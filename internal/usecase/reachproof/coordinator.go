// Package reachproof is the coordinator that turns a deterministic reachability result into a CONFIRMED
// reachability Judgment, reusing the existing audited propose→verify gate rather than any new
// confirmed-state path. It runs the reachability analysis for an engagement's target, and for each finding
// mints a ReachabilityClaim at the analyzer's tier (Go call-graph → Tier-2, Python source-import → Tier-1)
// that supersedes a weaker prior judgment (a stronger prior stands — a Tier-1 import proof never downgrades
// a Tier-2 call-path proof).
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

// Reserved deterministic-proof identities per analysis tier. They use the "system:" namespace – distinct
// from the "agent:<sid>" and "human:<id>" namespaces no real principal can collide with – and each
// tier's proposer/verifier are mutually distinct so verdict.SelfConfirm(verifier, proposer) is always
// false. Neither is mintable by the agent/human actor factories. The identities + proof label are
// tier-specific so a Tier-1 IMPORT proof is never attributed to the call-graph engine (audit accuracy).
func actorsForTier(tier judgment.ReachabilityTier) (proposer, verifier, proofLabel string) {
	switch tier {
	case judgment.Tier2:
		return "system:callgraph-scan", "system:callgraph-engine", "tier-2 call-graph proof"
	default: // Tier-1 source-import reachability (e.g. Python)
		return "system:pyimport-scan", "system:pyimport-engine", "tier-1 import-reachability proof"
	}
}

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

// Coordinator records deterministic reachability judgments from a call-graph/import analyzer. It implements
// ports.ReachabilityRecorder (a subject is ports.ReachabilitySubject), so the SCA pipeline can drive it
// without importing this package. The minted claim's tier reflects the ANALYZER's strength of proof: a Go
// call-graph analyzer proves Tier-2 (a reached call path); a source-import analyzer (e.g. Python) proves
// Tier-1 (the vulnerable package is/ isn't imported by first-party code) — a weaker but still deterministic
// signal. The tier is honest per analyzer; it is NOT inflated to Tier-2 for an import-level proof.
type Coordinator struct {
	analyzer   analyzer
	recorder   recorder
	audit      ports.AuditLogger
	clock      ports.Clock
	tier       judgment.ReachabilityTier
	proposer   string // reserved proposer identity (tier-specific, audit accuracy)
	verifier   string // reserved verifier identity (distinct from proposer → never self-confirms)
	proofLabel string // tier-appropriate prefix for the sealed proof rationale
}

var _ ports.ReachabilityRecorder = (*Coordinator)(nil)

// NewCoordinator validates and returns a Tier-2 coordinator (a call-graph analyzer that proves a reached
// call path — the Go/govulncheck default).
func NewCoordinator(a analyzer, r recorder, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	return NewCoordinatorForTier(a, r, audit, clock, judgment.Tier2)
}

// NewCoordinatorForTier validates and returns a coordinator whose minted judgments carry the given tier,
// honestly reflecting the analyzer's strength of proof (Tier-2 for a call-graph, Tier-1 for source-import
// reachability). It refuses an unknown tier rather than mint an unrankable claim.
func NewCoordinatorForTier(a analyzer, r recorder, audit ports.AuditLogger, clock ports.Clock, tier judgment.ReachabilityTier) (*Coordinator, error) {
	if a == nil || r == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: reachproof coordinator is missing a dependency", shared.ErrValidation)
	}
	if !tier.Valid() {
		return nil, fmt.Errorf("%w: reachproof coordinator needs a valid reachability tier, got %q", shared.ErrValidation, tier)
	}
	proposer, verifier, label := actorsForTier(tier)
	return &Coordinator{analyzer: a, recorder: r, audit: audit, clock: clock, tier: tier, proposer: proposer, verifier: verifier, proofLabel: label}, nil
}

// Record runs the analyzer over the engagement target ONCE and mints a deterministic reachability judgment
// (at the coordinator's tier) per subject. It returns the number of judgments minted. A no-coverage error aborts the
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
		claim := subjectClaim(sub, reachableBy, c.tier)
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

// deterministicClaimConfidence is the claim's OWN self-reported confidence for a deterministic result:
// maximal (100) – the engine is fully confident in what it computed (the call graph, or the import set).
// This is deliberately distinct from the evidence/verdict score (verdict.DeterministicProofScore=90),
// which is where the over-approximation discount lives: the claim asserts itself with full confidence; the
// gate weighs how much we trust that assertion as publishable evidence.
const deterministicClaimConfidence = 100

// subjectClaim aggregates a subject's affected symbols into a claim at the coordinator's tier: reachable
// (with the proof path) if ANY affected symbol is reached, else not-reachable.
func subjectClaim(sub ports.ReachabilitySubject, reachableBy map[string]reachability.Result, tier judgment.ReachabilityTier) judgment.ReachabilityClaim {
	for _, sym := range sub.Symbols {
		if r, ok := reachableBy[sym]; ok && r.Reachable {
			return judgment.ReachabilityClaim{
				Reachable: judgment.Reachable, Tier: tier, Path: r.Path,
				Confidence: deterministicClaimConfidence,
			}
		}
	}
	return judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: tier, Confidence: deterministicClaimConfidence}
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

// mint records the deterministic judgment via the audited propose→verify gate (tier-specific reserved
// identities, deterministic score, clean rationale) and, when it superseded a prior judgment, audits BOTH sides.
func (c *Coordinator) mint(ctx context.Context, engagementID, findingID shared.ID, claim judgment.ReachabilityClaim, prior priorJudgment) error {
	proposed, err := c.recorder.Propose(ctx, c.proposer, engagementID, judgment.CapReachability, judgment.SubjectFinding, findingID, claim)
	if err != nil {
		return fmt.Errorf("propose reachability judgment: %w", err)
	}
	if _, err := c.recorder.Verify(ctx, c.verifier, engagementID, proposed.ID, verdict.DeterministicProofScore, c.proofRationale(claim), proposed.Version); err != nil {
		return fmt.Errorf("verify reachability judgment: %w", err)
	}
	if !prior.id.IsZero() { // append-only – the prior row is untouched; record the supersession with BOTH ids/tiers
		if err := c.audit.Record(ctx, ports.AuditEntry{
			Actor: c.verifier, Action: "judgment.superseded", Target: proposed.ID.String(),
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

// proofRationale renders the sealed verdict rationale from ONLY the tier-appropriate label + normalized
// importPath.Symbol / import frames (no file contents, env, or paths). The label honestly names the proof
// STRENGTH (tier-2 call-graph vs tier-1 import-reachability) so a weaker import proof is never sealed as a
// call-graph proof. The reachability.Result.Path is already a normalized symbol/import chain.
func (c *Coordinator) proofRationale(claim judgment.ReachabilityClaim) string {
	if claim.Reachable == judgment.Reachable && len(claim.Path) > 0 {
		return c.proofLabel + ": reachable via " + strings.Join(claim.Path, " → ")
	}
	return c.proofLabel + ": no entrypoint reaches the affected symbol(s)"
}
