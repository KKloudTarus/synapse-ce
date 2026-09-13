// Package runtimereach is the coordinator that turns an OBSERVED runtime library load on a monitored host
// (EPIC #1042 #1061) into a CONFIRMED, RAISE-ONLY reachability Judgment, reusing the existing audited
// propose→verify gate rather than any new confirmed-state path. It sits beside reachproof and mirrors its
// safety design, differing only in that runtime observation is raise-only:
//
//   - It mints ONLY reachable claims at TierRuntime, never a not_reachable one. The absence of a load is not
//     evidence of unreachability, so no observation ever suppresses a finding.
//   - Its reserved identities (ProofActorRuntimeLibLoadedScan / Engine) are absent from
//     IsDeterministicReachabilityProof, so a runtime verdict can never become a VEX not_affected even though
//     it is confirmed. TierRuntime also falls through SuppressesFinding to false.
//   - The join that produces the per-finding hits is by PACKAGE OWNERSHIP (internal/domain/runtimereach),
//     never a bare path, so a path collision never misattributes a load to the wrong finding.
//
// SAFETY: proposer = the scan, verifier = the engine, two RESERVED, mutually-distinct, non-agent/non-human
// identities, so the domain self-confirm guard holds. Supersession is append-only: a new judgment row plus
// an audit entry naming both sides; the prior judgment is never mutated or deleted. It is not agent-reachable
// (composition-root-only), enforced by TestNotAgentReachable.
package runtimereach

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// recorder is the NARROW judgment-lifecycle slice the coordinator needs (analysis.Service satisfies it). It
// is injected only from the composition root, never handed to the agent tool catalog.
type recorder interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// runtimeClaimConfidence is the claim's own self-reported confidence for an observed load: an actual
// execution is certain evidence that the file was loaded, so it is 100. It is distinct from the evidence
// score (verdict.DeterministicProofScore=90), which gates publishability but, paired with a runtime actor
// absent from IsDeterministicReachabilityProof, still never makes the claim a suppressing proof.
const runtimeClaimConfidence = 100

// Coordinator records raise-only runtime-reachability judgments from observed host library loads.
type Coordinator struct {
	recorder recorder
	audit    ports.AuditLogger
	clock    ports.Clock
	proposer string
	verifier string
}

// NewCoordinator validates dependencies and returns a coordinator that mints TierRuntime library-load
// judgments under the reserved runtime-libloaded identities.
func NewCoordinator(r recorder, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	if r == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: runtimereach coordinator is missing a dependency", shared.ErrValidation)
	}
	return &Coordinator{
		recorder: r, audit: audit, clock: clock,
		proposer: judgment.ProofActorRuntimeLibLoadedScan,
		verifier: judgment.ProofActorRuntimeLibLoadedEngine,
	}, nil
}

// priorJudgment is the strongest existing reachability judgment for a finding.
type priorJudgment struct {
	id    shared.ID
	tier  judgment.ReachabilityTier
	claim judgment.ReachabilityClaim
}

// Record mints a raise-only TierRuntime reachable judgment for each finding whose owning package was
// observed loaded (a domain [runtimereach.Hit]). It returns the number of judgments minted. A judgment is
// minted only when it SUPERSEDES the prior reachability judgment (or there is none), so a finding already
// proven reachable at TierRuntime does not churn, and a runtime observation legitimately supersedes a
// weaker static verdict (including a prior static not_reachable, which observed execution refutes). It never
// mints not_reachable, so it can never lower a finding's priority or drive a VEX not_affected.
func (c *Coordinator) Record(ctx context.Context, engagementID shared.ID, hits []runtimereach.Hit) (int, error) {
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if len(hits) == 0 {
		return 0, nil
	}
	prior, err := c.priorReachability(ctx, engagementID)
	if err != nil {
		return 0, err
	}
	// Deterministic order and one judgment per finding (the strongest match kind wins) so repeated or
	// out-of-order hits never churn the audit trail.
	sorted := append([]runtimereach.Hit(nil), hits...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].FindingID < sorted[j].FindingID })
	seen := map[shared.ID]struct{}{}
	minted := 0
	for _, h := range sorted {
		if h.FindingID.IsZero() {
			continue
		}
		if _, dup := seen[h.FindingID]; dup {
			continue
		}
		seen[h.FindingID] = struct{}{}
		claim := judgment.ReachabilityClaim{
			Reachable:  judgment.Reachable,
			Tier:       judgment.TierRuntime,
			Confidence: runtimeClaimConfidence,
			Path:       []string{runtimePathElem(h)},
		}
		if p, ok := prior[h.FindingID]; ok && !claim.Supersedes(p.claim) {
			continue // a same-or-stronger prior reachability judgment stands, do not churn
		}
		if err := c.mint(ctx, engagementID, h, claim, prior[h.FindingID]); err != nil {
			return minted, err
		}
		minted++
	}
	return minted, nil
}

// runtimePathElem renders the sealed proof's single path element from ONLY the package identity and the
// attribution kind, never a raw filesystem path (which could leak a host path into the report). It names
// what was observed: the owning package and how the load was attributed to it.
func runtimePathElem(h runtimereach.Hit) string {
	pkg := strings.TrimSpace(h.Package.Name)
	if v := strings.TrimSpace(h.Package.Version); v != "" {
		pkg += "@" + v
	}
	kind := string(h.Match)
	if kind == "" {
		kind = "unattributed"
	}
	return "runtime load of " + pkg + " (" + kind + ")"
}

// priorReachability indexes the strongest existing reachability judgment per finding (highest tier wins),
// so the supersession check compares against the strongest prior proof.
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
		if j.State != judgment.StateConfirmed {
			// Only a CONFIRMED judgment stands. A proposed judgment is inert (a mint whose Verify never
			// cleared, e.g. after a transient store error), and a refuted one did not clear the bar; treating
			// either as a standing prior would let a failed mint permanently block the real raise, since a
			// same-tier claim does not supersede it. Skipping it lets the next report re-mint and recover.
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		if cur, seen := out[j.SubjectID]; seen && cur.tier.Rank() >= rc.Tier.Rank() {
			continue
		}
		out[j.SubjectID] = priorJudgment{id: j.ID, tier: rc.Tier, claim: rc}
	}
	return out, nil
}

// mint records the judgment via the audited propose→verify gate (reserved identities, deterministic score,
// clean rationale) and, when it superseded a prior judgment, audits BOTH sides append-only.
func (c *Coordinator) mint(ctx context.Context, engagementID shared.ID, h runtimereach.Hit, claim judgment.ReachabilityClaim, prior priorJudgment) error {
	proposed, err := c.recorder.Propose(ctx, c.proposer, engagementID, judgment.CapReachability, judgment.SubjectFinding, h.FindingID, claim)
	if err != nil {
		return fmt.Errorf("propose runtime reachability judgment: %w", err)
	}
	if _, err := c.recorder.Verify(ctx, c.verifier, engagementID, proposed.ID, verdict.DeterministicProofScore, c.proofRationale(h), proposed.Version); err != nil {
		return fmt.Errorf("verify runtime reachability judgment: %w", err)
	}
	if !prior.id.IsZero() {
		if err := c.audit.Record(ctx, ports.AuditEntry{
			Actor: c.verifier, Action: "judgment.superseded", Target: proposed.ID.String(),
			Metadata: map[string]string{
				"engagement": engagementID.String(), "subject": h.FindingID.String(),
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

// proofRationale renders the sealed verdict rationale from ONLY the package identity and attribution kind,
// never a raw host path.
func (c *Coordinator) proofRationale(h runtimereach.Hit) string {
	return "tier-runtime library-load observation: " + runtimePathElem(h)
}
