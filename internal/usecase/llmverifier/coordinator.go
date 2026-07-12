// Package llmverifier is the automated LLM judgment-verifier: it makes SYNAPSE_VERIFIER_MODEL live on the
// server. For each PROPOSED gated judgment (reachability/sast/critique/threat/vex_justification) it asks a
// DISTINCT verifier model to independently score how strongly the claim's evidence holds, then seals that
// score as a verdict through analysis.Service.Verify — the same gate a human reviewer uses.
//
// It can never confirm a claim it "owns": its verifier identity is "llm:<model>", and the analysis gate's
// verdict.SelfConfirm rejects a verifier equal to the proposer. The coordinator additionally skips any
// judgment whose proposer is this same identity (belt-and-suspenders). The model's rationale is sealed
// into the hash-chained evidence ledger (never into the typed claim or the report), and only a structured
// {score, rationale} crosses the boundary — no free prose reaches a deliverable. Best-effort: a per-
// judgment model/verify error is counted and skipped, never aborting the batch or failing a scan.
//
// Accepted risk (LLM-as-judge): a crafted claim/subject could in principle coax a wrongful high score
// (the sharpest edge is a critique refutation wrongly dismissing a real finding). This is bounded and
// accepted: the verifier is a DISTINCT model, the ≥75 confirm bar is an un-lowerable Go constant, the
// batch is human-triggered under PermReview and stamped with the triggering principal, every verdict is
// sealed + audited, and only the typed {score, rationale} — never model prose — reaches a claim; the
// report path stays LLM-free. The verify prompt is skeptical and treats the claim/subject as untrusted
// data. It is a defense-in-depth verifier, not a sole authority.
package llmverifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Verifier is the narrow slice of analysis.Service the coordinator seals a verdict through. Keeping it
// narrow means the coordinator cannot propose or accept — only verify (seal a score for a distinct id).
type Verifier interface {
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
}

// Lister is the narrow read slice of the judgment store.
type Lister interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Coordinator runs the LLM verifier over an engagement's proposed judgments.
type Coordinator struct {
	llm      ports.LLM
	model    string
	verifier Verifier
	lister   Lister
}

// New builds a Coordinator. model is the distinct verifier model id; all deps are required.
func New(llm ports.LLM, model string, v Verifier, l Lister) *Coordinator {
	return &Coordinator{llm: llm, model: model, verifier: v, lister: l}
}

// Identity is the sealed verifier attribution ("llm:<model>"), distinct from any agent/human proposer.
func (c *Coordinator) Identity() string { return "llm:" + c.model }

// Result is the batch outcome (all counts over PROPOSED gated judgments in the engagement).
type Result struct {
	Attempted int `json:"attempted"` // judgments the verifier ran the model on
	Confirmed int `json:"confirmed"` // sealed verdict >= threshold → StateConfirmed
	Refuted   int `json:"refuted"`   // sealed verdict < threshold → StateRefuted
	Skipped   int `json:"skipped"`   // would self-confirm (proposer == this verifier)
	Errors    int `json:"errors"`    // model or verify failure (left proposed, gates normally)
}

// AutoVerify assesses every PROPOSED gated judgment in the engagement (except ones this verifier would
// self-confirm) and seals a verdict via analysis.Verify. Best-effort per judgment. triggeredBy is the
// human principal who initiated the batch; it is stamped into the sealed verdict rationale for
// accountability (the verdict is still attributed to the "llm:<model>" verifier that produced the score).
func (c *Coordinator) AutoVerify(ctx context.Context, engagementID shared.ID, triggeredBy string) (Result, error) {
	var res Result
	if c == nil || c.llm == nil || c.verifier == nil || c.lister == nil {
		return res, nil
	}
	js, err := c.lister.ListByEngagement(ctx, engagementID)
	if err != nil {
		return res, fmt.Errorf("list judgments: %w", err)
	}
	me := c.Identity()
	for _, j := range js {
		if ctx.Err() != nil {
			break
		}
		if j.State != judgment.StateProposed || !j.Capability.Gated() {
			continue
		}
		// Never confirm a claim this verifier proposed (the analysis gate enforces this too; skipping
		// here avoids a doomed Verify call and a misleading error count).
		if verdict.SelfConfirm(me, j.ProposedBy) {
			res.Skipped++
			continue
		}
		res.Attempted++
		score, rationale, ok := c.assess(ctx, j)
		if !ok {
			res.Errors++
			continue
		}
		if tb := strings.TrimSpace(triggeredBy); tb != "" {
			rationale = "[auto-verify triggered by " + tb + "] " + rationale
		}
		updated, verr := c.verifier.Verify(ctx, me, engagementID, j.ID, score, rationale, j.Version)
		if verr != nil {
			res.Errors++
			continue
		}
		switch updated.State {
		case judgment.StateConfirmed:
			res.Confirmed++
		default:
			res.Refuted++
		}
	}
	return res, nil
}
