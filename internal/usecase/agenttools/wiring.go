package agenttools

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AgentToolset bundles the dependencies that switch on the agent's engagement-scoped tools beyond the
// always-available read tools. Both composition roots — the inline agent in synapse-api and the durable
// agent in synapse-worker — enable their orchestrator catalog through THIS one struct, so a given agent
// run advertises an IDENTICAL tool set no matter WHERE it executes. Before this, the worker enabled only
// planning + finding proposals while the API enabled the full set, so the same session saw a smaller
// toolset when driven durably — a correctness bug (issue #161).
//
// Findings, Hypotheses and Reachability are REQUIRED: a durable run must never silently advertise fewer
// PROPOSAL tools than the inline run. Judgments and WriteupDrafts are OPTIONAL and mirror their feature
// flags — a nil field leaves that tool off in BOTH binaries (they are gated by SYNAPSE_JUDGMENTS_ENABLED /
// SYNAPSE_WRITEUP_DRAFTS_ENABLED). To keep a tool off, the composition root leaves the field nil; it must
// NOT assign a typed-nil service pointer (a non-nil interface wrapping a nil pointer), because that would
// wire a tool backed by nothing. Each field is a propose/read-only slice — the agent can never confirm.
type AgentToolset struct {
	Findings      findingProposer      // required: propose_finding
	Hypotheses    hypothesisProposer   // required: propose_attack_chain
	Reachability  scanResultReader     // required: reachability_context (read-only)
	Judgments     judgmentProposer     // optional (nil ⇒ off): propose_reachability/sast_validation/critique/risk_narrative/threat/vex_justification
	WriteupDrafts writeupdraftProposer // optional (nil ⇒ off): propose_writeup_draft
}

// EnableAgentToolset turns on planning + the proposal/read tools from a single dependency set, so the
// inline (API) and durable (worker) catalogs are wired identically — the durable/inline parity guarantee
// (issue #161). It FAILS CLOSED: a missing REQUIRED dependency returns an error rather than advertising a
// partial toolset (a durable agent with fewer tools than the inline one is a correctness bug, not a valid
// degraded mode). Planning is always on — both composition roots pair it with an orchestrator PlanStore.
//
// It calls the same narrow Enable* setters a composition root would, so the propose-only, never-confirm
// invariant is unchanged: the agent still only proposes (score 0); a distinct human/verifier confirms out
// of band. Optional deps are wired only when non-nil, matching each feature flag.
func (c *Catalog) EnableAgentToolset(t AgentToolset) error {
	if t.Findings == nil || t.Hypotheses == nil || t.Reachability == nil {
		return fmt.Errorf("%w: agent toolset requires findings, hypotheses and reachability dependencies (refusing to advertise a partial toolset)", shared.ErrValidation)
	}
	c.EnablePlanning()
	c.EnableFindingProposals(t.Findings)
	c.EnableHypotheses(t.Hypotheses)
	c.EnableReachability(t.Reachability)
	if t.Judgments != nil {
		c.EnableJudgments(t.Judgments)
	}
	if t.WriteupDrafts != nil {
		c.EnableWriteupDrafts(t.WriteupDrafts)
	}
	return nil
}
