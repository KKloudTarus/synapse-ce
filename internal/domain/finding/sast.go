package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SASTInput is the content for a finding promoted from a verifier-confirmed CapSAST (taint) judgment
// . It is filled DETERMINISTICALLY from the confirmed judgment (no LLM): the CWE, the
// location (the sink-using function's importPath.Symbol – function-granular in the E39 MVP), and the taint
// rule, anchored to the source judgment id for dedup.
type SASTInput struct {
	JudgmentID string          // the confirmed CapSAST judgment (dedup anchor – re-confirming updates in place)
	CWE        string          // the weakness, e.g. "CWE-89"
	Location   string          // where: "path[:line]" or the importPath.Symbol of the sink-using function
	Rule       string          // the taint rule that fired, e.g. "taint-sqli"
	Severity   shared.Severity // optional; defaults to Unknown (re-triaged via the normal finding workflow)
}

// NewSAST builds a first-party SAST finding (Kind=sast) from a verifier-confirmed taint judgment. The title
// + description are TEMPLATED from the structured CWE/rule/location (never LLM prose). It is idempotent by
// the sast:ai:<judgmentID> dedup key – a re-confirm updates in place rather than duplicating (distinct from
// the pattern-SAST "sast:rule:file:line" key, so deterministic E38 hits and gated E39 hits never collide).
// Severity defaults to Unknown so a human triages it through the standard workflow (a taint hit carries no
// CVSS). ProposedBy is deliberately LEFT EMPTY: the evidence gate already ran at the judgment layer (gated
// propose→verify, score ≥ threshold, a DISTINCT verifier), so this projection is publishable like a manual
// finding – setting it to the agent proposer would wrongly re-gate it stuck-at-score-0.
func NewSAST(id, engagementID shared.ID, in SASTInput, now time.Time) (Finding, error) {
	cwe := strings.TrimSpace(in.CWE)
	loc := strings.TrimSpace(in.Location)
	rule := strings.TrimSpace(in.Rule)
	anchor := strings.TrimSpace(in.JudgmentID)
	if cwe == "" || loc == "" || rule == "" {
		return Finding{}, fmt.Errorf("%w: sast finding needs a CWE, location, and rule", shared.ErrValidation)
	}
	if anchor == "" {
		return Finding{}, fmt.Errorf("%w: sast finding needs a source judgment id (dedup anchor)", shared.ErrValidation)
	}
	sev := in.Severity
	if sev == "" {
		sev = shared.SeverityUnknown
	}
	if !sev.Valid() {
		return Finding{}, fmt.Errorf("%w: unknown severity %q", shared.ErrValidation, sev)
	}
	return Finding{
		ID:           id,
		EngagementID: engagementID,
		Title:        "Taint: " + rule + " (" + cwe + ") at " + loc,
		Description:  "Tainted (attacker-controllable) data reaches a " + cwe + " sink. Promoted from a verifier-confirmed taint judgment (rule " + rule + ").",
		Severity:     sev,
		CWE:          cwe,
		Sources:      []string{"synapse-taint"},
		Class:        ClassFirstParty, // a first-party source-code issue
		Scope:        "unknown",
		Reachability: "unknown",
		Priority:     priorityForSeverity(sev),
		Status:       StatusOpen,
		Kind:         KindSAST,
		DedupKey:     "sast:ai:" + anchor,
		// ProposedBy LEFT EMPTY (the judgment-layer gate already ran) – see the doc above.
		Version: 1,
		Audit:   shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}
