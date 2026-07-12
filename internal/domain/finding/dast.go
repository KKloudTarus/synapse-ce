package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DASTInput is the content for a finding promoted from a RUNTIME-verifier-confirmed judgment: a safe HTTP
// probe (governed by scope + sandbox egress + HITL approval upstream) confirmed the exploitability of an
// existing gated CapSAST hypothesis. It is filled DETERMINISTICALLY from the confirmed judgment (no LLM):
// the CWE, the location, and the taint rule, anchored to the source judgment id for dedup. It is the
// runtime twin of SASTInput — the SAME structured claim, but confirmed at runtime rather than by a static
// verifier, so it earns a distinct Kind (stronger, dynamically-proven evidence).
type DASTInput struct {
	JudgmentID string          // the confirmed CapSAST judgment (dedup anchor – re-confirming updates in place)
	CWE        string          // the weakness, e.g. "CWE-89"
	Location   string          // where: "path[:line]" or the importPath.Symbol of the sink-using function
	Rule       string          // the taint rule that fired, e.g. "taint-sqli"
	Severity   shared.Severity // optional; defaults to Unknown (re-triaged via the normal finding workflow)
}

// NewDAST builds a runtime-confirmed DAST finding (Kind=dast) from a judgment a DISTINCT runtime verifier
// confirmed via a safe probe. The title + description are TEMPLATED from the structured CWE/rule/location
// (never LLM prose). It is idempotent by the dast:ai:<judgmentID> dedup key — a re-confirm updates in place
// rather than duplicating; the key is distinct from the SAST projection's "sast:ai:<id>" so a claim confirmed
// statically (Kind=sast) and one confirmed at runtime (Kind=dast) never collide, and the runtime finding is
// its own row. Reachability is "reachable": unlike a static SAST hit, a runtime probe DEMONSTRATED the sink
// is reachable and exploitable. Severity defaults to Unknown so a human triages it through the standard
// workflow (a probe carries no CVSS). ProposedBy is deliberately LEFT EMPTY: the evidence gate already ran
// at the judgment layer (a distinct verifier sealed a verdict ≥ threshold), so this projection is publishable
// like a manual finding — setting it to the agent proposer would wrongly re-gate it stuck-at-score-0.
func NewDAST(id, engagementID shared.ID, in DASTInput, now time.Time) (Finding, error) {
	cwe := strings.TrimSpace(in.CWE)
	loc := strings.TrimSpace(in.Location)
	rule := strings.TrimSpace(in.Rule)
	anchor := strings.TrimSpace(in.JudgmentID)
	if cwe == "" || loc == "" || rule == "" {
		return Finding{}, fmt.Errorf("%w: dast finding needs a CWE, location, and rule", shared.ErrValidation)
	}
	if anchor == "" {
		return Finding{}, fmt.Errorf("%w: dast finding needs a source judgment id (dedup anchor)", shared.ErrValidation)
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
		Title:        "Runtime-confirmed: " + rule + " (" + cwe + ") at " + loc,
		Description:  "A safe runtime probe (scope- and egress-governed, HITL-approved) confirmed a " + cwe + " is exploitable at runtime. Promoted from a runtime-verifier-confirmed judgment (rule " + rule + ").",
		Severity:     sev,
		CWE:          cwe,
		Sources:      []string{"synapse-dast"},
		Class:        ClassFirstParty, // a runtime issue in the project's OWN application
		Scope:        "unknown",
		Reachability: "reachable", // a runtime probe DEMONSTRATED reachability/exploitability (stronger than a static hit)
		Priority:     priorityForSeverity(sev),
		Status:       StatusOpen,
		Kind:         KindDAST,
		DedupKey:     "dast:ai:" + anchor,
		// ProposedBy LEFT EMPTY (the judgment-layer gate already ran) – see the doc above.
		Version: 1,
		Audit:   shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}
