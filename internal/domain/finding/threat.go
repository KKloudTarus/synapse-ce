package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ThreatInput is the content for a finding promoted from a human-ratified STRIDE threat judgment.
// It is filled DETERMINISTICALLY from the confirmed judgment (no LLM): the STRIDE category +
// the threatened model element + the optional asset at risk, anchored to the source judgment id for dedup.
type ThreatInput struct {
	JudgmentID string          // the confirmed threat judgment (dedup anchor – re-confirming updates in place)
	Category   string          // STRIDE category token (e.g. "spoofing", "info_disclosure")
	Element    string          // the threatened model element id (a component or data flow)
	Asset      string          // optional Asset.ID at risk ("" when none)
	Severity   shared.Severity // optional; defaults to Unknown (re-triaged via the normal finding workflow)
}

// NewThreat builds a first-party threat-model finding (Kind=threat) from a confirmed STRIDE threat. The
// title is TEMPLATED from the structured category + element (never LLM prose). It is idempotent by the
// threat:<judgmentID> dedup key – a re-confirm updates in place rather than duplicating. Severity defaults to
// Unknown so a human triages it through the standard finding workflow (a STRIDE threat carries no CVSS).
func NewThreat(id, engagementID shared.ID, in ThreatInput, now time.Time) (Finding, error) {
	cat := strings.TrimSpace(in.Category)
	elem := strings.TrimSpace(in.Element)
	anchor := strings.TrimSpace(in.JudgmentID)
	if cat == "" || elem == "" {
		return Finding{}, fmt.Errorf("%w: threat finding needs a STRIDE category + model element", shared.ErrValidation)
	}
	if anchor == "" {
		return Finding{}, fmt.Errorf("%w: threat finding needs a source judgment id (dedup anchor)", shared.ErrValidation)
	}
	sev := in.Severity
	if sev == "" {
		sev = shared.SeverityUnknown
	}
	if !sev.Valid() {
		return Finding{}, fmt.Errorf("%w: unknown severity %q", shared.ErrValidation, sev)
	}
	desc := "Threat-model finding promoted from a human-ratified STRIDE judgment."
	if asset := strings.TrimSpace(in.Asset); asset != "" {
		desc += " Asset at risk: " + asset + "."
	}
	return Finding{
		ID:           id,
		EngagementID: engagementID,
		Title:        "STRIDE " + cat + " threat on " + elem,
		Description:  desc,
		Severity:     sev,
		Status:       StatusOpen,
		Kind:         KindThreat,
		Class:        ClassFirstParty, // a threat to the system's OWN architecture
		Scope:        "unknown",
		Reachability: "unknown",
		Priority:     priorityForSeverity(sev),
		DedupKey:     "threat:" + anchor,
		// ProposedBy is deliberately LEFT EMPTY: the evidence gate already ran at the judgment layer
		// (gated propose→verify, score ≥ threshold, PermReview/SoD), so this projection is ungated like a
		// manual finding. Do NOT set it to the agent proposer – that would re-gate it stuck-at-score-0.
		Version: 1,
		Audit:   shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}
