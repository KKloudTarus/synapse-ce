package finding

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// HypothesisInput is the content for an attack-chain HYPOTHESIS finding: the AI's narrative that a
// SET of existing findings chain into an attack path. It is a PROPOSAL – non-publishable until a distinct
// human verifies it (evidence-gated like an exploitation finding). The constituent finding ids are the chain
// being hypothesized; building the hypothesis NEVER modifies or merges them – it only NAMES them.
type HypothesisInput struct {
	Title          string
	Description    string
	ConstituentIDs []string        // the finding ids this chain links (>= 2; a chain links multiple findings)
	Severity       shared.Severity // optional; defaults to Unknown (a human triages the chain's severity)
}

// NewHypothesis builds an AI-proposed attack-chain hypothesis finding (Kind=hypothesis). Unlike a threat
// projection (ungated – its evidence gate ran at the judgment layer), a hypothesis is the agent's UNPROVEN
// claim, so ProposedBy is SET → it RequiresEvidenceGate and starts at score 0 → it is non-publishable: it can
// reach the report only once a DISTINCT human raises its EvidenceScore to the bar (>= EvidenceThreshold) via
// the standard finding verify path (exploitation.Service.Confirm → ApplyVerdict, which gates on
// RequiresEvidenceGate so it serves a hypothesis too); the agent can never raise its own score (SoD). Still
// pending: a CREATE path – the agent propose tool that calls NewHypothesis – until which nothing
// produces a hypothesis to verify; that tool MUST redact the prose at the agent edge (like propose_finding).
// The constituent finding ids are recorded in the TEMPLATED description
// (Finding has no structured cross-reference field; folding them in keeps the chain self-contained and the
// report path templated) – the constructor never loads or mutates the constituent findings (no auto-merge).
// Dedup is by the sorted constituent set, so re-proposing the same chain updates in place.
func NewHypothesis(id, engagementID shared.ID, in HypothesisInput, proposer string, now time.Time) (Finding, error) {
	title := strings.TrimSpace(in.Title)
	desc := strings.TrimSpace(in.Description)
	proposer = strings.TrimSpace(proposer)
	if title == "" || desc == "" {
		return Finding{}, fmt.Errorf("%w: hypothesis finding needs a title and description", shared.ErrValidation)
	}
	if proposer == "" {
		return Finding{}, fmt.Errorf("%w: hypothesis finding needs a proposer (it is evidence-gated until a human verifies it)", shared.ErrValidation)
	}
	ids := dedupSortedNonEmpty(in.ConstituentIDs)
	if len(ids) < 2 {
		return Finding{}, fmt.Errorf("%w: an attack-chain hypothesis must link at least two findings", shared.ErrValidation)
	}
	sev := in.Severity
	if sev == "" {
		sev = shared.SeverityUnknown
	}
	if !sev.Valid() {
		return Finding{}, fmt.Errorf("%w: unknown severity %q", shared.ErrValidation, sev)
	}
	return Finding{
		ID:            id,
		EngagementID:  engagementID,
		Title:         title,
		Description:   desc + "\n\nChained findings: " + strings.Join(ids, ", ") + ".",
		Severity:      sev,
		Status:        StatusOpen,
		Kind:          KindHypothesis,
		Class:         ClassFirstParty, // an attack chain over the engagement's OWN findings
		Scope:         "unknown",
		Reachability:  "unknown",
		Priority:      priorityForSeverity(sev),
		DedupKey:      "hypothesis:" + strings.Join(ids, ","),
		ProposedBy:    proposer, // SET → evidence-gated → non-publishable until a distinct human verifies it
		EvidenceScore: 0,
		Version:       1,
		Audit:         shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// dedupSortedNonEmpty trims, drops empties, de-duplicates, and sorts ids for a deterministic chain identity.
func dedupSortedNonEmpty(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
