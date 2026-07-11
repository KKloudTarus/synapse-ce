// Package writeupdraft holds AI-proposed, human-gated finding write-up DRAFTS
// ("human-gated authoritative drafts").
//
// A Draft is the ONE place LLM-authored PROSE enters the system as a proposal. The AI drafts a finding's
// description + remediation, but a draft is inert until a human signs off. It is kept DELIBERATELY SEPARATE
// from the judgment claim union (internal/domain/judgment), whose claims are structured tokens and carry
// a "never free prose" invariant – a write-up is inherently prose, so it cannot live there without breaking that
// invariant. The safety here is therefore PROCEDURAL, not structural:
//
// A draft NEVER auto-flows into the templated report. Only a human-Accepted draft is
// eligible to be applied to its finding (a separate use case), and the report renders only the
// authoritative finding/writeup data – never a Draft.
// The agent may only Propose a draft. Accept/Reject is the human sign-off; the proposer cannot sign off
// its own draft (separation of duties, enforced here as defense-in-depth and again by RBAC/SoD at the
// usecase + HTTP layers, mirroring the judgment review gate).
// Both text fields are length-bounded so a proposal cannot dump unbounded model output.
package writeupdraft

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Text-length bounds: generous for real finding prose, but bounded so an LLM cannot dump unbounded text
// into a draft. Every mutation (Propose / Edit) funnels through validateContent.
const (
	maxDescriptionLen = 8192
	maxRemediationLen = 8192
)

// State is the closed draft lifecycle (fail-closed: an unknown state is invalid).
type State string

const (
	StateProposed State = "proposed" // AI-proposed, awaiting human sign-off
	StateAccepted State = "accepted" // a human signed off – eligible to be applied to the finding
	StateRejected State = "rejected" // a human discarded the draft
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateProposed, StateAccepted, StateRejected:
		return true
	}
	return false
}

// Draft is an AI-proposed finding write-up (description + remediation) awaiting explicit human sign-off.
type Draft struct {
	ID           shared.ID
	EngagementID shared.ID
	FindingID    shared.ID // the finding this draft proposes text for (the subject)
	Description  string
	Remediation  string
	State        State
	ProposedBy   string // the proposer identity (an agent id) – never the acceptor
	DecidedBy    string // the human who accepted/rejected; "" while Proposed
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Propose creates a new draft in StateProposed. It requires a subject finding, a proposer, and at least
// one non-empty text field, and it bounds both text fields. The agent proposes; it cannot accept.
func Propose(id, engagementID, findingID shared.ID, description, remediation, proposedBy string, now time.Time) (Draft, error) {
	d := Draft{
		ID:           id,
		EngagementID: engagementID,
		FindingID:    findingID,
		Description:  strings.TrimSpace(description),
		Remediation:  strings.TrimSpace(remediation),
		State:        StateProposed,
		ProposedBy:   strings.TrimSpace(proposedBy),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if d.ID == "" || d.EngagementID == "" || d.FindingID == "" {
		return Draft{}, fmt.Errorf("%w: writeup draft needs id, engagement, and finding", shared.ErrValidation)
	}
	if d.ProposedBy == "" {
		return Draft{}, fmt.Errorf("%w: writeup draft needs a proposer", shared.ErrValidation)
	}
	if err := d.validateContent(); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// validateContent enforces the text bounds and that the draft carries at least one non-empty field.
func (d Draft) validateContent() error {
	if d.Description == "" && d.Remediation == "" {
		return fmt.Errorf("%w: writeup draft must propose a description or remediation", shared.ErrValidation)
	}
	if len(d.Description) > maxDescriptionLen {
		return fmt.Errorf("%w: writeup draft description exceeds %d bytes", shared.ErrValidation, maxDescriptionLen)
	}
	if len(d.Remediation) > maxRemediationLen {
		return fmt.Errorf("%w: writeup draft remediation exceeds %d bytes", shared.ErrValidation, maxRemediationLen)
	}
	return nil
}

// Edit replaces a still-Proposed draft's text (a human revising the AI draft before sign-off). It fails on
// a decided (Accepted/Rejected) draft. Editing does not change attribution – ProposedBy is preserved.
func (d Draft) Edit(description, remediation string, now time.Time) (Draft, error) {
	if d.State != StateProposed {
		return Draft{}, fmt.Errorf("%w: only a proposed draft can be edited (state=%s)", shared.ErrValidation, d.State)
	}
	d.Description = strings.TrimSpace(description)
	d.Remediation = strings.TrimSpace(remediation)
	if err := d.validateContent(); err != nil {
		return Draft{}, err
	}
	d.UpdatedAt = now
	return d, nil
}

// Accept is the human sign-off: a Proposed draft becomes Accepted, attributed to the accepting human. An
// accepted draft is only ELIGIBLE to be applied to its finding (a separate use case) – acceptance itself
// renders nothing.
func (d Draft) Accept(acceptedBy string, now time.Time) (Draft, error) {
	return d.decide(StateAccepted, acceptedBy, now)
}

// Reject discards a Proposed draft, attributed to the rejecting human. A rejected draft is terminal – it
// is never applied to a finding and never rendered.
func (d Draft) Reject(rejectedBy string, now time.Time) (Draft, error) {
	return d.decide(StateRejected, rejectedBy, now)
}

// decide transitions a Proposed draft to a terminal state, enforcing attribution and separation of duties
// (the proposer cannot sign off its own draft).
func (d Draft) decide(target State, by string, now time.Time) (Draft, error) {
	if d.State != StateProposed {
		return Draft{}, fmt.Errorf("%w: only a proposed draft can become %s (state=%s)", shared.ErrValidation, target, d.State)
	}
	by = strings.TrimSpace(by)
	if by == "" {
		return Draft{}, fmt.Errorf("%w: a draft decision must be attributed to a human", shared.ErrValidation)
	}
	if by == d.ProposedBy {
		return Draft{}, fmt.Errorf("%w: the proposer cannot sign off its own draft (separation of duties)", shared.ErrValidation)
	}
	d.State = target
	d.DecidedBy = by
	d.UpdatedAt = now
	return d, nil
}
