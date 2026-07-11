// Package writeupdraftuc is the use case for AI-proposed, human-gated finding write-up drafts
// ("human-gated authoritative drafts"). It orchestrates the writeupdraft.Draft lifecycle over a store and
// writes an append-only audit entry for every state change.
//
// Tenant isolation is enforced UPSTREAM at the HTTP route (withEngTenant), so these methods take an
// already-tenant-proven engagement id. The agent reaches ONLY Propose (via a narrow proposer interface it
// declares); Edit/Accept/Reject are human actions gated by RBAC (PermReview) + separation of duties at the
// route – and the domain enforces SoD again (a proposer cannot sign off its own draft) as defense-in-depth.
// A draft never renders into a report by itself.
package writeupdraftuc

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service drives the write-up-draft lifecycle.
type Service struct {
	store   ports.WriteupDraftStore
	audit   ports.AuditLogger
	clock   ports.Clock
	ids     ports.IDGenerator
	applier ports.FindingWriteupApplier // optional: on Accept, apply the draft's prose to its finding
}

// SetFindingWriteupApplier wires the on-accept hook that applies an accepted draft's prose to its finding
// . Optional – without it, Accept just marks the draft accepted (no apply). The composition root
// supplies *findings.Service through the narrow ports.FindingWriteupApplier (writeupdraftuc never imports
// the findings use case).
func (s *Service) SetFindingWriteupApplier(a ports.FindingWriteupApplier) { s.applier = a }

// NewService validates its dependencies and returns the service.
func NewService(store ports.WriteupDraftStore, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: writeupdraft service needs store + audit + clock + ids", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock, ids: ids}, nil
}

// Propose records a new AI-proposed draft (StateProposed). proposer is the agent identity. The draft is
// inert until a human signs off; this only persists the proposal and audits it.
func (s *Service) Propose(ctx context.Context, proposer string, engagementID, findingID shared.ID, description, remediation string) (writeupdraft.Draft, error) {
	now := s.clock.Now()
	d, err := writeupdraft.Propose(s.ids.NewID(), engagementID, findingID, description, remediation, proposer, now)
	if err != nil {
		return writeupdraft.Draft{}, err
	}
	if err := s.store.Save(ctx, d); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("save writeup draft: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    proposer,
		Action:   "writeup_draft.proposed",
		Target:   d.ID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "finding": findingID.String()},
		At:       now,
	}); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("audit writeup-draft proposal: %w", err)
	}
	return d, nil
}

// Edit replaces a still-proposed draft's text (a human revising the AI draft before sign-off).
func (s *Service) Edit(ctx context.Context, principal string, engagementID, id shared.ID, description, remediation string) (writeupdraft.Draft, error) {
	d, err := s.store.Get(ctx, engagementID, id)
	if err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("load writeup draft: %w", err)
	}
	edited, err := d.Edit(description, remediation, s.clock.Now())
	if err != nil {
		return writeupdraft.Draft{}, err
	}
	if err := s.store.Save(ctx, edited); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("save writeup draft: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    principal,
		Action:   "writeup_draft.edited",
		Target:   id.String(),
		Metadata: map[string]string{"engagement": engagementID.String()},
		At:       edited.UpdatedAt,
	}); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("audit writeup-draft edit: %w", err)
	}
	return edited, nil
}

// Accept is the human sign-off on a proposed draft. The domain rejects a proposer signing off its own
// draft (separation of duties).
func (s *Service) Accept(ctx context.Context, principal string, engagementID, id shared.ID) (writeupdraft.Draft, error) {
	return s.decide(ctx, principal, engagementID, id, accept)
}

// Reject discards a proposed draft.
func (s *Service) Reject(ctx context.Context, principal string, engagementID, id shared.ID) (writeupdraft.Draft, error) {
	return s.decide(ctx, principal, engagementID, id, reject)
}

// ListByEngagement returns the engagement's drafts (tenant already proven upstream).
func (s *Service) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error) {
	return s.store.ListByEngagement(ctx, engagementID)
}

type decision int

const (
	accept decision = iota
	reject
)

// decide loads the draft, applies the terminal transition, persists it, and audits the action (the audit
// action name is derived from the resulting state, e.g. "writeup_draft.accepted").
func (s *Service) decide(ctx context.Context, principal string, engagementID, id shared.ID, what decision) (writeupdraft.Draft, error) {
	d, err := s.store.Get(ctx, engagementID, id)
	if err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("load writeup draft: %w", err)
	}
	// The audit action is set explicitly per decision so the audit vocabulary stays independent of the
	// domain State string values; the clock is read at the point of mutation (as in Edit).
	var (
		decided writeupdraft.Draft
		action  string
	)
	switch what {
	case accept:
		decided, err = d.Accept(principal, s.clock.Now())
		action = "writeup_draft.accepted"
	case reject:
		decided, err = d.Reject(principal, s.clock.Now())
		action = "writeup_draft.rejected"
	default:
		return writeupdraft.Draft{}, fmt.Errorf("%w: unknown draft decision", shared.ErrValidation)
	}
	if err != nil {
		return writeupdraft.Draft{}, err
	}
	// on accept, apply the draft's prose to its finding BEFORE persisting the acceptance, so an
	// accepted draft is never left un-applied. The applier validates finding ∈ engagement before mutating
	// (a cross-engagement / unknown finding id aborts the accept with nothing changed). Hard-fail: the apply
	// IS the purpose of accepting, so a failed apply fails the accept (the draft stays Proposed).
	if what == accept && s.applier != nil {
		if err := s.applier.ApplyWriteupDraft(ctx, principal, decided.EngagementID, decided.FindingID, decided.Description, decided.Remediation); err != nil {
			return writeupdraft.Draft{}, fmt.Errorf("apply writeup draft to finding: %w", err)
		}
	}
	if err := s.store.Save(ctx, decided); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("save writeup draft: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    principal,
		Action:   action,
		Target:   id.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "proposed_by": decided.ProposedBy},
		At:       decided.UpdatedAt,
	}); err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("audit writeup-draft decision: %w", err)
	}
	return decided, nil
}
