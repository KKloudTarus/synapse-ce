package response

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ApprovalState reads the current decision for a tenant-scoped durable response.
// A reversal requester is provenance, not proof that its decision is still pending.
// Missing or mismatched historical approval bindings expose no actionable state.
func (s *Service) ApprovalState(ctx context.Context, rec Record) (agent.ApprovalState, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || rec.TenantID != tenant {
		return "", fmt.Errorf("%w: response approval state requires the record's tenant", shared.ErrForbidden)
	}
	if rec.State != StatePending && !(rec.State == StateApplied && rec.ReversalRequestedBy != "") {
		return "", nil
	}
	if s.approvals == nil {
		return "", nil
	}
	reversal := rec.ReversalRequestedBy != ""
	id := rec.ID
	if reversal {
		id = shared.ID("revert:" + id.String())
	}
	proposal, decision, err := s.approvals.Get(ctx, id)
	if errors.Is(err, shared.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read response approval state: %w", err)
	}
	if !responseApprovalMatchesRecord(proposal, rec, reversal) || decision.ActionID != id {
		return "", nil
	}
	return decision.State, nil
}
