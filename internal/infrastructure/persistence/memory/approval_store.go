package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ApprovalStore is the in-memory ports.ApprovalStore (dev/tests). Decide is
// idempotent: the first terminal decision wins; a second returns ErrConflict (so a
// double-click / race cannot re-open an admitted action).
type ApprovalStore struct {
	mu        sync.Mutex
	actions   map[shared.ID]agent.ProposedAction
	decisions map[shared.ID]agent.ApprovalDecision
	// tenants records the tenant an action was enqueued under, so EngagementsWithPending can
	// hand the sweeper the same tenant-bound scopes the Postgres twin does.
	tenants map[shared.ID]shared.ID
}

// NewApprovalStore returns an empty in-memory approval store.
func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{
		actions:   map[shared.ID]agent.ProposedAction{},
		decisions: map[shared.ID]agent.ApprovalDecision{},
		tenants:   map[shared.ID]shared.ID{},
	}
}

var _ ports.ApprovalStore = (*ApprovalStore)(nil)

func (s *ApprovalStore) Enqueue(ctx context.Context, a agent.ProposedAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.actions[a.ID]; exists {
		return nil // already enqueued (idempotent re-enqueue on resume)
	}
	s.actions[a.ID] = a
	s.decisions[a.ID] = agent.ApprovalDecision{ActionID: a.ID, State: agent.ApprovalPending}
	if tenantID, ok := shared.TenantFrom(ctx); ok {
		s.tenants[a.ID] = tenantID
	}
	return nil
}

func (s *ApprovalStore) Pending(_ context.Context, engagementID shared.ID) ([]agent.ProposedAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []agent.ProposedAction
	for id, a := range s.actions {
		if a.EngagementID == engagementID && s.decisions[id].State == agent.ApprovalPending {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProposedAt.Before(out[j].ProposedAt) })
	return out, nil
}

func (s *ApprovalStore) EngagementsWithPending(_ context.Context) ([]ports.ApprovalSweepScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[ports.ApprovalSweepScope]bool{}
	var out []ports.ApprovalSweepScope
	for id, a := range s.actions {
		if s.decisions[id].State != agent.ApprovalPending {
			continue
		}
		scope := ports.ApprovalSweepScope{TenantID: s.tenants[id], EngagementID: a.EngagementID}
		if seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].EngagementID < out[j].EngagementID
	})
	return out, nil
}

func (s *ApprovalStore) Get(_ context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.actions[actionID]
	if !ok {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
	}
	return a, s.decisions[actionID], nil
}

func (s *ApprovalStore) Decide(_ context.Context, d agent.ApprovalDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.decisions[d.ActionID]
	if !ok {
		return fmt.Errorf("approval %s: %w", d.ActionID, shared.ErrNotFound)
	}
	if cur.State != agent.ApprovalPending {
		return fmt.Errorf("approval %s already decided (%s): %w", d.ActionID, cur.State, shared.ErrConflict)
	}
	s.decisions[d.ActionID] = d
	return nil
}

func (s *ApprovalStore) Consume(_ context.Context, actionID shared.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.decisions[actionID]
	if !ok {
		return fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
	}
	if cur.State != agent.ApprovalApproved {
		return fmt.Errorf("approval %s cannot be consumed from state %s: %w", actionID, cur.State, shared.ErrConflict)
	}
	cur.State = agent.ApprovalConsumed
	s.decisions[actionID] = cur
	return nil
}
