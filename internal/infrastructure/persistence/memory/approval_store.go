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
		if tenantID, scoped := shared.TenantFrom(ctx); scoped && s.tenants[a.ID] != tenantID {
			return fmt.Errorf("approval %s: %w", a.ID, shared.ErrNotFound)
		}
		return nil // already enqueued under this tenant (idempotent resume)
	}
	s.checkpoint(ctx)
	s.actions[a.ID] = a
	s.decisions[a.ID] = agent.ApprovalDecision{ActionID: a.ID, State: agent.ApprovalPending}
	if tenantID, ok := shared.TenantFrom(ctx); ok {
		s.tenants[a.ID] = tenantID
	}
	return nil
}

func (s *ApprovalStore) Pending(ctx context.Context, engagementID shared.ID) ([]agent.ProposedAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []agent.ProposedAction
	tenantID, scoped := shared.TenantFrom(ctx)
	for id, a := range s.actions {
		if (!scoped || s.tenants[id] == tenantID) && a.EngagementID == engagementID && s.decisions[id].State == agent.ApprovalPending {
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

func (s *ApprovalStore) Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.actions[actionID]
	if tenantID, scoped := shared.TenantFrom(ctx); scoped && (!ok || s.tenants[actionID] != tenantID) {
		ok = false
	}
	if !ok {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
	}
	return a, s.decisions[actionID], nil
}

func (s *ApprovalStore) Decide(ctx context.Context, d agent.ApprovalDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.decisions[d.ActionID]
	if tenantID, scoped := shared.TenantFrom(ctx); scoped && (!ok || s.tenants[d.ActionID] != tenantID) {
		ok = false
	}
	if !ok {
		return fmt.Errorf("approval %s: %w", d.ActionID, shared.ErrNotFound)
	}
	if cur.State != agent.ApprovalPending {
		return fmt.Errorf("approval %s already decided (%s): %w", d.ActionID, cur.State, shared.ErrConflict)
	}
	s.checkpoint(ctx)
	s.decisions[d.ActionID] = d
	return nil
}

func (s *ApprovalStore) Consume(ctx context.Context, actionID shared.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.decisions[actionID]
	if tenantID, scoped := shared.TenantFrom(ctx); scoped && (!ok || s.tenants[actionID] != tenantID) {
		ok = false
	}
	if !ok {
		return fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
	}
	if cur.State != agent.ApprovalApproved {
		return fmt.Errorf("approval %s cannot be consumed from state %s: %w", actionID, cur.State, shared.ErrConflict)
	}
	s.checkpoint(ctx)
	cur.State = agent.ApprovalConsumed
	s.decisions[actionID] = cur
	return nil
}

func (s *ApprovalStore) checkpoint(ctx context.Context) {
	registerTenantCheckpoint(ctx, s, func(tenantID shared.ID) func() {
		actions := make(map[shared.ID]agent.ProposedAction)
		decisions := make(map[shared.ID]agent.ApprovalDecision)
		for id, action := range s.actions {
			if s.tenants[id] != tenantID {
				continue
			}
			action.Argv = append([]string(nil), action.Argv...)
			action.EgressPreview = append([]string(nil), action.EgressPreview...)
			actions[id] = action
			decisions[id] = s.decisions[id]
		}
		return func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for id, recordTenant := range s.tenants {
				if recordTenant == tenantID {
					delete(s.actions, id)
					delete(s.decisions, id)
					delete(s.tenants, id)
				}
			}
			for id, action := range actions {
				s.actions[id] = action
				s.decisions[id] = decisions[id]
				s.tenants[id] = tenantID
			}
		}
	})
}
