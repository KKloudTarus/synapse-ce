package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FleetAgentStore is an in-memory ports.FleetAgentStore for dev and tests.
type FleetAgentStore struct {
	mu     sync.Mutex
	agents map[string]*fleetagent.Agent      // key: tenant|id
	tokens map[string]*fleetagent.EnrolToken // key: tenant|hash
}

// NewFleetAgentStore returns an empty in-memory fleet agent store.
func NewFleetAgentStore() *FleetAgentStore {
	return &FleetAgentStore{agents: map[string]*fleetagent.Agent{}, tokens: map[string]*fleetagent.EnrolToken{}}
}

var _ ports.FleetAgentStore = (*FleetAgentStore)(nil)

func agentKey(tenant, id shared.ID) string { return tenant.String() + "|" + id.String() }
func tokKey(tenant shared.ID, hash string) string {
	return tenant.String() + "|" + hash
}

func (s *FleetAgentStore) CreateEnrolToken(_ context.Context, t *fleetagent.EnrolToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.tokens[tokKey(t.TenantID, t.Hash)] = &cp
	return nil
}

func (s *FleetAgentStore) ConsumeEnrolToken(_ context.Context, tenantID shared.ID, hash string, now time.Time) (*fleetagent.EnrolToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokKey(tenantID, hash)]
	if !ok || !t.Usable(now) {
		return nil, shared.ErrNotFound
	}
	t.UsedAt = now
	cp := *t
	return &cp, nil
}

func (s *FleetAgentStore) CreateAgent(_ context.Context, a *fleetagent.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	cp.Capabilities = append([]string(nil), a.Capabilities...)
	s.agents[agentKey(a.TenantID, a.ID)] = &cp
	return nil
}

func (s *FleetAgentStore) GetAgent(_ context.Context, tenantID, id shared.ID) (*fleetagent.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentKey(tenantID, id)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *a
	cp.Capabilities = append([]string(nil), a.Capabilities...)
	return &cp, nil
}

func (s *FleetAgentStore) Heartbeat(_ context.Context, tenantID, id shared.ID, platform, osVersion, agentVersion string, capabilities []string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentKey(tenantID, id)]
	if !ok {
		return shared.ErrNotFound
	}
	if platform != "" {
		a.Platform = platform
	}
	if osVersion != "" {
		a.OSVersion = osVersion
	}
	if agentVersion != "" {
		a.AgentVersion = agentVersion
	}
	if capabilities != nil {
		a.Capabilities = append([]string(nil), capabilities...)
	}
	a.LastSeenAt = now
	a.Audit.UpdatedAt = now
	return nil
}

func (s *FleetAgentStore) Revoke(_ context.Context, tenantID, id shared.ID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentKey(tenantID, id)]
	if !ok {
		return shared.ErrNotFound
	}
	a.State = fleetagent.StateRevoked
	a.Audit.UpdatedAt = now
	return nil
}

func (s *FleetAgentStore) ListAgents(_ context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*fleetagent.Agent
	for _, a := range s.agents {
		if a.TenantID != tenantID {
			continue
		}
		cp := *a
		cp.Capabilities = append([]string(nil), a.Capabilities...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
