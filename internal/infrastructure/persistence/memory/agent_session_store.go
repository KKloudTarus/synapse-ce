package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentSessionStore is the in-memory ports.AgentSessionStore (dev/tests). It keeps
// the same (session, seq) transcript fork-guard as the Postgres adapter so a duplicate seq
// is rejected, not silently overwritten.
type AgentSessionStore struct {
	mu       sync.Mutex
	sessions map[shared.ID]agent.Session
	msgs     map[shared.ID]map[int]agent.Message
}

// NewAgentSessionStore returns an empty in-memory agent session store.
func NewAgentSessionStore() *AgentSessionStore {
	return &AgentSessionStore{sessions: map[shared.ID]agent.Session{}, msgs: map[shared.ID]map[int]agent.Message{}}
}

var _ ports.AgentSessionStore = (*AgentSessionStore)(nil)

func (s *AgentSessionStore) SaveSession(_ context.Context, sess agent.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess // upsert (status/steps/tokens advance)
	return nil
}

func (s *AgentSessionStore) GetSession(_ context.Context, id shared.ID) (agent.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return agent.Session{}, fmt.Errorf("agent session %s: %w", id, shared.ErrNotFound)
	}
	return sess, nil
}

func (s *AgentSessionStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]agent.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []agent.Session
	for _, sess := range s.sessions {
		if sess.EngagementID == engagementID {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *AgentSessionStore) TenantIDs(_ context.Context) ([]shared.ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[shared.ID]struct{}{}
	for _, sess := range s.sessions {
		seen[sess.TenantID] = struct{}{}
	}
	out := make([]shared.ID, 0, len(seen))
	for tenantID := range seen {
		out = append(out, tenantID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *AgentSessionStore) ListResumable(_ context.Context, staleFor time.Duration, now time.Time, limit int) ([]agent.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100 // match the postgres adapter's default cap (port-contract parity)
	}
	cutoff := now.Add(-staleFor)
	var out []agent.Session
	for _, sess := range s.sessions {
		if (sess.Status == agent.StatusRunning || sess.Status == agent.StatusAwaitingApproval) && sess.UpdatedAt.Before(cutoff) {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *AgentSessionStore) AppendMessage(_ context.Context, sessionID shared.ID, seq int, m agent.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sessionID]; !ok {
		return fmt.Errorf("agent session %s: %w", sessionID, shared.ErrNotFound)
	}
	if s.msgs[sessionID] == nil {
		s.msgs[sessionID] = map[int]agent.Message{}
	}
	if _, exists := s.msgs[sessionID][seq]; exists {
		return fmt.Errorf("agent message (%s, seq %d) already exists: %w", sessionID, seq, shared.ErrConflict)
	}
	s.msgs[sessionID][seq] = m
	return nil
}

func (s *AgentSessionStore) Messages(_ context.Context, sessionID shared.ID) ([]agent.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySeq := s.msgs[sessionID]
	seqs := make([]int, 0, len(bySeq))
	for seq := range bySeq {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)
	out := make([]agent.Message, 0, len(seqs))
	for _, seq := range seqs {
		out = append(out, bySeq[seq])
	}
	return out, nil
}
