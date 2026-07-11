package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TimestampStore is an in-memory ports.TimestampStore for dev/tests: external RFC-3161
// tokens keyed by (chain, engagement, head).
type TimestampStore struct {
	mu     sync.RWMutex
	m      map[string]ports.TimestampToken
	latest map[string]string // (chain,engagement) -> most-recently-Put head
}

// NewTimestampStore returns an empty in-memory timestamp store.
func NewTimestampStore() *TimestampStore {
	return &TimestampStore{m: map[string]ports.TimestampToken{}, latest: map[string]string{}}
}

var _ ports.TimestampStore = (*TimestampStore)(nil)

func tsKey(chain string, eng shared.ID, head string) string {
	return chain + "\x1f" + eng.String() + "\x1f" + head
}

// Get returns the stored token for a head, or nil if not yet anchored.
func (s *TimestampStore) Get(_ context.Context, chain string, eng shared.ID, head string) (*ports.TimestampToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.m[tsKey(chain, eng, head)]; ok {
		c := t
		return &c, nil
	}
	return nil, nil
}

// Put stores a token for a head (idempotent – first write wins, like the SQL ON
// CONFLICT DO NOTHING).
func (s *TimestampStore) Put(_ context.Context, chain string, eng shared.ID, head string, token ports.TimestampToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[tsKey(chain, eng, head)]; !ok {
		s.m[tsKey(chain, eng, head)] = token
	}
	s.latest[chain+"\x1f"+eng.String()] = head // most-recently-anchored head
	return nil
}

// LatestHead returns the most-recently-Put head for a chain (ok=false if none) – the retained
// head for out-of-band tail-truncation detection.
func (s *TimestampStore) LatestHead(_ context.Context, chain string, eng shared.ID) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.latest[chain+"\x1f"+eng.String()]
	return h, ok, nil
}
