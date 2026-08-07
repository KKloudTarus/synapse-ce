package memory

import (
	"context"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LeaderStore is an in-memory ports.LeaderStore for dev and single-process tests. It mirrors the
// Postgres fenced-lease semantics under a mutex.
type LeaderStore struct {
	mu     sync.Mutex
	leases map[string]*lease
}

type lease struct {
	holder  string
	fence   int64
	expires time.Time
}

// NewLeaderStore returns an empty in-memory leader store.
func NewLeaderStore() *LeaderStore { return &LeaderStore{leases: map[string]*lease{}} }

var _ ports.LeaderStore = (*LeaderStore)(nil)

// Acquire takes the lease when it is free (expired) or already held by holder, renewing the term;
// a takeover from an expired holder bumps the fence. Otherwise another instance holds it.
func (s *LeaderStore) Acquire(_ context.Context, resource, holder string, term time.Duration, now time.Time) (bool, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[resource]
	if !ok {
		s.leases[resource] = &lease{holder: holder, fence: 1, expires: now.Add(term)}
		return true, 1, nil
	}
	switch {
	case l.holder == holder:
		l.expires = now.Add(term) // renew
		return true, l.fence, nil
	case !l.expires.After(now):
		l.holder = holder // takeover of an expired lease
		l.fence++
		l.expires = now.Add(term)
		return true, l.fence, nil
	default:
		return false, l.fence, nil // someone else holds a live lease
	}
}

// Resign releases the lease if held by holder.
func (s *LeaderStore) Resign(_ context.Context, resource, holder string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[resource]; ok && l.holder == holder {
		delete(s.leases, resource)
	}
	return nil
}
