package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AccuracyRunStore is an in-memory ports.AccuracyRunStore for dev and tests. Detection-accuracy runs
// are deployment-global engine data (no tenant).
type AccuracyRunStore struct {
	mu   sync.RWMutex
	runs []accuracy.Run
}

// NewAccuracyRunStore returns an empty in-memory accuracy-run store.
func NewAccuracyRunStore() *AccuracyRunStore { return &AccuracyRunStore{} }

var _ ports.AccuracyRunStore = (*AccuracyRunStore)(nil)

// Save appends a run.
func (s *AccuracyRunStore) Save(_ context.Context, run accuracy.Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, run)
	return nil
}

// Recent returns the most recent runs, newest first, capped at limit (all when limit <= 0).
func (s *AccuracyRunStore) Recent(_ context.Context, limit int) ([]accuracy.Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]accuracy.Run(nil), s.runs...)
	sort.Slice(out, func(i, j int) bool { return out[i].RanAt.After(out[j].RanAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
