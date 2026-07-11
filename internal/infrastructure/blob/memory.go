package blob

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Memory is an in-memory content-addressed BlobStore for dev + tests (no object
// store required). Not durable – artifacts are lost on restart.
type Memory struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemory returns an empty in-memory blob store.
func NewMemory() *Memory { return &Memory{m: map[string][]byte{}} }

var _ ports.BlobStore = (*Memory)(nil)

func (s *Memory) Put(_ context.Context, key string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.m[key] = cp
	s.mu.Unlock()
	return nil
}

func (s *Memory) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.m[key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := make([]byte, len(d))
	copy(cp, d)
	return cp, nil
}
