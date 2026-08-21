package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
var _ ports.RestoreBlobReader = (*Memory)(nil)

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

// Verify streams the stored bytes into SHA-256 and compares them with expected.
// It deliberately derives the digest from data rather than trusting the key.
func (s *Memory) Verify(_ context.Context, key, expected string) error {
	s.mu.RLock()
	d, ok := s.m[key]
	if !ok {
		s.mu.RUnlock()
		return shared.ErrNotFound
	}
	actual := sha256.Sum256(d)
	s.mu.RUnlock()
	if hex.EncodeToString(actual[:]) != expected {
		return fmt.Errorf("artifact checksum does not match expected SHA-256")
	}
	return nil
}

// Stat reports the digest derived from the stored bytes. It exists for read-only
// restore verification; callers must compare SHA256 with their expected digest.
func (s *Memory) Stat(ctx context.Context, key string) (ObjectMetadata, error) {
	data, err := s.Get(ctx, key)
	if err != nil {
		return ObjectMetadata{}, err
	}
	sum := sha256.Sum256(data)
	return ObjectMetadata{SHA256: hex.EncodeToString(sum[:])}, nil
}
