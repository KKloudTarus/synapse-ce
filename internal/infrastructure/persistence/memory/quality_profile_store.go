package memory

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// QualityProfileStore is a goroutine-safe in-memory custom quality-profile store.
type QualityProfileStore struct {
	mu   sync.RWMutex
	data map[string]qualityprofile.Profile
}

func NewQualityProfileStore() *QualityProfileStore {
	return &QualityProfileStore{data: map[string]qualityprofile.Profile{}}
}

var _ ports.QualityProfileStore = (*QualityProfileStore)(nil)

func qualityProfileStoreKey(tenantID shared.ID, key string) string {
	return tenantID.String() + "\x00" + strings.TrimSpace(key)
}

func (s *QualityProfileStore) Create(_ context.Context, tenantID shared.ID, profile qualityprofile.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := qualityProfileStoreKey(tenantID, profile.Key)
	if _, found := s.data[key]; found {
		return shared.ErrConflict
	}
	s.data[key] = profile.Clone()
	return nil
}

func (s *QualityProfileStore) List(_ context.Context, tenantID shared.ID) ([]qualityprofile.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]qualityprofile.Profile, 0, len(s.data))
	prefix := tenantID.String() + "\x00"
	for key, profile := range s.data {
		if tenantID.IsZero() || strings.HasPrefix(key, prefix) {
			out = append(out, profile.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *QualityProfileStore) Get(_ context.Context, tenantID shared.ID, key string) (qualityprofile.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, found := s.data[qualityProfileStoreKey(tenantID, key)]
	if !found {
		return qualityprofile.Profile{}, shared.ErrNotFound
	}
	return profile.Clone(), nil
}

func (s *QualityProfileStore) Update(_ context.Context, tenantID shared.ID, profile qualityprofile.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := qualityProfileStoreKey(tenantID, profile.Key)
	if _, found := s.data[key]; !found {
		return shared.ErrNotFound
	}
	s.data[key] = profile.Clone()
	return nil
}

func (s *QualityProfileStore) Delete(_ context.Context, tenantID shared.ID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	storeKey := qualityProfileStoreKey(tenantID, key)
	if _, found := s.data[storeKey]; !found {
		return shared.ErrNotFound
	}
	delete(s.data, storeKey)
	return nil
}
