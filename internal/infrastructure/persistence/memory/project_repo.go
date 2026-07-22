package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ProjectRepository is a goroutine-safe in-memory project store.
type ProjectRepository struct {
	mu   sync.RWMutex
	data map[string]*project.Project
}

func NewProjectRepository() *ProjectRepository {
	return &ProjectRepository{data: make(map[string]*project.Project)}
}

var _ ports.ProjectRepository = (*ProjectRepository)(nil)

func projectStoreKey(tenantID shared.ID, key string) string { return tenantID.String() + "\x00" + key }

func cloneProject(p *project.Project) *project.Project {
	cp := *p
	cp.DefaultProfileByLang = make(map[string]string, len(p.DefaultProfileByLang))
	for k, v := range p.DefaultProfileByLang {
		cp.DefaultProfileByLang[k] = v
	}
	return &cp
}

func (r *ProjectRepository) Create(_ context.Context, p *project.Project) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := projectStoreKey(p.TenantID, p.Key)
	if _, ok := r.data[key]; ok {
		return fmt.Errorf("project key %q already exists: %w", p.Key, shared.ErrConflict)
	}
	r.data[key] = cloneProject(p)
	return nil
}

func (r *ProjectRepository) List(_ context.Context, tenantID shared.ID) ([]*project.Project, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*project.Project, 0, len(r.data))
	for _, p := range r.data {
		if tenantID.IsZero() || p.TenantID == tenantID {
			out = append(out, cloneProject(p))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Audit.CreatedAt.Equal(out[j].Audit.CreatedAt) {
			return out[i].Key < out[j].Key
		}
		return out[i].Audit.CreatedAt.After(out[j].Audit.CreatedAt)
	})
	return out, nil
}

func olderProject(a, b *project.Project) bool {
	return a.Audit.CreatedAt.Before(b.Audit.CreatedAt) || (a.Audit.CreatedAt.Equal(b.Audit.CreatedAt) && a.ID < b.ID)
}

func (r *ProjectRepository) GetByKey(_ context.Context, tenantID shared.ID, key string) (*project.Project, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if tenantID.IsZero() {
		var found *project.Project
		for _, p := range r.data {
			if p.Key == key && (found == nil || olderProject(p, found)) {
				found = p
			}
		}
		if found == nil {
			return nil, shared.ErrNotFound
		}
		return cloneProject(found), nil
	}
	p, ok := r.data[projectStoreKey(tenantID, key)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return cloneProject(p), nil
}

func (r *ProjectRepository) GetByID(_ context.Context, tenantID, projectID shared.ID) (*project.Project, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.data {
		if p.ID == projectID && (tenantID.IsZero() || p.TenantID == tenantID) {
			return cloneProject(p), nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *ProjectRepository) UpdateGate(_ context.Context, tenantID shared.ID, key, gateID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, found := r.data[projectStoreKey(tenantID, key)]
	if !found {
		return shared.ErrNotFound
	}
	p.GateID = gateID
	return nil
}

func (r *ProjectRepository) AssignProfile(_ context.Context, tenantID shared.ID, projectKey, language, profileKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, found := r.data[projectStoreKey(tenantID, projectKey)]
	if !found {
		return shared.ErrNotFound
	}
	if p.DefaultProfileByLang == nil {
		p.DefaultProfileByLang = map[string]string{}
	}
	if strings.TrimSpace(profileKey) == "" {
		delete(p.DefaultProfileByLang, language)
		return nil
	}
	p.DefaultProfileByLang[language] = profileKey
	return nil
}

func (r *ProjectRepository) CountByGate(_ context.Context, tenantID shared.ID, gateID string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, p := range r.data {
		if (tenantID.IsZero() || p.TenantID == tenantID) && p.GateID == gateID {
			n++
		}
	}
	return n, nil
}

func (r *ProjectRepository) DeleteByKey(_ context.Context, tenantID shared.ID, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID.IsZero() {
		var foundKey string
		var found *project.Project
		for storeKey, p := range r.data {
			if p.Key == key && (found == nil || olderProject(p, found)) {
				foundKey, found = storeKey, p
			}
		}
		if found == nil {
			return shared.ErrNotFound
		}
		delete(r.data, foundKey)
		return nil
	}
	storeKey := projectStoreKey(tenantID, key)
	if _, ok := r.data[storeKey]; !ok {
		return shared.ErrNotFound
	}
	delete(r.data, storeKey)
	return nil
}
