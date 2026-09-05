package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SCMConnectorStore is the in-memory twin of the tenant-scoped source-control connector
// store, for dev and tests. It keys by (tenant, id) and reads the tenant from ctx, mirroring
// the Postgres store's RLS. The token is held in memory as-is (the Postgres twin seals it);
// it is returned ONLY via ResolveGitCredential, never by List/Get.
type SCMConnectorStore struct {
	mu   sync.RWMutex
	data map[shared.ID]map[shared.ID]scmRow // tenant -> id -> row
}

type scmRow struct {
	conn  scmconnector.Connector
	token []byte
}

// NewSCMConnectorStore constructs an empty store.
func NewSCMConnectorStore() *SCMConnectorStore {
	return &SCMConnectorStore{data: map[shared.ID]map[shared.ID]scmRow{}}
}

var _ ports.SCMConnectorStore = (*SCMConnectorStore)(nil)

func (s *SCMConnectorStore) tenant(ctx context.Context) (shared.ID, error) {
	t, ok := shared.TenantFrom(ctx)
	if !ok || t.IsZero() {
		return "", shared.ErrValidation
	}
	return t, nil
}

// Put upserts by id under the caller's tenant. A token is always required. A different connector
// already holding the same host is a conflict, mirroring the Postgres UNIQUE(tenant_id, host).
func (s *SCMConnectorStore) Put(ctx context.Context, c scmconnector.Connector, token []byte) error {
	t, err := s.tenant(ctx)
	if err != nil {
		return err
	}
	if c.ID.IsZero() || len(token) == 0 {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[t] == nil {
		s.data[t] = map[shared.ID]scmRow{}
	}
	for id, row := range s.data[t] {
		if id != c.ID && row.conn.Host == c.Host {
			return shared.ErrConflict // one connector per host per tenant
		}
	}
	c.TenantID = t
	s.data[t][c.ID] = scmRow{conn: c, token: append([]byte(nil), token...)}
	return nil
}

func (s *SCMConnectorStore) List(ctx context.Context) ([]ports.SCMConnectorMeta, error) {
	t, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.SCMConnectorMeta, 0, len(s.data[t]))
	for _, row := range s.data[t] {
		out = append(out, metaOf(row.conn))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *SCMConnectorStore) Get(ctx context.Context, id shared.ID) (ports.SCMConnectorMeta, error) {
	t, err := s.tenant(ctx)
	if err != nil {
		return ports.SCMConnectorMeta{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	row, ok := s.data[t][id]
	if !ok {
		return ports.SCMConnectorMeta{}, shared.ErrNotFound
	}
	return metaOf(row.conn), nil
}

func (s *SCMConnectorStore) Delete(ctx context.Context, id shared.ID) error {
	t, err := s.tenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[t][id]; !ok {
		return shared.ErrNotFound
	}
	delete(s.data[t], id)
	return nil
}

// ResolveGitCredential returns the credential whose connector host matches the given
// normalized host, under the caller's tenant. ok=false when none matches.
func (s *SCMConnectorStore) ResolveGitCredential(ctx context.Context, host string) (ports.GitCredential, bool, error) {
	t, err := s.tenant(ctx)
	if err != nil {
		return ports.GitCredential{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, row := range s.data[t] {
		if row.conn.Host == host {
			return ports.GitCredential{Username: row.conn.Username, Token: append([]byte(nil), row.token...)}, true, nil
		}
	}
	return ports.GitCredential{}, false, nil
}

func metaOf(c scmconnector.Connector) ports.SCMConnectorMeta {
	return ports.SCMConnectorMeta{
		ID: c.ID, Name: c.Name, Provider: c.Provider, Host: c.Host,
		Username: c.Username, AuthKind: c.AuthKind, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}
