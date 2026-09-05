// Package scmconnectoruc is the management use case for tenant-scoped source-control
// connectors: create, list, and delete the git-host + PAT bindings the acquirer uses to
// clone a PRIVATE repository. The plaintext token enters only through Create and is handed
// straight to the store to be sealed; it is never returned, logged, or held on the domain
// type. Every operation is tenant-scoped from ctx (the store enforces RLS).
package scmconnectoruc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxTokenBytes bounds a stored PAT. A personal access token is well under this; the cap
// keeps a caller from stuffing arbitrary data into the sealed column.
const MaxTokenBytes = 4096

// Service manages source-control connectors.
type Service struct {
	store ports.SCMConnectorStore
	ids   ports.IDGenerator
	clock ports.Clock
}

// NewService validates its dependencies.
func NewService(store ports.SCMConnectorStore, ids ports.IDGenerator, clock ports.Clock) (*Service, error) {
	if store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: scm connector service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, ids: ids, clock: clock}, nil
}

// CreateInput is a new connector plus its plaintext token. Token is required and is sealed
// by the store; it never appears on the returned metadata.
type CreateInput struct {
	TenantID shared.ID
	Name     string
	Provider scmconnector.Provider
	Host     string
	Username string
	Token    string
}

// Create validates and stores a connector, returning its non-secret metadata. A second
// connector for the same host is a conflict (the store enforces UNIQUE(tenant, host)).
func (s *Service) Create(ctx context.Context, in CreateInput) (ports.SCMConnectorMeta, error) {
	token := strings.TrimSpace(in.Token)
	if token == "" {
		return ports.SCMConnectorMeta{}, fmt.Errorf("%w: a personal access token is required", shared.ErrValidation)
	}
	if len(token) > MaxTokenBytes {
		return ports.SCMConnectorMeta{}, fmt.Errorf("%w: token exceeds %d bytes", shared.ErrValidation, MaxTokenBytes)
	}
	id := s.ids.NewID()
	c, err := scmconnector.NewConnector(id, in.TenantID, in.Name, in.Provider, in.Host, in.Username, scmconnector.AuthPAT, s.clock.Now())
	if err != nil {
		return ports.SCMConnectorMeta{}, err
	}
	// Refuse a credential aimed at an internal address (SSRF/metadata guard); the acquirer enforces the
	// same at clone time, but rejecting at creation keeps such a connector from ever being stored.
	if scmconnector.IsInternalHost(c.Host) {
		return ports.SCMConnectorMeta{}, fmt.Errorf("%w: a connector host must not be a loopback or link-local address", shared.ErrValidation)
	}
	if err := s.store.Put(ctx, *c, []byte(token)); err != nil {
		return ports.SCMConnectorMeta{}, err
	}
	return s.store.Get(ctx, id)
}

// List returns the tenant's connectors as metadata (never the token).
func (s *Service) List(ctx context.Context) ([]ports.SCMConnectorMeta, error) {
	return s.store.List(ctx)
}

// Delete removes a connector by id.
func (s *Service) Delete(ctx context.Context, id shared.ID) error {
	if id.IsZero() {
		return fmt.Errorf("%w: connector id is required", shared.ErrValidation)
	}
	return s.store.Delete(ctx, id)
}
