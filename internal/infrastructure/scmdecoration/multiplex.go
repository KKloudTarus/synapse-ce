package scmdecoration

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MultiplexDecorator dispatches one decoration to the owned adapter for its forge, chosen from the
// decoration's Provider claim. It exists for the server, where a single tenant can host projects on
// different forges: one injected decorator must be able to reach GitHub, GitLab, and Bitbucket. Every
// adapter shares the same tenant-scoped credential resolver (the SCM connector store), so the concrete
// token is resolved per call from tenant context and is never held here.
type MultiplexDecorator struct {
	credentials ports.GitCredentialResolver
	mu          sync.Mutex
	byProvider  map[string]ports.PRDecorator
}

var _ ports.PRDecorator = (*MultiplexDecorator)(nil)

// NewMultiplexDecorator builds a provider-multiplexing decorator over one credential resolver.
func NewMultiplexDecorator(credentials ports.GitCredentialResolver) (*MultiplexDecorator, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: multiplex decoration needs a credential resolver", shared.ErrValidation)
	}
	return &MultiplexDecorator{credentials: credentials, byProvider: make(map[string]ports.PRDecorator)}, nil
}

// Decorate routes to the adapter for decoration.Provider. An empty or unsupported provider is a
// validation error the caller treats as fail-soft, so a project on an unsupported forge is simply not
// decorated rather than failing the analysis.
func (m *MultiplexDecorator) Decorate(ctx context.Context, decoration ports.PRDecoration) error {
	decorator, err := m.decoratorFor(decoration.Provider)
	if err != nil {
		return err
	}
	return decorator.Decorate(ctx, decoration)
}

func (m *MultiplexDecorator) decoratorFor(provider string) (ports.PRDecorator, error) {
	key := normalizeProvider(provider)
	m.mu.Lock()
	defer m.mu.Unlock()
	if decorator, ok := m.byProvider[key]; ok {
		return decorator, nil
	}
	decorator, err := ForProvider(provider, m.credentials)
	if err != nil {
		return nil, err
	}
	m.byProvider[key] = decorator
	return decorator, nil
}
