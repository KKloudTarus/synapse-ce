package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ConnectionFactory struct {
	protector   ports.IdentitySecretProtector
	callbackURL string
	mu          sync.Mutex
	providers   map[string]*Provider
	order       []string
}

var _ ports.IdentityOIDCProviderFactory = (*ConnectionFactory)(nil)

func NewConnectionFactory(protector ports.IdentitySecretProtector, callbackURL string) (*ConnectionFactory, error) {
	if protector == nil || callbackURL == "" {
		return nil, fmt.Errorf("%w: OIDC connection factory requires protector and callback URL", shared.ErrValidation)
	}
	return &ConnectionFactory{protector: protector, callbackURL: callbackURL}, nil
}

func (f *ConnectionFactory) ProviderForConnection(ctx context.Context, c ports.IdentityConnection) (ports.OIDCProvider, error) {
	if c.Settings.RedirectURL != f.callbackURL || c.TenantID.IsZero() || c.ID.IsZero() {
		return nil, shared.ErrForbidden
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	revision := c.SettingsRevision
	if revision == 0 {
		revision = c.Revision
	}
	cacheKey := fmt.Sprintf("%s:%s:%d", c.TenantID, c.ID, revision)
	if p := f.providers[cacheKey]; p != nil {
		return p, nil
	}
	plain, err := f.protector.Open(ctx, c.Settings.SealedClientSecret, []byte("identity-connection:"+c.TenantID.String()+":"+c.ID.String()))
	if err != nil {
		return nil, fmt.Errorf("open connection client secret: %w", err)
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	p, err := New(ctx, Config{Issuer: c.Issuer, ClientID: c.Settings.ClientID, ClientSecret: string(plain), RedirectURL: f.callbackURL, ConnectionRevision: int64(revision)})
	if err != nil {
		return nil, err
	}
	if f.providers == nil {
		f.providers = make(map[string]*Provider)
	}
	if len(f.order) == 256 {
		delete(f.providers, f.order[0])
		f.order = f.order[1:]
	}
	f.providers[cacheKey] = p
	f.order = append(f.order, cacheKey)
	return p, nil
}
