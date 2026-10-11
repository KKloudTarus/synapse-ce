package bitbucket

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const Provider integration.Provider = "bitbucket"

var descriptor = integration.ProviderDescriptor{
	Provider: Provider, Name: "Bitbucket Cloud",
	Description: "Inbound Bitbucket Cloud push and pull-request webhooks for existing Projects.",
}

type Adapter struct{}

var _ integration.Adapter = (*Adapter)(nil)

func Register(registry *integration.Registry) error { return registry.Register(descriptor, New) }

func New(item integration.Integration, credentials integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	if item.Provider != Provider || len(credentials) != 0 {
		return nil, fmt.Errorf("%w: Bitbucket inbound integration does not accept polling credentials", shared.ErrValidation)
	}
	return &Adapter{}, nil
}

func (*Adapter) Descriptor() integration.ProviderDescriptor { return descriptor }
