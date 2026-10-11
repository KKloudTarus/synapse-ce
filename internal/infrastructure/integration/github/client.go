package github

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const Provider integration.Provider = "github"

var descriptor = integration.ProviderDescriptor{
	Provider: Provider,
	Name: "GitHub",
	Description: "Inbound GitHub push and pull-request webhooks for existing Synapse projects.",
}

type Adapter struct{ descriptor integration.ProviderDescriptor }

func Register(registry *integration.Registry) error { return registry.Register(descriptor, New) }

func New(item integration.Integration, credentials integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	if item.Provider != Provider {
		return nil, fmt.Errorf("%w: GitHub adapter received provider %q", shared.ErrValidation, item.Provider)
	}
	if len(credentials) != 0 {
		return nil, fmt.Errorf("%w: GitHub inbound integration does not accept polling credentials", shared.ErrValidation)
	}
	return &Adapter{descriptor: descriptor}, nil
}

func (a *Adapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }
