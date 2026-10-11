// Package gitlab registers the inbound-only GitLab integration identity used
// by the WS10 webhook plane. It performs no outbound GitLab requests: source
// cloning and optional PR decoration remain owned by scmconnector.
package gitlab

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const Provider integration.Provider = "gitlab"

var descriptor = integration.ProviderDescriptor{
	Provider: Provider,
	Name: "GitLab",
	Description: "Inbound GitLab push and merge-request webhooks for existing projects.",
	// Intentionally no polling/discovery/test capabilities. The integration
	// scheduler filters on read_runs, so an inbound-only row never consumes a
	// poll slot or opens an outbound connection.
	Capabilities: []integration.Capability{},
}

type Adapter struct{}

func Register(registry *integration.Registry) error {
	if registry == nil {
		return fmt.Errorf("%w: GitLab integration registry is required", shared.ErrValidation)
	}
	return registry.Register(descriptor, New)
}

func New(item integration.Integration, credentials integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	if item.Provider != Provider {
		return nil, fmt.Errorf("%w: GitLab inbound adapter received provider %q", shared.ErrValidation, item.Provider)
	}
	if err := descriptor.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	return &Adapter{}, nil
}

func (*Adapter) Descriptor() integration.ProviderDescriptor { return descriptor }
