package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type CredentialBundle map[string]string

func (bundle CredentialBundle) Clone() CredentialBundle {
	out := make(CredentialBundle, len(bundle))
	for key, value := range bundle {
		out[key] = value
	}
	return out
}

type ConnectionTester interface {
	TestConnection(ctx context.Context) error
}

type PipelineDiscoverer interface {
	DiscoverPipelines(ctx context.Context, checkpoint string) (pipelines []Pipeline, nextCheckpoint string, err error)
}

type RunReader interface {
	ReadRuns(ctx context.Context, binding Binding, checkpoint string) (runs []ExternalRun, nextCheckpoint string, err error)
}

type Adapter interface {
	Descriptor() ProviderDescriptor
}

// Factory builds an adapter for one integration. rules are the operator's self-hosted endpoint
// rules; a provider that opens outbound connections builds its dialer policy from them, so the
// operator's current settings apply to every connection, not only to the ones saved after a change.
type Factory func(Integration, CredentialBundle, selfhosted.Rules) (Adapter, error)

type ProviderError struct {
	// Err must contain a bounded, credential-free diagnostic suitable for an
	// integration operation history entry. Provider adapters are code-owned.
	Retryable bool
	Err       error
}

func (providerError *ProviderError) Error() string {
	if providerError == nil || providerError.Err == nil {
		return "integration provider error"
	}
	return providerError.Err.Error()
}

func (providerError *ProviderError) Unwrap() error {
	if providerError == nil {
		return nil
	}
	return providerError.Err
}

func RetryableError(err error) error {
	if err == nil {
		return nil
	}
	return &ProviderError{Retryable: true, Err: err}
}

func PermanentError(err error) error {
	if err == nil {
		return nil
	}
	return &ProviderError{Retryable: false, Err: err}
}

func IsRetryable(err error) bool {
	var providerError *ProviderError
	return errors.As(err, &providerError) && providerError.Retryable
}

type registeredProvider struct {
	descriptor ProviderDescriptor
	factory    Factory
}

// Registry is code-owned. Runtime configuration can select a reviewed provider,
// but cannot upload or execute provider code.
type Registry struct {
	mu        sync.RWMutex
	providers map[Provider]registeredProvider
	rules     selfhosted.Rules
}

func NewRegistry() *Registry {
	return &Registry{providers: map[Provider]registeredProvider{}}
}

// SetSelfHostedRules installs the operator's self-hosted endpoint rules. The registry is their one
// holder: the integration service checks them at save time and Resolve at adapter build time, so
// the two can never disagree.
func (registry *Registry) SetSelfHostedRules(rules selfhosted.Rules) {
	registry.mu.Lock()
	registry.rules = rules
	registry.mu.Unlock()
}

// SelfHostedRules returns the operator's self-hosted endpoint rules.
func (registry *Registry) SelfHostedRules() selfhosted.Rules {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.rules
}

func (registry *Registry) Register(descriptor ProviderDescriptor, factory Factory) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if factory == nil {
		return fmt.Errorf("%w: integration provider factory is required", shared.ErrValidation)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.providers[descriptor.Provider]; exists {
		return fmt.Errorf("%w: integration provider %q is already registered", shared.ErrConflict, descriptor.Provider)
	}
	registry.providers[descriptor.Provider] = registeredProvider{descriptor: descriptor, factory: factory}
	return nil
}

func (registry *Registry) Descriptor(provider Provider) (ProviderDescriptor, error) {
	registry.mu.RLock()
	registered, exists := registry.providers[provider]
	registry.mu.RUnlock()
	if !exists {
		return ProviderDescriptor{}, fmt.Errorf("%w: integration provider %q is not registered", shared.ErrNotFound, provider)
	}
	return registered.descriptor, nil
}

func (registry *Registry) Descriptors() []ProviderDescriptor {
	registry.mu.RLock()
	descriptors := make([]ProviderDescriptor, 0, len(registry.providers))
	for _, registered := range registry.providers {
		descriptors = append(descriptors, registered.descriptor)
	}
	registry.mu.RUnlock()
	SortDescriptors(descriptors)
	return descriptors
}

func (registry *Registry) Resolve(item Integration, credentials CredentialBundle) (Adapter, error) {
	registry.mu.RLock()
	registered, exists := registry.providers[item.Provider]
	rules := registry.rules
	registry.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("%w: integration provider %q is not registered", shared.ErrNotFound, item.Provider)
	}
	// An integration saved before the operator tightened the rules is refused here, before any
	// connection is attempted. SaaS providers pin their vendor host and are not subject to them.
	if registered.descriptor.SelfHosted {
		if err := rules.CheckEndpoint(item.Endpoint, item.AllowPrivateNetwork); err != nil {
			return nil, err
		}
	}
	adapter, err := registered.factory(item.Clone(), credentials.Clone(), rules)
	if err != nil {
		return nil, err
	}
	if adapter == nil || !strings.EqualFold(string(adapter.Descriptor().Provider), string(item.Provider)) {
		return nil, fmt.Errorf("%w: provider factory returned an invalid adapter", shared.ErrValidation)
	}
	return adapter, nil
}
