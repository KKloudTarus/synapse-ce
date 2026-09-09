// Package responseobserver provides endpoint-side observation infrastructure.
package responseobserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BindingResolver resolves an agent's immutable primary host ownership and independently authorizes
// a response observer's secondary target. The secondary binding never changes general telemetry
// ownership; response-observation telemetry must additionally name a live observation work order and is
// authorized through ObservationTelemetryAuthorizer.
type BindingResolver struct {
	primary   bindingReferenceStore
	observers ports.ResponseObserverBindingStore
	clock     ports.Clock
}

type bindingReferenceStore interface {
	ports.TelemetryAssetBindingStore
	ports.TelemetryReferenceResolver
}

var _ ports.TelemetryAssetBindingStore = (*BindingResolver)(nil)
var _ ports.TelemetryReferenceResolver = (*BindingResolver)(nil)
var _ ports.ResponseObservationTargetResolver = (*BindingResolver)(nil)

func NewBindingResolver(primary bindingReferenceStore, observers ports.ResponseObserverBindingStore, clock ports.Clock) (*BindingResolver, error) {
	if primary == nil || observers == nil || clock == nil {
		return nil, fmt.Errorf("%w: observer-aware telemetry binding resolver is missing a dependency", shared.ErrValidation)
	}
	return &BindingResolver{primary: primary, observers: observers, clock: clock}, nil
}

func (r *BindingResolver) ResolveTelemetryReferences(ctx context.Context, agentID, assetID shared.ID, redactionPolicyDigest string, refs []fleetagent.TelemetryReference) (ports.TelemetryReferenceStatus, error) {
	boundAssetID, err := r.ResolveTelemetryAsset(ctx, agentID)
	if err != nil {
		return "", err
	}
	if boundAssetID != assetID {
		return ports.TelemetryReferencesContradictory, nil
	}
	return r.primary.ResolveTelemetryReferences(ctx, agentID, assetID, redactionPolicyDigest, refs)
}

func (r *BindingResolver) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	return r.primary.BindTelemetryAsset(ctx, binding)
}

func (r *BindingResolver) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	assetID, err := r.primary.ResolveTelemetryAsset(ctx, agentID)
	if errors.Is(err, shared.ErrNotFound) {
		return "", fmt.Errorf("%w: primary telemetry asset binding is not established", shared.ErrNotFound)
	}
	return assetID, err
}

// ResolveResponseObservationAsset authorizes an independently enrolled observer to report on a
// target asset. It first requires the observer's own primary binding, then checks the operator-owned
// target assignment against the tenant and its live lifetime.
func (r *BindingResolver) ResolveResponseObservationAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	if _, err := r.ResolveTelemetryAsset(ctx, agentID); err != nil {
		return "", err
	}
	binding, err := r.observers.GetResponseObserverBinding(ctx, agentID)
	if err != nil {
		return "", err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || binding.TenantID != tenantID || binding.AgentID != agentID || !binding.ActiveAt(r.clock.Now()) {
		return "", fmt.Errorf("%w: response-observer binding is absent or expired", shared.ErrNotFound)
	}
	return binding.AssetID, nil
}
