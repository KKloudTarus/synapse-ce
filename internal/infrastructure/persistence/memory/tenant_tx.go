package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TenantTransactionRunner provides an in-memory implementation of ports.TenantTransactionRunner.
type TenantTransactionRunner struct {
	mu sync.Mutex
}

type tenantTransactionKey struct{}

// NewTenantTransactionRunner constructs an in-memory TenantTransactionRunner.
func NewTenantTransactionRunner() *TenantTransactionRunner {
	return &TenantTransactionRunner{}
}

var _ ports.TenantTransactionRunner = (*TenantTransactionRunner)(nil)

// Run runs the given function within a simulated thread-safe tenant context.
func (r *TenantTransactionRunner) Run(ctx context.Context, tenantID shared.ID, fn func(context.Context) error) error {
	if tenantID.IsZero() || fn == nil {
		return fmt.Errorf("%w: tenant transaction identity is required", shared.ErrValidation)
	}
	if boundTenant, ok := ctx.Value(tenantTransactionKey{}).(shared.ID); ok {
		if boundTenant != tenantID {
			return fmt.Errorf("%w: nested tenant transaction mismatch", shared.ErrValidation)
		}
		return fn(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	txCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantID)
	return fn(shared.WithTenant(txCtx, tenantID))
}
