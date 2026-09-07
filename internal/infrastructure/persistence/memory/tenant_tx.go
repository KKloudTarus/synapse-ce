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

type tenantTransaction struct {
	tenantID  shared.ID
	rollbacks []func()
}

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
	if transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction); ok {
		if transaction.tenantID != tenantID {
			return fmt.Errorf("%w: nested tenant transaction mismatch", shared.ErrValidation)
		}
		return fn(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	transaction := &tenantTransaction{tenantID: tenantID}
	txCtx := shared.WithTenant(context.WithValue(ctx, tenantTransactionKey{}, transaction), tenantID)
	if err := fn(txCtx); err != nil {
		for index := len(transaction.rollbacks) - 1; index >= 0; index-- {
			transaction.rollbacks[index]()
		}
		return err
	}
	return nil
}

// registerTenantRollback adds a repository-local compensation to the current
// in-memory transaction. Repositories call it while holding their own mutex and
// restore the captured state only after the mutation has returned and unlocked.
func registerTenantRollback(ctx context.Context, rollback func()) bool {
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok || rollback == nil {
		return false
	}
	transaction.rollbacks = append(transaction.rollbacks, rollback)
	return true
}
