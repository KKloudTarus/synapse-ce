package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TenantTransactionRunner provides an in-memory implementation of ports.TenantTransactionRunner.
type TenantTransactionRunner struct{}

// All runners may share repositories in the same process. Serialize their
// transactions together so one runner cannot roll back another runner's commit.
// The memory adapter is a development/test fallback, not a throughput backend.
var memoryTenantTransactions sync.Mutex

type tenantTransactionKey struct{}

type tenantTransaction struct {
	tenantID    shared.ID
	rollbacks   []func()
	checkpoints map[any]bool
	afterCommit []func()
}

// NewTenantTransactionRunner constructs an in-memory TenantTransactionRunner.
func NewTenantTransactionRunner() *TenantTransactionRunner {
	return &TenantTransactionRunner{}
}

var _ ports.TenantTransactionRunner = (*TenantTransactionRunner)(nil)

// Run runs the given function within a simulated thread-safe tenant context.
func (r *TenantTransactionRunner) Run(ctx context.Context, tenantID shared.ID, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenantID.IsZero() || fn == nil {
		return fmt.Errorf("%w: tenant transaction identity is required", shared.ErrValidation)
	}
	if transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction); ok {
		if transaction.tenantID != tenantID {
			return fmt.Errorf("%w: nested tenant transaction mismatch", shared.ErrValidation)
		}
		return fn(ctx)
	}
	memoryTenantTransactions.Lock()
	defer memoryTenantTransactions.Unlock()
	transaction := &tenantTransaction{tenantID: tenantID, checkpoints: make(map[any]bool)}
	txCtx := shared.WithTenant(context.WithValue(ctx, tenantTransactionKey{}, transaction), tenantID)
	committed := false
	defer func() {
		if !committed {
			for index := len(transaction.rollbacks) - 1; index >= 0; index-- {
				transaction.rollbacks[index]()
			}
		}
	}()
	if err := fn(txCtx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed = true
	for _, publish := range transaction.afterCommit {
		publish()
	}
	return nil
}

// registerTenantCommit defers publishing process-local work until the enclosing
// transaction (including its audit) succeeds. Failed transactions publish nothing.
func registerTenantCommit(ctx context.Context, publish func()) bool {
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok {
		return false
	}
	transaction.afterCommit = append(transaction.afterCommit, publish)
	return true
}

// registerTenantCheckpoint captures each repository once per transaction. This
// avoids quadratic copying when a snapshot appends thousands of observations.
// Callers hold their repository mutex while capturing and lock it on rollback.
func registerTenantCheckpoint(ctx context.Context, repository any, capture func(shared.ID) func()) {
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok || transaction.checkpoints[repository] {
		return
	}
	transaction.checkpoints[repository] = true
	transaction.rollbacks = append(transaction.rollbacks, capture(transaction.tenantID))
}

func cloneMapValues[K comparable, V any](source map[K]V, clone func(V) V) map[K]V {
	result := make(map[K]V, len(source))
	for key, value := range source {
		result[key] = clone(value)
	}
	return result
}

// captureTenantEntries is for copy-on-write records; it restores only the
// transaction tenant, preserving unrelated tenants' concurrent writes.
func captureTenantEntries[K comparable, V any](entries map[K]V, belongs func(K, V) bool) func() {
	previous := make(map[K]V)
	for key, value := range entries {
		if belongs(key, value) {
			previous[key] = value
		}
	}
	return func() {
		for key, value := range entries {
			if belongs(key, value) {
				delete(entries, key)
			}
		}
		for key, value := range previous {
			entries[key] = value
		}
	}
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
