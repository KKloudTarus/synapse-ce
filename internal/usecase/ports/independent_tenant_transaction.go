package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IndependentTenantTransactionRunner commits an append-only alert independently
// of a caller's transaction, so a failed report cannot erase the custody alert.
// Callbacks must not acquire locks held by the enclosing transaction, including
// the tenant audit-chain head. Verify custody before appending audit in that transaction.
type IndependentTenantTransactionRunner interface {
	RunIndependent(context.Context, shared.ID, func(context.Context) error) error
}
