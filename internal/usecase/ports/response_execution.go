package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

// ResponseCommandKeyResolver resolves a control-plane command key by its immutable fingerprint.
// Implementations must reject keys that were not valid at issuedAt, including revoked keys.
type ResponseCommandKeyResolver interface {
	ResolveResponseCommandKey(ctx context.Context, keyID string) (fleetagent.ResponseCommandSigningKey, error)
}

// ResponseExecutionJournal is endpoint-local durable state. Save must return only after the state is
// durable enough to survive process restart; the caller serializes transitions for one agent process.
type ResponseExecutionJournal interface {
	LoadResponseExecution(context.Context, string) (fleetagent.ResponseExecutionJournalEntry, bool, error)
	ListResponseExecutions(context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error)
	SaveResponseExecution(context.Context, fleetagent.ResponseExecutionJournalEntry) error
	CurrentResponseHaltFence(context.Context) (generation int64, halted bool, err error)
	RaiseResponseHaltFence(context.Context, int64) error
}
