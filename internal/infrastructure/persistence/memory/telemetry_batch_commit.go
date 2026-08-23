package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func memoryBatchCommit(batch ports.TelemetryEventBatch) (storedBatchCommit, error) {
	if err := batch.Validate(); err != nil {
		return storedBatchCommit{}, err
	}
	var priority fleetagent.DeliveryPriority
	var minAt, maxAt time.Time
	for i, event := range batch.Events {
		p, err := fleetagent.TelemetryPriority(event.Class)
		if err != nil {
			return storedBatchCommit{}, err
		}
		if i == 0 {
			priority = p
		} else if p != priority {
			return storedBatchCommit{}, fmt.Errorf("%w: telemetry batch crosses delivery-priority lanes", shared.ErrValidation)
		}
		// Keep the in-memory tier byte-for-byte aligned with PostgreSQL's
		// timestamptz precision so replay and gap-window semantics do not differ by adapter.
		at := event.ObservedAt.UTC().Truncate(time.Microsecond)
		if minAt.IsZero() || at.Before(minAt) {
			minAt = at
		}
		if maxAt.IsZero() || at.After(maxAt) {
			maxAt = at
		}
	}
	return storedBatchCommit{
		batchID: batch.BatchID, payloadDigest: batch.PayloadDigest, asset: batch.AssetID,
		schemaVersion: batch.SchemaVersion, eventCount: len(batch.Events), priority: priority,
		fromAt: minAt, toAt: maxAt,
	}, nil
}

func (s *TelemetryTransportStore) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	want, err := memoryBatchCommit(batch)
	if err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commits[tenant] == nil {
		s.commits[tenant] = map[batchKey]storedBatchCommit{}
	}
	coord := batchKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence}
	if existing, ok := s.commits[tenant][coord]; ok {
		if existing != want {
			return fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
		}
		return nil
	}
	s.commits[tenant][coord] = want
	return nil
}
