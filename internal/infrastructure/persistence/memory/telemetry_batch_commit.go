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
	priority := batch.Priority
	minAt := batch.EventTimeMin.UTC().Truncate(time.Microsecond)
	maxAt := batch.EventTimeMax.UTC().Truncate(time.Microsecond)
	for _, event := range batch.Events {
		p, err := fleetagent.TelemetryPriority(event.Class)
		if err != nil {
			return storedBatchCommit{}, err
		}
		if p != priority {
			return storedBatchCommit{}, fmt.Errorf("%w: telemetry batch event crosses its signed delivery-priority lane", shared.ErrValidation)
		}
		at := event.ObservedAt.UTC().Truncate(time.Microsecond)
		if at.Before(minAt) || at.After(maxAt) {
			return storedBatchCommit{}, fmt.Errorf("%w: telemetry event falls outside the signed event-time bounds", shared.ErrValidation)
		}
	}
	return storedBatchCommit{
		batchID: batch.BatchID, payloadDigest: batch.PayloadDigest, asset: batch.AssetID,
		schemaVersion: batch.SchemaVersion, eventCount: len(batch.Events),
		observedCount: batch.ObservedCount, keptCount: batch.KeptCount,
		sampledOutCount: batch.SampledOutCount, truncatedCount: batch.TruncatedCount,
		droppedCount: batch.DroppedCount, samplingPolicyDigest: batch.SamplingPolicyDigest,
		priority: priority, fromAt: minAt, toAt: maxAt,
	}, nil
}

func (s *TelemetryTransportStore) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	_, err := s.commitBatchWithAudit(ctx, batch, nil)
	return err
}

func (s *TelemetryTransportStore) CommitBatchWithAudit(
	ctx context.Context,
	batch ports.TelemetryEventBatch,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	return s.commitBatchWithAudit(ctx, batch, &intent)
}

func (s *TelemetryTransportStore) commitBatchWithAudit(
	ctx context.Context,
	batch ports.TelemetryEventBatch,
	intent *ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	want, err := memoryBatchCommit(batch)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	if intent != nil {
		normalized, err := validateMemoryFleetAuditIntent(*intent)
		if err != nil {
			return ports.FleetAuditIntent{}, err
		}
		intent = &normalized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commits[tenant] == nil {
		s.commits[tenant] = map[batchKey]storedBatchCommit{}
	}
	coord := batchKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence}
	if existing, ok := s.commits[tenant][coord]; ok && existing != want {
		return ports.FleetAuditIntent{}, fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
	}
	if intent == nil {
		s.commits[tenant][coord] = want
		return ports.FleetAuditIntent{}, nil
	}
	auditKey := fleetAuditKey{tenant: tenant, id: intent.ID}
	candidate := *intent
	if existing, ok := s.auditIntents[auditKey]; ok {
		candidate.Entry.At = existing.Entry.At
		if !memoryFleetAuditIntentEqual(existing, candidate) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
		}
	}
	s.commits[tenant][coord] = want
	if _, ok := s.auditIntents[auditKey]; !ok {
		s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(candidate)
	}
	return cloneMemoryFleetAuditIntent(candidate), nil
}
