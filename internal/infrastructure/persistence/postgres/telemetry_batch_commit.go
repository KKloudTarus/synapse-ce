package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type postgresBatchCommit struct {
	batchID              shared.ID
	assetID              shared.ID
	priority             fleetagent.DeliveryPriority
	schemaVersion        int
	payloadDigest        string
	eventCount           int
	observedCount        int
	keptCount            int
	sampledOutCount      int
	truncatedCount       int
	droppedCount         int
	samplingPolicyDigest string
	fromAt               time.Time
	toAt                 time.Time
}

func derivePostgresBatchCommit(batch ports.TelemetryEventBatch) (postgresBatchCommit, error) {
	if err := batch.Validate(); err != nil {
		return postgresBatchCommit{}, err
	}
	priority := batch.Priority
	fromAt := batch.EventTimeMin.UTC().Truncate(time.Microsecond)
	toAt := batch.EventTimeMax.UTC().Truncate(time.Microsecond)
	for _, event := range batch.Events {
		p, err := fleetagent.TelemetryPriority(event.Class)
		if err != nil {
			return postgresBatchCommit{}, err
		}
		if p != priority {
			return postgresBatchCommit{}, fmt.Errorf("%w: telemetry batch event crosses its signed delivery-priority lane", shared.ErrValidation)
		}
		at := event.ObservedAt.UTC().Truncate(time.Microsecond)
		if at.Before(fromAt) || at.After(toAt) {
			return postgresBatchCommit{}, fmt.Errorf("%w: telemetry event falls outside the signed event-time bounds", shared.ErrValidation)
		}
	}
	return postgresBatchCommit{
		batchID: batch.BatchID, assetID: batch.AssetID, priority: priority,
		schemaVersion: batch.SchemaVersion, payloadDigest: batch.PayloadDigest,
		eventCount: len(batch.Events), observedCount: batch.ObservedCount,
		keptCount: batch.KeptCount, sampledOutCount: batch.SampledOutCount,
		truncatedCount: batch.TruncatedCount, droppedCount: batch.DroppedCount,
		samplingPolicyDigest: batch.SamplingPolicyDigest, fromAt: fromAt, toAt: toAt,
	}, nil
}

// CommitBatch atomically claims one delivery coordinate for the exact signed batch
// identity. Concurrent identical replays converge; any equivocation at the same
// (tenant, agent, stream, epoch, sequence) fails closed before ACK classification.
func (r *TelemetryTransportRepository) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	_, err := r.commitBatchWithAudit(ctx, batch, nil)
	return err
}

func (r *TelemetryTransportRepository) CommitBatchWithAudit(
	ctx context.Context,
	batch ports.TelemetryEventBatch,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	return r.commitBatchWithAudit(ctx, batch, &intent)
}

func (r *TelemetryTransportRepository) commitBatchWithAudit(
	ctx context.Context,
	batch ports.TelemetryEventBatch,
	intent *ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	want, err := derivePostgresBatchCommit(batch)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	var committed ports.FleetAuditIntent
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `INSERT INTO telemetry_batch_commits
			(tenant_id,agent_id,stream_id,epoch,sequence,batch_id,asset_id,priority,schema_version,payload_digest,event_count,
			 observed_count,kept_count,sampled_out_count,truncated_count,dropped_count,sampling_policy_digest,event_time_min,event_time_max)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (tenant_id,agent_id,stream_id,epoch,sequence) DO NOTHING`,
			tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence),
			want.batchID.String(), want.assetID.String(), int(want.priority), want.schemaVersion, want.payloadDigest,
			want.eventCount, want.observedCount, want.keptCount, want.sampledOutCount, want.truncatedCount,
			want.droppedCount, want.samplingPolicyDigest, want.fromAt, want.toAt)
		if err != nil {
			return fmt.Errorf("commit telemetry batch identity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			var (
				batchID, assetID, payloadDigest, samplingPolicyDigest string
				priority, schemaVersion, eventCount                   int
				observedCount, keptCount, sampledOutCount             int
				truncatedCount, droppedCount                          int
				fromAt, toAt                                          time.Time
			)
			if err := tx.QueryRow(ctx, `SELECT batch_id,asset_id,priority,schema_version,payload_digest,event_count,
				observed_count,kept_count,sampled_out_count,truncated_count,dropped_count,sampling_policy_digest,event_time_min,event_time_max
				FROM telemetry_batch_commits
				WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
				tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence)).
				Scan(&batchID, &assetID, &priority, &schemaVersion, &payloadDigest, &eventCount,
					&observedCount, &keptCount, &sampledOutCount, &truncatedCount, &droppedCount,
					&samplingPolicyDigest, &fromAt, &toAt); err != nil {
				return fmt.Errorf("read telemetry batch commitment collision: %w", err)
			}
			if batchID != want.batchID.String() || assetID != want.assetID.String() ||
				priority != int(want.priority) || schemaVersion != want.schemaVersion ||
				payloadDigest != want.payloadDigest || eventCount != want.eventCount ||
				observedCount != want.observedCount || keptCount != want.keptCount ||
				sampledOutCount != want.sampledOutCount || truncatedCount != want.truncatedCount ||
				droppedCount != want.droppedCount || samplingPolicyDigest != want.samplingPolicyDigest ||
				!fromAt.Equal(want.fromAt) || !toAt.Equal(want.toAt) {
				return fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
			}
		}
		if intent == nil {
			return nil
		}
		// Normalize BEFORE using the id as a lookup key. Reading with an untrimmed id
		// would miss the existing row, keep the retry's wall clock, then collide on the
		// trimmed primary key and report a spurious equivocation conflict.
		candidate, _, err := validateFleetAuditIntent(*intent)
		if err != nil {
			return err
		}
		// An exact batch retry must re-deliver the ORIGINAL audit payload, so the
		// already-durable occurred_at wins over the retry's wall clock.
		var existingAt time.Time
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM fleet_audit_intents
			WHERE tenant_id=$1 AND intent_id=$2`, tenant.String(), candidate.ID).Scan(&existingAt)
		if err == nil {
			candidate.Entry.At = existingAt.UTC()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read telemetry batch audit intention: %w", err)
		}
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{
			tenantID: tenant.String(),
			tx:       tx,
		})
		stored, err := r.InsertFleetAudit(transactionCtx, candidate)
		if err != nil {
			return err
		}
		committed = stored
		return nil
	})
	return committed, err
}
