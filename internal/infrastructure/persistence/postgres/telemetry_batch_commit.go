package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type postgresBatchCommit struct {
	batchID       shared.ID
	assetID       shared.ID
	priority      fleetagent.DeliveryPriority
	schemaVersion int
	payloadDigest string
	eventCount    int
	fromAt        time.Time
	toAt          time.Time
}

func derivePostgresBatchCommit(batch ports.TelemetryEventBatch) (postgresBatchCommit, error) {
	if err := batch.Validate(); err != nil {
		return postgresBatchCommit{}, err
	}
	var priority fleetagent.DeliveryPriority
	var fromAt, toAt time.Time
	for i, event := range batch.Events {
		p, err := fleetagent.TelemetryPriority(event.Class)
		if err != nil {
			return postgresBatchCommit{}, err
		}
		if i == 0 {
			priority = p
		} else if p != priority {
			return postgresBatchCommit{}, fmt.Errorf("%w: telemetry batch crosses delivery-priority lanes", shared.ErrValidation)
		}
		// PostgreSQL timestamptz has microsecond precision. Normalize here so an
		// exact replay compares equal after a round trip through the database.
		at := event.ObservedAt.UTC().Truncate(time.Microsecond)
		if fromAt.IsZero() || at.Before(fromAt) {
			fromAt = at
		}
		if toAt.IsZero() || at.After(toAt) {
			toAt = at
		}
	}
	return postgresBatchCommit{
		batchID: batch.BatchID, assetID: batch.AssetID, priority: priority,
		schemaVersion: batch.SchemaVersion, payloadDigest: batch.PayloadDigest,
		eventCount: len(batch.Events), fromAt: fromAt, toAt: toAt,
	}, nil
}

// CommitBatch atomically claims one delivery coordinate for the exact signed batch
// identity. Concurrent identical replays converge; any equivocation at the same
// (tenant, agent, stream, epoch, sequence) fails closed before ACK classification.
func (r *TelemetryTransportRepository) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	want, err := derivePostgresBatchCommit(batch)
	if err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `INSERT INTO telemetry_batch_commits
			(tenant_id,agent_id,stream_id,epoch,sequence,batch_id,asset_id,priority,schema_version,payload_digest,event_count,event_time_min,event_time_max)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id,agent_id,stream_id,epoch,sequence) DO NOTHING`,
			tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence),
			want.batchID.String(), want.assetID.String(), int(want.priority), want.schemaVersion, want.payloadDigest,
			want.eventCount, want.fromAt, want.toAt)
		if err != nil {
			return fmt.Errorf("commit telemetry batch identity: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		var (
			batchID, assetID, payloadDigest     string
			priority, schemaVersion, eventCount int
			fromAt, toAt                        time.Time
		)
		if err := tx.QueryRow(ctx, `SELECT batch_id,asset_id,priority,schema_version,payload_digest,event_count,event_time_min,event_time_max
			FROM telemetry_batch_commits
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
			tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence)).
			Scan(&batchID, &assetID, &priority, &schemaVersion, &payloadDigest, &eventCount, &fromAt, &toAt); err != nil {
			return fmt.Errorf("read telemetry batch commitment collision: %w", err)
		}
		if batchID != want.batchID.String() || assetID != want.assetID.String() ||
			priority != int(want.priority) || schemaVersion != want.schemaVersion ||
			payloadDigest != want.payloadDigest || eventCount != want.eventCount ||
			!fromAt.Equal(want.fromAt) || !toAt.Equal(want.toAt) {
			return fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
		}
		return nil
	})
}
