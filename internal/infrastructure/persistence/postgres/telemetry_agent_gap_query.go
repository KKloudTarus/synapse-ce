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

// QueryAgentGaps returns durable agent-origin loss whose observed span overlaps
// the requested hunt window. It never consults/resolves delivery ACK state: these
// rows describe local loss facts that remain provenance even if sequence holes fill.
func (r *TelemetryTransportRepository) QueryAgentGaps(ctx context.Context, q ports.TelemetryGapQuery) ([]ports.TelemetryGap, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	var out []ports.TelemetryGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		var priority any
		if q.Priority != nil {
			priority = int(*q.Priority)
		}
		var since, until any
		if !q.Since.IsZero() {
			since = q.Since.UTC()
		}
		if !q.Until.IsZero() {
			until = q.Until.UTC()
		}
		rows, err := tx.Query(ctx, `SELECT agent_id,asset_id,stream_id,priority,epoch,known_sequence,
			COALESCE(from_sequence,0),COALESCE(to_sequence,0),from_at,to_at,first_reported_at
			FROM telemetry_agent_gaps
			WHERE tenant_id=$1
			  AND ($2='' OR agent_id=$2)
			  AND ($3='' OR asset_id=$3)
			  AND ($4::integer IS NULL OR priority=$4)
			  AND ($5::timestamptz IS NULL OR to_at >= $5)
			  AND ($6::timestamptz IS NULL OR from_at <= $6)
			ORDER BY from_at, first_reported_at, gap_id`,
			tenant.String(), q.AgentID.String(), q.AssetID.String(), priority, since, until)
		if err != nil {
			return fmt.Errorf("query telemetry agent gaps: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				agentID, assetID, streamID string
				priorityValue              int
				epoch, fromSeq, toSeq      int64
				known                      bool
				fromAt, toAt, detectedAt   time.Time
			)
			if err := rows.Scan(&agentID, &assetID, &streamID, &priorityValue, &epoch, &known,
				&fromSeq, &toSeq, &fromAt, &toAt, &detectedAt); err != nil {
				return fmt.Errorf("scan telemetry agent gap: %w", err)
			}
			_ = known // zero sequence coordinates intentionally represent unknown-coordinate loss.
			out = append(out, ports.TelemetryGap{
				AgentID: shared.ID(agentID), AssetID: shared.ID(assetID), StreamID: shared.ID(streamID),
				Priority: fleetagent.DeliveryPriority(priorityValue), Epoch: uint64(epoch),
				FromSequence: uint64(fromSeq), ToSequence: uint64(toSeq),
				FromAt: fromAt.UTC(), ToAt: toAt.UTC(), DetectedAt: detectedAt.UTC(),
			})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate telemetry agent gaps: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
