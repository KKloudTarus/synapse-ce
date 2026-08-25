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

func postgresAgentGapCompatibleExtension(current, next ports.TelemetryAgentGap) bool {
	if current.GapID != next.GapID || current.AgentID != next.AgentID || current.AssetID != next.AssetID ||
		current.StreamID != next.StreamID || current.Priority != next.Priority || current.Epoch != next.Epoch ||
		current.KnownSequence != next.KnownSequence || current.Reason != next.Reason || next.Count < current.Count ||
		next.FromAt.After(current.FromAt) || next.ToAt.Before(current.ToAt) {
		return false
	}
	if current.KnownSequence {
		return next.FromSequence <= current.FromSequence && next.ToSequence >= current.ToSequence
	}
	return next.FromSequence == 0 && next.ToSequence == 0
}

func scanAgentGapRow(row pgx.Row) (ports.TelemetryAgentGap, error) {
	var (
		gap                               ports.TelemetryAgentGap
		gapID, agentID, assetID, streamID string
		priority                          int
		epoch, count                      int64
		known                             bool
		fromSeq, toSeq                    *int64
		reason                            string
		fromAt, toAt, firstAt, updatedAt  time.Time
	)
	if err := row.Scan(&gapID, &agentID, &assetID, &streamID, &priority, &epoch, &known,
		&fromSeq, &toSeq, &count, &reason, &fromAt, &toAt, &firstAt, &updatedAt); err != nil {
		return ports.TelemetryAgentGap{}, err
	}
	gap = ports.TelemetryAgentGap{
		GapID: shared.ID(gapID), AgentID: shared.ID(agentID), AssetID: shared.ID(assetID), StreamID: shared.ID(streamID),
		Priority: fleetagent.DeliveryPriority(priority), Epoch: uint64(epoch), KnownSequence: known, Count: uint64(count),
		Reason: fleetagent.TelemetryGapReason(reason), FromAt: fromAt.UTC(), ToAt: toAt.UTC(),
		FirstReportedAt: firstAt.UTC(), UpdatedAt: updatedAt.UTC(),
	}
	if fromSeq != nil {
		gap.FromSequence = uint64(*fromSeq)
	}
	if toSeq != nil {
		gap.ToSequence = uint64(*toSeq)
	}
	return gap, nil
}

func (r *TelemetryTransportRepository) RecordAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		current, err := scanAgentGapRow(tx.QueryRow(ctx, `SELECT gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,
			from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at
			FROM telemetry_agent_gaps WHERE tenant_id=$1 AND gap_id=$2 FOR UPDATE`, tenant.String(), gap.GapID.String()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			var fromSeq, toSeq any
			if gap.KnownSequence {
				fromSeq, toSeq = int64(gap.FromSequence), int64(gap.ToSequence)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO telemetry_agent_gaps
				(tenant_id,gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				tenant.String(), gap.GapID.String(), gap.AgentID.String(), gap.AssetID.String(), gap.StreamID.String(), int(gap.Priority),
				int64(gap.Epoch), gap.KnownSequence, fromSeq, toSeq, int64(gap.Count), string(gap.Reason),
				gap.FromAt.UTC(), gap.ToAt.UTC(), gap.FirstReportedAt.UTC(), gap.UpdatedAt.UTC()); err != nil {
				return fmt.Errorf("insert telemetry agent gap: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("read telemetry agent gap collision: %w", err)
		}

		if !postgresAgentGapCompatibleExtension(current, gap) {
			return fmt.Errorf("%w: telemetry agent gap id is already committed to incompatible or larger evidence", shared.ErrConflict)
		}
		// Exact retry is intentionally a no-op except UpdatedAt: this keeps first_reported_at
		// stable while still exposing the latest successful receipt time.
		var fromSeq, toSeq any
		if gap.KnownSequence {
			fromSeq, toSeq = int64(gap.FromSequence), int64(gap.ToSequence)
		}
		updatedAt := gap.UpdatedAt.UTC()
		if updatedAt.Before(current.UpdatedAt) {
			updatedAt = current.UpdatedAt
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_agent_gaps SET
			from_sequence=$1,to_sequence=$2,count=$3,from_at=$4,to_at=$5,updated_at=$6
			WHERE tenant_id=$7 AND gap_id=$8`,
			fromSeq, toSeq, int64(gap.Count), gap.FromAt.UTC(), gap.ToAt.UTC(), updatedAt,
			tenant.String(), gap.GapID.String()); err != nil {
			return fmt.Errorf("extend telemetry agent gap: %w", err)
		}
		return nil
	})
}
